from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from cve_agent.models import ClassificationResult, ClassificationStatus, EvidenceRecord, InvestigationState
from cve_agent.logging_config import LogTone, log_extra
from cve_agent.persistence import Database, PersistenceError
from cve_agent.ports import CVESource, Classifier
from cve_agent.taxonomy import Taxonomy


logger = logging.getLogger(__name__)


def persisted_taxonomy_fingerprint(taxonomy: Taxonomy) -> str:
    """Return the fingerprint format stored in run metadata."""
    taxonomy_json = json.dumps(taxonomy.to_dict(), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(taxonomy_json.encode()).hexdigest()


class Pipeline:
    def __init__(self, cve_source: CVESource, classifier: Classifier, database: Database, *, run_metadata: dict[str, Any] | None = None):
        self.cve_source = cve_source
        self.classifier = classifier
        self.database = database
        self.run_metadata = run_metadata or {"model": "injected", "settings": {}}

    def run(self, cve_ids: list[str], taxonomy: Taxonomy) -> list[ClassificationResult]:
        results: list[ClassificationResult] = []
        preflight = getattr(self.classifier, "preflight", None)
        if preflight is not None:
            preflight(taxonomy)
        with self.database as db:
            run_id = db.start_run(
                taxonomy_sha256=persisted_taxonomy_fingerprint(taxonomy),
                model=str(self.run_metadata.get("model", "unknown")),
                settings=dict(self.run_metadata.get("settings", {})),
            )
            try:
                for input_position, cve_id in enumerate(cve_ids):
                    state = InvestigationState()
                    logger.info(
                        "[%s] starting investigation run_id=%d input=%d/%d",
                        cve_id,
                        run_id,
                        input_position + 1,
                        len(cve_ids),
                        extra=log_extra(section=True),
                    )
                    try:
                        cve = self.cve_source.get_cve(cve_id)
                        logger.info("[%s] NVD evidence initialized description_chars=%d references=%d", cve_id, len(cve.description), len(cve.references))
                        state.facts.append(cve.description)
                        if cve.description.strip():
                            state.evidence.append(EvidenceRecord(
                                evidence_id="nvd-description",
                                url=f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
                                quote=cve.description,
                                source_type="nvd_description",
                                verification="exact",
                            ))
                        state.tool_history.append({"tool": "get_cve", "status": "success", "source": "NVD", "reference_count": len(cve.references)})
                        db.save_investigation(run_id, input_position, cve_id, "investigating", state)

                        def checkpoint() -> None:
                            db.save_investigation(run_id, input_position, cve_id, "investigating", state)

                        result = self.classifier.classify(cve, taxonomy, state, checkpoint=checkpoint)
                    except PersistenceError:
                        raise
                    except Exception as exc:
                        logger.exception("[%s] investigation failed", cve_id)
                        result = ClassificationResult(cve_id, ClassificationStatus.FAILED, error=str(exc))

                    result.operational.setdefault("run_id", run_id)
                    db.save_investigation(run_id, input_position, cve_id, result.status, state, result, result.error)
                    results.append(result)
                    logger.info(
                        "[%s] investigation persisted run_id=%d status=%s labels=%d coverage_complete=%s",
                        cve_id,
                        run_id,
                        result.status,
                        len(result.labels),
                        result.operational.get("coverage", {}).get("complete"),
                        extra=log_extra(
                            LogTone.ERROR
                            if result.status == ClassificationStatus.FAILED
                            else LogTone.INCOMPLETE
                            if result.status in {ClassificationStatus.PARTIAL, ClassificationStatus.NOT_ENOUGH_INFORMATION}
                            else LogTone.SUCCESS
                        ),
                    )
                run_status = "complete" if all(item.status != ClassificationStatus.FAILED for item in results) else "completed_with_failures"
                db.finish_run(run_id, run_status)
                logger.info(
                    "run_id=%d persisted status=%s results=%d",
                    run_id,
                    run_status,
                    len(results),
                    extra=log_extra(
                        LogTone.ERROR
                        if run_status == "completed_with_failures"
                        else LogTone.INCOMPLETE
                        if any(item.status in {ClassificationStatus.PARTIAL, ClassificationStatus.NOT_ENOUGH_INFORMATION} for item in results)
                        else LogTone.SUCCESS,
                        section=True,
                    ),
                )
            except Exception:
                db.finish_run(run_id, "failed")
                raise
        return results
