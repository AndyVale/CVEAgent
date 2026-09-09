from __future__ import annotations

from typing import Any
import logging

from cve_agent.core.errors import PersistenceError
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.ports import AnalysisProgress, AnalysisWriter, CVESource, Classifier
from cve_agent.core.results import ClassificationResult, ClassificationStatus
from cve_agent.core.sources import EvidenceRecord
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.diagnostics import LogTone, log_extra


logger = logging.getLogger("cve_agent.pipeline")


class Pipeline:
    def __init__(self, cve_source: CVESource, classifier: Classifier, database: AnalysisWriter, *, run_metadata: dict[str, Any] | None = None):
        self.cve_source = cve_source
        self.classifier = classifier
        self.database = database
        self.run_metadata = run_metadata or {"model": "injected", "settings": {}}

    def run(
        self,
        cve_ids: list[str],
        taxonomy: Taxonomy,
        *,
        progress: AnalysisProgress | None = None,
    ) -> list[ClassificationResult]:
        results: list[ClassificationResult] = []
        preflight = getattr(self.classifier, "preflight", None)
        if preflight is not None:
            preflight(taxonomy)
        database_context = self.database
        db = database_context.__enter__()
        primary_failure: BaseException | None = None
        try:
            run_id = db.start_run(
                taxonomy=taxonomy,
                model=str(self.run_metadata.get("model", "unknown")),
                settings=dict(self.run_metadata.get("settings", {})),
            )
            try:
                for input_position, cve_id in enumerate(cve_ids):
                    state = InvestigationState()
                    db.save_investigation(
                        run_id,
                        input_position,
                        cve_id,
                        "investigating",
                        state,
                    )
                    if progress is not None:
                        try:
                            progress.bind(f"{run_id}:{input_position}", cve_id)
                        except Exception as exc:
                            logger.error(
                                "[%s] progress target could not bind run_id=%d "
                                "error_type=%s",
                                cve_id,
                                run_id,
                                type(exc).__name__,
                            )
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
            except BaseException as exc:
                try:
                    db.finish_run(run_id, "failed")
                except BaseException as cleanup_exc:
                    _log_secondary_failure(
                        operation="marking the run failed",
                        primary=exc,
                        secondary=cleanup_exc,
                        run_id=run_id,
                    )
                raise
        except BaseException as exc:
            primary_failure = exc
            raise
        finally:
            try:
                database_context.__exit__(
                    type(primary_failure) if primary_failure is not None else None,
                    primary_failure,
                    primary_failure.__traceback__ if primary_failure is not None else None,
                )
            except BaseException as cleanup_exc:
                if primary_failure is None:
                    raise
                _log_secondary_failure(
                    operation="closing the analysis writer",
                    primary=primary_failure,
                    secondary=cleanup_exc,
                    run_id=None,
                )
        return results


def _log_secondary_failure(
    *,
    operation: str,
    primary: BaseException,
    secondary: BaseException,
    run_id: int | None,
) -> None:
    logger.error(
        "secondary cleanup failure while %s%s; original failure preserved "
        "primary_type=%s cleanup_type=%s",
        operation,
        f" run_id={run_id}" if run_id is not None else "",
        type(primary).__name__,
        type(secondary).__name__,
    )
