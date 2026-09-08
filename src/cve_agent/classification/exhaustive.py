from __future__ import annotations

from dataclasses import asdict
from typing import Callable
import json
import logging

from cve_agent.classification.context import profile_evidence
from cve_agent.classification.contracts import TaxonomyScanOutcome
from cve_agent.classification.prompts import CLASSIFICATION_SYSTEM_PROMPT
from cve_agent.classification.responses import ClassificationResponseError
from cve_agent.classification.responses import decode_json_content
from cve_agent.classification.responses import supported_labels
from cve_agent.classification.schemas import classification_response_format
from cve_agent.classification.taxonomy import TaxonomyChunk, label_dict, normalize_label_references
from cve_agent.classification.validation import normalize_classification_labels, validate_classification
from cve_agent.core.investigation import InvestigationState, InvestigationStopReason
from cve_agent.core.results import LabelClassification
from cve_agent.core.sources import CVERecord
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.budget import BudgetExceeded, TokenBudget
from cve_agent.runtime.diagnostics import LogTone, log_extra
from cve_agent.runtime.ports import ModelCall


logger = logging.getLogger("cve_agent.taxonomy_scan")


class ExhaustiveTaxonomyScanner:
    """Evaluate every taxonomy chunk and checkpoint each validated result."""

    def __init__(
        self,
        chat: ModelCall,
        chunks: tuple[TaxonomyChunk, ...],
        *,
        tool_name: str = "classify_taxonomy_chunk",
    ):
        self.chat = chat
        self.chunks = chunks
        self.tool_name = tool_name
        self.request_count = 0

    def scan(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> TaxonomyScanOutcome:
        chunks = self.chunks
        tool_name = self.tool_name
        candidates: list[LabelClassification] = []
        completed_chunks = 0
        evaluated_ids: list[str] = []
        all_ids = [label.id for label in taxonomy.labels]
        requests_before = self.request_count
        logger.info(
            "[%s] classification scan started chunks=%d labels=%d findings=%d evidence=%d",
            cve.cve_id,
            len(chunks),
            len(taxonomy.labels),
            len(state.findings),
            len(state.evidence),
            extra=log_extra(section=True),
        )
        for position, chunk in enumerate(chunks, start=1):
            logger.info(
                "[%s] classification chunk started chunk=%d/%d chunk_id=%d labels=%d",
                cve.cve_id,
                position,
                len(chunks),
                chunk.chunk_id,
                len(chunk.labels),
            )
            try:
                supported = self._classify_chunk(cve, chunk, state, budget)
            except BudgetExceeded as exc:
                self._checkpoint_error(chunk, state, budget, checkpoint, str(exc), tool_name)
                logger.warning(
                    "[%s] classification scan stopped reason=%s chunk_id=%d completed_chunks=%d",
                    cve.cve_id,
                    InvestigationStopReason.TOKEN_BUDGET.value,
                    chunk.chunk_id,
                    completed_chunks,
                )
                return TaxonomyScanOutcome(
                    candidates=tuple(candidates),
                    evaluated_ids=tuple(evaluated_ids),
                    unresolved_ids=tuple(label_id for label_id in all_ids if label_id not in evaluated_ids),
                    classification_requests=self.request_count - requests_before,
                    stop_reason=InvestigationStopReason.TOKEN_BUDGET,
                    error=str(exc),
                )
            except ClassificationResponseError as exc:
                self._checkpoint_error(chunk, state, budget, checkpoint, str(exc), tool_name)
                logger.error(
                    "[%s] classification scan stopped reason=%s chunk_id=%d completed_chunks=%d detail=%s",
                    cve.cve_id,
                    InvestigationStopReason.CLASSIFICATION_ERROR.value,
                    chunk.chunk_id,
                    completed_chunks,
                    str(exc),
                )
                return TaxonomyScanOutcome(
                    candidates=tuple(candidates),
                    evaluated_ids=tuple(evaluated_ids),
                    unresolved_ids=tuple(label_id for label_id in all_ids if label_id not in evaluated_ids),
                    classification_requests=self.request_count - requests_before,
                    stop_reason=InvestigationStopReason.CLASSIFICATION_ERROR,
                    error=str(exc),
                )

            candidates.extend(supported)
            completed_chunks += 1
            evaluated_ids.extend(label.id for label in chunk.labels)
            state.tool_history.append({
                "tool": tool_name,
                "status": "success",
                "chunk_id": chunk.chunk_id,
                "label_count": len(chunk.labels),
                "supported_count": len(supported),
            })
            state.token_usage = budget.to_dict()
            checkpoint()
            logger.info(
                "[%s] classification chunk accepted chunk_id=%d supported=%d supported_labels=%s completed_chunks=%d/%d",
                cve.cve_id,
                chunk.chunk_id,
                len(supported),
                _label_summary(supported),
                completed_chunks,
                len(chunks),
            )

        logger.info(
            "[%s] classification scan finished completed_chunks=%d labels_evaluated=%d candidates=%d",
            cve.cve_id,
            completed_chunks,
            len(evaluated_ids),
            len(candidates),
            extra=log_extra(LogTone.SUCCESS),
        )
        return TaxonomyScanOutcome(
            candidates=tuple(candidates),
            evaluated_ids=tuple(evaluated_ids),
            classification_requests=self.request_count - requests_before,
        )

    def _classify_chunk(
        self,
        cve: CVERecord,
        chunk: TaxonomyChunk,
        state: InvestigationState,
        budget: TokenBudget,
    ) -> list[LabelClassification]:
        selected_evidence = profile_evidence(state)
        payload = {
            "vulnerability_profile": {
                "cve_id": cve.cve_id,
                "information_status": state.research_information_status,
                "findings": [asdict(item) for item in state.findings],
            },
            "evidence": [asdict(item) for item in selected_evidence],
            "taxonomy_chunk": {
                "chunk_id": chunk.chunk_id,
                "labels": [label_dict(item) for item in chunk.labels],
            },
        }
        messages = [
            {"role": "system", "content": CLASSIFICATION_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]
        allowed = {item.id for item in chunk.labels}
        chunk_taxonomy = Taxonomy(tuple(chunk.labels))
        for correction_attempt in range(2):
            self.request_count += 1
            response = self.chat(
                cve.cve_id,
                budget,
                "classification",
                messages=messages,
                response_format=classification_response_format(),
            )
            try:
                supported = supported_labels(decode_json_content(response), chunk.chunk_id)
                supported, replacements = normalize_label_references(supported, chunk.labels)
                for reference, label_id in replacements:
                    logger.warning(
                        "[%s] normalized taxonomy label reference from name=%r to id=%r chunk_id=%d",
                        cve.cve_id,
                        reference,
                        label_id,
                        chunk.chunk_id,
                    )
                outside = [
                    item.get("label") if isinstance(item, dict) else item
                    for item in supported
                    if not isinstance(item, dict) or item.get("label") not in allowed
                ]
                if outside:
                    raise ValueError(f"taxonomy chunk returned labels outside its chunk: {outside}")
                normalized = normalize_classification_labels(supported)
                if not normalized:
                    return []
                _, materialized = validate_classification(
                    "classified",
                    normalized,
                    chunk_taxonomy,
                    selected_evidence,
                )
                return materialized
            except ValueError as exc:
                if correction_attempt:
                    raise ClassificationResponseError(str(exc)) from exc
                logger.warning(
                    "[%s] classification chunk invalid chunk_id=%d correction=1/1 detail=%s",
                    cve.cve_id,
                    chunk.chunk_id,
                    str(exc),
                )
                messages.extend([
                    {"role": "assistant", "content": response.choices[0].message.content or ""},
                    {"role": "user", "content": f"The response was invalid: {exc}. Return a corrected JSON object for this same chunk."},
                ])
        raise AssertionError("unreachable")

    @staticmethod
    def _checkpoint_error(
        chunk: TaxonomyChunk,
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
        error: str,
        tool_name: str,
    ) -> None:
        state.tool_history.append({
            "tool": tool_name,
            "status": "error",
            "chunk_id": chunk.chunk_id,
            "label_count": len(chunk.labels),
            "error": error[:500],
        })
        state.token_usage = budget.to_dict()
        checkpoint()


def _label_summary(labels: list[LabelClassification], limit: int = 8) -> str:
    identifiers = [item.label for item in labels]
    if not identifiers:
        return "none"
    shown = ",".join(identifiers[:limit])
    return shown if len(identifiers) <= limit else f"{shown},…(+{len(identifiers) - limit})"
