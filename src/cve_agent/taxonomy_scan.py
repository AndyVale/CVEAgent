from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any, Callable

from cve_agent.budget import BudgetExceeded, TokenBudget
from cve_agent.classification import TaxonomyChunk, label_dict
from cve_agent.models import MAX_INVESTIGATION_FINDINGS, CVERecord, EvidenceRecord, InvestigationState, InvestigationStopReason, LabelClassification
from cve_agent.prompts import CLASSIFICATION_SYSTEM_PROMPT
from cve_agent.schemas import classification_response_format
from cve_agent.taxonomy import Taxonomy
from cve_agent.validation import normalize_classification_labels, validate_classification


logger = logging.getLogger(__name__)


class ClassificationResponseError(ValueError):
    """A taxonomy-chunk response remained invalid after its correction attempt."""


@dataclass(frozen=True)
class TaxonomyScanOutcome:
    candidates: tuple[LabelClassification, ...]
    completed_chunks: int
    evaluated_labels: int
    stop_reason: InvestigationStopReason | None = None
    error: str | None = None


class TaxonomyScanner:
    """Evaluate every taxonomy chunk and checkpoint each validated result."""

    def __init__(self, chat: Callable[..., Any]):
        self.chat = chat

    def scan(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        chunks: tuple[TaxonomyChunk, ...],
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> TaxonomyScanOutcome:
        candidates: list[LabelClassification] = []
        completed_chunks = evaluated_labels = 0
        logger.info(
            "[%s] classification scan started chunks=%d labels=%d findings=%d evidence=%d",
            cve.cve_id,
            len(chunks),
            len(taxonomy.labels),
            len(state.findings),
            len(state.evidence),
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
                self._checkpoint_error(chunk, state, budget, checkpoint, str(exc))
                logger.warning(
                    "[%s] classification scan stopped reason=%s chunk_id=%d completed_chunks=%d",
                    cve.cve_id,
                    InvestigationStopReason.TOKEN_BUDGET.value,
                    chunk.chunk_id,
                    completed_chunks,
                )
                return TaxonomyScanOutcome(
                    tuple(candidates),
                    completed_chunks,
                    evaluated_labels,
                    InvestigationStopReason.TOKEN_BUDGET,
                    str(exc),
                )
            except ClassificationResponseError as exc:
                self._checkpoint_error(chunk, state, budget, checkpoint, str(exc))
                logger.error(
                    "[%s] classification scan stopped reason=%s chunk_id=%d completed_chunks=%d detail=%s",
                    cve.cve_id,
                    InvestigationStopReason.CLASSIFICATION_ERROR.value,
                    chunk.chunk_id,
                    completed_chunks,
                    str(exc),
                )
                return TaxonomyScanOutcome(
                    tuple(candidates),
                    completed_chunks,
                    evaluated_labels,
                    InvestigationStopReason.CLASSIFICATION_ERROR,
                    str(exc),
                )

            candidates.extend(supported)
            completed_chunks += 1
            evaluated_labels += len(chunk.labels)
            state.tool_history.append({
                "tool": "classify_taxonomy_chunk",
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
            evaluated_labels,
            len(candidates),
        )
        return TaxonomyScanOutcome(tuple(candidates), completed_chunks, evaluated_labels)

    def _classify_chunk(
        self,
        cve: CVERecord,
        chunk: TaxonomyChunk,
        state: InvestigationState,
        budget: TokenBudget,
    ) -> list[LabelClassification]:
        profile_evidence = _profile_evidence(state)
        payload = {
            "vulnerability_profile": {
                "cve_id": cve.cve_id,
                "information_status": state.research_information_status,
                "findings": [asdict(item) for item in state.findings],
            },
            "evidence": [asdict(item) for item in profile_evidence],
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
            response = self.chat(
                cve.cve_id,
                budget,
                "classification",
                messages=messages,
                response_format=classification_response_format(),
            )
            try:
                supported = _supported_labels(_decode_json_content(response), chunk.chunk_id)
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
                    profile_evidence,
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
    ) -> None:
        state.tool_history.append({
            "tool": "classify_taxonomy_chunk",
            "status": "error",
            "chunk_id": chunk.chunk_id,
            "label_count": len(chunk.labels),
            "error": error[:500],
        })
        state.token_usage = budget.to_dict()
        checkpoint()


def _decode_json_content(response: Any) -> dict[str, Any] | list[Any]:
    content = (response.choices[0].message.content or "").strip()
    if "</think>" in content:
        content = content.rsplit("</think>", 1)[1].strip()
    content = content.removeprefix("```json").removesuffix("```").strip()
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("provider returned non-JSON classification content") from exc
    if not isinstance(decoded, (dict, list)):
        raise ValueError("classification response must be a JSON object or array")
    return decoded


def _supported_labels(decoded: dict[str, Any] | list[Any], chunk_id: int) -> list[Any]:
    if isinstance(decoded, list):
        return decoded
    returned_chunk_id = decoded.get("chunk_id", chunk_id)
    if returned_chunk_id != chunk_id:
        raise ValueError(f"classifier returned chunk_id {returned_chunk_id!r}, expected {chunk_id}")
    supported = decoded.get("supported")
    if supported is None:
        supported = decoded.get("supported_labels", decoded.get("labels"))
    if not isinstance(supported, list):
        raise ValueError("taxonomy chunk response requires a supported array")
    return supported


def _profile_evidence(state: InvestigationState) -> list[EvidenceRecord]:
    evidence_ids = {evidence_id for finding in state.findings for evidence_id in finding.evidence_ids}
    selected = [item for item in state.evidence if item.evidence_id in evidence_ids]
    if selected:
        return selected
    return _fallback_evidence(state.evidence)


def _fallback_evidence(evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
    """Preserve bounded raw evidence when research stops before producing findings."""
    if len(evidence) <= MAX_INVESTIGATION_FINDINGS:
        return list(evidence)
    nvd = next((item for item in evidence if item.source_type == "nvd_description"), None)
    remaining = [item for item in evidence if item is not nvd]
    selected = remaining[-(MAX_INVESTIGATION_FINDINGS - int(nvd is not None)):]
    return ([nvd] if nvd else []) + selected


def _label_summary(labels: list[LabelClassification], limit: int = 8) -> str:
    identifiers = [item.label for item in labels]
    if not identifiers:
        return "none"
    shown = ",".join(identifiers[:limit])
    return shown if len(identifiers) <= limit else f"{shown},…(+{len(identifiers) - limit})"
