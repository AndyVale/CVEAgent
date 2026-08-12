from __future__ import annotations

from .models import ClassificationResult, InvestigationState
from .persistence import Database
from .ports import CVESource, Classifier, WebSource
from .taxonomy import Taxonomy


class Pipeline:
    def __init__(self, cve_source: CVESource, web_source: WebSource, classifier: Classifier, database: Database):
        self.cve_source, self.web_source, self.classifier, self.database = cve_source, web_source, classifier, database

    def run(self, cve_ids: list[str], taxonomy: Taxonomy) -> list[ClassificationResult]:
        results: list[ClassificationResult] = []
        with self.database as db:
            for cve_id in cve_ids:
                state = InvestigationState()
                try:
                    cve = self.cve_source.get_cve(cve_id)
                    state.facts.append(cve.description)
                    state.visited_urls.extend(ref.url for ref in cve.references)
                    result = self.classifier.classify(cve, [], taxonomy, state)
                    db.save(cve_id, result.status, state, result)
                except Exception as exc:  # isolate CVE failures; database errors escape from save
                    result = ClassificationResult(cve_id, "failed", error=str(exc))
                    db.save(cve_id, "failed", state, result, str(exc))
                results.append(result)
        return results
