from cve_agent.core.history import StoredAnalysis
from cve_agent.core.ports import ResultLookup


class ResultCache:
    """Reuse only terminal successful results with identical input snapshots."""

    def __init__(self, repository: ResultLookup):
        self.repository = repository

    def find_cached(self, *, cve_id: str, taxonomy_fingerprint: str, settings_fingerprint_value: str) -> StoredAnalysis | None:
        return self.repository.find_result(
            cve_id=cve_id, taxonomy_fingerprint=taxonomy_fingerprint,
            settings_fingerprint_value=settings_fingerprint_value,
            accepted_statuses=("classified", "no_matching_label", "not_enough_information"),
        )
