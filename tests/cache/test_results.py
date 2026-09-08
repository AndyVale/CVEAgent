from dataclasses import replace

import pytest

from cve_agent.cache.results import ResultCache
from cve_agent.core.config import settings_fingerprint
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.results import ClassificationResult
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.persistence.repository import AnalysisRepository
from cve_agent.persistence.writer import Database


@pytest.mark.parametrize('status,eligible', [
    ('classified', True), ('no_matching_label', True), ('not_enough_information', True),
    ('partial', False), ('failed', False),
])
def test_cache_eligibility_and_exact_snapshots(tmp_path, status, eligible):
    path = tmp_path / 'results.sqlite'
    taxonomy = Taxonomy((TaxonomyLabel('A', 'A', 'Original definition.'),))
    settings = {'model': 'fixture', 'temperature': 0.0}
    with Database(path) as writer:
        run_id = writer.start_run(taxonomy=taxonomy, model='fixture', settings=settings)
        result = ClassificationResult('CVE-2026-0001', status)
        writer.save_investigation(run_id, 0, result.cve_id, status, InvestigationState(), result)
        writer.finish_run(run_id, 'complete')

    cache = ResultCache(AnalysisRepository(path))
    query = dict(cve_id=result.cve_id, taxonomy_fingerprint=taxonomy.fingerprint,
                 settings_fingerprint_value=settings_fingerprint(settings))
    found = cache.find_cached(**query)
    assert (found is not None) == eligible
    if found:
        assert found.analysis_id == f'{run_id}:0'
        assert found.result['status'] == status
    assert cache.find_cached(**{**query, 'cve_id': 'CVE-2026-0002'}) is None
    changed_taxonomy = replace(taxonomy, labels=(TaxonomyLabel('A', 'A', 'Changed definition.'),))
    assert cache.find_cached(**{**query, 'taxonomy_fingerprint': changed_taxonomy.fingerprint}) is None
    changed_settings = settings_fingerprint({**settings, 'temperature': 0.5})
    assert cache.find_cached(**{**query, 'settings_fingerprint_value': changed_settings}) is None
