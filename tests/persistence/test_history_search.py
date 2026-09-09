import pytest

from cve_agent.core.history import HistorySearch
from cve_agent.persistence.repository import AnalysisRepository
from tests.persistence.test_repository import persisted_analysis


def test_history_search_matches_exact_and_partial_ids_before_pagination(tmp_path):
    path = tmp_path / 'history.sqlite3'
    old, _, _ = persisted_analysis(path, cve_id='CVE-2020-2889')
    for index in range(202):
        persisted_analysis(path, cve_id=f'CVE-2025-{1000 + index}')
    repository = AnalysisRepository(path)
    assert old not in {item.analysis_id for item in repository.list_analyses()}
    for query in ['2889', '2020', ' cve-2020-2889 ']:
        assert [item.analysis_id for item in repository.list_analyses(search=HistorySearch(query))] == [old]
    first = repository.list_analyses(limit=100)
    second = repository.list_analyses(limit=100, offset=100)
    assert not {item.analysis_id for item in first} & {item.analysis_id for item in second}
    assert len(repository.list_analyses(offset=200)) == 3


def test_history_search_prioritizes_exact_ids_and_treats_wildcards_literally(tmp_path):
    path = tmp_path / 'history.sqlite3'
    exact, _, _ = persisted_analysis(path, cve_id='CVE-2020-2889')
    persisted_analysis(path, cve_id='CVE-2020-28890')
    repository = AnalysisRepository(path)
    assert repository.list_analyses(search=HistorySearch('CVE-2020-2889'))[0].analysis_id == exact
    for query in ['%', '_', "' OR 1=1 --", 'missing']:
        assert repository.list_analyses(search=HistorySearch(query)) == []
    with pytest.raises(ValueError):
        repository.list_analyses(offset=-1)
