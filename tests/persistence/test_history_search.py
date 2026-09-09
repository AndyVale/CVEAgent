import sqlite3

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


def test_cursor_pages_are_stable_across_concurrent_insertions_and_updates(tmp_path):
    path = tmp_path / 'history.sqlite3'
    original_ids = [persisted_analysis(path, cve_id=f'CVE-2025-{1000 + index}')[0] for index in range(5)]
    repository = AnalysisRepository(path)

    first = repository.list_analysis_page(limit=2)
    inserted, _, _ = persisted_analysis(path, cve_id='CVE-2026-9999')
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE analyses SET updated_at='2099-01-01T00:00:00+00:00' WHERE run_id=1"
        )
        connection.execute(
            """INSERT INTO analyses(
                run_id,input_position,cve_id,status,error,label_ids_json,
                created_at,updated_at,completed_at
            ) VALUES(1,1,'CVE-2025-0999','classified',NULL,'[]',?,?,?)""",
            ('2026-09-09T00:00:00+00:00',) * 3,
        )
    second = repository.list_analysis_page(limit=2, cursor=first.next_cursor)
    third = repository.list_analysis_page(limit=2, cursor=second.next_cursor)

    seen = [item.analysis_id for page in (first, second, third) for item in page.analyses]
    assert seen == list(reversed(original_ids))
    assert inserted not in seen
    assert '1:1' not in seen
    assert len(seen) == len(set(seen))
    assert third.next_cursor is None


def test_cursor_search_preserves_exact_priority_and_repeated_analyses(tmp_path):
    path = tmp_path / 'history.sqlite3'
    exact_ids = [persisted_analysis(path, cve_id='CVE-2020-2889')[0] for _ in range(2)]
    partial, _, _ = persisted_analysis(path, cve_id='CVE-2020-28890')
    repository = AnalysisRepository(path)

    first = repository.list_analysis_page(
        limit=1, search=HistorySearch('cve-2020-2889'),
    )
    second = repository.list_analysis_page(
        limit=1, cursor=first.next_cursor, search=HistorySearch('cve-2020-2889'),
    )
    third = repository.list_analysis_page(
        limit=1, cursor=second.next_cursor, search=HistorySearch('cve-2020-2889'),
    )

    assert [first.analyses[0].analysis_id, second.analyses[0].analysis_id] == list(
        reversed(exact_ids)
    )
    assert third.analyses[0].analysis_id == partial
    assert third.next_cursor is None


def test_cursor_boundaries_ties_and_invalid_values(tmp_path):
    path = tmp_path / 'history.sqlite3'
    persisted_analysis(path, cve_id='CVE-2020-2889')
    repository = AnalysisRepository(path)
    empty = repository.list_analysis_page(limit=10, search=HistorySearch('missing'))
    single = repository.list_analysis_page(limit=1)

    assert empty.analyses == () and empty.next_cursor is None
    assert len(single.analyses) == 1 and single.next_cursor is None
    for cursor in ['invalid', 'e30', '%%%']:
        with pytest.raises(ValueError, match='invalid history cursor'):
            repository.list_analysis_page(cursor=cursor)

    for _ in range(2):
        persisted_analysis(path, cve_id='CVE-2020-2889')
    page = repository.list_analysis_page(limit=1, search=HistorySearch('2889'))
    with pytest.raises(ValueError, match='invalid history cursor'):
        repository.list_analysis_page(
            cursor=page.next_cursor,
            search=HistorySearch('2020'),
        )
