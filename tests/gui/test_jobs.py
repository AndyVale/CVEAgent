import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cve_agent.application.service import ApplicationRun
from cve_agent.core.errors import PersistenceError
from cve_agent.core.results import ClassificationResult
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.gui.configuration import AnalysisConfiguration
from cve_agent.gui.jobs import AnalysisJobs
from tests.support.agent import settings


class ImmediateExecutor:
    def submit(self, function, *args):
        function(*args)


@pytest.mark.parametrize('failure', ['provider', 'events'])
def test_job_failure_handling_preserves_outcome_and_restores_logging(tmp_path, failure):
    configured = replace(settings(tmp_path), api_key='fixture-credential')
    taxonomy = Taxonomy((TaxonomyLabel('A', 'A', 'Definition.'),))
    configuration = AnalysisConfiguration(configured, taxonomy, tmp_path / 'taxonomy.json', 'Fixture', taxonomy.fingerprint, 'settings')

    def run(cve_ids, taxonomy, **kwargs):
        if failure == 'provider':
            raise RuntimeError('fixture-credential unavailable')
        return ApplicationRun((ClassificationResult(cve_ids[0], 'classified', operational={'run_id': 1}),))

    def save_events(*args, **kwargs):
        raise PersistenceError('fixture-credential event write failed')

    logger = logging.getLogger('cve_agent')
    previous = (logger.level, logger.propagate, tuple(logger.handlers))
    repository = SimpleNamespace(save_events=save_events)
    jobs = AnalysisJobs(lambda _: SimpleNamespace(run=run), lambda _path: repository, threading.RLock(), ImmediateExecutor())
    queued = jobs.submit('CVE-2026-0001', configuration)
    running, stored = jobs.lookup(queued['id'])
    assert not jobs.has_active()
    if failure == 'provider':
        snapshot = running.snapshot()
        assert snapshot['lifecycle'] == 'failed'
        assert stored is None
        assert 'fixture-credential' not in str(snapshot)
        assert '[REDACTED]' in snapshot['error']
    else:
        # Event persistence is auxiliary: the completed classification remains accessible.
        assert running is None
        assert stored.analysis_id == '1:0'
        assert stored.database_path == configured.database.resolve()
        warning = jobs.progress_warning(queued['id'])
        assert warning['tone'] == 'warning'
        assert 'fixture-credential' not in warning['message']
        assert '[REDACTED]' in warning['message']
    assert (logger.level, logger.propagate, tuple(logger.handlers)) == previous


def test_rejected_submission_does_not_leave_an_active_job(tmp_path):
    class RejectingExecutor:
        def submit(self, *args):
            raise RuntimeError('executor unavailable')

    jobs = AnalysisJobs(lambda _: None, lambda _path: None, threading.RLock(), RejectingExecutor())
    configuration = SimpleNamespace(taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]), settings=settings(tmp_path), taxonomy_fingerprint='taxonomy', settings_fingerprint='settings')
    with pytest.raises(RuntimeError, match='executor unavailable'):
        jobs.submit('CVE-2026-0001', configuration)
    assert not jobs.has_active()
    assert not jobs._running
    assert not jobs._active


class QueuedExecutor:
    def __init__(self):
        self.calls = []

    def submit(self, function, *args):
        self.calls.append((function, args))


def test_concurrent_identical_submissions_share_one_job(tmp_path):
    executor = QueuedExecutor()
    jobs = AnalysisJobs(lambda _: None, lambda _path: None, threading.RLock(), executor)
    configuration = SimpleNamespace(taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]),
                                    settings=settings(tmp_path), taxonomy_fingerprint='taxonomy', settings_fingerprint='settings')
    with ThreadPoolExecutor(max_workers=8) as callers:
        results = list(callers.map(lambda _: jobs.submit('CVE-2020-2889', configuration), range(20)))
    assert len({result['id'] for result in results}) == 1
    assert sum(not result['already_running'] for result in results) == 1
    assert len(executor.calls) == 1
    running, _ = jobs.lookup(results[0]['id'])
    running.lifecycle = 'running'
    assert jobs.submit('CVE-2020-2889', configuration)['lifecycle'] == 'running'


@pytest.mark.parametrize('difference', ['cve', 'taxonomy', 'settings', 'database'])
def test_different_analysis_keys_are_not_deduplicated(tmp_path, difference):
    executor = QueuedExecutor()
    jobs = AnalysisJobs(lambda _: None, lambda _path: None, threading.RLock(), executor)
    configuration = SimpleNamespace(taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]),
                                    settings=settings(tmp_path), taxonomy_fingerprint='taxonomy', settings_fingerprint='settings')
    first = jobs.submit('CVE-2020-2889', configuration)
    other = SimpleNamespace(**vars(configuration))
    cve = 'CVE-2020-2889'
    if difference == 'cve':
        cve = 'CVE-2020-2890'
    elif difference == 'database':
        other.settings = replace(configuration.settings, database=tmp_path / 'other.sqlite')
    else:
        setattr(other, f'{difference}_fingerprint', 'different')
    second = jobs.submit(cve, other)
    assert first['id'] != second['id']
    assert len(executor.calls) == 2


def test_failed_job_releases_key_for_retry(tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError('provider unavailable')

    jobs = AnalysisJobs(lambda _: SimpleNamespace(run=fail), lambda _path: None, threading.RLock(), ImmediateExecutor())
    configuration = SimpleNamespace(taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]),
                                    settings=settings(tmp_path), taxonomy_fingerprint='taxonomy', settings_fingerprint='settings')
    first = jobs.submit('CVE-2020-2889', configuration)
    second = jobs.submit('CVE-2020-2889', configuration)
    assert first['id'] != second['id']
    assert not jobs._active


def test_progress_is_persisted_incrementally_with_stable_sequences(tmp_path):
    calls = []

    class Repository:
        def save_events(self, analysis_id, events, *, start_sequence=0):
            calls.append((analysis_id, start_sequence, [event['message'] for event in events]))

    class App:
        def run(self, cve_ids, taxonomy, *, progress=None):
            progress.bind('7:0', cve_ids[0])
            logging.getLogger('cve_agent.fixture').info('durable mid-run progress')
            assert any('durable mid-run progress' in messages for _, _, messages in calls)
            return ApplicationRun((ClassificationResult(
                cve_ids[0], 'classified', operational={'run_id': 7},
            ),))

    configured = settings(tmp_path)
    taxonomy = Taxonomy((TaxonomyLabel('A', 'A', 'Definition.'),))
    configuration = AnalysisConfiguration(
        configured, taxonomy, tmp_path / 'taxonomy.json', 'Fixture', taxonomy.fingerprint, 'settings',
    )
    jobs = AnalysisJobs(
        lambda _: App(), lambda _path: Repository(), threading.RLock(), ImmediateExecutor(),
    )

    pending = jobs.submit('CVE-2026-0001', configuration)['id']

    _, completed = jobs.lookup(pending)
    assert completed.analysis_id == '7:0'
    incremental = [(start, messages) for _, start, messages in calls if start > 0]
    assert incremental
    assert [start for start, _ in incremental] == sorted(start for start, _ in incremental)


def test_progress_capture_isolates_concurrent_runs(tmp_path):
    from cve_agent.gui.progress import capture_progress

    class Sink:
        def __init__(self):
            self.messages = []

        def add_event(self, **event):
            self.messages.append(event['message'])

    barrier = threading.Barrier(2)
    sinks = [Sink(), Sink()]

    def emit(index):
        with capture_progress(sinks[index], settings(tmp_path)):
            barrier.wait()
            logging.getLogger('cve_agent.fixture').info('event-from-%d', index)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(emit, range(2)))

    assert sinks[0].messages == ['event-from-0']
    assert sinks[1].messages == ['event-from-1']


def test_terminal_job_retention_is_bounded_for_completed_and_failed_jobs(tmp_path):
    def fail_event_storage(*args, **kwargs):
        raise PersistenceError('event storage unavailable')

    repository = SimpleNamespace(save_events=fail_event_storage)
    run_ids = iter(range(1, 10))

    def completed(cve_ids, taxonomy, **kwargs):
        run_id = next(run_ids)
        return ApplicationRun((ClassificationResult(
            cve_ids[0], 'classified', operational={'run_id': run_id},
        ),))

    configuration = SimpleNamespace(
        taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]), settings=settings(tmp_path),
        taxonomy_fingerprint='taxonomy', settings_fingerprint='settings',
    )
    jobs = AnalysisJobs(
        lambda _: SimpleNamespace(run=completed),
        lambda _path: repository,
        threading.RLock(),
        ImmediateExecutor(),
        terminal_retention=2,
    )
    completed_ids = [
        jobs.submit(f'CVE-2026-{1000 + index}', configuration)['id']
        for index in range(3)
    ]
    assert jobs.lookup(completed_ids[0]) == (None, None)
    assert jobs.progress_warning(completed_ids[0]) is None
    assert jobs.lookup(completed_ids[-1])[1] is not None
    assert jobs.progress_warning(completed_ids[-1]) is not None
    assert len(jobs._terminal) == 2

    def failed(*args, **kwargs):
        raise RuntimeError('provider unavailable')

    failed_jobs = AnalysisJobs(
        lambda _: SimpleNamespace(run=failed),
        lambda _path: repository,
        threading.RLock(),
        ImmediateExecutor(),
        terminal_retention=2,
    )
    failed_ids = [
        failed_jobs.submit(f'CVE-2027-{1000 + index}', configuration)['id']
        for index in range(3)
    ]
    assert failed_jobs.lookup(failed_ids[0]) == (None, None)
    assert failed_jobs.lookup(failed_ids[-1])[0].lifecycle == 'failed'
    assert len(failed_jobs._terminal) == 2
