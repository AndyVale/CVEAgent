import logging
import threading
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

    def run(cve_ids, taxonomy):
        if failure == 'provider':
            raise RuntimeError('fixture-credential unavailable')
        return ApplicationRun((ClassificationResult(cve_ids[0], 'classified', operational={'run_id': 1}),))

    def save_events(*args):
        raise PersistenceError('fixture-credential event write failed')

    logger = logging.getLogger('cve_agent')
    previous = (logger.level, logger.propagate, tuple(logger.handlers))
    jobs = AnalysisJobs(lambda _: SimpleNamespace(run=run), lambda: SimpleNamespace(save_events=save_events), threading.RLock(), ImmediateExecutor())
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
        assert stored == '1:0'
        warning = jobs.progress_warning(queued['id'])
        assert warning['tone'] == 'warning'
        assert 'fixture-credential' not in warning['message']
        assert '[REDACTED]' in warning['message']
    assert (logger.level, logger.propagate, tuple(logger.handlers)) == previous


def test_rejected_submission_does_not_leave_an_active_job():
    class RejectingExecutor:
        def submit(self, *args):
            raise RuntimeError('executor unavailable')

    jobs = AnalysisJobs(lambda _: None, lambda: None, threading.RLock(), RejectingExecutor())
    configuration = SimpleNamespace(taxonomy_name='Fixture', taxonomy=SimpleNamespace(labels=[]))
    with pytest.raises(RuntimeError, match='executor unavailable'):
        jobs.submit('CVE-2026-0001', configuration)
    assert not jobs.has_active()
    assert not jobs._running
