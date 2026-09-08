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
def test_failed_job_remains_visible_and_restores_logging(tmp_path, failure):
    configured = replace(settings(tmp_path), api_key='fixture-credential')
    taxonomy = Taxonomy((TaxonomyLabel('A', 'A', 'Definition.'),))
    configuration = AnalysisConfiguration(configured, taxonomy, tmp_path / 'taxonomy.json', 'Fixture', taxonomy.fingerprint, 'settings')

    def run(cve_ids, taxonomy):
        if failure == 'provider':
            raise RuntimeError('fixture-credential unavailable')
        return ApplicationRun((ClassificationResult(cve_ids[0], 'classified', operational={'run_id': 1}),))

    def save_events(*args):
        raise PersistenceError('event write failed')

    logger = logging.getLogger('cve_agent')
    previous = (logger.level, logger.propagate, tuple(logger.handlers))
    jobs = AnalysisJobs(lambda _: SimpleNamespace(run=run), lambda: SimpleNamespace(save_events=save_events), threading.RLock(), ImmediateExecutor())
    queued = jobs.submit('CVE-2026-0001', configuration)
    running, stored = jobs.lookup(queued['id'])
    snapshot = running.snapshot()

    assert snapshot['lifecycle'] == 'failed'
    assert stored is None
    assert not jobs.has_active()
    assert 'fixture-credential' not in str(snapshot)
    if failure == 'provider':
        assert '[REDACTED]' in snapshot['error']
    else:
        assert snapshot['error'] == 'event write failed'
    assert (logger.level, logger.propagate, tuple(logger.handlers)) == previous
