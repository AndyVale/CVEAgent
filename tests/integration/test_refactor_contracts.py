"""Frozen pre-refactor contracts: update only for an intentional behavior change."""
from dataclasses import asdict, replace
from pathlib import Path
import copy
import hashlib
import json

import pytest

from cve_agent.application.coordinator import ClassificationCoordinator
from cve_agent.classification.hybrid import HybridTaxonomyScanner
from cve_agent.classification.prompts import CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.classification.schemas import classification_response_format, hierarchy_routing_response_format
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import CVERecord, Reference
from cve_agent.core.strategy import ClassificationStrategy
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.investigation.prompts import RESEARCH_SYSTEM_PROMPT
from cve_agent.investigation.schemas import AGENT_TOOLS, research_tools
from tests.support.agent import FixtureWeb, FullFlowClient, HybridFlowClient, FinishCorrectionClient, settings
from tests.support.routing import RoutingChat, PureHybridScanner, run_scan


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def capture(case, tmp_path, monkeypatch):
    monkeypatch.setattr('time.monotonic', lambda: 100.0)
    configured = replace(settings(tmp_path), token_budget=100_000)
    taxonomy = Taxonomy((TaxonomyLabel('MEMORY', 'Memory', 'Memory safety issue.'),))
    if case == 'hybrid':
        configured = replace(configured, classification_strategy=ClassificationStrategy.HYBRID)
        taxonomy = Taxonomy((TaxonomyLabel('MEMORY', 'Memory', 'Memory safety issue.'), TaxonomyLabel('COPY', 'Copy', 'Unchecked copy.', 'MEMORY')))
        client = HybridFlowClient()
    elif case == 'correction':
        client = FullFlowClient(malformed_first=True, malformed_chunk=True)
    elif case == 'finish_correction':
        client = FinishCorrectionClient(repeat_invalid=True)
    else:
        client = FullFlowClient(empty_chunk=case == 'empty')
    requests = []
    create = client.chat.completions.create
    def record_request(**request):
        requests.append(copy.deepcopy(request))
        return create(**request)
    client.chat.completions.create = record_request
    state = InvestigationState()
    checkpoints = []
    result = ClassificationCoordinator(configured, FixtureWeb(), client).classify(
        CVERecord('CVE-2026-0001', 'Memory corruption from unchecked aggregate input.', (Reference('https://fixture.test/advisory'),)),
        taxonomy, state, checkpoint=lambda: checkpoints.append(digest(state.to_dict())),
    )
    return {
        'requests': [digest(request) for request in requests],
        'result': json.loads(json.dumps(result.to_dict())),
        'state': digest(state.to_dict()),
        'checkpoints': checkpoints,
    }


def model_contract():
    return digest({
        'prompts': [RESEARCH_SYSTEM_PROMPT, CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT],
        'tools': AGENT_TOOLS,
        'dynamic_tools': [research_tools(()), research_tools(('doc-1', 'doc-2', 'doc-1'))],
        'classification': classification_response_format(),
        'routing': hierarchy_routing_response_format(),
    })


def baseline():
    return json.loads((Path(__file__).parents[1] / 'fixtures/refactor_contracts.json').read_text())


def test_model_facing_contract_is_unchanged():
    assert model_contract() == baseline()['model_contract']


@pytest.mark.parametrize('case', ['exhaustive', 'hybrid', 'correction', 'finish_correction', 'empty'])
def test_requests_results_and_checkpoints_match_before_refactor(case, tmp_path, monkeypatch):
    assert capture(case, tmp_path, monkeypatch) == baseline()[case]


def capture_routing(case, tmp_path):
    decisions = {
        'ROOT': ('supported', 0.9), 'OTHER': ('unsupported', 0.95),
        'CHILD': ('uncertain', 0.6), 'LEAF': ('supported', 0.9),
    }
    if case == 'uncertain':
        decisions.update(ROOT=('unsupported', 0.7), CHILD=('uncertain', 0.5), LEAF=('uncertain', 0.5))
    chat = RoutingChat(decisions, binary_supported=('LEAF',))
    scanner = HybridTaxonomyScanner if case == 'switch' else PureHybridScanner
    outcome, state, checkpoints = run_scan(tmp_path, scanner, chat)
    return {
        'requests': [digest(request) for request in chat.requests],
        'outcome': json.loads(json.dumps(asdict(outcome))),
        'state': digest(state.to_dict()), 'checkpoints': checkpoints,
    }


@pytest.mark.parametrize('case', ['pruning', 'uncertain', 'switch'])
def test_routing_matches_before_refactor(case, tmp_path):
    assert capture_routing(case, tmp_path) == baseline()[case]
