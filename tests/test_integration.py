import json
from dataclasses import replace
from types import SimpleNamespace

from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings, non_secret_settings
from cve_agent.models import CVERecord, Document, InvestigationAspect, Reference
from cve_agent.persistence import AnalysisRepository, Database
from cve_agent.pipeline import Pipeline
from cve_agent.prompts import HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.strategy import ClassificationStrategy
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


def finish_arguments():
    return {
        "findings": [
            {"aspect": aspect.value, "statement": f"Source-grounded {aspect.value} finding.", "evidence_ids": ["fixture-doc:p1"]}
            for aspect in (InvestigationAspect.ROOT_CAUSE, InvestigationAspect.EXPLOITATION_MECHANISM)
        ],
        "summary": "The product performs an unchecked buffer copy.",
    }


class FixtureSource:
    def __init__(self, record):
        self.record = record

    def get_cve(self, cve_id):
        assert cve_id == self.record["cve_id"]
        references = tuple(Reference(**item) for item in self.record["references"])
        return CVERecord(cve_id, self.record["description"], references)


class FixtureWeb:
    def __init__(self, content):
        self.content = content

    def search(self, query):
        return []

    def fetch(self, url):
        return Document(url, "Fixture advisory", self.content, document_id="fixture-doc", requested_url=url)


class ToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=json.dumps(arguments))


class Message:
    def __init__(self, *, calls=None, content=None):
        self.tool_calls = calls or []
        self.content = content

    def model_dump(self, exclude_none=True):
        if self.tool_calls:
            return {"role": "assistant", "tool_calls": [{"id": call.id, "type": "function", "function": {"name": call.function.name, "arguments": call.function.arguments}} for call in self.tool_calls]}
        return {"role": "assistant", "content": self.content}


class FixtureClient:
    def __init__(self):
        self.research_step = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        if "tools" in request:
            steps = [
                ("search", {"query": "fixture unchecked buffer copy advisory"}),
                ("fetch", {"url": "https://example.test/advisory"}),
                ("finish_investigation", finish_arguments()),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            message = Message(calls=[ToolCall(str(self.research_step), name, arguments)])
        else:
            system = request["messages"][0]["content"]
            if system.startswith("You are a cybersecurity taxonomy classifier"):
                payload = json.loads(request["messages"][1]["content"])
                message = Message(content=json.dumps({"chunk_id": payload["taxonomy_chunk"]["chunk_id"], "supported": [{
                    "label": "CWE-120", "confidence": 0.95,
                    "evidence": [{"evidence_id": "fixture-doc:p1", "explanation": "The advisory directly describes an unchecked buffer copy."}],
                }]}))
            else:
                raise AssertionError("unexpected model request after taxonomy chunk classification")
        usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


class HierarchicalFixtureClient(FixtureClient):
    def create(self, **request):
        if "tools" in request:
            return super().create(**request)
        payload = json.loads(request["messages"][1]["content"])
        if request["messages"][0]["content"] == HIERARCHY_ROUTING_SYSTEM_PROMPT:
            level = payload["taxonomy_level"]
            message = Message(content=json.dumps({
                "level_id": level["level_id"],
                "decisions": [{
                    "label": label["id"],
                    "decision": "supported",
                    "confidence": 0.95,
                    "explanation": "The advisory supports the broad family.",
                    "evidence": [{
                        "evidence_id": "fixture-doc:p1",
                        "explanation": "The advisory directly establishes this family.",
                    }],
                } for label in level["labels"]],
            }))
        else:
            chunk = payload["taxonomy_chunk"]
            message = Message(content=json.dumps({
                "chunk_id": chunk["chunk_id"],
                "supported": [{
                    "label": chunk["labels"][0]["id"],
                    "confidence": 0.95,
                    "evidence": [{
                        "evidence_id": "fixture-doc:p1",
                        "explanation": "The advisory directly describes the specific mechanism.",
                    }],
                }],
            }))
        usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def settings(tmp_path):
    return Settings(
        model="fixture", endpoint="https://fixture.test/v1", api_key=None, max_tokens=500,
        temperature=0, top_p=1, llm_timeout=5, llm_retry_count=0, llm_retry_wait=0,
        llm_retry_max_wait=0, llm_min_request_interval=0, nvd_base_url="https://nvd.test",
        nvd_timeout=5, nvd_retry_count=0, web_timeout=5, web_retry_count=0,
        web_provider="none", tavily_base_url="https://tavily.test", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None, cache_dir=tmp_path / "cache",
        max_document_chars=10000, max_preview_chars=1000, max_download_bytes=100000,
        database=tmp_path / "results.sqlite3", token_budget=12000, max_agent_turns=6,
        max_search_calls=1, max_fetch_calls=1, max_investigation_seconds=30,
    )


def test_fixture_driven_pipeline_matches_expected_result(tmp_path):
    record = {
        "cve_id": "CVE-2026-0001",
        "description": "A buffer copy in Example Product does not validate input length.",
        "references": [{"url": "https://example.test/advisory", "source": "Example"}],
    }
    expected = {
        "cve_id": "CVE-2026-0001",
        "status": "classified",
        "labels": [{
            "label": "CWE-120",
            "confidence": 0.95,
            "evidence": [{
                "url": "https://example.test/advisory",
                "quote": record["description"],
                "explanation": "The advisory directly describes an unchecked buffer copy.",
                "evidence_id": "fixture-doc:p1",
            }],
        }],
    }
    taxonomy = Taxonomy((
        TaxonomyLabel("CWE-120", "Unchecked Buffer Copy", "Copies input without checking destination size."),
        TaxonomyLabel("CWE-79", "Web Output Neutralization", "Fails to neutralize input placed in web output."),
    ))
    configured = settings(tmp_path)
    web = FixtureWeb(record["description"])
    result = Pipeline(
        FixtureSource(record), InvestigationAgent(configured, web, FixtureClient()), Database(configured.database)
    ).run([record["cve_id"]], taxonomy)[0].to_dict()
    result = json.loads(json.dumps(result))
    assert {key: result[key] for key in ("cve_id", "status", "labels")} == expected
    persisted = AnalysisRepository(configured.database).get_analysis(
        f'{result["operational"]["run_id"]}:0'
    )
    assert persisted is not None
    scratchpad = persisted.scratchpad
    assert scratchpad["research_information_status"] == "sufficient"
    assert scratchpad["research_summary"]
    assert scratchpad["provenance"]["target_cve_id"] == record["cve_id"]
    assert scratchpad["provenance"]["label_links"][0]["label"] == "CWE-120"
    assert scratchpad["provenance"]["sources"][1]["passages"][0]["text"] == record["description"]
    assert result["provenance"]["evidence"][0]["evidence_id"] == "fixture-doc:p1"
    assert {item["aspect"] for item in scratchpad["findings"]} == {
        InvestigationAspect.ROOT_CAUSE.value,
        InvestigationAspect.EXPLOITATION_MECHANISM.value,
    }


def test_hierarchical_fixture_pipeline_persists_strategy_routing_and_exact_coverage(tmp_path):
    record = {
        "cve_id": "CVE-2026-0002",
        "description": "Example Product performs an unchecked buffer copy.",
        "references": [{"url": "https://example.test/advisory", "source": "Example"}],
    }
    taxonomy = Taxonomy((
        TaxonomyLabel("MEMORY", "Memory", "Memory-management vulnerability."),
        TaxonomyLabel("BUFFER", "Buffer overflow", "An unchecked copy exceeds a buffer boundary.", "MEMORY"),
    ))
    configured = replace(
        settings(tmp_path),
        classification_strategy=ClassificationStrategy.HYBRID,
        token_budget=100_000,
    )
    result = Pipeline(
        FixtureSource(record),
        InvestigationAgent(configured, FixtureWeb(record["description"]), HierarchicalFixtureClient()),
        Database(configured.database),
        run_metadata={"model": configured.model, "settings": non_secret_settings(configured)},
    ).run([record["cve_id"]], taxonomy)[0]

    assert [item.label for item in result.labels] == ["BUFFER"]
    assert result.operational["classification"]["effective_strategy"] == "hybrid"
    assert result.operational["coverage"] == {
        "effective_strategy": "hybrid",
        "total_labels": 2,
        "evaluated_labels": 2,
        "pruned_labels": 0,
        "unresolved_labels": 0,
        "classification_requests": 2,
        "routing_levels": 1,
        "complete": True,
    }
    persisted = AnalysisRepository(configured.database).get_analysis(
        f'{result.operational["run_id"]}:0'
    )
    assert persisted is not None
    persisted_result = persisted.result
    coverage = persisted_result["operational"]["coverage"]
    scratchpad = persisted.scratchpad
    persisted_settings = persisted.settings
    assert coverage == result.operational["coverage"]
    assert persisted_result["operational"]["classification"]["effective_strategy"] == "hybrid"
    assert persisted_settings["classification_strategy"] == "hybrid"
    assert persisted_settings["pruning_confidence_threshold"] == 0.8
    assert {entry["tool"] for entry in scratchpad["tool_history"]} >= {
        "route_taxonomy_level",
        "switch_taxonomy_strategy",
        "hybrid_exhaustive_fallback",
    }
    route = next(entry for entry in scratchpad["tool_history"] if entry["tool"] == "route_taxonomy_level")
    assert route["decisions"][0]["decision"] == "supported"
    assert route["decisions"][0]["confidence"] == 0.95
