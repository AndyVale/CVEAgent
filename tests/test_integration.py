import json
from pathlib import Path
from types import SimpleNamespace

from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings
from cve_agent.models import CVERecord, Document, InvestigationAspect, Reference
from cve_agent.persistence import Database
from cve_agent.pipeline import Pipeline
from cve_agent.taxonomy import load_taxonomy


FIXTURES = Path(__file__).parents[1] / "fixtures"


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
    record = json.loads((FIXTURES / "cve-example.json").read_text(encoding="utf-8"))
    expected = json.loads((FIXTURES / "expected-easy-classification.json").read_text(encoding="utf-8"))
    taxonomy = load_taxonomy(FIXTURES / "example_taxonomy_easy.json")
    configured = settings(tmp_path)
    web = FixtureWeb(record["description"])
    result = Pipeline(
        FixtureSource(record), InvestigationAgent(configured, web, FixtureClient()), Database(configured.database)
    ).run([record["cve_id"]], taxonomy)[0].to_dict()
    result = json.loads(json.dumps(result))
    assert {key: result[key] for key in ("cve_id", "status", "labels")} == expected
    with Database(configured.database) as database:
        persisted = database.get(result["operational"]["run_id"], record["cve_id"])
        scratchpad = json.loads(persisted["scratchpad_json"])
    assert scratchpad["research_information_status"] == "sufficient"
    assert scratchpad["research_summary"]
    assert {item["aspect"] for item in scratchpad["findings"]} == {
        InvestigationAspect.ROOT_CAUSE.value,
        InvestigationAspect.EXPLOITATION_MECHANISM.value,
    }
