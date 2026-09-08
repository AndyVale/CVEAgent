from types import SimpleNamespace
import json

import httpx

from cve_agent.cache.disk import JsonDiskCache
from cve_agent.cache.web import CachedWebClient
from cve_agent.classification.prompts import HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationAspect
from cve_agent.core.sources import Document, SearchResult
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.integrations.web import WebClient
from cve_agent.integrations.web_policy import PublicWebUrlPolicy


def settings(tmp_path):
    return Settings(
        model="fixture-model", endpoint="https://fixture.test/v1", api_key=None,
        max_tokens=500, temperature=0.0, top_p=1.0, llm_timeout=5, llm_retry_count=0,
        llm_retry_wait=0.01, llm_retry_max_wait=0.02, llm_min_request_interval=0.0,
        nvd_base_url="https://nvd.test", nvd_timeout=5, nvd_retry_count=0, web_timeout=5, web_retry_count=0,
        web_provider="tavily", tavily_base_url="https://api.tavily.com", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None, cache_dir=tmp_path / "cache",
        max_document_chars=10000, max_preview_chars=1000, max_download_bytes=100000, database=tmp_path / "db.sqlite",
        token_budget=12000, max_agent_turns=8, max_search_calls=1, max_fetch_calls=1,
        max_investigation_seconds=30,
    )


class FixtureWeb:
    def search(self, query):
        return [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]

    def fetch(self, url):
        return Document(url, "Advisory", "The issue causes memory corruption in aggregate processing.", document_id="doc-1")


class FailingFetchWeb(FixtureWeb):
    def fetch(self, url):
        request = httpx.Request("GET", url)
        raise httpx.HTTPStatusError("forbidden", request=request, response=httpx.Response(403, request=request))


class MultiDocumentWeb(FixtureWeb):
    def fetch(self, url):
        if url.endswith("/secondary"):
            return Document(
                url,
                "Technical analysis",
                "A crafted request bypasses authentication before reaching the vulnerable handler.",
                document_id="doc-2",
            )
        return super().fetch(url)


class ToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=arguments if isinstance(arguments, str) else json.dumps(arguments))


class Message:
    def __init__(self, calls=None, content=None):
        self.tool_calls = calls or []
        self.content = content

    def model_dump(self, exclude_none=True):
        result = {"role": "assistant"}
        if self.tool_calls:
            result["tool_calls"] = [{"id": call.id, "type": "function", "function": {"name": call.function.name, "arguments": call.function.arguments}} for call in self.tool_calls]
        if self.content is not None:
            result["content"] = self.content
        return result


def response(message, total=15):
    usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": total - 5, "completion_tokens": 5, "total_tokens": total})
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def finish_arguments(evidence_id="doc-1:p1", *, mechanism_supported=True):
    aspect = InvestigationAspect.ROOT_CAUSE if mechanism_supported else InvestigationAspect.IMPACT
    return {
        "findings": [
            {"aspect": aspect.value, "statement": f"Source-grounded {aspect.value} finding.", "evidence_ids": [evidence_id]},
        ],
        "summary": "The product corrupts memory while processing attacker-controlled aggregate input.",
    }


class FullFlowClient:
    def __init__(self, *, malformed_first=False, malformed_chunk=False, malformed_chunk_id=None, invalid_chunk_confidence=False, qualitative_chunk_confidence=False, array_chunk=False, empty_chunk=False, mechanism_supported=True):
        self.requests = []
        self.research_step = -1 if malformed_first else 0
        self.malformed_chunk = malformed_chunk
        self.malformed_chunk_id = malformed_chunk_id
        self.invalid_chunk_confidence = invalid_chunk_confidence
        self.qualitative_chunk_confidence = qualitative_chunk_confidence
        self.array_chunk = array_chunk
        self.empty_chunk = empty_chunk
        self.mechanism_supported = mechanism_supported
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if "tools" in kwargs:
            if self.research_step == -1:
                self.research_step = 0
                return response(Message([ToolCall("bad", "search", "{")]))
            steps = [
                ("search", {"query": "generic vulnerability mechanism"}),
                ("fetch", {"url": "https://fixture.test/advisory"}),
                ("finish_investigation", finish_arguments(mechanism_supported=self.mechanism_supported)),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        system = kwargs["messages"][0]["content"]
        if system.startswith("You are a cybersecurity taxonomy classifier"):
            payload = json.loads(kwargs["messages"][1]["content"])
            taxonomy_chunk = payload["taxonomy_chunk"]
            if taxonomy_chunk["chunk_id"] == self.malformed_chunk_id:
                return response(Message(content='{"wrong":"shape"}'))
            if self.malformed_chunk:
                self.malformed_chunk = False
                return response(Message(content='{"wrong":"shape"}'))
            confidence = 0.9
            if self.invalid_chunk_confidence:
                self.invalid_chunk_confidence = False
                confidence = "very certain"
            elif self.qualitative_chunk_confidence:
                confidence = "high"
            supported = [{
                "label": taxonomy_chunk["labels"][0]["id"], "confidence": confidence,
                "evidence": [{"evidence_id": "doc-1:p1", "explanation": "The exact passage supports the label."}],
            }] if not self.empty_chunk else []
            content = supported if self.array_chunk else {"chunk_id": taxonomy_chunk["chunk_id"], "supported": supported}
            return response(Message(content=json.dumps(content)))
        raise AssertionError("unexpected model request after taxonomy chunk classification")


class RecordEvidenceFlowClient(FullFlowClient):
    def create(self, **kwargs):
        if "tools" in kwargs:
            self.requests.append(kwargs)
            steps = [
                ("search", {"query": "generic vulnerability mechanism"}),
                ("fetch", {"url": "https://fixture.test/advisory"}),
                ("record_evidence", {"document_id": "doc-1", "passage_id": "p1", "quote_anchor": ""}),
                ("finish_investigation", finish_arguments()),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        return super().create(**kwargs)


class FinishCorrectionClient(FullFlowClient):
    def __init__(self, *, repeat_invalid=False):
        super().__init__()
        invalid = finish_arguments()
        invalid["findings"].append({
            "aspect": "impact",
            "statement": "Unsupported impact claim.",
            "evidence_ids": ["doc-1:p99"],
        })
        self.research_steps = [
            ("search", {"query": "generic vulnerability mechanism"}),
            ("fetch", {"url": "https://fixture.test/advisory"}),
            ("finish_investigation", invalid),
            ("finish_investigation", invalid if repeat_invalid else finish_arguments()),
        ]

    def create(self, **kwargs):
        if "tools" in kwargs:
            self.requests.append(kwargs)
            name, arguments = self.research_steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        return super().create(**kwargs)


class FinishCorrectionResearchClient(FinishCorrectionClient):
    def __init__(self):
        super().__init__()
        corrected = finish_arguments()
        corrected["findings"].append({
            "aspect": "exploitation_mechanism",
            "statement": "A crafted request bypasses authentication before reaching the handler.",
            "evidence_ids": ["doc-2:p1"],
        })
        self.research_steps[3:3] = [
            (None, {}),
            ("search", {"query": "specific vendor vulnerability mechanism"}),
            ("fetch", {"url": "https://fixture.test/secondary"}),
        ]
        self.research_steps[-1] = ("finish_investigation", corrected)

    def create(self, **kwargs):
        if "tools" in kwargs and self.research_steps[self.research_step][0] is None:
            self.requests.append(kwargs)
            self.research_step += 1
            return response(Message(content="I need another source before correcting the citations."))
        return super().create(**kwargs)


class HybridFlowClient(FullFlowClient):
    def create(self, **kwargs):
        if "tools" not in kwargs and kwargs["messages"][0]["content"] == HIERARCHY_ROUTING_SYSTEM_PROMPT:
            self.requests.append(kwargs)
            payload = json.loads(kwargs["messages"][1]["content"])
            level = payload["taxonomy_level"]
            return response(Message(content=json.dumps({
                "level_id": level["level_id"],
                "decisions": [{
                    "label": label["id"],
                    "decision": "supported",
                    "confidence": 0.9,
                    "explanation": "The evidence supports this hierarchy branch.",
                    "evidence": [{
                        "evidence_id": "doc-1:p1",
                        "explanation": "The exact passage supports this hierarchy branch.",
                    }],
                } for label in level["labels"]],
            })))
        return super().create(**kwargs)


def taxonomy():
    return Taxonomy((TaxonomyLabel("MEMORY", "Memory Safety Error", "Invalid memory access or corruption."),))


def public_url_policy():
    return PublicWebUrlPolicy(lambda _hostname, _port: ("93.184.216.34",))


def cached_web_client(settings, searcher=None, http_client=None, url_policy=None):
    policy = url_policy or PublicWebUrlPolicy()
    return CachedWebClient(WebClient(settings, searcher, http_client, policy), JsonDiskCache(settings.cache_dir), policy)
