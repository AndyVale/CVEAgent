from types import SimpleNamespace

from cve_agent.adapters import OpenAIClassifier
import json

from cve_agent.models import CVERecord, Reference
from cve_agent.config import Settings, load_settings
from cve_agent.models import InvestigationState
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


class FakeCompletions:
    def __init__(self):
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 8})
        message = SimpleNamespace(content='{"cve_id":"CVE-1","status":"not_enough_information","labels":[]}')
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


class FakeClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=FakeCompletions())


def test_settings_use_openrouter_defaults_and_api_key(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text("[runtime]\n", encoding="utf-8")
    monkeypatch.setenv("API_KEY", "fixture-key")
    loaded = load_settings(config)
    assert loaded.endpoint == "https://openrouter.ai/api/v1"
    assert loaded.model == "nvidia/nemotron-3-ultra-550b-a55b:free"
    assert loaded.api_key == "fixture-key"


def settings(tmp_path):
    return Settings(
        model="fixture-model", endpoint="https://203.0.113.10:8000/v1", api_key=None,
        max_tokens=321, temperature=0.0, top_p=0.9, llm_timeout=45, llm_retry_count=2, llm_retry_wait=0.01, llm_retry_max_wait=0.02,
        nvd_base_url="https://nvd.test", nvd_timeout=5, retry_count=2,
        web_provider="tavily", tavily_base_url="https://api.tavily.com", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None,
        web_timeout=5, cache_dir=tmp_path / "cache", max_document_chars=100000, max_preview_chars=12000,
        database=tmp_path / "db.sqlite", token_budget=1000, max_agent_turns=12,
        max_search_calls=5, max_fetch_calls=8, max_investigation_seconds=300,
    )


def test_openai_classifier_uses_compatible_chat_client(tmp_path):
    fake = FakeClient()
    classifier = OpenAIClassifier(settings(tmp_path), client=fake)
    result = classifier.classify(
        CVERecord("CVE-1", "fixture description", (Reference("https://fixture.test/advisory"),)), [],
        Taxonomy((TaxonomyLabel("CWE-1", "Example", "fixture"),)), InvestigationState(),
    )
    request = fake.chat.completions.kwargs
    assert request["model"] == "fixture-model"
    assert request["max_tokens"] == 321
    assert request["top_p"] == 0.9
    assert request["response_format"] == {"type": "json_object"}
    assert "extra_body" not in request
    prompt = json.loads(request["messages"][1]["content"])
    assert prompt["cve"]["references"][0]["url"] == "https://fixture.test/advisory"
    assert result.status == "not_enough_information"
    assert result.operational["token_usage"]["prompt_tokens"] == 10


def test_openai_classifier_retries_empty_completion(tmp_path):
    class FlakyCompletions:
        def __init__(self):
            self.calls = 0

        def create(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(id="empty-1", model=None, choices=None, error={"code": "provider_error", "message": "temporary"})
            usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": 1, "completion_tokens": 1})
            message = SimpleNamespace(content='{"cve_id":"CVE-1","status":"not_enough_information","labels":[]}')
            return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)

    completions = FlakyCompletions()
    fake = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    result = OpenAIClassifier(settings(tmp_path), client=fake).classify(
        CVERecord("CVE-1", "fixture description"), [],
        Taxonomy((TaxonomyLabel("CWE-1", "Example", "fixture"),)), InvestigationState(),
    )
    assert result.status == "not_enough_information"
    assert completions.calls == 2


def test_openai_classifier_accepts_reasoning_wrapper(tmp_path):
    fake = FakeClient()
    fake.chat.completions.create = lambda **kwargs: SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='<think>internal reasoning</think>\n{"cve_id":"CVE-1","status":"not_enough_information","labels":[]}'))],
        usage=None,
    )
    result = OpenAIClassifier(settings(tmp_path), client=fake).classify(
        CVERecord("CVE-1", "fixture description"), [],
        Taxonomy((TaxonomyLabel("CWE-1", "Example", "fixture"),)), InvestigationState(),
    )
    assert result.status == "not_enough_information"
