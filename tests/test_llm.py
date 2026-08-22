import logging
from types import SimpleNamespace

from cve_agent.config import load_settings
from cve_agent.llm import call_chat_completion


def test_settings_use_openrouter_defaults_and_api_key(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text("[runtime]\n", encoding="utf-8")
    monkeypatch.setenv("API_KEY", "fixture-key")
    loaded = load_settings(config)
    assert loaded.endpoint == "https://openrouter.ai/api/v1"
    assert loaded.api_key == "fixture-key"


def test_chat_completion_retries_empty_provider_response(tmp_path):
    class FlakyCompletions:
        def __init__(self):
            self.calls = 0

        def create(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(id="empty", choices=None, error={"code": "temporary"})
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))], usage=None)

    completions = FlakyCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    config = tmp_path / "config.toml"
    config.write_text("[runtime]\nretry_count = 1\nretry_wait_seconds = 0.001\nretry_max_wait_seconds = 0.001\n", encoding="utf-8")
    result = call_chat_completion(client, load_settings(config), logging.getLogger(__name__), context="fixture", messages=[])
    assert result.choices
    assert completions.calls == 2
