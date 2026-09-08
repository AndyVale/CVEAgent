from types import SimpleNamespace
import logging

import pytest

from cve_agent.core.config import load_settings
from cve_agent.runtime.llm import EmptyCompletionError, call_chat_completion


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


def test_empty_provider_diagnostics_redact_configured_key(tmp_path, monkeypatch, caplog):
    secret = "fixture-provider-secret"
    monkeypatch.setenv("API_KEY", secret)
    config = tmp_path / "config.toml"
    config.write_text("[runtime]\nretry_count = 0\n", encoding="utf-8")
    response = SimpleNamespace(id="empty", choices=None, error={"message": f"provider echoed {secret}"})
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: response)))
    caplog.set_level(logging.ERROR)

    with pytest.raises(EmptyCompletionError) as caught:
        call_chat_completion(client, load_settings(config), logging.getLogger(__name__), context="fixture", messages=[])

    assert secret not in caplog.text
    assert secret not in str(caught.value)
    assert "[REDACTED]" in caplog.text
    assert "[REDACTED]" in str(caught.value)
