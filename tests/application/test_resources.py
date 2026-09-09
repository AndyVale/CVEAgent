from types import SimpleNamespace

import pytest

from cve_agent.application.factory import create_application, create_web_source
from tests.support.agent import settings


@pytest.mark.parametrize('fails', [False, True])
@pytest.mark.parametrize('injected', [False, True])
def test_application_closes_only_owned_web_source_after_run(tmp_path, monkeypatch, fails, injected):
    closed = []
    source = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr('cve_agent.application.factory.create_web_source', lambda _: source)
    monkeypatch.setattr('cve_agent.application.factory.ClassificationCoordinator', lambda *args: object())
    app = create_application(settings(tmp_path), web_source=source if injected else None)

    def run(*args):
        if fails:
            raise RuntimeError('pipeline failure')
        return []

    app.pipeline = SimpleNamespace(run=run)
    for _ in range(2):
        if fails:
            with pytest.raises(RuntimeError, match='pipeline failure'):
                app.run([], None)
        else:
            assert app.run([], None).results == ()
    assert closed == ([] if injected else [True, True])


def test_default_web_cleanup_attempts_source_and_provider_and_preserves_first_failure(
    tmp_path, monkeypatch, caplog,
):
    calls = []

    class Source:
        def __init__(self, *args, **kwargs): pass
        def close(self):
            calls.append("source")
            raise RuntimeError("source close failure")

    class Provider:
        def __init__(self, *args, **kwargs): pass
        def search(self, query): return []
        def close(self):
            calls.append("provider")
            raise ValueError("provider close failure")

    monkeypatch.setattr("cve_agent.application.factory.WebClient", Source)
    monkeypatch.setattr("cve_agent.application.factory.TavilySearchProvider", Provider)
    configured = settings(tmp_path)

    with caplog.at_level("ERROR", logger="cve_agent.application"):
        with pytest.raises(RuntimeError, match="source close failure"):
            create_web_source(configured).close()

    assert calls == ["source", "provider"]
    assert "secondary HTTP cleanup failure" in caplog.text
