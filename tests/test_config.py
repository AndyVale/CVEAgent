import pytest

from cve_agent.config import load_settings


def test_settings_split_retries_and_resolve_paths_from_config(tmp_path):
    config = tmp_path / "nested" / "config.toml"
    config.parent.mkdir()
    config.write_text(
        "[nvd]\nretry_count = 1\n[web]\nretry_count = 7\ncache_dir = 'cache'\n[storage]\ndatabase = 'data/results.sqlite3'\n",
        encoding="utf-8",
    )
    loaded = load_settings(config)
    assert loaded.nvd_retry_count == 1
    assert loaded.web_retry_count == 7
    assert loaded.cache_dir == config.parent / "cache"
    assert loaded.database == config.parent / "data/results.sqlite3"


@pytest.mark.parametrize(
    "content, message",
    [
        ("[web]\nprovider = 'invented'\n", "unsupported web provider"),
        ("[web]\nmax_preview_chars = 20\nmax_document_chars = 10\n", "max_preview_chars"),
        ("[limits]\nfinalization_overrun_percent = -1\n", "finalization_overrun_percent"),
    ],
)
def test_invalid_settings_fail_at_startup(tmp_path, content, message):
    config = tmp_path / "config.toml"
    config.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_settings(config)
