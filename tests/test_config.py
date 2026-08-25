import pytest

from cve_agent.config import load_settings
from cve_agent.strategy import ClassificationStrategy


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
    assert loaded.classification_strategy == ClassificationStrategy.AUTO
    assert loaded.pruning_confidence_threshold == 0.8


def test_loads_classification_strategy_and_pruning_threshold(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        "[classification]\nstrategy = 'hybrid'\npruning_confidence_threshold = 0.9\n",
        encoding="utf-8",
    )
    loaded = load_settings(config)
    assert loaded.classification_strategy == ClassificationStrategy.HYBRID
    assert loaded.pruning_confidence_threshold == 0.9


@pytest.mark.parametrize("strategy", list(ClassificationStrategy))
def test_loads_every_supported_classification_strategy(tmp_path, strategy):
    config = tmp_path / "config.toml"
    config.write_text(
        f"[classification]\nstrategy = '{strategy.value}'\n",
        encoding="utf-8",
    )

    assert load_settings(config).classification_strategy == strategy


@pytest.mark.parametrize("threshold", [0.0, 1.0])
def test_pruning_threshold_accepts_closed_interval_boundaries(tmp_path, threshold):
    config = tmp_path / "config.toml"
    config.write_text(
        f"[classification]\npruning_confidence_threshold = {threshold}\n",
        encoding="utf-8",
    )

    assert load_settings(config).pruning_confidence_threshold == threshold


@pytest.mark.parametrize(
    "content, message",
    [
        ("[web]\nprovider = 'invented'\n", "unsupported web provider"),
        ("[web]\nmax_preview_chars = 20\nmax_document_chars = 10\n", "max_preview_chars"),
        ("[limits]\nfinalization_overrun_percent = -1\n", "finalization_overrun_percent"),
        ("[classification]\nstrategy = 'invented'\n", "classification strategy"),
        ("[classification]\npruning_confidence_threshold = 1.1\n", "pruning_confidence_threshold"),
    ],
)
def test_invalid_settings_fail_at_startup(tmp_path, content, message):
    config = tmp_path / "config.toml"
    config.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_settings(config)
