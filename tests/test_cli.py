import json
import logging

from cve_agent.cli import run
from cve_agent.evaluation import taxonomy_fingerprint
from cve_agent.models import CVERecord, ClassificationResult, LabelClassification
from cve_agent.taxonomy import load_taxonomy


class Source:
    def get_cve(self, cve_id):
        return CVERecord(cve_id, "fixture")


class Web:
    def search(self, query):
        return []

    def fetch(self, url):
        raise AssertionError("not used")


class Classifier:
    def classify(self, cve, taxonomy, state, checkpoint=None):
        return ClassificationResult(cve.cve_id, "not_enough_information")


class PartialClassifier(Classifier):
    def classify(self, cve, taxonomy, state, checkpoint=None):
        return ClassificationResult(cve.cve_id, "partial", operational={"stop_reason": "token_budget"})


class ExpectedClassifier(Classifier):
    def classify(self, cve, taxonomy, state, checkpoint=None):
        return ClassificationResult(cve.cve_id, "classified", [LabelClassification("EXPECTED", 0.9, ())])


def test_verbose_keeps_json_on_stdout_and_logs_on_stderr(tmp_path, capsys):
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps({"labels": [{"id": "CWE-1", "name": "Example", "description": "fixture"}]}), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_path.write_text("[storage]\ndatabase = 'results.sqlite'\n", encoding="utf-8")
    exit_code = run(["--verbose", "--taxonomy", str(taxonomy_path), "--config", str(config_path), "CVE-1"], cve_source=Source(), web_source=Web(), classifier=Classifier())
    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)[0]["cve_id"] == "CVE-1"
    assert "starting investigation" in captured.err
    assert "effective configuration" in captured.err
    assert "[LLM]" in captured.err
    assert "nvidia/nemotron-3-ultra-550b-a55b:free" in captured.err
    assert "API key" in captured.err
    assert '"api_key"' not in captured.err


def test_cli_request_interval_overrides_configuration(tmp_path, capsys):
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps({"labels": [{"id": "CWE-1", "name": "Example", "description": "fixture"}]}), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_path.write_text("[runtime]\nmin_request_interval_seconds = 1\n[storage]\ndatabase = 'results.sqlite'\n", encoding="utf-8")
    exit_code = run(["--verbose", "--llm-min-request-interval", "2.5", "--taxonomy", str(taxonomy_path), "--config", str(config_path), "CVE-1"], cve_source=Source(), web_source=Web(), classifier=Classifier())
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Min request interval" in captured.err
    assert "2.5s" in captured.err


def test_partial_result_has_nonzero_exit_code(tmp_path, capsys):
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps({"labels": [{"id": "CWE-1", "name": "Example", "description": "fixture"}]}), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_path.write_text("[storage]\ndatabase = 'results.sqlite'\n", encoding="utf-8")
    exit_code = run(["--taxonomy", str(taxonomy_path), "--config", str(config_path), "CVE-1"], cve_source=Source(), web_source=Web(), classifier=PartialClassifier())
    capsys.readouterr()
    assert exit_code == 2


def test_verbose_logging_restores_third_party_logger_levels(tmp_path, capsys):
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps({"labels": [{"id": "GENERIC", "name": "Example", "description": "fixture"}]}), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_path.write_text("[storage]\ndatabase = 'results.sqlite'\n", encoding="utf-8")
    httpx_logger = logging.getLogger("httpx")
    previous = httpx_logger.level
    httpx_logger.setLevel(logging.DEBUG)
    try:
        assert run(["--verbose", "--taxonomy", str(taxonomy_path), "--config", str(config_path), "VULN-1"], cve_source=Source(), web_source=Web(), classifier=Classifier()) == 0
        assert httpx_logger.level == logging.DEBUG
    finally:
        httpx_logger.setLevel(previous)
    capsys.readouterr()


def test_validate_supplies_cves_and_prints_metrics_in_table_without_breaking_json(tmp_path, capsys):
    taxonomy_path = tmp_path / "taxonomy.json"
    taxonomy_path.write_text(json.dumps({"labels": [{"id": "EXPECTED", "name": "Expected", "description": "fixture"}]}), encoding="utf-8")
    expected_path = tmp_path / "expected.json"
    expected_path.write_text(json.dumps({
        "taxonomy_sha256": taxonomy_fingerprint(load_taxonomy(taxonomy_path)),
        "cases": [{"cve_id": "CVE-2020-0001", "labels": ["EXPECTED"]}],
    }), encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_path.write_text("[storage]\ndatabase = 'results.sqlite'\n", encoding="utf-8")

    exit_code = run([
        "--taxonomy", str(taxonomy_path),
        "--validate", str(expected_path),
        "--config", str(config_path),
    ], cve_source=Source(), web_source=Web(), classifier=ExpectedClassifier())

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)[0]["cve_id"] == "CVE-2020-0001"
    assert "ID            | Labels   | Precision | Recall | F1" in captured.err
    assert "CVE-2020-0001 | EXPECTED | 1.000" in captured.err
    assert "exact matches : 1/1" in captured.err
    assert "micro P/R/F1  : 1.000 / 1.000 / 1.000" in captured.err
