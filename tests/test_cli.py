import json

from cve_agent.cli import run
from cve_agent.models import CVERecord, ClassificationResult


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
