from pathlib import Path

from cve_agent.gui import create_gui_app
from cve_agent.gui_config import ensure_gui_config
from cve_agent.gui_paths import GuiPathPolicy


class FakeService:
    def global_settings(self):
        return {"database_path": "/tmp/db", "default_config_path": "/tmp/config", "default_taxonomy_path": "/tmp/taxonomy"}

    def update_global_settings(self, raw):
        return raw

    def path_options(self):
        return {
            "configuration": {"prefix": "./", "name": "config.gui.toml"},
            "taxonomies": [],
            "databases": [],
        }

    def history(self):
        return [{"id": "1:0", "cve_id": "CVE-2024-1000"}]

    def defaults(self, from_analysis_id=None):
        return {"source": from_analysis_id or "global"}

    def update_analysis_options(self, raw):
        return {"validated": raw}

    def start_analysis(self, raw):
        return {"id": "pending-fixture", "cached": False, "lifecycle": "queued"}

    def get_analysis(self, analysis_id):
        return None if analysis_id == "missing" else {"id": analysis_id, "lifecycle": "running"}


def client():
    app = create_gui_app(FakeService())
    app.testing = True
    return app.test_client()


def test_gui_serves_separate_web_entrypoint_and_assets():
    gui = client()

    index = gui.get("/")
    script = gui.get("/assets/app.js")
    styles = gui.get("/assets/styles.css")

    assert index.status_code == 200
    assert b"CVE Agent" in index.data
    assert "default-src 'self'" in index.headers["Content-Security-Policy"]
    assert script.status_code == 200
    assert b"/api/analyses" in script.data
    assert styles.status_code == 200
    assert Path("src/cve_agent/cli.py").read_text(encoding="utf-8").find("Flask") == -1


def test_gui_home_starts_analysis_without_a_separate_new_analysis_button():
    gui = client()

    markup = gui.get("/").get_data(as_text=True)

    assert 'id="welcomeComposer"' in markup
    assert 'id="welcomeCveInput"' in markup
    assert 'id="newAnalysisButton"' not in markup
    assert 'id="homeButton"' in markup
    assert 'id="backButton"' in markup
    assert 'id="configurationOptionsButton"' in markup
    assert 'id="welcomeOptionsButton"' not in markup
    assert 'id="chatOptionsButton"' not in markup
    assert 'name="config_path"' not in markup
    assert '<span class="path-prefix">fixtures/</span>' in markup
    assert '<span class="path-prefix">.data/</span>' in markup
    assert 'id="analysisTaxonomySelect"' in markup
    assert 'id="globalDatabaseSelect"' in markup
    assert 'id="globalTaxonomySelect"' in markup
    assert "Validate and save" in markup


def test_gui_settings_submit_on_enter_and_keep_dialog_errors_visible():
    gui = client()

    markup = gui.get("/").get_data(as_text=True)
    script = gui.get("/assets/app.js").get_data(as_text=True)

    assert '<form id="globalSettingsForm">' in markup
    assert '<form id="chatSettingsForm">' in markup
    assert 'id="saveGlobalButton" class="primary-button" type="submit"' in markup
    assert 'id="saveChatSettingsButton" class="primary-button" type="submit"' in markup
    assert 'method="dialog"' not in markup
    assert 'elements.globalSettingsForm.addEventListener("submit"' in script
    assert 'elements.globalSettingsForm.addEventListener("keydown"' in script
    assert 'elements.globalSettingsForm.requestSubmit();' in script
    assert 'elements.chatSettingsForm.addEventListener("submit"' in script
    assert 'const activeDialog = document.querySelector("dialog[open]")' in script
    assert 'api("/api/analysis-options"' in script
    assert "settingIsRelevant" in script
    assert "exclusiveMinimum" in script
    assert '.settings-dialog .toast { z-index: 2; }' in gui.get("/assets/styles.css").get_data(as_text=True)


def test_gui_panels_scroll_independently_and_history_views_reset_scroll():
    gui = client()

    script = gui.get("/assets/app.js").get_data(as_text=True)
    styles = gui.get("/assets/styles.css").get_data(as_text=True)

    assert 'renderAnalysis({followProgress: false})' in script
    assert 'if (state.analysis?.id !== analysis.id) return;' in script
    assert 'if (!followProgress) elements.chatViewport.scrollTop = 0;' in script
    assert '.history-list { flex: 1 1 auto; min-height: 0; overflow-y: auto;' in styles
    assert '.chat-viewport { flex: 1 1 auto; min-width: 0; min-height: 0; overflow: auto;' in styles
    assert '.configuration-view { flex: 1 1 auto; min-width: 0; min-height: 0; overflow-y: auto;' in styles


def test_gui_json_routes_delegate_to_service():
    gui = client()

    assert gui.get("/api/health").json == {"status": "ok"}
    assert gui.get("/api/path-options").json["configuration"]["name"] == "config.gui.toml"
    assert gui.get("/api/history").json["analyses"][0]["cve_id"] == "CVE-2024-1000"
    assert gui.get("/api/defaults?from=1:0").json == {"source": "1:0"}
    assert gui.put("/api/analysis-options", json={"temperature": 0.2}).json == {
        "validated": {"temperature": 0.2}
    }
    assert gui.post("/api/analyses", json={"cve_id": "CVE-2024-1000"}).status_code == 202
    assert gui.get("/api/analyses/missing").status_code == 404


def test_gui_rejects_non_object_json_bodies():
    response = client().post("/api/analyses", json=[])

    assert response.status_code == 400
    assert "JSON object" in response.json["error"]


def test_gui_rejects_non_json_cross_origin_and_oversized_mutations():
    gui = client()

    non_json = gui.post("/api/analyses", data="cve_id=CVE-2024-1000")
    cross_origin = gui.post(
        "/api/analyses",
        json={"cve_id": "CVE-2024-1000"},
        headers={"Origin": "https://attacker.example"},
    )
    oversized = gui.post(
        "/api/analyses",
        data=b"{" + b"x" * 1_000_001 + b"}",
        content_type="application/json",
    )

    assert non_json.status_code == 415
    assert cross_origin.status_code == 403
    assert cross_origin.json == {"error": "cross-origin requests are not allowed"}
    assert oversized.status_code == 413


def test_gui_configuration_is_initialized_separately_from_cli_configuration(tmp_path):
    (tmp_path / "fixtures").mkdir()
    policy = GuiPathPolicy(tmp_path)
    policy.prepare_runtime_directories()
    source = tmp_path / "config.toml"
    source.write_text("# CLI configuration\n[runtime]\ntemperature = 0.2\n", encoding="utf-8")

    gui_config = ensure_gui_config(source, policy)
    gui_config.write_text("# GUI configuration\n[runtime]\ntemperature = 0.5\n", encoding="utf-8")

    assert gui_config == tmp_path / "config.gui.toml"
    assert source.read_text(encoding="utf-8").startswith("# CLI configuration")
    assert ensure_gui_config(source, policy).read_text(encoding="utf-8").startswith("# GUI configuration")


def test_gui_rejects_non_local_host_headers():
    response = client().get("/api/health", headers={"Host": "example.test"})

    assert response.status_code == 403
    assert response.json == {"error": "the GUI accepts local requests only"}
