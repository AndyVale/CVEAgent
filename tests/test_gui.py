from pathlib import Path

from cve_agent.gui import create_gui_app


class FakeService:
    def global_settings(self):
        return {"database_path": "/tmp/db", "default_config_path": "/tmp/config", "default_taxonomy_path": "/tmp/taxonomy"}

    def update_global_settings(self, raw):
        return raw

    def history(self):
        return [{"id": "1:0", "cve_id": "CVE-2024-1000"}]

    def defaults(self, from_analysis_id=None):
        return {"source": from_analysis_id or "global"}

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

    assert index.status_code == 200
    assert b"CVE Agent" in index.data
    assert "default-src 'self'" in index.headers["Content-Security-Policy"]
    assert script.status_code == 200
    assert b"/api/analyses" in script.data
    assert Path("src/cve_agent/cli.py").read_text(encoding="utf-8").find("Flask") == -1


def test_gui_json_routes_delegate_to_service():
    gui = client()

    assert gui.get("/api/health").json == {"status": "ok"}
    assert gui.get("/api/history").json["analyses"][0]["cve_id"] == "CVE-2024-1000"
    assert gui.get("/api/defaults?from=1:0").json == {"source": "1:0"}
    assert gui.post("/api/analyses", json={"cve_id": "CVE-2024-1000"}).status_code == 202
    assert gui.get("/api/analyses/missing").status_code == 404


def test_gui_rejects_non_object_json_bodies():
    response = client().post("/api/analyses", json=[])

    assert response.status_code == 400
    assert "JSON object" in response.json["error"]


def test_gui_rejects_non_local_host_headers():
    response = client().get("/api/health", headers={"Host": "example.test"})

    assert response.status_code == 403
    assert response.json == {"error": "the GUI accepts local requests only"}
