from __future__ import annotations

import argparse
import atexit
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory

from cve_agent.gui_config import GlobalGuiSettings, GlobalSettingsStore, GuiConfigurationError, ensure_gui_config
from cve_agent.gui_paths import GuiPathPolicy
from cve_agent.gui_service import GuiService
from cve_agent.persistence import IncompatibleDatabaseError, PersistenceError
from cve_agent.taxonomy import TaxonomyError


def create_gui_app(service: GuiService) -> Flask:
    """Create the GUI HTTP adapter; the CLI remains an independent presentation layer."""
    static_directory = Path(__file__).with_name("gui_static")
    app = Flask(__name__, static_folder=None)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000

    @app.before_request
    def require_local_host():  # type: ignore[no-untyped-def]
        hostname = (urlsplit(f"//{request.host}").hostname or "").lower()
        if hostname not in {"127.0.0.1", "localhost", "::1"}:
            return jsonify({"error": "the GUI accepts local requests only"}), 403
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not request.is_json:
                return jsonify({"error": "state-changing requests must use JSON"}), 415
            origin = request.headers.get("Origin")
            if origin:
                parsed_origin = urlsplit(origin)
                if parsed_origin.scheme not in {"http", "https"} or parsed_origin.netloc != request.host:
                    return jsonify({"error": "cross-origin requests are not allowed"}), 403
        return None

    @app.after_request
    def disable_api_caching(response):  # type: ignore[no-untyped-def]
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(413)
    def request_too_large(_exc):  # type: ignore[no-untyped-def]
        return jsonify({"error": "request body is too large"}), 413

    @app.get("/")
    def index():  # type: ignore[no-untyped-def]
        return send_from_directory(static_directory, "index.html")

    @app.get("/assets/<path:filename>")
    def asset(filename: str):  # type: ignore[no-untyped-def]
        return send_from_directory(static_directory, filename)

    @app.get("/api/health")
    def health():  # type: ignore[no-untyped-def]
        return jsonify({"status": "ok"})

    @app.get("/api/global-settings")
    def get_global_settings():  # type: ignore[no-untyped-def]
        return jsonify(service.global_settings())

    @app.get("/api/path-options")
    def path_options():  # type: ignore[no-untyped-def]
        return jsonify(service.path_options())

    @app.put("/api/global-settings")
    def update_global_settings():  # type: ignore[no-untyped-def]
        return jsonify(service.update_global_settings(_json_body()))

    @app.get("/api/history")
    def history():  # type: ignore[no-untyped-def]
        return jsonify({"analyses": service.history()})

    @app.get("/api/defaults")
    def defaults():  # type: ignore[no-untyped-def]
        return jsonify(service.defaults(request.args.get("from")))

    @app.put("/api/analysis-options")
    def update_analysis_options():  # type: ignore[no-untyped-def]
        return jsonify(service.update_analysis_options(_json_body()))

    @app.post("/api/analyses")
    def start_analysis():  # type: ignore[no-untyped-def]
        return jsonify(service.start_analysis(_json_body())), 202

    @app.get("/api/analyses/<path:analysis_id>")
    def get_analysis(analysis_id: str):  # type: ignore[no-untyped-def]
        analysis = service.get_analysis(analysis_id)
        if analysis is None:
            return jsonify({"error": "analysis not found"}), 404
        return jsonify(analysis)

    @app.errorhandler(GuiConfigurationError)
    @app.errorhandler(TaxonomyError)
    @app.errorhandler(ValueError)
    def bad_request(exc: Exception):  # type: ignore[no-untyped-def]
        return jsonify({"error": str(exc)}), 400

    @app.errorhandler(IncompatibleDatabaseError)
    @app.errorhandler(PersistenceError)
    def persistence_failure(exc: Exception):  # type: ignore[no-untyped-def]
        return jsonify({"error": str(exc)}), 500

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-agent-gui")
    parser.add_argument("--port", type=int, default=8765, help="local port to bind")
    parser.add_argument("--state", default=".data/cve-agent-gui.json", help="path to GUI global settings")
    parser.add_argument(
        "--config",
        default="config.toml",
        help="configuration used to initialize config.gui.toml on first use",
    )
    parser.add_argument(
        "--taxonomy",
        default="fixtures/hybrid_taxonomy.json",
        help="initial taxonomy path",
    )
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be in [1, 65535]")
    try:
        # The configured database is resolved by load_settings when defaults are read.
        from cve_agent.config import load_settings

        path_policy = GuiPathPolicy(Path.cwd())
        path_policy.prepare_runtime_directories()
        source_config_path = path_policy.configuration_file(args.config, must_exist=False)
        taxonomy_path = path_policy.taxonomy_file(args.taxonomy)
        config_path = ensure_gui_config(source_config_path, path_policy)
        initial_settings = load_settings(config_path)
        database_path = path_policy.database_file(initial_settings.database)
        path_policy.cache_directory(initial_settings.cache_dir)
        store = GlobalSettingsStore(
            args.state,
            GlobalGuiSettings(database_path, config_path, taxonomy_path),
            path_policy,
        )
        current = store.get()
        current_config_path = ensure_gui_config(current.default_config_path, path_policy)
        if current_config_path != current.default_config_path:
            store.update({
                **current.to_dict(),
                "default_config_path": str(current_config_path),
            })
        service = GuiService(store)
    except Exception as exc:
        raise SystemExit(f"GUI startup error: {exc}") from exc
    atexit.register(service.close)
    app = create_gui_app(service)
    host = "127.0.0.1"
    url = f"http://{host}:{args.port}"
    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    print(f"CVE Agent GUI: {url}", file=sys.stderr)
    app.run(host=host, port=args.port, debug=False, use_reloader=False, threaded=True)


def _json_body() -> dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise GuiConfigurationError("request body must be a JSON object")
    return body


if __name__ == "__main__":
    main()
