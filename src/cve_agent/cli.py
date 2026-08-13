from __future__ import annotations

import argparse
import json
import sys

from .config import load_settings
from .adapters import CachedWebClient, NVDClient, VLLMClassifier
from .pipeline import Pipeline
from .ports import CVESource, Classifier, WebSource
from .persistence import Database
from .taxonomy import TaxonomyError, load_taxonomy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-agent")
    parser.add_argument("--taxonomy", required=True, help="path to taxonomy JSON")
    parser.add_argument("--config", default="config.toml", help="path to TOML configuration")
    parser.add_argument("cve_ids", nargs="+", metavar="CVE_ID")
    return parser


def run(argv: list[str], *, cve_source: CVESource | None = None, web_source: WebSource | None = None, classifier: Classifier | None = None, database: Database | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        taxonomy = load_taxonomy(args.taxonomy)
        settings = load_settings(args.config)
        pipeline = Pipeline(
            cve_source or NVDClient(settings),
            web_source or CachedWebClient(settings),
            classifier or VLLMClassifier(settings),
            database or Database(settings.database),
        )
        results = pipeline.run(args.cve_ids, taxonomy)
        print(json.dumps([result.to_dict() for result in results], indent=2))
        return 0 if all(result.status != "failed" for result in results) else 2
    except TaxonomyError as exc:
        print(f"taxonomy error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"fatal error: {exc}", file=sys.stderr)
        return 4


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))
