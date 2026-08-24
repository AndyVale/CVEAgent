from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import replace

from cve_agent.adapters import CachedWebClient, NVDClient, TavilySearchProvider
from cve_agent.agent import InvestigationAgent
from cve_agent.config import format_settings_table, load_settings, non_secret_settings
from cve_agent.evaluation import BenchmarkError, evaluate_results, format_classification_summary, format_evaluation_report, load_benchmark
from cve_agent.logging_config import verbose_logging
from cve_agent.models import ClassificationStatus
from cve_agent.persistence import Database
from cve_agent.pipeline import Pipeline
from cve_agent.ports import CVESource, Classifier, WebSource
from cve_agent.taxonomy import TaxonomyError, load_taxonomy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-agent")
    parser.add_argument("--taxonomy", required=True, help="path to taxonomy JSON")
    parser.add_argument("--config", default="config.toml", help="path to TOML configuration")
    parser.add_argument("--verbose", action="store_true", help="log pipeline and agent progress to stderr")
    parser.add_argument("--validate", metavar="PATH", help="compare results with expected classifications; uses all validation CVEs when no CVE_ID is supplied")
    parser.add_argument("--llm-min-request-interval", type=float, default=None, metavar="SECONDS", help="minimum seconds between model request starts (overrides config)")
    parser.add_argument("cve_ids", nargs="*", metavar="CVE_ID")
    return parser


def run(argv: list[str], *, cve_source: CVESource | None = None, web_source: WebSource | None = None, classifier: Classifier | None = None, database: Database | None = None) -> int:
    args = build_parser().parse_args(argv)
    with verbose_logging(args.verbose):
        logger = logging.getLogger(__name__)
        try:
            taxonomy = load_taxonomy(args.taxonomy)
            benchmark = load_benchmark(args.validate, taxonomy) if args.validate else None
            if benchmark:
                benchmark = benchmark.select(args.cve_ids) if args.cve_ids else benchmark
                cve_ids = benchmark.cve_ids
            else:
                if not args.cve_ids:
                    raise BenchmarkError("provide at least one CVE_ID or use --validate")
                cve_ids = args.cve_ids
            settings = load_settings(args.config)
            if args.llm_min_request_interval is not None:
                if args.llm_min_request_interval < 0:
                    raise ValueError("--llm-min-request-interval must be non-negative")
                settings = replace(settings, llm_min_request_interval=args.llm_min_request_interval)
            logger.info("loaded taxonomy=%s labels=%d", args.taxonomy, len(taxonomy.labels))
            if benchmark:
                logger.info("loaded validation classifications=%s cases=%d", args.validate, len(benchmark.cases))
            logger.info("%s", format_settings_table(settings))
            logger.info("processing %d CVE(s)", len(cve_ids))
            active_web_source = web_source or CachedWebClient(settings, searcher=TavilySearchProvider(settings).search if settings.web_provider == "tavily" else None)
            pipeline = Pipeline(
                cve_source or NVDClient(settings),
                classifier or InvestigationAgent(settings, active_web_source),
                database or Database(settings.database),
                run_metadata={"model": settings.model, "settings": non_secret_settings(settings)},
            )
            results = pipeline.run(cve_ids, taxonomy)
            print(json.dumps([result.to_dict() for result in results], indent=2), flush=True)
            report = evaluate_results(results, benchmark, taxonomy) if benchmark else None
            print(format_classification_summary(results, report), file=sys.stderr)
            if report:
                print(format_evaluation_report(report), file=sys.stderr)
            failed = sum(result.status == ClassificationStatus.FAILED for result in results)
            incomplete = sum(result.status == ClassificationStatus.PARTIAL for result in results)
            logger.info("run completed: %d classified/information-limited, %d partial, %d failed", len(results) - failed - incomplete, incomplete, failed)
            return 0 if all(result.status in {ClassificationStatus.CLASSIFIED, ClassificationStatus.NO_MATCHING_LABEL, ClassificationStatus.NOT_ENOUGH_INFORMATION} for result in results) else 2
        except TaxonomyError as exc:
            print(f"taxonomy error: {exc}", file=sys.stderr)
            return 3
        except BenchmarkError as exc:
            print(f"evaluation error: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"fatal error: {exc}", file=sys.stderr)
            return 4


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))
