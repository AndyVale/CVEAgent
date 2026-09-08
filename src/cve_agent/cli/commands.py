from __future__ import annotations

from dataclasses import replace
import argparse
import json
import logging
import sys

from cve_agent.application.factory import create_application
from cve_agent.classification.evaluation import BenchmarkError, load_benchmark
from cve_agent.cli.evaluation_format import (
    format_classification_summary,
    format_evaluation_report,
    format_output_header,
)
from cve_agent.cli.logging import verbose_logging
from cve_agent.cli.settings_format import format_settings_table
from cve_agent.core.config import load_settings, parse_finite_number
from cve_agent.core.identifiers import CVEIdentifierError, normalize_cve_id
from cve_agent.core.ports import AnalysisWriter, CVESource, Classifier, WebSource
from cve_agent.core.taxonomy import TaxonomyError, load_taxonomy
from cve_agent.runtime.diagnostics import LogTone, log_extra


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cve-agent")
    parser.add_argument("--taxonomy", required=True, help="path to taxonomy JSON")
    parser.add_argument("--config", default="config.toml", help="path to TOML configuration")
    parser.add_argument("--verbose", action="store_true", help="log pipeline and agent progress to stderr")
    parser.add_argument("--validate", metavar="PATH", help="compare results with expected classifications; uses all validation CVEs when no CVE_ID is supplied")
    parser.add_argument("--llm-min-request-interval", type=float, default=None, metavar="SECONDS", help="minimum seconds between model request starts (overrides config)")
    parser.add_argument("cve_ids", nargs="*", metavar="CVE_ID")
    return parser


def run(argv: list[str], *, cve_source: CVESource | None = None, web_source: WebSource | None = None, classifier: Classifier | None = None, database: AnalysisWriter | None = None) -> int:
    args = build_parser().parse_args(argv)
    with verbose_logging(args.verbose):
        logger = logging.getLogger("cve_agent.cli")
        try:
            taxonomy = load_taxonomy(args.taxonomy)
            benchmark = load_benchmark(args.validate, taxonomy) if args.validate else None
            if benchmark:
                benchmark = benchmark.select(args.cve_ids) if args.cve_ids else benchmark
                cve_ids = benchmark.cve_ids
            else:
                if not args.cve_ids:
                    raise BenchmarkError("provide at least one CVE_ID or use --validate")
                cve_ids = [normalize_cve_id(cve_id) for cve_id in args.cve_ids]
            settings = load_settings(args.config)
            if args.llm_min_request_interval is not None:
                request_interval = parse_finite_number(
                    args.llm_min_request_interval,
                    "--llm-min-request-interval",
                )
                if request_interval < 0:
                    raise ValueError("--llm-min-request-interval must be non-negative")
                settings = replace(settings, llm_min_request_interval=request_interval)
            logger.info("loaded taxonomy=%s labels=%d", args.taxonomy, len(taxonomy.labels))
            if benchmark:
                logger.info("loaded validation classifications=%s cases=%d", args.validate, len(benchmark.cases))
            logger.info("%s", format_settings_table(settings))
            logger.info("processing %d CVE(s)", len(cve_ids))
            application = create_application(
                settings,
                cve_source=cve_source,
                web_source=web_source,
                classifier=classifier,
                database=database,
            )
            outcome = application.run(cve_ids, taxonomy, benchmark)
            results = list(outcome.results)
            print("\n" + format_output_header("Classification results (JSON)"), file=sys.stderr, flush=True)
            print(json.dumps([result.to_dict() for result in results], indent=2), flush=True)
            print("\n" + format_classification_summary(results, outcome.evaluation), file=sys.stderr)
            if outcome.evaluation:
                print("\n" + format_evaluation_report(outcome.evaluation), file=sys.stderr)
            logger.info(
                "run completed successful=%d partial=%d failed=%d",
                outcome.successful_count,
                outcome.partial_count,
                outcome.failed_count,
                extra=log_extra(
                    LogTone.ERROR
                    if outcome.failed_count
                    else LogTone.INCOMPLETE
                    if outcome.partial_count
                    else LogTone.SUCCESS,
                    section=True,
                ),
            )
            return 0 if outcome.complete else 2
        except TaxonomyError as exc:
            _report_error(logger, args.verbose, "taxonomy", exc)
            return 3
        except BenchmarkError as exc:
            _report_error(logger, args.verbose, "evaluation", exc)
            return 3
        except CVEIdentifierError as exc:
            _report_error(logger, args.verbose, "input", exc)
            return 3
        except Exception as exc:
            _report_error(logger, args.verbose, "fatal", exc)
            return 4


def _report_error(logger: logging.Logger, verbose: bool, category: str, exc: Exception) -> None:
    message = f"{category} error: {exc}"
    if verbose:
        logger.error(message, extra=log_extra(LogTone.ERROR, section=True))
    else:
        print(message, file=sys.stderr)


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))
