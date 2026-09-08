from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
import logging
import threading
import uuid

from cve_agent.application.service import ApplicationRun
from cve_agent.core.config import Settings
from cve_agent.core.ports import AnalysisHistory
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.gui.configuration import AnalysisConfiguration
from cve_agent.gui.progress import _ProgressHandler, _result_tone
from cve_agent.gui.progress import _event
from cve_agent.runtime.diagnostics import redact_secrets


class Application(Protocol):
    def run(self, cve_ids: list[str], taxonomy: Taxonomy) -> ApplicationRun: ...


ApplicationFactory = Callable[[Settings], Application]


@dataclass
class RunningAnalysis:
    analysis_id: str
    cve_id: str
    configuration: AnalysisConfiguration
    lifecycle: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    stored_analysis_id: str | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add_event(self, *, tone: str, component: str, message: str) -> None:
        with self._lock:
            self.events.append(_event(tone=tone, component=component, message=message))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.analysis_id,
                "cve_id": self.cve_id,
                "lifecycle": self.lifecycle,
                "stored_analysis_id": self.stored_analysis_id,
                "events": [dict(event) for event in self.events],
                "configuration": self.configuration.to_public_dict(),
                "result": None,
                "error": self.error,
            }


class AnalysisJobs:
    """Own background execution and the pending-to-persisted ID lifecycle."""

    def __init__(self, application_factory: ApplicationFactory, get_repository: Callable[[], AnalysisHistory], lock, executor: ThreadPoolExecutor | None = None):
        self.application_factory = application_factory
        self._get_repository = get_repository
        self._lock = lock
        self._executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="cve-gui")
        self._owns_executor = executor is None
        self._running: dict[str, RunningAnalysis] = {}
        self._completed_aliases: dict[str, str] = {}

    def close(self) -> None:
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=False)

    def submit(self, cve_id: str, configuration: AnalysisConfiguration) -> dict[str, Any]:
        analysis_id = f"pending-{uuid.uuid4().hex}"
        running = RunningAnalysis(analysis_id, cve_id, configuration)
        running.add_event(tone="normal", component="YOU", message=f"Analyze {cve_id}")
        running.add_event(
            tone="normal",
            component="SYSTEM",
            message=f"Queued with taxonomy {configuration.taxonomy_name} ({len(configuration.taxonomy.labels)} labels).",
        )
        with self._lock:
            self._running[analysis_id] = running
        self._executor.submit(self._run_analysis, running)
        return {"id": analysis_id, "cached": False, "lifecycle": "queued"}

    def _run_analysis(self, running: RunningAnalysis) -> None:
        configuration = running.configuration
        with running._lock:
            running.lifecycle = "running"
        running.add_event(tone="normal", component="SYSTEM", message="Analysis started.")
        handler = _ProgressHandler(running, configuration.settings)
        package_logger = logging.getLogger("cve_agent")
        previous_level = package_logger.level
        previous_propagate = package_logger.propagate
        package_logger.addHandler(handler)
        package_logger.setLevel(logging.INFO)
        package_logger.propagate = False
        try:
            outcome = self.application_factory(configuration.settings).run(
                [running.cve_id], configuration.taxonomy
            )
            if not outcome.results:
                raise RuntimeError("classification pipeline returned no result")
            result = outcome.results[0]
            run_id = result.operational.get("run_id")
            if not isinstance(run_id, int):
                raise RuntimeError("classification result does not identify its persisted run")
            stored_id = f"{run_id}:0"
            running.add_event(
                tone=_result_tone(str(result.status)),
                component="SYSTEM",
                message=f"Analysis finished with status {result.status} and {len(result.labels)} label(s).",
            )
            self._get_repository().save_events(stored_id, running.events)
            with running._lock:
                running.stored_analysis_id = stored_id
                running.lifecycle = "completed"
            with self._lock:
                self._completed_aliases[running.analysis_id] = stored_id
                self._running.pop(running.analysis_id, None)
        except Exception as exc:
            detail = redact_secrets(exc, configuration.settings.api_key, configuration.settings.tavily_api_key)
            running.add_event(tone="error", component="SYSTEM", message=f"Analysis failed: {detail}")
            with running._lock:
                running.lifecycle = "failed"
                running.error = detail
        finally:
            package_logger.removeHandler(handler)
            handler.close()
            package_logger.setLevel(previous_level)
            package_logger.propagate = previous_propagate

    def lookup(self, analysis_id: str) -> tuple[RunningAnalysis | None, str | None]:
        with self._lock:
            return self._running.get(analysis_id), self._completed_aliases.get(analysis_id)

    def has_active(self) -> bool:
        with self._lock:
            return any(item.lifecycle in {"queued", "running"} for item in self._running.values())
