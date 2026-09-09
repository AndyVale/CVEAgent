from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol
import threading
import uuid

from cve_agent.application.service import ApplicationRun
from cve_agent.core.config import Settings
from cve_agent.core.ports import AnalysisHistory, AnalysisProgress
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.gui.configuration import AnalysisConfiguration
from cve_agent.gui.progress import _event, _result_tone, capture_progress
from cve_agent.runtime.diagnostics import redact_secrets


class Application(Protocol):
    def run(
        self,
        cve_ids: list[str],
        taxonomy: Taxonomy,
        *,
        progress: AnalysisProgress | None = None,
    ) -> ApplicationRun: ...


ApplicationFactory = Callable[[Settings], Application]


@dataclass
class RunningAnalysis:
    analysis_id: str
    cve_id: str
    configuration: AnalysisConfiguration
    repository: AnalysisHistory
    lifecycle: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    stored_analysis_id: str | None = None
    _progress_warning: dict[str, Any] | None = field(default=None, repr=False)
    _persistence_paused: bool = field(default=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add_event(self, *, tone: str, component: str, message: str) -> None:
        with self._lock:
            event = _event(tone=tone, component=component, message=message)
            sequence = len(self.events)
            self.events.append(event)
            if self.stored_analysis_id is not None and not self._persistence_paused:
                self._save_events([event], start_sequence=sequence)

    def bind(self, analysis_id: str, cve_id: str) -> None:
        if cve_id != self.cve_id:
            raise ValueError("progress target CVE does not match the running analysis")
        with self._lock:
            if self.stored_analysis_id not in {None, analysis_id}:
                raise ValueError("progress target is already bound to another analysis")
            self.stored_analysis_id = analysis_id
            self._save_events(self.events, start_sequence=0, retry=True)

    def finish_progress(self) -> None:
        """Retry one complete, idempotent event flush before terminal eviction."""
        with self._lock:
            if self.stored_analysis_id is not None:
                self._save_events(self.events, start_sequence=0, retry=True)

    def progress_warning(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._progress_warning) if self._progress_warning else None

    def _save_events(
        self,
        events: list[dict[str, Any]],
        *,
        start_sequence: int,
        retry: bool = False,
    ) -> None:
        if not events or self.stored_analysis_id is None:
            return
        if self._persistence_paused and not retry:
            return
        try:
            self.repository.save_events(
                self.stored_analysis_id,
                events,
                start_sequence=start_sequence,
            )
        except Exception as exc:
            detail = redact_secrets(
                exc,
                self.configuration.settings.api_key,
                self.configuration.settings.tavily_api_key,
            )
            self._persistence_paused = True
            self._progress_warning = _event(
                tone="warning",
                component="SYSTEM",
                message=f"Analysis progress could not be saved: {detail}",
            )
        else:
            self._persistence_paused = False
            self._progress_warning = None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            events = [dict(event) for event in self.events]
            if self._progress_warning:
                events.append(dict(self._progress_warning))
            return {
                "id": self.analysis_id,
                "cve_id": self.cve_id,
                "lifecycle": self.lifecycle,
                "stored_analysis_id": self.stored_analysis_id,
                "events": events,
                "configuration": self.configuration.to_public_dict(),
                "result": None,
                "error": self.error,
            }


@dataclass(frozen=True)
class CompletedAnalysisReference:
    analysis_id: str
    database_path: Path
    warning: dict[str, Any] | None = None


@dataclass(frozen=True)
class TerminalAnalysis:
    running: RunningAnalysis | None = None
    completed: CompletedAnalysisReference | None = None


class AnalysisJobs:
    """Own background execution and the pending-to-persisted ID lifecycle."""

    def __init__(
        self,
        application_factory: ApplicationFactory,
        get_repository: Callable[[Path | None], AnalysisHistory],
        lock,
        executor: ThreadPoolExecutor | None = None,
        *,
        terminal_retention: int = 128,
    ):
        if terminal_retention <= 0:
            raise ValueError("terminal retention must be positive")
        self.application_factory = application_factory
        self._get_repository = get_repository
        self._lock = lock
        self._executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="cve-gui")
        self._owns_executor = executor is None
        self._running: dict[str, RunningAnalysis] = {}
        self._active: dict[tuple[str, str, str, str], RunningAnalysis] = {}
        self._terminal: OrderedDict[str, TerminalAnalysis] = OrderedDict()
        self._terminal_retention = terminal_retention

    def close(self) -> None:
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=False)

    def submit(self, cve_id: str, configuration: AnalysisConfiguration) -> dict[str, Any]:
        key = self._key(cve_id, configuration)
        analysis_id = f"pending-{uuid.uuid4().hex}"
        repository = self._get_repository(configuration.settings.database.resolve())
        running = RunningAnalysis(analysis_id, cve_id, configuration, repository)
        running.add_event(tone="normal", component="YOU", message=f"Analyze {cve_id}")
        running.add_event(
            tone="normal",
            component="SYSTEM",
            message=f"Queued with taxonomy {configuration.taxonomy_name} ({len(configuration.taxonomy.labels)} labels).",
        )
        with self._lock:
            existing = self._active.get(key)
            if existing and existing.lifecycle in {"queued", "running"}:
                return {"id": existing.analysis_id, "already_running": True, "lifecycle": existing.lifecycle}
            self._running[analysis_id] = running
            self._active[key] = running
            try:
                self._executor.submit(self._run_analysis, running)
            except Exception:
                self._running.pop(analysis_id, None)
                self._active.pop(key, None)
                raise
        return {"id": analysis_id, "already_running": False, "lifecycle": "queued"}

    @staticmethod
    def _key(cve_id: str, configuration: AnalysisConfiguration) -> tuple[str, str, str, str]:
        return (str(configuration.settings.database.resolve()), cve_id,
                configuration.taxonomy_fingerprint, configuration.settings_fingerprint)

    def _run_analysis(self, running: RunningAnalysis) -> None:
        configuration = running.configuration
        with running._lock:
            running.lifecycle = "running"
        running.add_event(tone="normal", component="SYSTEM", message="Analysis started.")
        try:
            with capture_progress(running, configuration.settings):
                outcome = self.application_factory(configuration.settings).run(
                    [running.cve_id],
                    configuration.taxonomy,
                    progress=running,
                )
            if not outcome.results:
                raise RuntimeError("classification pipeline returned no result")
            result = outcome.results[0]
            run_id = result.operational.get("run_id")
            if not isinstance(run_id, int):
                raise RuntimeError("classification result does not identify its persisted run")
            stored_id = f"{run_id}:0"
            running.bind(stored_id, running.cve_id)
            running.add_event(
                tone=_result_tone(str(result.status)),
                component="SYSTEM",
                message=f"Analysis finished with status {result.status} and {len(result.labels)} label(s).",
            )
            running.finish_progress()
            with running._lock:
                running.lifecycle = "completed"
            with self._lock:
                self._running.pop(running.analysis_id, None)
                self._remember_terminal(
                    running.analysis_id,
                    TerminalAnalysis(completed=CompletedAnalysisReference(
                        analysis_id=stored_id,
                        database_path=configuration.settings.database.resolve(),
                        warning=running.progress_warning(),
                    )),
                )
        except Exception as exc:
            detail = redact_secrets(exc, configuration.settings.api_key, configuration.settings.tavily_api_key)
            running.add_event(tone="error", component="SYSTEM", message=f"Analysis failed: {detail}")
            with running._lock:
                running.lifecycle = "failed"
                running.error = detail
            running.finish_progress()
            with self._lock:
                self._running.pop(running.analysis_id, None)
                self._remember_terminal(
                    running.analysis_id,
                    TerminalAnalysis(running=running),
                )
        finally:
            with self._lock:
                key = self._key(running.cve_id, configuration)
                if self._active.get(key) is running:
                    self._active.pop(key)

    def lookup(
        self,
        analysis_id: str,
    ) -> tuple[RunningAnalysis | None, CompletedAnalysisReference | None]:
        with self._lock:
            running = self._running.get(analysis_id)
            if running is not None:
                return running, None
            terminal = self._terminal.get(analysis_id)
            if terminal is None:
                return None, None
            self._terminal.move_to_end(analysis_id)
            return terminal.running, terminal.completed

    def progress_warning(self, analysis_id: str) -> dict[str, Any] | None:
        with self._lock:
            running = self._running.get(analysis_id)
            if running is not None:
                return running.progress_warning()
            terminal = self._terminal.get(analysis_id)
            if terminal is None:
                return None
            warning = (
                terminal.running.progress_warning()
                if terminal.running is not None
                else terminal.completed.warning
                if terminal.completed is not None
                else None
            )
            return dict(warning) if warning else None

    def has_active(self) -> bool:
        with self._lock:
            return any(item.lifecycle in {"queued", "running"} for item in self._running.values())

    def _remember_terminal(self, analysis_id: str, terminal: TerminalAnalysis) -> None:
        self._terminal[analysis_id] = terminal
        self._terminal.move_to_end(analysis_id)
        while len(self._terminal) > self._terminal_retention:
            self._terminal.popitem(last=False)
