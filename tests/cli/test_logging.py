import io
import logging

from cve_agent.cli.logging import VerboseFormatter, supports_color
from cve_agent.runtime.diagnostics import LogTone, log_extra


class TerminalBuffer(io.StringIO):
    def isatty(self):
        return True


def record(message="first line\n\nthird line", level=logging.INFO, **attributes):
    item = logging.LogRecord("cve_agent.pipeline", level, __file__, 1, message, (), None)
    for name, value in attributes.items():
        setattr(item, name, value)
    return item


def test_verbose_formatter_aligns_multiline_messages_and_sections_without_color():
    rendered = VerboseFormatter(color=False).format(record(section_break=True))
    lines = rendered.splitlines()

    assert lines[0] == ""
    assert "INFO" in lines[1]
    assert "PIPELINE" in lines[1]
    assert lines[1].endswith("first line")
    assert lines[2] == ""
    assert lines[3].endswith("third line")
    assert lines[3].index("third line") == lines[1].index("first line")
    assert "\033[" not in rendered


def test_verbose_formatter_uses_semantic_badges_and_colors():
    complete = VerboseFormatter(color=True).format(record("done", **log_extra(LogTone.SUCCESS)))
    incomplete = VerboseFormatter(color=True).format(record("partial", **log_extra(LogTone.INCOMPLETE)))
    warning = VerboseFormatter(color=True).format(record("warning", level=logging.WARNING))
    error = VerboseFormatter(color=True).format(record("bad", level=logging.ERROR))

    assert "\033[32m" in complete and "COMPLETE" in complete
    assert "\033[35m" in incomplete and "INCOMPLETE" in incomplete
    assert "\033[33m" in warning and "WARNING" in warning
    assert "\033[31m" in error and "ERROR" in error


def test_verbose_formatter_ignores_missing_or_invalid_external_tones():
    formatter = VerboseFormatter(color=False)

    assert "INFO" in formatter.format(record("missing", tone=None))
    assert "INFO" in formatter.format(record("unknown", tone="provider-defined"))
    assert "WARNING" in formatter.format(record("warning", level=logging.WARNING, tone=None))
    assert "ERROR" in formatter.format(record("error", level=logging.ERROR, tone=[]))


def test_color_support_requires_a_tty_and_honors_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert supports_color(TerminalBuffer())
    assert not supports_color(io.StringIO())
    monkeypatch.setenv("NO_COLOR", "1")
    assert not supports_color(TerminalBuffer())
