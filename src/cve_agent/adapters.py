from __future__ import annotations

import json
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from openai import OpenAI

from .config import Settings
from .models import CVERecord, ClassificationResult, Document, Evidence, LabelClassification, Reference, SearchResult


def _request_json(url: str, timeout: float, retries: int, headers: dict[str, str] | None = None) -> Any:
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (TimeoutError, urllib.error.URLError):
            if attempt >= retries:
                raise
            time.sleep(0.2 * (2**attempt))


class NVDClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def get_cve(self, cve_id: str) -> CVERecord:
        url = f"{self.settings.nvd_base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        payload = _request_json(url, self.settings.nvd_timeout, self.settings.retry_count)
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise LookupError(f"CVE not found: {cve_id}")
        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), descriptions[0].get("value", "") if descriptions else "")
        references = tuple(Reference(x.get("url", ""), x.get("source"), tuple(x.get("tags", []))) for x in cve.get("references", []) if x.get("url"))
        return CVERecord(cve.get("id", cve_id), description, references, {"published": cve.get("published"), "last_modified": cve.get("lastModified"), "source_identifier": cve.get("sourceIdentifier")})


class CachedWebClient:
    def __init__(self, settings: Settings, searcher: Callable[[str], list[SearchResult]] | None = None):
        self.settings = settings
        self.searcher = searcher
        self.settings.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache(self, prefix: str, key: str) -> Path:
        import hashlib
        return self.settings.cache_dir / f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()}.json"

    def search(self, query: str) -> list[SearchResult]:
        path = self._cache("search", query)
        if path.exists():
            return [SearchResult(**item) for item in json.loads(path.read_text(encoding="utf-8"))]
        if self.searcher is None:
            raise RuntimeError("no web search provider configured")
        results = self.searcher(query)
        path.write_text(json.dumps([x.__dict__ for x in results]), encoding="utf-8")
        return results

    def fetch(self, url: str) -> Document:
        path = self._cache("fetch", url)
        if path.exists():
            return Document(**json.loads(path.read_text(encoding="utf-8")))
        request = urllib.request.Request(url, headers={"User-Agent": "cve-agent/0.1"})
        with urllib.request.urlopen(request, timeout=self.settings.web_timeout) as response:
            content = response.read().decode("utf-8", errors="replace")
        document = Document(url=url, content=content)
        path.write_text(json.dumps(document.__dict__), encoding="utf-8")
        return document


class VLLMClassifier:
    def __init__(self, settings: Settings, client: OpenAI | None = None):
        self.settings = settings
        self.client = client or OpenAI(
            api_key=settings.api_key or "EMPTY",
            base_url=settings.endpoint,
            timeout=settings.llm_timeout,
            max_retries=settings.retry_count,
        )

    def classify(self, cve, evidence, taxonomy, state) -> ClassificationResult:
        prompt = {"cve": cve.__dict__, "evidence": [getattr(x, "__dict__", {}) for x in evidence], "taxonomy": taxonomy.to_dict(), "investigation": state.to_dict()}
        response = self.client.chat.completions.create(
            model=self.settings.model,
            temperature=self.settings.temperature,
            top_p=self.settings.top_p,
            max_tokens=self.settings.max_tokens,
            messages=[
                {"role": "system", "content": "Return only valid JSON matching the requested CVE classification schema."},
                {"role": "user", "content": json.dumps(prompt)},
            ],
        )
        content = response.choices[0].message.content or ""
        decoded = json.loads(content[content.find("{"):content.rfind("}") + 1])
        status = decoded.get("status")
        if status not in {"classified", "not_enough_information"}:
            raise ValueError(f"invalid classification status: {status!r}")
        labels = [LabelClassification(x["label"], float(x["confidence"]), tuple(Evidence(**e) for e in x.get("evidence", []))) for x in decoded.get("labels", [])]
        allowed = taxonomy.by_id
        invalid = [x.label for x in labels if x.label not in allowed]
        if invalid:
            raise ValueError(f"classifier returned labels outside taxonomy: {invalid}")
        if any(not 0 <= x.confidence <= 1 or not x.evidence for x in labels):
            raise ValueError("each selected label requires confidence in [0, 1] and supporting evidence")
        if status == "not_enough_information" and labels:
            raise ValueError("not_enough_information results cannot contain labels")
        usage = response.usage.model_dump() if response.usage else {}
        return ClassificationResult(cve.cve_id, status, labels, operational={"token_usage": usage})
