from __future__ import annotations

from typing import Any
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from cve_agent.core.config import Settings
from cve_agent.core.identifiers import normalize_cve_id
from cve_agent.core.sources import CVERecord, Reference


logger = logging.getLogger("cve_agent.adapters")


def _request_json(url: str, timeout: float, retries: int, headers: dict[str, str] | None = None) -> Any:
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (TimeoutError, urllib.error.URLError) as exc:
            logger.warning(
                "NVD request failed attempt=%d/%d retrying=%s error_type=%s",
                attempt + 1,
                retries + 1,
                attempt < retries,
                type(exc).__name__,
            )
            if attempt >= retries:
                raise
            time.sleep(0.2 * (2**attempt))


class NVDClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def get_cve(self, cve_id: str) -> CVERecord:
        cve_id = normalize_cve_id(cve_id)
        logger.info("[%s] NVD request started", cve_id)
        url = f"{self.settings.nvd_base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        payload = _request_json(url, self.settings.nvd_timeout, self.settings.nvd_retry_count)
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise LookupError(f"CVE not found: {cve_id}")
        cve = vulnerabilities[0].get("cve", {})
        try:
            returned_cve_id = normalize_cve_id(cve.get("id"))
        except ValueError as exc:
            raise LookupError("NVD returned a response without a valid CVE ID") from exc
        if returned_cve_id != cve_id:
            raise LookupError(f"NVD returned {returned_cve_id} for requested {cve_id}")
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), descriptions[0].get("value", "") if descriptions else "")
        references = tuple(Reference(x.get("url", ""), x.get("source"), tuple(x.get("tags", []))) for x in cve.get("references", []) if x.get("url"))
        record = CVERecord(returned_cve_id, description, references, {"published": cve.get("published"), "last_modified": cve.get("lastModified"), "source_identifier": cve.get("sourceIdentifier")})
        logger.info("[%s] NVD request finished description_chars=%d references=%d", cve_id, len(description), len(references))
        return record
