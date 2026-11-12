"""CVE intelligence feeds — NVD, CISA KEV, FIRST EPSS.

Enriches findings with real-time vulnerability intelligence without
external dependencies (stdlib urllib only). Results cached locally to
respect rate limits and avoid redundant fetches.
"""

import json
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


CACHE_TTL_SECONDS = 86400  # 24 hours

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
ZERO_WIRE_RSS = "https://radar.cloudflare.com/security/zero-wire/rss.xml"


@dataclass
class CVERecord:
    cve_id: str
    description: str = ""
    cvss_v31_score: float = 0.0
    cvss_v31_vector: str = ""
    cvss_v40_score: float = 0.0
    cvss_v40_vector: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    in_kev: bool = False
    kev_due_date: str = ""
    references: list[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""
    fetched_at: str = ""

    def __post_init__(self):
        if not self.fetched_at:
            self.fetched_at = datetime.now(timezone.utc).isoformat()


class CVEFeedClient:
    def __init__(self, audit_dir: str, api_key: str = ""):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.cache_file = self.state_dir / "cve_cache.json"
        self.api_key = api_key
        self._cache: dict[str, dict] = {}
        self._kev_set: set[str] | None = None
        self._load_cache()

    def _load_cache(self):
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text())
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save_cache(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(json.dumps(self._cache, indent=2))

    def _is_cached(self, key: str) -> bool:
        entry = self._cache.get(key)
        if not entry:
            return False
        fetched = entry.get("fetched_at", "")
        if not fetched:
            return False
        try:
            ts = datetime.fromisoformat(fetched.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - ts).total_seconds()
            return age < CACHE_TTL_SECONDS
        except (ValueError, TypeError):
            return False

    def _http_get(self, url: str, headers: dict | None = None) -> dict | None:
        hdrs = {"User-Agent": "quarry/1.0"}
        if headers:
            hdrs.update(headers)
        if self.api_key and "nvd.nist.gov" in url:
            hdrs["apiKey"] = self.api_key
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
                OSError, TimeoutError):
            return None

    def query_nvd(self, cve_id: str = "", cpe: str = "",
                  keyword: str = "") -> list[CVERecord]:
        if cve_id and self._is_cached(cve_id):
            return [CVERecord(**self._cache[cve_id])]

        params: dict[str, str] = {}
        if cve_id:
            params["cveId"] = cve_id
        if cpe:
            params["cpeName"] = cpe
        if keyword:
            params["keywordSearch"] = keyword

        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        data = self._http_get(url)
        if not data:
            return []

        records = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cid = cve.get("id", "")

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            cvss31_score, cvss31_vec = 0.0, ""
            cvss40_score, cvss40_vec = 0.0, ""
            metrics = cve.get("metrics", {})
            for m in metrics.get("cvssMetricV31", []):
                cd = m.get("cvssData", {})
                cvss31_score = cd.get("baseScore", 0.0)
                cvss31_vec = cd.get("vectorString", "")
                break
            for m in metrics.get("cvssMetricV40", []):
                cd = m.get("cvssData", {})
                cvss40_score = cd.get("baseScore", 0.0)
                cvss40_vec = cd.get("vectorString", "")
                break

            refs = [r.get("url", "") for r in cve.get("references", [])
                    if r.get("url")][:10]

            rec = CVERecord(
                cve_id=cid,
                description=desc,
                cvss_v31_score=cvss31_score,
                cvss_v31_vector=cvss31_vec,
                cvss_v40_score=cvss40_score,
                cvss_v40_vector=cvss40_vec,
                references=refs,
                published=cve.get("published", ""),
                last_modified=cve.get("lastModified", ""),
            )
            records.append(rec)
            self._cache[cid] = asdict(rec)

        self._save_cache()
        time.sleep(0.6)  # NVD rate limit: ~50 req/30s without API key
        return records

    def query_kev(self) -> set[str]:
        if self._kev_set is not None:
            return self._kev_set

        cache_key = "_kev_catalog"
        if self._is_cached(cache_key):
            self._kev_set = set(self._cache[cache_key].get("cve_ids", []))
            return self._kev_set

        data = self._http_get(KEV_URL)
        if not data:
            self._kev_set = set()
            return self._kev_set

        kev_map: dict[str, str] = {}
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID", "")
            if cid:
                kev_map[cid] = v.get("dueDate", "")

        self._kev_set = set(kev_map.keys())
        self._cache[cache_key] = {
            "cve_ids": sorted(self._kev_set),
            "due_dates": kev_map,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_cache()
        return self._kev_set

    def query_epss(self, cve_ids: list[str]) -> dict[str, dict]:
        results: dict[str, dict] = {}
        uncached = [c for c in cve_ids if not self._is_cached(f"epss:{c}")]

        for c in cve_ids:
            cached = self._cache.get(f"epss:{c}")
            if cached and self._is_cached(f"epss:{c}"):
                results[c] = cached

        if uncached:
            batch_size = 30
            for i in range(0, len(uncached), batch_size):
                batch = uncached[i:i + batch_size]
                url = f"{EPSS_API_BASE}?cve={','.join(batch)}"
                data = self._http_get(url)
                if data:
                    for item in data.get("data", []):
                        cid = item.get("cve", "")
                        entry = {
                            "epss": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                        }
                        results[cid] = entry
                        self._cache[f"epss:{cid}"] = entry

        self._save_cache()
        return results

    def _enrich_base(self, finding: dict, cve_id: str) -> dict:
        """Add NVD + KEV + EPSS data to a finding dict. Returns enriched copy."""
        enriched = dict(finding)

        nvd_results = self.query_nvd(cve_id=cve_id)
        if nvd_results:
            rec = nvd_results[0]
            enriched["cve_data"] = {
                "cve_id": rec.cve_id,
                "description": rec.description[:500],
                "cvss_v31": {"score": rec.cvss_v31_score, "vector": rec.cvss_v31_vector},
                "cvss_v40": {"score": rec.cvss_v40_score, "vector": rec.cvss_v40_vector},
                "references": rec.references,
                "published": rec.published,
            }

        kev = self.query_kev()
        enriched["in_kev"] = cve_id in kev
        if cve_id in kev:
            kev_data = self._cache.get("_kev_catalog", {})
            enriched["kev_due_date"] = kev_data.get("due_dates", {}).get(cve_id, "")

        epss = self.query_epss([cve_id])
        if cve_id in epss:
            enriched["epss"] = epss[cve_id]

        return enriched

    def query_zero_wire(self, cve_id: str = "") -> list[dict]:
        """Check Cloudflare Zero Wire for active vulnerability briefings.

        Returns briefing metadata for CVEs tracked by Zero Wire. These are
        high-priority: Cloudflare only covers critical, actively-exploited vulns.
        """
        cache_key = "_zero_wire"
        if not self._is_cached(cache_key):
            self._fetch_zero_wire_feed()

        entries = self._cache.get(cache_key, {}).get("entries", [])
        if cve_id:
            return [e for e in entries if cve_id.upper() in e.get("cves", [])]
        return entries

    def _fetch_zero_wire_feed(self):
        import re as _re
        import xml.etree.ElementTree as ET
        req = urllib.request.Request(ZERO_WIRE_RSS, headers={"User-Agent": "quarry/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
            self._cache["_zero_wire"] = {
                "entries": [],
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_cache()
            return

        entries = []
        try:
            root = ET.fromstring(raw)
            for item in root.findall(".//item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                desc = (item.findtext("description") or "").strip()
                pub_date = (item.findtext("pubDate") or "").strip()

                cves = _re.findall(r"CVE-\d{4}-\d{4,7}", f"{title} {desc}")
                cves = sorted(set(c.upper() for c in cves))

                if title:
                    entries.append({
                        "title": title,
                        "url": link,
                        "description": desc[:500],
                        "published": pub_date,
                        "cves": cves,
                        "source": "cloudflare_zero_wire",
                    })
        except ET.ParseError:
            pass

        self._cache["_zero_wire"] = {
            "entries": entries,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_cache()

    def enrich_finding(self, finding: dict, cve_id: str) -> dict:
        """Add NVD + KEV + EPSS + Zero Wire data to a finding dict."""
        enriched = self._enrich_base(finding, cve_id)

        zw = self.query_zero_wire(cve_id)
        if zw:
            enriched["zero_wire"] = {
                "tracked": True,
                "briefings": [{"title": b["title"], "url": b["url"]} for b in zw],
            }
            if not enriched.get("priority_boost"):
                enriched["priority_boost"] = "zero_wire_active"

        return enriched

    def summary(self) -> dict:
        cached_cves = [k for k in self._cache if k.startswith("CVE-")]
        zw = self._cache.get("_zero_wire", {})
        return {
            "cached_cves": len(cached_cves),
            "kev_loaded": self._kev_set is not None,
            "kev_count": len(self._kev_set) if self._kev_set else 0,
            "zero_wire_entries": len(zw.get("entries", [])),
        }
