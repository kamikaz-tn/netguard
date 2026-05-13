"""
netguard/backend/routers/cve.py
────────────────────────────────
CVE lookup proxy — queries the NVD (National Vulnerability Database) API
for known vulnerabilities matching a detected service + version string.

Why proxy instead of hitting NVD directly from the browser?
  - NVD rate limits by IP: 5 req/30s without an API key
  - We can cache results server-side so repeat lookups are instant
  - We can enrich/filter results before sending to the client

Endpoints:
  GET /api/cve/lookup?service=apache&version=2.4.51   → list of CVEs
  GET /api/cve/port/{port}                            → CVEs for a known port/service
"""

import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel

from core.auth import get_current_user

router = APIRouter(prefix="/api/cve", tags=["CVE Lookup"])
limiter = Limiter(key_func=get_remote_address)

# ── In-memory cache: key → (timestamp, data) ─────────────────────────────────
# Avoids hammering NVD on repeated lookups for the same service.
# TTL: 1 hour (CVE data doesn't change by the minute).
_cache: dict = {}
CACHE_TTL_SECONDS = 3600

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Known service names for well-known ports (fallback when no version banner)
PORT_SERVICE_MAP = {
    21:    "ftp",
    22:    "openssh",
    23:    "telnet",
    80:    "apache http",
    135:   "microsoft rpc",
    139:   "netbios",
    443:   "openssl",
    445:   "samba",
    3306:  "mysql",
    3389:  "windows remote desktop",
    4444:  "metasploit",
    5900:  "vnc",
    8080:  "apache tomcat",
}


# ── Response schema ───────────────────────────────────────────────────────────
class CVEItem(BaseModel):
    cve_id: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_score: float
    published: str
    url: str


class CVEResponse(BaseModel):
    query: str
    total_results: int
    cves: List[CVEItem]
    cached: bool


# ── Cache helpers ─────────────────────────────────────────────────────────────
def _cache_get(key: str):
    if key not in _cache:
        return None
    ts, data = _cache[key]
    if datetime.utcnow() - ts > timedelta(seconds=CACHE_TTL_SECONDS):
        del _cache[key]
        return None
    return data


def _cache_set(key: str, data):
    _cache[key] = (datetime.utcnow(), data)


# ── CVE severity from CVSS score ──────────────────────────────────────────────
def _severity_from_score(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"


# ── NVD API fetch ─────────────────────────────────────────────────────────────
async def _fetch_nvd(keyword: str, max_results: int = 8) -> List[CVEItem]:
    """
    Query NVD CVE 2.0 API.
    Returns up to max_results CVEs sorted by CVSS score descending.
    Falls back gracefully if NVD is unreachable.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results * 2, 20),  # fetch more, filter after
        "startIndex": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(NVD_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="NVD API timed out. Try again in a moment.")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="NVD rate limit hit. Wait 30 seconds and retry, or add an NVD_API_KEY to your .env."
            )
        raise HTTPException(status_code=502, detail=f"NVD API error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach NVD: {str(e)}")

    items: List[CVEItem] = []

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Description — prefer English
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description available.")
        # Truncate long descriptions
        if len(desc) > 220:
            desc = desc[:217] + "..."

        # CVSS score — try v3.1 first, then v3.0, then v2
        metrics   = cve.get("metrics", {})
        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or
            metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) or
            metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {}) or {}
        )
        score    = float(cvss_data.get("baseScore", 0.0))
        severity = cvss_data.get("baseSeverity", _severity_from_score(score))

        published = cve.get("published", "")[:10]  # just the date part

        items.append(CVEItem(
            cve_id=cve_id,
            description=desc,
            severity=severity.upper(),
            cvss_score=score,
            published=published,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))

    # Sort by severity, then CVSS score
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    items.sort(key=lambda x: (severity_order.get(x.severity, 5), -x.cvss_score))

    return items[:max_results]


# ── GET /api/cve/lookup ───────────────────────────────────────────────────────
@router.get("/lookup", response_model=CVEResponse)
@limiter.limit("30/minute")
async def lookup_cve(
    request: Request,
    service: str = Query(..., min_length=2, max_length=60, description="Service name, e.g. 'apache'"),
    version: Optional[str] = Query(None, max_length=40, description="Version string, e.g. '2.4.51'"),
    current_user: dict = Depends(get_current_user),
):
    """
    Look up CVEs for a detected service + optional version.
    Results are cached for 1 hour.

    Example: GET /api/cve/lookup?service=apache&version=2.4.51
    """
    # Build search keyword — service + version gives much more precise results
    keyword = service.strip().lower()
    if version and version.strip():
        keyword = f"{keyword} {version.strip()}"

    cache_key = f"cve:{keyword}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return CVEResponse(
            query=keyword,
            total_results=len(cached),
            cves=cached,
            cached=True,
        )

    cves = await _fetch_nvd(keyword)
    _cache_set(cache_key, cves)

    return CVEResponse(
        query=keyword,
        total_results=len(cves),
        cves=cves,
        cached=False,
    )


# ── GET /api/cve/port/{port} ──────────────────────────────────────────────────
@router.get("/port/{port}", response_model=CVEResponse)
@limiter.limit("30/minute")
async def lookup_cve_by_port(
    request: Request,
    port: int,
    current_user: dict = Depends(get_current_user),
):
    """
    Look up CVEs for a well-known port using the built-in service map.
    Useful when no version banner is available.

    Example: GET /api/cve/port/445 → CVEs for 'samba'
    """
    service = PORT_SERVICE_MAP.get(port)
    if not service:
        raise HTTPException(
            status_code=404,
            detail=f"No known service mapping for port {port}. Use /lookup?service=<name> instead."
        )

    cache_key = f"cve:port:{port}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return CVEResponse(query=service, total_results=len(cached), cves=cached, cached=True)

    cves = await _fetch_nvd(service)
    _cache_set(cache_key, cves)

    return CVEResponse(query=service, total_results=len(cves), cves=cves, cached=False)
