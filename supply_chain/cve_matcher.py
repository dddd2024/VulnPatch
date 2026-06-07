"""
CVE Vulnerability Matching Engine.

Matches dependency lists against known vulnerability databases (OSV, NVD,
GitHub Advisory via OSV) with semantic version range support and in-memory
TTL caching.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from supply_chain.models import (
    CVEMatch,
    Dependency,
    Ecosystem,
    SeverityLevel,
    VulnerabilityInfo,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ECOSYSTEM_MAP: Dict[Ecosystem, str] = {
    Ecosystem.PYTHON: "PyPI",
    Ecosystem.JAVASCRIPT: "npm",
    Ecosystem.TYPESCRIPT: "npm",
    Ecosystem.JAVA: "Maven",
    Ecosystem.GO: "Go",
    Ecosystem.RUST: "crates.io",
    Ecosystem.PHP: "Packagist",
    Ecosystem.RUBY: "RubyGems",
    Ecosystem.DOTNET: "NuGet",
}

# Regex helpers for version parsing
_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?"
    r"(?:[-+].*)?$"
)

_RANGE_OP_RE = re.compile(
    r"^(?P<op>>=|<=|>|<|=|~|\^)?(?P<ver>.+)$"
)


class CVEMatcher:
    """Matches project dependencies against known CVE / vulnerability databases.

    Supports OSV (primary), NVD (supplementary), and GitHub Advisory
    (via OSV ``GHSA-`` prefixed results).  Results are cached in memory with
    a configurable TTL to avoid redundant HTTP requests.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, cache_ttl: int = 3600, timeout: int = 30):
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        # cache key -> (timestamp, value)
        self._cache: Dict[str, Tuple[float, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def match_dependencies(
        self, dependencies: List[Dependency]
    ) -> List[CVEMatch]:
        """Batch CVE matching for a list of dependencies.

        Queries OSV (and optionally NVD) concurrently for every dependency,
        deduplicates results, and returns a flat list of :class:`CVEMatch`.
        """
        matches: List[CVEMatch] = []
        seen: set = set()

        tasks = [self.match_single(dep) for dep in dependencies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for dep, result in zip(dependencies, results):
            if isinstance(result, Exception):
                logger.warning(
                    "Error matching dependency %s@%s: %s",
                    dep.name,
                    dep.resolved_version or dep.version,
                    result,
                )
                continue
            for match in result:
                key = (dep.name, dep.resolved_version or dep.version, match.vulnerability.cve_id or match.vulnerability.vuln_id)
                if key not in seen:
                    seen.add(key)
                    matches.append(match)

        return matches

    async def match_single(self, dependency: Dependency) -> List[CVEMatch]:
        """Match a single dependency against known vulnerability databases.

        Returns all applicable :class:`CVEMatch` objects (may be empty).
        """
        version = dependency.resolved_version or dependency.version
        if not version:
            logger.debug("Skipping dependency %s – no version resolved.", dependency.name)
            return []

        vulns: List[VulnerabilityInfo] = []

        # Primary source: OSV (also covers GitHub Advisory via GHSA-)
        try:
            osv_vulns = await self.query_osv(dependency)
            vulns.extend(osv_vulns)
        except Exception as exc:
            logger.warning("OSV query failed for %s: %s", dependency.name, exc)

        # Supplementary source: NVD
        try:
            nvd_vulns = await self.query_nvd(dependency)
            vulns.extend(nvd_vulns)
        except Exception as exc:
            logger.warning("NVD query failed for %s: %s", dependency.name, exc)

        # Deduplicate by vulnerability ID
        deduped = self._deduplicate_vulns(vulns)

        matches: List[CVEMatch] = []
        for vuln in deduped:
            is_affected, reason = self._check_vulnerability(version, vuln)
            match = CVEMatch(
                dependency=dependency,
                vulnerability=vuln,
                is_affected=is_affected,
                confidence="high" if vuln.source in ("OSV", "NVD") else "medium",
                match_reason=reason,
                remediation=self._build_remediation(dependency, vuln),
            )
            matches.append(match)

        return matches

    # ------------------------------------------------------------------
    # Data source queries
    # ------------------------------------------------------------------

    async def query_osv(self, dependency: Dependency) -> List[VulnerabilityInfo]:
        """Query the OSV API for vulnerabilities affecting *dependency*.

        Request format::

            {
                "version": "1.2.3",
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI"
                }
            }
        """
        version = dependency.resolved_version or dependency.version
        if not version:
            return []

        ecosystem_str = ECOSYSTEM_MAP.get(dependency.ecosystem)
        if not ecosystem_str:
            logger.debug(
                "No OSV ecosystem mapping for %s, skipping OSV query.",
                dependency.ecosystem.value,
            )
            return []

        cache_key = self._osv_cache_key(dependency.name, ecosystem_str, version)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        payload = {
            "version": version,
            "package": {
                "name": dependency.name,
                "ecosystem": ecosystem_str,
            },
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(OSV_API_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()

        vulns = self._parse_osv_response(data)
        self._cache_set(cache_key, vulns)
        return vulns

    async def query_nvd(self, dependency: Dependency) -> List[VulnerabilityInfo]:
        """Query the NVD API (CVE 2.0) as a supplementary data source.

        Uses keyword search ``packageName:version`` and then filters results
        by version range heuristics.
        """
        version = dependency.resolved_version or dependency.version
        if not version:
            return []

        cache_key = self._nvd_cache_key(dependency.name, version)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        params: Dict[str, str] = {
            "keywordSearch": f"{dependency.name} {version}",
            "resultsPerPage": "20",
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(NVD_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()

        vulns = self._parse_nvd_response(data)
        self._cache_set(cache_key, vulns)
        return vulns

    # ------------------------------------------------------------------
    # Version range parsing & comparison
    # ------------------------------------------------------------------

    def _parse_version_range(self, range_str: str) -> Tuple[str, str]:
        """Parse a version range string into ``(operator, version)``.

        Supports ``>=``, ``<=``, ``>``, ``<``, ``=``, ``^``, ``~``.
        Falls back to ``("="``, ``range_str``) when no operator is detected.
        """
        range_str = range_str.strip()
        if not range_str:
            return ("=", "")

        m = _RANGE_OP_RE.match(range_str)
        if m:
            op = m.group("op") or "="
            ver = m.group("ver").strip()
            return (op, ver)
        return ("=", range_str)

    def _version_affected(self, version: str, range_str: str) -> bool:
        """Check whether *version* falls within the affected *range_str*.

        Handles comma-separated ranges (AND logic), e.g.
        ``">=1.0.0,<2.0.0"``.
        """
        if not range_str or not version:
            return False

        # Split on comma for compound ranges (all must match)
        parts = [p.strip() for p in range_str.split(",") if p.strip()]
        if not parts:
            return False

        return all(self._check_single_range(version, part) for part in parts)

    def _check_single_range(self, version: str, range_part: str) -> bool:
        """Evaluate a single version range expression against *version*."""
        op, range_ver = self._parse_version_range(range_part)
        if not range_ver:
            return False

        cmp = self._compare_versions(version, range_ver)

        if op == ">=":
            return cmp >= 0
        elif op == "<=":
            return cmp <= 0
        elif op == ">":
            return cmp > 0
        elif op == "<":
            return cmp < 0
        elif op == "=" or op == "==":
            return cmp == 0
        elif op == "^":
            return self._caret_match(version, range_ver)
        elif op == "~":
            return self._tilde_match(version, range_ver)
        else:
            # Unknown operator – fall back to equality
            return cmp == 0

    def _caret_match(self, version: str, constraint: str) -> bool:
        """Caret ``^`` range: allows changes that do not modify the left-most
        non-zero digit.

        ``^1.2.3``  -> ``>=1.2.3 <2.0.0``
        ``^0.2.3``  -> ``>=0.2.3 <0.3.0``
        ``^0.0.3``  -> ``>=0.0.3 <0.0.4``
        """
        cmp_low = self._compare_versions(version, constraint)
        if cmp_low < 0:
            return False

        norm = self._normalize_version(constraint)
        if len(norm) < 1:
            return False

        # Determine the "floor" – first non-zero component
        if norm[0] != 0:
            upper = (norm[0] + 1, 0, 0)
        elif len(norm) >= 2 and norm[1] != 0:
            upper = (0, norm[1] + 1, 0)
        elif len(norm) >= 3:
            upper = (0, 0, norm[2] + 1)
        else:
            upper = (norm[0] + 1, 0, 0)

        upper_str = ".".join(str(x) for x in upper)
        cmp_high = self._compare_versions(version, upper_str)
        return cmp_high < 0

    def _tilde_match(self, version: str, constraint: str) -> bool:
        """Tilde ``~`` range: allows patch-level changes.

        ``~1.2.3`` -> ``>=1.2.3 <1.3.0``
        ``~1.2``   -> ``>=1.2.0 <1.3.0``
        """
        cmp_low = self._compare_versions(version, constraint)
        if cmp_low < 0:
            return False

        norm = self._normalize_version(constraint)
        if len(norm) < 2:
            return cmp_low == 0

        upper = list(norm)
        upper[1] = upper[1] + 1
        if len(upper) > 2:
            upper[2] = 0
        upper_str = ".".join(str(x) for x in upper)
        cmp_high = self._compare_versions(version, upper_str)
        return cmp_high < 0

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two semantic version strings.

        Returns ``-1`` if *v1* < *v2*, ``0`` if equal, ``1`` if *v1* > *v2*.
        """
        n1 = self._normalize_version(v1)
        n2 = self._normalize_version(v2)

        # Pad shorter tuple with zeros
        max_len = max(len(n1), len(n2))
        n1 = n1 + (0,) * (max_len - len(n1))
        n2 = n2 + (0,) * (max_len - len(n2))

        for a, b in zip(n1, n2):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0

    def _normalize_version(self, version: str) -> Tuple[int, ...]:
        """Normalize a version string into a tuple of integers.

        Strips leading ``v``/``V``, strips pre-release / build metadata
        suffixes, and splits on ``.``.
        """
        if not version:
            return (0,)

        # Strip leading v/V
        version = version.lstrip("vV")

        # Remove pre-release/build metadata suffixes (-alpha, +build, etc.)
        version = re.split(r"[-+]", version, maxsplit=1)[0]

        parts: List[int] = []
        for segment in version.split("."):
            segment = segment.strip()
            if not segment:
                continue
            # Extract leading digits
            m = re.match(r"(\d+)", segment)
            if m:
                parts.append(int(m.group(1)))
            else:
                parts.append(0)

        return tuple(parts) if parts else (0,)

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    def _severity_from_cvss(self, score: float) -> SeverityLevel:
        """Map a CVSS score to a :class:`SeverityLevel`.

        +-----------+----------+
        | Score     | Severity |
        +===========+==========+
        | 9.0 – 10  | CRITICAL |
        +-----------+----------+
        | 7.0 – 8.9 | HIGH     |
        +-----------+----------+
        | 4.0 – 6.9 | MEDIUM   |
        +-----------+----------+
        | 0.1 – 3.9 | LOW      |
        +-----------+----------+
        | 0         | INFO     |
        +-----------+----------+
        """
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 0.1:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    # ------------------------------------------------------------------
    # Remediation builder
    # ------------------------------------------------------------------

    def _build_remediation(self, dep: Dependency, vuln: VulnerabilityInfo) -> str:
        """Generate a human-readable remediation suggestion."""
        pkg = dep.name
        current = dep.resolved_version or dep.version or "unknown"

        if vuln.patched_versions:
            return f"Upgrade {pkg} from {current} to {vuln.patched_versions}"

        # Try to derive a suggestion from affected_versions
        if vuln.affected_versions:
            return (
                f"Upgrade {pkg} from {current} to a version outside "
                f"the affected range ({vuln.affected_versions})"
            )

        vuln_ref = vuln.cve_id or vuln.vuln_id or "this vulnerability"
        return (
            f"Upgrade {pkg} ({current}) to the latest version to resolve "
            f"{vuln_ref}. Consult the references for specific patch guidance."
        )

    # ------------------------------------------------------------------
    # Vulnerability check
    # ------------------------------------------------------------------

    def _check_vulnerability(
        self, version: str, vuln: VulnerabilityInfo
    ) -> Tuple[bool, str]:
        """Determine whether *version* is affected by *vuln*.

        Returns ``(is_affected, reason)``.
        """
        # 1. Check via affected_versions range string (if present)
        if vuln.affected_versions:
            if self._version_affected(version, vuln.affected_versions):
                return (
                    True,
                    f"Version {version} is within affected range "
                    f"'{vuln.affected_versions}'",
                )

        # 2. Check via raw version list stored in metadata (populated from OSV)
        raw_versions = vuln.metadata.get("affected_version_list")
        if raw_versions and isinstance(raw_versions, list):
            if version in raw_versions:
                return (
                    True,
                    f"Version {version} appears in the explicit affected "
                    f"versions list",
                )

        # 3. Check via raw ranges stored in metadata (populated from OSV)
        raw_ranges = vuln.metadata.get("affected_ranges")
        if raw_ranges and isinstance(raw_ranges, list):
            for rng in raw_ranges:
                if self._evaluate_osv_range(version, rng):
                    return (
                        True,
                        f"Version {version} matches OSV range {rng}",
                    )

        return (False, f"Version {version} does not appear to be affected")

    def _evaluate_osv_range(self, version: str, range_info: Dict) -> bool:
        """Evaluate an OSV-style range dict against *version*.

        OSV range format::

            {
                "type": "SEMVER" | "ECOSYSTEM" | "GIT",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "2.0.0"}
                ]
            }
        """
        range_type = range_info.get("type", "")
        events = range_info.get("events", [])

        if range_type in ("SEMVER", "ECOSYSTEM"):
            return self._evaluate_semver_events(version, events)
        elif range_type == "GIT":
            # Git-based ranges cannot be evaluated by version number alone
            return False
        return False

    def _evaluate_semver_events(
        self, version: str, events: List[Dict[str, str]]
    ) -> bool:
        """Evaluate SEMVER/ECOSYSTEM events.

        The algorithm tracks an ``affected`` flag that starts as ``False`` and
        toggles based on ``introduced`` / ``fixed`` / ``last_affected`` events
        in order.
        """
        affected = False
        for event in events:
            if "introduced" in event:
                intro_ver = event["introduced"]
                if intro_ver == "0" or self._compare_versions(version, intro_ver) >= 0:
                    affected = True
            elif "fixed" in event:
                fixed_ver = event["fixed"]
                if self._compare_versions(version, fixed_ver) >= 0:
                    affected = False
            elif "last_affected" in event:
                last_ver = event["last_affected"]
                if self._compare_versions(version, last_ver) > 0:
                    affected = False
        return affected

    # ------------------------------------------------------------------
    # OSV response parser
    # ------------------------------------------------------------------

    def _parse_osv_response(self, data: Dict) -> List[VulnerabilityInfo]:
        """Parse the OSV API JSON response into a list of VulnerabilityInfo."""
        vulns: List[VulnerabilityInfo] = []
        for vuln_data in data.get("vulns", []):
            vuln = self._osv_vuln_to_info(vuln_data)
            if vuln:
                vulns.append(vuln)
        return vulns

    def _osv_vuln_to_info(self, vuln_data: Dict) -> Optional[VulnerabilityInfo]:
        """Convert a single OSV vuln dict to :class:`VulnerabilityInfo`."""
        vuln_id = vuln_data.get("id", "")
        if not vuln_id:
            return None

        # Determine CVE ID (OSV may use its own ID scheme)
        cve_id: Optional[str] = None
        aliases = vuln_data.get("aliases", [])
        for alias in aliases:
            if alias.upper().startswith("CVE-"):
                cve_id = alias
                break
        # If no alias, check if the ID itself is a CVE
        if not cve_id and vuln_id.upper().startswith("CVE-"):
            cve_id = vuln_id

        # Determine source
        source = "OSV"
        if vuln_id.startswith("GHSA-"):
            source = "GitHub Advisory"

        # Severity – OSV may provide a database_specific.cvss
        severity = SeverityLevel.UNKNOWN
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None

        severity_data = vuln_data.get("severity", [])
        for sev_item in severity_data:
            if isinstance(sev_item, dict):
                score_str = sev_item.get("score", "")
                # Attempt to parse CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
                if score_str.startswith("CVSS:"):
                    cvss_vector = score_str
                    # Try to extract numeric score from the type field or score field
                    cvss_score = self._extract_cvss_score_from_vector(score_str)
                    if cvss_score is not None:
                        severity = self._severity_from_cvss(cvss_score)

        # Also check database_specific for CVSS
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            if cvss_score is None:
                db_cvss = db_specific.get("cvss", {})
                if isinstance(db_cvss, dict):
                    cvss_score = db_cvss.get("score")
                    cvss_vector = db_cvss.get("vector", cvss_vector)
                    if cvss_score is not None:
                        severity = self._severity_from_cvss(float(cvss_score))
            # CWE IDs
            cwe_ids = db_specific.get("cwe_ids", [])
        else:
            cwe_ids = []

        # Affected versions & ranges
        affected_versions_list: List[str] = []
        affected_ranges_raw: List[Dict] = []
        patched_versions_list: List[str] = []

        for affected_block in vuln_data.get("affected", []):
            # Direct version list
            affected_versions_list.extend(affected_block.get("versions", []))
            # Ranges
            affected_ranges_raw.extend(affected_block.get("ranges", []))
            # Patched versions (less common in OSV)
            pkg = affected_block.get("package", {})
            patched_versions_list.extend(pkg.get("patched_versions", []))

        # Build affected_versions string for display
        affected_versions_str = ", ".join(affected_versions_list[:20]) if affected_versions_list else None
        patched_versions_str = ", ".join(patched_versions_list[:10]) if patched_versions_list else None

        # References
        references = [
            ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")
        ]

        # Published date
        published = vuln_data.get("published")

        # CWE IDs from severity items if not found in database_specific
        if not cwe_ids:
            for sev_item in severity_data:
                if isinstance(sev_item, dict):
                    cwe_from_sev = sev_item.get("cwe", {})
                    if isinstance(cwe_from_sev, dict):
                        cwe_id = cwe_from_sev.get("id")
                        if cwe_id:
                            cwe_ids.append(cwe_id)

        return VulnerabilityInfo(
            cve_id=cve_id,
            vuln_id=vuln_id,
            title=vuln_data.get("summary", ""),
            description=vuln_data.get("details", ""),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_versions=affected_versions_str,
            patched_versions=patched_versions_str,
            references=references,
            published_date=published,
            source=source,
            metadata={
                "affected_version_list": affected_versions_list,
                "affected_ranges": affected_ranges_raw,
                "osv_raw_id": vuln_id,
            },
        )

    def _extract_cvss_score_from_vector(self, vector: str) -> Optional[float]:
        """Attempt to derive a numeric CVSS score from a vector string.

        This is a best-effort heuristic.  The vector string itself does not
        contain the base score, so we parse the metrics and compute an
        approximate score.  If parsing fails, returns ``None``.
        """
        # Quick lookup for well-known CVSS v3.1 metric values
        # This is a simplified scoring approximation
        try:
            metrics: Dict[str, str] = {}
            parts = vector.split("/")
            for part in parts:
                if ":" in part:
                    key, val = part.split(":", 1)
                    metrics[key] = val

            # AV (Attack Vector)
            av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
            # AC (Attack Complexity)
            ac_scores = {"L": 0.77, "H": 0.44}
            # PR (Privileges Required)
            pr_scores = {"N": 0.85, "L": 0.62, "H": 0.27}
            # UI (User Interaction)
            ui_scores = {"N": 0.85, "R": 0.62}
            # S (Scope)
            s_values = {"C": True, "U": False}
            # C (Confidentiality), I (Integrity), A (Availability)
            cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

            av = av_scores.get(metrics.get("AV", ""), 0.85)
            ac = ac_scores.get(metrics.get("AC", ""), 0.77)
            pr = pr_scores.get(metrics.get("PR", ""), 0.85)
            ui = ui_scores.get(metrics.get("UI", ""), 0.85)
            scope_changed = s_values.get(metrics.get("S", "U"), False)
            c = cia_scores.get(metrics.get("C", "H"), 0.56)
            i = cia_scores.get(metrics.get("I", "H"), 0.56)
            a = cia_scores.get(metrics.get("A", "H"), 0.56)

            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            if scope_changed:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                exploitability = 8.22 * av * ac * pr * ui
            else:
                impact = 6.42 * iss
                exploitability = 3.9 * av * ac * pr * ui

            if impact <= 0:
                return 0.0

            base_score = min(impact + exploitability, 10.0)
            if scope_changed:
                base_score = min(1.08 * (impact + exploitability), 10.0)

            return round(base_score, 1)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # NVD response parser
    # ------------------------------------------------------------------

    def _parse_nvd_response(self, data: Dict) -> List[VulnerabilityInfo]:
        """Parse the NVD CVE 2.0 JSON response."""
        vulns: List[VulnerabilityInfo] = []
        for cve_item in data.get("vulnerabilities", []):
            cve = cve_item.get("cve", {})
            vuln = self._nvd_cve_to_info(cve)
            if vuln:
                vulns.append(vuln)
        return vulns

    def _nvd_cve_to_info(self, cve: Dict) -> Optional[VulnerabilityInfo]:
        """Convert a single NVD CVE dict to :class:`VulnerabilityInfo`."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Descriptions – prefer English
        descriptions = cve.get("descriptions", [])
        title = ""
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                # Use first sentence as title
                sentences = re.split(r"(?<=[.!?])\s+", description, maxsplit=1)
                title = sentences[0] if sentences else ""
                break

        # CVSS metrics – prefer v3.1, then v3.0
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        severity = SeverityLevel.UNKNOWN

        for cvss_version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(cvss_version, [])
            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                if cvss_score is not None:
                    severity = self._severity_from_cvss(float(cvss_score))
                break

        # CWE IDs
        weaknesses = cve.get("weaknesses", [])
        cwe_ids: List[str] = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)

        # References
        references = [
            ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")
        ]

        # Published date
        published = cve.get("published")

        # Build affected versions from configurations (CPE matching)
        affected_versions_str = self._extract_nvd_affected_versions(cve)

        return VulnerabilityInfo(
            cve_id=cve_id,
            vuln_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_versions=affected_versions_str,
            references=references,
            published_date=published,
            source="NVD",
            metadata={},
        )

    def _extract_nvd_affected_versions(self, cve: Dict) -> Optional[str]:
        """Extract affected version information from NVD configurations.

        NVD uses CPE match criteria in configurations.  This method extracts
        version start/end ranges when available.
        """
        configurations = cve.get("configurations", [])
        versions_parts: List[str] = []

        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable") is not True:
                        continue
                    ver_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                    ver_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")

                    if ver_start and ver_end:
                        start_op = ">= " if cpe_match.get("versionStartIncluding") else "> "
                        end_op = " <= " if cpe_match.get("versionEndIncluding") else " < "
                        versions_parts.append(f"{start_op}{ver_start}{end_op}{ver_end}")
                    elif ver_start:
                        start_op = ">= " if cpe_match.get("versionStartIncluding") else "> "
                        versions_parts.append(f"{start_op}{ver_start}")
                    elif ver_end:
                        end_op = " <= " if cpe_match.get("versionEndIncluding") else " < "
                        versions_parts.append(f"{end_op}{ver_end}")

        return ", ".join(versions_parts[:10]) if versions_parts else None

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _cache_get(self, key: str) -> Optional[Any]:
        """Retrieve a value from cache if it has not expired."""
        if key in self._cache:
            ts, value = self._cache[key]
            if time.monotonic() - ts < self._cache_ttl:
                return value
            del self._cache[key]
        return None

    def _cache_set(self, key: str, value: Any) -> None:
        """Store a value in cache with the current timestamp."""
        self._cache[key] = (time.monotonic(), value)

    def _osv_cache_key(self, name: str, ecosystem: str, version: str) -> str:
        """Build a deterministic cache key for OSV queries."""
        raw = f"osv:{name}:{ecosystem}:{version}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _nvd_cache_key(self, name: str, version: str) -> str:
        """Build a deterministic cache key for NVD queries."""
        raw = f"nvd:{name}:{version}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def clear_cache(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_vulns(vulns: List[VulnerabilityInfo]) -> List[VulnerabilityInfo]:
        """Deduplicate vulnerability entries by ID (CVE or vuln ID)."""
        seen: Dict[str, VulnerabilityInfo] = {}
        for v in vulns:
            key = v.cve_id or v.vuln_id or id(v)
            if key not in seen:
                seen[key] = v
            else:
                # Merge: prefer the entry with more information
                existing = seen[key]
                if v.cvss_score is not None and existing.cvss_score is None:
                    seen[key] = v
                elif v.description and not existing.description:
                    seen[key] = v
        return list(seen.values())
