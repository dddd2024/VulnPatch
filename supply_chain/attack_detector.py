"""
Supply Chain Attack Detector.

Detects various supply chain attack patterns including:
- Typosquatting: packages with names similar to popular packages
- Dependency confusion: internal package names published to public registries
- Malicious package indicators: suspicious metadata, recent creation, etc.
- Star jacking / brand jacking: fake popularity metrics
- Published after clone: packages that appeared after a repo was cloned
- Suspicious versions: unusual version numbering patterns
"""

import logging
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from supply_chain.models import (
    AttackIndicator, AttackType, Dependency, DependencyFile,
    Ecosystem, SeverityLevel,
)

logger = logging.getLogger(__name__)


# Popular packages per ecosystem (for typosquatting detection)
POPULAR_PACKAGES: Dict[Ecosystem, Set[str]] = {
    Ecosystem.PYTHON: {
        "requests", "numpy", "pandas", "flask", "django", "pillow",
        "scipy", "matplotlib", "scikit-learn", "tensorflow", "pytorch",
        "celery", "redis", "boto3", "awscli", "pytest", "selenium",
        "beautifulsoup4", "lxml", "cryptography", "paramiko", "fabric",
        "sqlalchemy", "psycopg2", "fastapi", "uvicorn", "typer",
    },
    Ecosystem.JAVASCRIPT: {
        "lodash", "express", "axios", "react", "vue", "angular",
        "moment", "underscore", "jquery", "webpack", "babel", "eslint",
        "prettier", "jest", "mocha", "chai", "async", "bluebird",
        "debug", "colors", "mkdirp", "rimraf", "glob", "q",
        "body-parser", "cookie-parser", "cors", "helmet", "dotenv",
    },
    Ecosystem.JAVA: {
        "spring-core", "spring-boot", "jackson-databind", "log4j-core",
        "guava", "commons-lang3", "commons-io", "httpclient",
        "junit", "mockito", "slf4j-api", "gson", "okhttp",
        "retrofit", "hibernate-core", "tomcat-core", "struts2-core",
    },
    Ecosystem.GO: {
        "gin", "gorm", "cobra", "viper", "zap", "logrus",
        "chi", "echo", "fiber", "buffalo", "ent",
    },
    Ecosystem.RUST: {
        "serde", "tokio", "rand", "regex", "clap", "log",
        "hyper", "actix-web", "reqwest", "chrono", "anyhow",
    },
    Ecosystem.PHP: {
        "laravel/framework", "symfony/http-kernel", "guzzlehttp/guzzle",
        "doctrine/orm", "monolog/monolog", "phpunit/phpunit",
        "twig/twig", "nesbot/carbon", "vlucas/phpdotenv",
    },
    Ecosystem.RUBY: {
        "rails", "activesupport", "activerecord", "devise",
        "pundit", "sidekiq", "resque", "rack", "sinatra",
        "rspec", "nokogiri", "pg", "mysql2",
    },
    Ecosystem.DOTNET: {
        "Newtonsoft.Json", "System.Text.Json", "Microsoft.Extensions.Logging",
        "EntityFrameworkCore", "Dapper", "AutoMapper", "MediatR",
        "Serilog", "NLog", "Moq", "xunit",
    },
}

# Generic names that are strong indicators of dependency confusion
GENERIC_PACKAGE_NAMES: Set[str] = {
    "utils", "helpers", "core", "common", "shared", "base", "lib",
    "internal", "private", "config", "tools", "framework", "infra",
    "platform", "services", "api", "models", "types", "constants",
    "helpers", "misc", "support", "stdlib", "extensions", "plugins",
    "middleware", "database", "cache", "auth", "security", "logging",
}

# Suspicious domain patterns for homepage / repository URLs
SUSPICIOUS_DOMAIN_PATTERNS: List[re.Pattern] = [
    re.compile(r"(bitbucket\.org|github\.com|gitlab\.com)/(?:[a-z0-9]{6,}|[a-z0-9]{20,})", re.IGNORECASE),
    re.compile(r"[a-z0-9]{20,}\.(?:com|org|net|io)", re.IGNORECASE),
    re.compile(r"(?:free|cheap|download|crack|hack|keygen|warez)\.", re.IGNORECASE),
    re.compile(r"(?:temp|tmp|test|example|sample|demo)\.\w+\.\w+", re.IGNORECASE),
    re.compile(r"(?:goo\.gl|bit\.ly|t\.co)/", re.IGNORECASE),
]

# Version patterns that are suspicious
_RE_SUSPICIOUS_HIGH_VERSION = re.compile(r"^(?:999|10000|9999|100000|99999)\b")
_RE_SUSPICIOUS_MANY_COMPONENTS = re.compile(r"^\d+(?:\.\d+){5,}")
_RE_SUSPICIOUS_DATE_VERSION = re.compile(r"^(?:19|20)\d{2}[.-](?:0[1-9]|1[0-2])[.-](?:0[1-9]|[12]\d|3[01])$")
_RE_SUSPICIOUS_PRE_RELEASE = re.compile(r"(?:alpha|beta|rc|dev|pre|snapshot|snapshot|milestone)", re.IGNORECASE)

# Keyboard proximity map for common typosquatting substitutions
_KEYBOARD_PROXIMITY: Dict[str, List[str]] = {
    "a": ["s", "q", "w", "z"],
    "b": ["v", "g", "h", "n"],
    "c": ["x", "v", "d", "f"],
    "d": ["s", "f", "e", "r", "c", "x"],
    "e": ["w", "r", "s", "d", "3"],
    "f": ["d", "g", "r", "t", "v", "c"],
    "g": ["f", "h", "t", "y", "v", "b"],
    "h": ["g", "j", "y", "u", "b", "n"],
    "i": ["u", "j", "k", "8"],
    "j": ["h", "k", "u", "i", "n", "m"],
    "k": ["j", "l", "i", "o", "m"],
    "l": ["k", "o", "p"],
    "m": ["n", "j", "k"],
    "n": ["b", "m", "h", "j"],
    "o": ["i", "p", "k", "l", "9", "0"],
    "p": ["o", "[", "l"],
    "q": ["w", "a", "s", "1"],
    "r": ["e", "t", "d", "f", "4", "5"],
    "s": ["a", "d", "w", "e", "z", "x"],
    "t": ["r", "y", "f", "g", "5", "6"],
    "u": ["y", "i", "j", "k", "7", "8"],
    "v": ["c", "b", "f", "g"],
    "w": ["q", "e", "a", "s", "2"],
    "x": ["z", "c", "s", "d"],
    "y": ["t", "u", "g", "h", "6", "7"],
    "z": ["a", "x", "s"],
    "0": ["9", "o"],
    "1": ["2", "q"],
    "2": ["1", "3", "w"],
    "3": ["2", "4", "e"],
    "4": ["3", "5", "r"],
    "5": ["4", "6", "t"],
    "6": ["5", "7", "y"],
    "7": ["6", "8", "u"],
    "8": ["7", "9", "i"],
    "9": ["8", "0", "o"],
}

# Common prefix/suffix additions used in typosquatting
_TYPOSQUAT_PREFIXES = [
    "python-", "py-", "node-", "js-", "java-", "go-",
    "fast-", "mini-", "micro-", "super-", "ultra-",
    "my-", "the-", "a-", "an-", "lib-", "pkg-",
    "async-", "react-", "vue-", "angular-",
]

_TYPOSQUAT_SUFFIXES = [
    "-lib", "-utils", "-utils2", "-tools", "-core", "-js",
    "-py", "-ts", "-npm", "-pkg", "-module", "-plus",
    "-pro", "-lite", "-mini", "-fast", "-extra",
    "-v2", "-v3", "-new", "-updated", "-fork",
    "2", "3", "4", "-2", "-3", "-4",
    "s", "-s", "es", "-es",
]


class SupplyChainAttackDetector:
    """Detects supply chain attack patterns in project dependencies."""

    def __init__(self):
        self._popular_cache: Dict[Ecosystem, Set[str]] = POPULAR_PACKAGES.copy()

    def scan(
        self, dependency_files: List[DependencyFile]
    ) -> List[AttackIndicator]:
        """Run all attack detection checks on dependency files.

        Returns list of all detected attack indicators.
        """
        indicators: List[AttackIndicator] = []

        indicators.extend(self.detect_typosquatting(dependency_files))
        indicators.extend(self.detect_dependency_confusion(dependency_files))
        indicators.extend(self.detect_suspicious_metadata(dependency_files))
        indicators.extend(self.detect_suspicious_versions(dependency_files))

        logger.info(
            "Supply chain attack scan complete: %d indicators found",
            len(indicators),
        )
        return indicators

    # ------------------------------------------------------------------
    # Typosquatting detection
    # ------------------------------------------------------------------

    def detect_typosquatting(
        self, dependency_files: List[DependencyFile]
    ) -> List[AttackIndicator]:
        """Detect potential typosquatting packages.

        Uses Levenshtein distance and common substitution patterns:
        - Character transposition (e.g., 'reqeusts' instead of 'requests')
        - Character substitution (e.g., 'requsts' instead of 'requests')
        - Character insertion/deletion
        - Common prefix/suffix additions (e.g., 'python-requests', 'requests-lib')
        - Dot/underscore confusion (e.g., 'python_requests' vs 'python-requests')
        """
        indicators: List[AttackIndicator] = []

        for dep_file in dependency_files:
            for dep in dep_file.dependencies:
                popular = self._get_popular_packages(dep.ecosystem)
                if not popular:
                    continue

                dep_name_normalized = dep.name.lower().replace("-", "").replace("_", "").replace(".", "")

                for popular_name in popular:
                    popular_normalized = popular_name.lower().replace("-", "").replace("_", "").replace(".", "")

                    # Skip exact matches
                    if dep_name_normalized == popular_normalized:
                        continue

                    # Skip if the dependency name is significantly longer
                    # (likely a legitimate different package)
                    if len(dep_name_normalized) > len(popular_normalized) * 2:
                        continue

                    # Check Levenshtein distance (edit distance of 1-2 is suspicious)
                    distance = self._levenshtein_distance(dep_name_normalized, popular_normalized)
                    max_len = max(len(dep_name_normalized), len(popular_normalized))

                    if max_len > 0 and distance <= 2 and distance > 0:
                        # Very close match by edit distance
                        if distance == 1:
                            severity = SeverityLevel.HIGH
                            confidence = "high"
                        else:
                            severity = SeverityLevel.MEDIUM
                            confidence = "medium"

                        indicators.append(
                            self._build_indicator(
                                attack_type=AttackType.TYPOSQUATTING,
                                dep=dep,
                                severity=severity,
                                title=f"Potential typosquatting: '{dep.name}' resembles '{popular_name}'",
                                description=(
                                    f"Package '{dep.name}' has a Levenshtein distance of {distance} "
                                    f"from popular package '{popular_name}'. This may be an attempt "
                                    f"to trick developers into installing a malicious package."
                                ),
                                evidence=[
                                    f"Levenshtein distance: {distance}",
                                    f"Popular package: {popular_name}",
                                    f"Dependency name: {dep.name}",
                                ],
                                recommendation=(
                                    f"Verify that '{dep.name}' is the intended package. "
                                    f"If you meant '{popular_name}', update your dependency to use "
                                    f"the correct package name."
                                ),
                                confidence=confidence,
                            )
                        )
                        break  # One match per dependency is enough

                    # Check prefix/suffix typosquatting
                    # e.g., 'python-requests' when the real package is 'requests'
                    if dep_name_normalized.startswith(popular_normalized) or dep_name_normalized.endswith(popular_normalized):
                        diff = abs(len(dep_name_normalized) - len(popular_normalized))
                        if 1 <= diff <= 6:
                            indicators.append(
                                self._build_indicator(
                                    attack_type=AttackType.TYPOSQUATTING,
                                    dep=dep,
                                    severity=SeverityLevel.MEDIUM,
                                    title=f"Potential typosquatting (prefix/suffix): '{dep.name}' wraps '{popular_name}'",
                                    description=(
                                        f"Package '{dep.name}' contains the popular package name "
                                        f"'{popular_name}' with an added prefix or suffix. "
                                        f"This is a common typosquatting technique."
                                    ),
                                    evidence=[
                                        f"Popular package: {popular_name}",
                                        f"Dependency name: {dep.name}",
                                        f"Pattern: prefix/suffix addition",
                                    ],
                                    recommendation=(
                                        f"Verify that '{dep.name}' is the intended package and not "
                                        f"a typosquatting variant of '{popular_name}'."
                                    ),
                                    confidence="medium",
                                )
                            )
                            break

                    # Check hyphen/underscore confusion
                    dep_hyphen = dep.name.lower().replace("_", "-")
                    dep_underscore = dep.name.lower().replace("-", "_")
                    if dep_hyphen == popular_name.lower() or dep_underscore == popular_name.lower():
                        indicators.append(
                            self._build_indicator(
                                attack_type=AttackType.TYPOSQUATTING,
                                dep=dep,
                                severity=SeverityLevel.MEDIUM,
                                title=f"Potential typosquatting (hyphen/underscore): '{dep.name}' vs '{popular_name}'",
                                description=(
                                    f"Package '{dep.name}' differs from popular package "
                                    f"'{popular_name}' only by hyphen/underscore substitution."
                                ),
                                evidence=[
                                    f"Popular package: {popular_name}",
                                    f"Dependency name: {dep.name}",
                                    f"Pattern: hyphen/underscore confusion",
                                ],
                                recommendation=(
                                    f"Verify that '{dep.name}' is the intended package. "
                                    f"The name is very similar to '{popular_name}' with only "
                                    f"hyphen/underscore differences."
                                ),
                                confidence="medium",
                            )
                        )
                        break

        return indicators

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings.

        Uses the Wagner-Fischer dynamic programming algorithm.
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))

        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost is 0 if characters match, 1 otherwise
                cost = 0 if c1 == c2 else 1
                curr_row.append(
                    min(
                        curr_row[j] + 1,       # insertion
                        prev_row[j + 1] + 1,    # deletion
                        prev_row[j] + cost,     # substitution
                    )
                )
            prev_row = curr_row

        return prev_row[-1]

    def _generate_typosquat_candidates(self, name: str) -> List[str]:
        """Generate common typosquatting variations of a package name.

        Includes:
        - Single character omission
        - Single character addition
        - Adjacent character swap
        - Common keyboard proximity substitutions
        - Hyphen/underscore swap
        """
        candidates: List[str] = []
        seen: Set[str] = set()
        name_lower = name.lower()

        def _add(candidate: str) -> None:
            if candidate and candidate != name_lower and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

        # 1. Single character omission (deletion)
        for i in range(len(name_lower)):
            _add(name_lower[:i] + name_lower[i + 1:])

        # 2. Single character addition (insertion)
        for i in range(len(name_lower) + 1):
            for c in "abcdefghijklmnopqrstuvwxyz0123456789-_.":
                _add(name_lower[:i] + c + name_lower[i:])

        # 3. Adjacent character swap (transposition)
        for i in range(len(name_lower) - 1):
            swapped = list(name_lower)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            _add("".join(swapped))

        # 4. Keyboard proximity substitutions
        for i, c in enumerate(name_lower):
            nearby = _KEYBOARD_PROXIMITY.get(c, [])
            for substitute in nearby:
                _add(name_lower[:i] + substitute + name_lower[i + 1:])

        # 5. Hyphen/underscore swap
        _add(name_lower.replace("-", "_"))
        _add(name_lower.replace("_", "-"))
        _add(name_lower.replace("-", ""))
        _add(name_lower.replace("_", ""))

        # 6. Common prefix additions
        for prefix in _TYPOSQUAT_PREFIXES:
            _add(prefix + name_lower)

        # 7. Common suffix additions
        for suffix in _TYPOSQUAT_SUFFIXES:
            _add(name_lower + suffix)

        return candidates

    # ------------------------------------------------------------------
    # Dependency confusion detection
    # ------------------------------------------------------------------

    def detect_dependency_confusion(
        self, dependency_files: List[DependencyFile]
    ) -> List[AttackIndicator]:
        """Detect potential dependency confusion attacks.

        Dependency confusion occurs when an internal/private package name
        is also published to a public registry. An attacker can publish a
        malicious package with the same name to the public registry, and
        if the build system checks public registries first, the malicious
        package will be used instead of the internal one.

        Detection heuristics:
        - Packages with generic names that are likely to also exist internally
        - Packages without a clear namespace/organization prefix
        - Packages that seem unusually generic (e.g., 'utils', 'helpers', 'core')
        """
        indicators: List[AttackIndicator] = []

        for dep_file in dependency_files:
            for dep in dep_file.dependencies:
                evidence: List[str] = []
                is_suspicious = False

                dep_name_lower = dep.name.lower().strip()

                # Check against generic name list
                if dep_name_lower in GENERIC_PACKAGE_NAMES:
                    evidence.append(f"Package name '{dep.name}' is a generic name commonly used for internal packages")
                    is_suspicious = True

                # Check for very short names (1-2 chars) which are often internal
                if len(dep_name_lower) <= 2:
                    evidence.append(f"Package name '{dep.name}' is very short ({len(dep_name_lower)} chars)")
                    is_suspicious = True

                # Check if the package lacks a namespace/organization prefix
                # (for ecosystems that commonly use namespaces)
                if dep.ecosystem in (Ecosystem.JAVA, Ecosystem.PHP, Ecosystem.RUBY, Ecosystem.GO):
                    if "/" not in dep.name:
                        evidence.append(
                            f"Package '{dep.name}' in {dep.ecosystem.value} ecosystem lacks a namespace/organization prefix"
                        )
                        is_suspicious = True

                # Check for names that look like internal project modules
                # (camelCase or snake_case with project-sounding words)
                internal_indicators = re.compile(
                    r"(internal|private|corp|company|project|mycompany|myproject)",
                    re.IGNORECASE,
                )
                if internal_indicators.search(dep.name):
                    evidence.append(
                        f"Package name '{dep.name}' contains internal/corporate naming indicators"
                    )
                    is_suspicious = True

                # Check for names that look like they could be internal utils
                if re.match(r"^(?:app|project|internal|private)[-_]", dep_name_lower):
                    evidence.append(
                        f"Package name '{dep.name}' starts with a common internal prefix"
                    )
                    is_suspicious = True

                if is_suspicious:
                    severity = SeverityLevel.MEDIUM
                    if dep_name_lower in GENERIC_PACKAGE_NAMES and len(dep_name_lower) <= 3:
                        severity = SeverityLevel.HIGH

                    indicators.append(
                        self._build_indicator(
                            attack_type=AttackType.DEPENDENCY_CONFUSION,
                            dep=dep,
                            severity=severity,
                            title=f"Potential dependency confusion: '{dep.name}'",
                            description=(
                                f"Package '{dep.name}' has characteristics commonly associated "
                                f"with dependency confusion attacks. Generic or internal-sounding "
                                f"package names may be published to public registries by attackers, "
                                f"causing build systems to resolve the malicious public version "
                                f"instead of the intended internal package."
                            ),
                            evidence=evidence,
                            recommendation=(
                                f"Verify that '{dep.name}' is sourced from the correct registry. "
                                f"Consider using scoped/namespace-prefixed names for internal "
                                f"packages (e.g., '@mycompany/utils' for npm, or a private Maven "
                                f"repository with proper configuration)."
                            ),
                            confidence="medium",
                        )
                    )

        return indicators

    # ------------------------------------------------------------------
    # Suspicious metadata detection
    # ------------------------------------------------------------------

    def detect_suspicious_metadata(
        self, dependency_files: List[DependencyFile]
    ) -> List[AttackIndicator]:
        """Detect packages with suspicious metadata patterns.

        Checks for:
        - Packages with very short or generic descriptions
        - Packages mimicking popular package names with slight modifications
        - Packages with suspicious version patterns (e.g., version > 999.0.0)
        - Packages with homepage/repo URLs pointing to suspicious domains
        """
        indicators: List[AttackIndicator] = []

        for dep_file in dependency_files:
            for dep in dep_file.dependencies:
                evidence: List[str] = []
                is_suspicious = False

                # Check for very short or empty descriptions
                if dep.description:
                    desc = dep.description.strip()
                    if len(desc) <= 5:
                        evidence.append(
                            f"Package '{dep.name}' has a very short description: '{desc}'"
                        )
                        is_suspicious = True
                    # Check for generic descriptions
                    generic_descriptions = {
                        "a package", "library", "utility", "helper",
                        "tools", "package", "lib", "module",
                        "a python package", "a javascript library",
                        "a library", "utility library", "helper library",
                    }
                    if desc.lower() in generic_descriptions:
                        evidence.append(
                            f"Package '{dep.name}' has a generic description: '{desc}'"
                        )
                        is_suspicious = True
                else:
                    # No description at all is mildly suspicious
                    evidence.append(f"Package '{dep.name}' has no description")
                    is_suspicious = True

                # Check homepage / repository URLs for suspicious patterns
                for url_field, url_val in [("homepage", dep.homepage), ("repository", dep.repository)]:
                    if not url_val:
                        continue
                    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
                        if pattern.search(url_val):
                            evidence.append(
                                f"Suspicious {url_field} URL pattern detected: {url_val}"
                            )
                            is_suspicious = True
                            break

                # Check if the package name closely mimics a popular package
                # but with slight modifications (brand jacking)
                popular = self._get_popular_packages(dep.ecosystem)
                if popular:
                    dep_name_lower = dep.name.lower()
                    for popular_name in popular:
                        pop_lower = popular_name.lower()
                        # Check if popular name is a substring and the dep name is longer
                        if pop_lower in dep_name_lower and dep_name_lower != pop_lower:
                            # The dep name contains a popular name but is different
                            extra = dep_name_lower.replace(pop_lower, "")
                            if len(extra) <= 3 and extra:
                                evidence.append(
                                    f"Package '{dep.name}' contains popular package name "
                                    f"'{popular_name}' with minor additions"
                                )
                                is_suspicious = True
                                break

                if is_suspicious:
                    indicators.append(
                        self._build_indicator(
                            attack_type=AttackType.SUSPICIOUS_METADATA,
                            dep=dep,
                            severity=SeverityLevel.LOW,
                            title=f"Suspicious metadata for package '{dep.name}'",
                            description=(
                                f"Package '{dep.name}' exhibits suspicious metadata patterns "
                                f"that may indicate a malicious or low-quality package."
                            ),
                            evidence=evidence,
                            recommendation=(
                                f"Review the metadata for '{dep.name}' carefully. Check the "
                                f"homepage, repository, and maintainer information to verify "
                                f"the package's legitimacy."
                            ),
                            confidence="low",
                        )
                    )

        return indicators

    # ------------------------------------------------------------------
    # Suspicious version detection
    # ------------------------------------------------------------------

    def detect_suspicious_versions(
        self, dependency_files: List[DependencyFile]
    ) -> List[AttackIndicator]:
        """Detect packages with suspicious version patterns.

        Checks for:
        - Versions that are unusually high (e.g., 9999.0.0, 100000.0.0)
        - Versions using date-based schemes that seem fake
        - Versions with very many components (e.g., 1.2.3.4.5.6.7)
        - Pre-release versions used in production dependencies
        """
        indicators: List[AttackIndicator] = []

        for dep_file in dependency_files:
            for dep in dep_file.dependencies:
                version = dep.resolved_version or dep.version
                if not version:
                    continue

                is_suspicious, reason = self._is_suspicious_version(version, dep.is_dev)
                if is_suspicious:
                    severity = SeverityLevel.MEDIUM
                    confidence = "medium"

                    # Higher severity for production deps with suspicious versions
                    if not dep.is_dev and dep.scope.value in ("production", "required", "unknown"):
                        severity = SeverityLevel.HIGH
                        confidence = "high"

                    indicators.append(
                        self._build_indicator(
                            attack_type=AttackType.SUSPICIOUS_VERSION,
                            dep=dep,
                            severity=severity,
                            title=f"Suspicious version for '{dep.name}': {version}",
                            description=(
                                f"Package '{dep.name}' uses version '{version}' which "
                                f"matches a suspicious version pattern: {reason}"
                            ),
                            evidence=[
                                f"Version: {version}",
                                f"Reason: {reason}",
                                f"Is dev dependency: {dep.is_dev}",
                                f"Scope: {dep.scope.value}",
                            ],
                            recommendation=(
                                f"Review the version '{version}' of '{dep.name}'. "
                                f"Suspicious version numbers may indicate a compromised "
                                f"or malicious package release."
                            ),
                            confidence=confidence,
                        )
                    )

        return indicators

    def _is_suspicious_version(self, version: str, is_dev: bool) -> Tuple[bool, str]:
        """Check if a version string looks suspicious. Returns (is_suspicious, reason)."""
        # Strip leading 'v' or 'V' if present
        clean_version = version.lstrip("vV")

        # 1. Unusually high version numbers
        if _RE_SUSPICIOUS_HIGH_VERSION.match(clean_version):
            return True, "Version number is unusually high (>= 999), which may indicate version spoofing"

        # 2. Very many version components (e.g., 1.2.3.4.5.6.7)
        if _RE_SUSPICIOUS_MANY_COMPONENTS.match(clean_version):
            parts = clean_version.split(".")
            return True, f"Version has {len(parts)} components, which is unusual"

        # 3. Date-based version that looks fake
        if _RE_SUSPICIOUS_DATE_VERSION.match(clean_version):
            return True, "Version uses a date-based scheme that may be suspicious"

        # 4. Pre-release versions in production dependencies
        if not is_dev and _RE_SUSPICIOUS_PRE_RELEASE.search(clean_version):
            return True, "Pre-release version used in a non-dev dependency"

        # 5. Check for extremely long version strings
        if len(clean_version) > 50:
            return True, f"Version string is unusually long ({len(clean_version)} characters)"

        # 6. Check for versions with only zeros (e.g., 0.0.0, 0.0.0.0)
        parts = clean_version.split(".")
        numeric_parts = []
        for part in parts:
            # Extract leading numeric portion
            match = re.match(r"^(\d+)", part)
            if match:
                numeric_parts.append(int(match.group(1)))
            else:
                numeric_parts = []
                break

        if numeric_parts and all(p == 0 for p in numeric_parts) and len(numeric_parts) >= 3:
            return True, "Version is all zeros (e.g., 0.0.0), which may indicate an uninitialized or placeholder package"

        return False, ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_popular_packages(self, ecosystem: Ecosystem) -> Set[str]:
        """Get popular package names for an ecosystem."""
        return self._popular_cache.get(ecosystem, set())

    def _build_indicator(
        self,
        attack_type: AttackType,
        dep: Dependency,
        severity: SeverityLevel,
        title: str,
        description: str,
        evidence: List[str],
        recommendation: str,
        confidence: str = "medium",
    ) -> AttackIndicator:
        """Helper to build an AttackIndicator."""
        return AttackIndicator(
            attack_type=attack_type,
            dependency=dep,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            confidence=confidence,
        )
