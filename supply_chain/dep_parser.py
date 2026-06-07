"""
Dependency file parser for supply chain security analysis.

Supports parsing of dependency/lock files across multiple ecosystems:
- Python: requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg
- JavaScript/TypeScript: package.json, package-lock.json, yarn.lock
- Java: pom.xml
- Go: go.mod
- .NET: *.csproj, packages.config
- PHP: composer.json
- Ruby: Gemfile, Gemfile.lock
- Rust: Cargo.toml
"""

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from supply_chain.models import (
    Dependency, DependencyFile, DependencyScope, Ecosystem,
)

logger = logging.getLogger(__name__)


class DependencyParser:
    """Parser for various dependency file formats across ecosystems."""

    # File name -> (ecosystem, file_type, is_lockfile)
    FILE_NAME_MAP: Dict[str, Tuple[str, str, bool]] = {
        # Python
        "requirements.txt": (Ecosystem.PYTHON, "requirements.txt", False),
        "pyproject.toml": (Ecosystem.PYTHON, "pyproject.toml", False),
        "Pipfile": (Ecosystem.PYTHON, "Pipfile", False),
        "Pipfile.lock": (Ecosystem.PYTHON, "Pipfile.lock", True),
        "setup.py": (Ecosystem.PYTHON, "setup.py", False),
        "setup.cfg": (Ecosystem.PYTHON, "setup.cfg", False),
        # JavaScript / TypeScript
        "package.json": (Ecosystem.JAVASCRIPT, "package.json", False),
        "package-lock.json": (Ecosystem.JAVASCRIPT, "package-lock.json", True),
        "yarn.lock": (Ecosystem.JAVASCRIPT, "yarn.lock", True),
        # Java
        "pom.xml": (Ecosystem.JAVA, "pom.xml", False),
        # Go
        "go.mod": (Ecosystem.GO, "go.mod", False),
        "go.sum": (Ecosystem.GO, "go.sum", True),
        # PHP
        "composer.json": (Ecosystem.PHP, "composer.json", False),
        "composer.lock": (Ecosystem.PHP, "composer.lock", True),
        # Ruby
        "Gemfile": (Ecosystem.RUBY, "Gemfile", False),
        "Gemfile.lock": (Ecosystem.RUBY, "Gemfile.lock", True),
        # Rust
        "Cargo.toml": (Ecosystem.RUST, "Cargo.toml", False),
        "Cargo.lock": (Ecosystem.RUST, "Cargo.lock", True),
        # .NET (handled by glob pattern in scan_project)
        "packages.config": (Ecosystem.DOTNET, "packages.config", True),
    }

    # Glob patterns for files that are matched by extension or pattern
    GLOB_PATTERNS: Dict[str, Tuple[str, str, bool]] = {
        "*.csproj": (Ecosystem.DOTNET, "csproj", False),
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_project(self, path: str) -> List[DependencyFile]:
        """Scan a directory tree and parse all recognised dependency files.

        Parameters
        ----------
        path:
            Root directory of the project to scan.

        Returns
        -------
        List[DependencyFile]
            Parsed dependency files (empty list on failure).
        """
        root = Path(path)
        if not root.is_dir():
            logger.error("scan_project: path '%s' is not a directory", path)
            return []

        results: List[DependencyFile] = []

        # 1. Exact filename matches
        for filename, (ecosystem, file_type, is_lockfile) in self.FILE_NAME_MAP.items():
            for match in root.rglob(filename):
                rel = str(match.relative_to(root))
                logger.info("Found dependency file: %s", rel)
                try:
                    dep_file = self._parse_file(match, ecosystem, file_type, is_lockfile)
                    results.append(dep_file)
                except Exception as exc:
                    logger.error("Failed to parse %s: %s", rel, exc)

        # 2. Glob pattern matches (e.g. *.csproj)
        for pattern, (ecosystem, file_type, is_lockfile) in self.GLOB_PATTERNS.items():
            for match in root.rglob(pattern):
                rel = str(match.relative_to(root))
                # Skip files already matched by exact name
                if match.name in self.FILE_NAME_MAP:
                    continue
                logger.info("Found dependency file: %s", rel)
                try:
                    dep_file = self._parse_file(match, ecosystem, file_type, is_lockfile)
                    results.append(dep_file)
                except Exception as exc:
                    logger.error("Failed to parse %s: %s", rel, exc)

        logger.info(
            "scan_project complete: %d dependency file(s) found in '%s'",
            len(results),
            path,
        )
        return results

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _parse_file(
        self,
        filepath: Path,
        ecosystem: str,
        file_type: str,
        is_lockfile: bool,
    ) -> DependencyFile:
        """Dispatch to the appropriate parser based on *file_type*."""
        rel_path = str(filepath)

        dep_file = DependencyFile(
            path=rel_path,
            ecosystem=Ecosystem(ecosystem),
            file_type=file_type,
            is_lockfile=is_lockfile,
        )

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            msg = f"Cannot read file: {exc}"
            logger.error(msg)
            dep_file.parse_errors.append(msg)
            return dep_file

        parser_map = {
            "requirements.txt": self._parse_requirements_txt,
            "pyproject.toml": self._parse_pyproject_toml,
            "Pipfile": self._parse_pipfile,
            "Pipfile.lock": self._parse_pipfile_lock,
            "setup.py": self._parse_setup_py,
            "setup.cfg": self._parse_setup_cfg,
            "package.json": self._parse_package_json,
            "package-lock.json": self._parse_package_lock_json,
            "yarn.lock": self._parse_yarn_lock,
            "pom.xml": self._parse_pom_xml,
            "go.mod": self._parse_go_mod,
            "go.sum": self._parse_go_sum,
            "composer.json": self._parse_composer_json,
            "composer.lock": self._parse_composer_lock,
            "Gemfile": self._parse_gemfile,
            "Gemfile.lock": self._parse_gemfile_lock,
            "Cargo.toml": self._parse_cargo_toml,
            "Cargo.lock": self._parse_cargo_lock,
            "csproj": self._parse_csproj,
            "packages.config": self._parse_packages_config,
        }

        parser_func = parser_map.get(file_type)
        if parser_func is None:
            msg = f"No parser implemented for file type '{file_type}'"
            logger.warning(msg)
            dep_file.parse_errors.append(msg)
            return dep_file

        try:
            parser_func(content, dep_file)
        except Exception as exc:
            msg = f"Parse error in {file_type}: {exc}"
            logger.error(msg, exc_info=True)
            dep_file.parse_errors.append(msg)

        return dep_file

    # ==================================================================
    # Python parsers
    # ==================================================================

    def _parse_requirements_txt(self, content: str, dep_file: DependencyFile) -> None:
        """Parse a requirements.txt file.

        Supports version specifiers (==, >=, <=, ~=, !=, >, <), comments,
        blank lines, -r references, and --index-url / --extra-index-url
        options.
        """
        deps: List[Dependency] = []
        lines = content.splitlines()

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip empty and comment lines
            if not line or line.startswith("#"):
                continue

            # Skip options (--index-url, --extra-index-url, etc.)
            if line.startswith("--"):
                logger.debug("requirements.txt: skipping option line %d: %s", line_no, line)
                continue

            # -r / --requirement reference
            if line.startswith("-r ") or line.startswith("--requirement "):
                ref_path = line.split(None, 1)[1].strip()
                logger.info(
                    "requirements.txt: -r reference at line %d -> %s (not followed)",
                    line_no,
                    ref_path,
                )
                continue

            # Environment markers (after ;) – strip them for the version
            if ";" in line:
                line = line.split(";", 1)[0].strip()

            # Parse package name and version
            dep = self._parse_pip_requirement(line, line_no, dep_file.path)
            if dep is not None:
                deps.append(dep)

        dep_file.dependencies = deps
        logger.info(
            "requirements.txt: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    @staticmethod
    def _parse_pip_requirement(
        line: str, line_no: int, source_file: str
    ) -> Optional[Dependency]:
        """Parse a single pip requirement line into a Dependency."""
        # Pattern: name[extras] followed by optional version specifier
        m = re.match(
            r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
            r"(\[[^\]]*\])?"
            r"(?P<version>\s*(==|>=|<=|~=|!=|>|<)\s*[^\s;#]+)?",
            line,
        )
        if not m:
            return None

        name = m.group("name")
        version = m.group("version")
        if version is not None:
            version = version.strip()

        return Dependency(
            name=name,
            version=version or None,
            ecosystem=Ecosystem.PYTHON,
            scope=DependencyScope.PRODUCTION,
            source_file=source_file,
            line_number=line_no,
        )

    # ------------------------------------------------------------------
    # pyproject.toml (simple regex / string parsing, no third-party libs)
    # ------------------------------------------------------------------

    def _parse_pyproject_toml(self, content: str, dep_file: DependencyFile) -> None:
        """Parse pyproject.toml for [project.dependencies] and
        [project.optional-dependencies].

        Uses simple string / regex parsing to avoid third-party TOML
        libraries.
        """
        deps: List[Dependency] = []

        # --- [project.dependencies] ---
        section = self._extract_toml_section(content, "project", "dependencies")
        if section is not None:
            for line_no_offset, entry in enumerate(section):
                dep = self._parse_toml_dependency_entry(
                    entry, line_no_offset, dep_file.path, Ecosystem.PYTHON,
                    DependencyScope.PRODUCTION,
                )
                if dep is not None:
                    deps.append(dep)

        # --- [project.optional-dependencies] ---
        opt_section = self._extract_toml_section(
            content, "project", "optional-dependencies"
        )
        if opt_section is not None:
            group_name = ""
            for entry in opt_section:
                stripped = entry.strip()
                # Detect group header like [extras-name]
                header_m = re.match(r"^\[(?P<group>[^\]]+)\]\s*$", stripped)
                if header_m:
                    group_name = header_m.group("group")
                    continue
                dep = self._parse_toml_dependency_entry(
                    entry, 0, dep_file.path, Ecosystem.PYTHON,
                    DependencyScope.OPTIONAL,
                )
                if dep is not None:
                    dep.metadata["optional_group"] = group_name
                    deps.append(dep)

        dep_file.dependencies = deps
        logger.info(
            "pyproject.toml: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # Pipfile
    # ------------------------------------------------------------------

    def _parse_pipfile(self, content: str, dep_file: DependencyFile) -> None:
        """Parse a Pipfile (TOML-like) for [packages] and [dev-packages]."""
        deps: List[Dependency] = []

        # [packages]
        section = self._extract_toml_section(content, "packages")
        if section is not None:
            for entry in section:
                dep = self._parse_pipfile_entry(
                    entry, dep_file.path, DependencyScope.PRODUCTION,
                )
                if dep is not None:
                    deps.append(dep)

        # [dev-packages]
        section = self._extract_toml_section(content, "dev-packages")
        if section is not None:
            for entry in section:
                dep = self._parse_pipfile_entry(
                    entry, dep_file.path, DependencyScope.DEVELOPMENT,
                )
                if dep is not None:
                    deps.append(dep)

        dep_file.dependencies = deps
        logger.info("Pipfile: parsed %d dependency/ies from '%s'", len(deps), dep_file.path)

    def _parse_pipfile_entry(
        self, entry: str, source_file: str, scope: DependencyScope
    ) -> Optional[Dependency]:
        """Parse a single Pipfile entry like 'flask = "*"''."""
        m = re.match(r'^\s*(?P<name>[A-Za-z0-9_.-]+)\s*=\s*"(?P<version>[^"]*)"', entry)
        if not m:
            return None
        version = m.group("version")
        if version == "*":
            version = None
        return Dependency(
            name=m.group("name"),
            version=version,
            ecosystem=Ecosystem.PYTHON,
            scope=scope,
            source_file=source_file,
        )

    # ------------------------------------------------------------------
    # Pipfile.lock
    # ------------------------------------------------------------------

    def _parse_pipfile_lock(self, content: str, dep_file: DependencyFile) -> None:
        """Parse Pipfile.lock (JSON format) for resolved versions."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            dep_file.parse_errors.append(f"Invalid JSON in Pipfile.lock: {exc}")
            return

        deps: List[Dependency] = []
        for section_key, scope in [
            ("default", DependencyScope.PRODUCTION),
            ("develop", DependencyScope.DEVELOPMENT),
        ]:
            section = data.get(section_key, {})
            if not isinstance(section, dict):
                continue
            for name, info in section.items():
                version = None
                if isinstance(info, dict):
                    version = info.get("version")
                    if isinstance(version, str) and version.startswith("=="):
                        version = version[2:]
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        resolved_version=version,
                        ecosystem=Ecosystem.PYTHON,
                        scope=scope,
                        is_direct=True,
                        source_file=dep_file.path,
                    )
                )

        dep_file.dependencies = deps
        logger.info(
            "Pipfile.lock: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # setup.py
    # ------------------------------------------------------------------

    def _parse_setup_py(self, content: str, dep_file: DependencyFile) -> None:
        """Parse setup.py by looking for install_requires and extras_require."""
        deps: List[Dependency] = []

        # install_requires = [...]
        install_matches = re.findall(
            r"install_requires\s*=\s*\[(.*?)\]",
            content,
            re.DOTALL,
        )
        for match in install_matches:
            items = re.findall(r"""['"]([^'"]+)['"]""", match)
            for item in items:
                dep = self._parse_pip_requirement(item.strip(), 0, dep_file.path)
                if dep is not None:
                    dep.scope = DependencyScope.PRODUCTION
                    deps.append(dep)

        # extras_require = { ... }
        extras_match = re.search(
            r"extras_require\s*=\s*\{(.*?)\}",
            content,
            re.DOTALL,
        )
        if extras_match:
            extras_body = extras_match.group(1)
            # Find each group: "group": [...]
            groups = re.findall(
                r"""['"](\w+)['"]\s*:\s*\[(.*?)\]""",
                extras_body,
                re.DOTALL,
            )
            for group_name, group_body in groups:
                items = re.findall(r"""['"]([^'"]+)['"]""", group_body)
                for item in items:
                    dep = self._parse_pip_requirement(item.strip(), 0, dep_file.path)
                    if dep is not None:
                        dep.scope = DependencyScope.OPTIONAL
                        dep.metadata["optional_group"] = group_name
                        deps.append(dep)

        dep_file.dependencies = deps
        logger.info(
            "setup.py: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # setup.cfg
    # ------------------------------------------------------------------

    def _parse_setup_cfg(self, content: str, dep_file: DependencyFile) -> None:
        """Parse setup.cfg for [options] install_requires and
        [options.extras_require].
        """
        deps: List[Dependency] = []

        section = self._extract_ini_section(content, "options")
        if section is not None:
            for line_no, line in enumerate(section, start=1):
                stripped = line.strip()
                if stripped.startswith("install_requires"):
                    # install_requires =\n  pkg1\n  pkg2\n  ...
                    _, _, value = stripped.partition("=")
                    value = value.strip()
                    if value:
                        for item in value.splitlines():
                            item = item.strip().strip(",").strip()
                            if item:
                                dep = self._parse_pip_requirement(item, line_no, dep_file.path)
                                if dep is not None:
                                    deps.append(dep)

        # extras_require
        extras_section = self._extract_ini_section(content, "options.extras_require")
        if extras_section is not None:
            for line_no, line in enumerate(extras_section, start=1):
                stripped = line.strip()
                if "=" in stripped and not stripped.startswith("#"):
                    group, _, value = stripped.partition("=")
                    group = group.strip()
                    for item in value.splitlines():
                        item = item.strip().strip(",").strip()
                        if item:
                            dep = self._parse_pip_requirement(item, line_no, dep_file.path)
                            if dep is not None:
                                dep.scope = DependencyScope.OPTIONAL
                                dep.metadata["optional_group"] = group
                                deps.append(dep)

        dep_file.dependencies = deps
        logger.info(
            "setup.cfg: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # JavaScript / TypeScript parsers
    # ==================================================================

    def _parse_package_json(self, content: str, dep_file: DependencyFile) -> None:
        """Parse package.json for dependencies, devDependencies,
        peerDependencies, and optionalDependencies.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            dep_file.parse_errors.append(f"Invalid JSON in package.json: {exc}")
            return

        deps: List[Dependency] = []
        scope_map = {
            "dependencies": DependencyScope.PRODUCTION,
            "devDependencies": DependencyScope.DEVELOPMENT,
            "peerDependencies": DependencyScope.PEER,
            "optionalDependencies": DependencyScope.OPTIONAL,
        }

        for field, scope in scope_map.items():
            section = data.get(field)
            if not isinstance(section, dict):
                continue
            for name, version in section.items():
                deps.append(
                    Dependency(
                        name=name,
                        version=str(version) if version else None,
                        ecosystem=Ecosystem.JAVASCRIPT,
                        scope=scope,
                        is_dev=(scope == DependencyScope.DEVELOPMENT),
                        is_direct=True,
                        source_file=dep_file.path,
                    )
                )

        dep_file.dependencies = deps
        logger.info(
            "package.json: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # package-lock.json
    # ------------------------------------------------------------------

    def _parse_package_lock_json(self, content: str, dep_file: DependencyFile) -> None:
        """Parse package-lock.json for resolved dependency versions."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            dep_file.parse_errors.append(f"Invalid JSON in package-lock.json: {exc}")
            return

        deps: List[Dependency] = []
        packages = data.get("packages", {})
        if not isinstance(packages, dict):
            packages = {}
        # Also support npm v6 format (dependencies at top level)
        top_deps = data.get("dependencies", {})
        if isinstance(top_deps, dict):
            packages.update(top_deps)

        for pkg_key, info in packages.items():
            if not isinstance(info, dict):
                continue
            name = pkg_key.lstrip("node_modules/")
            if not name or name.startswith("@"):
                # scoped packages: keep the full name
                name = pkg_key
            version = info.get("version")
            deps.append(
                Dependency(
                    name=name,
                    version=None,
                    resolved_version=version,
                    ecosystem=Ecosystem.JAVASCRIPT,
                    scope=DependencyScope.PRODUCTION,
                    is_direct=(not pkg_key.startswith("node_modules/")),
                    source_file=dep_file.path,
                )
            )

        dep_file.dependencies = deps
        logger.info(
            "package-lock.json: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # yarn.lock (basic line parsing)
    # ------------------------------------------------------------------

    def _parse_yarn_lock(self, content: str, dep_file: DependencyFile) -> None:
        """Parse yarn.lock with basic line parsing.

        Yarn lock format:
          "package@version":
            version "1.2.3"
            resolved "https://..."
        """
        deps: List[Dependency] = []
        lines = content.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Package spec line: "name@version" or "@scope/name@version":
            if line.startswith('"') and line.endswith(":"):
                pkg_spec = line[1:-1]  # remove quotes and colon
                name = pkg_spec
                version = None

                # Look ahead for version and resolved
                j = i + 1
                while j < len(lines) and lines[j].strip() and not lines[j].strip().startswith('"'):
                    stripped = lines[j].strip()
                    if stripped.startswith("version"):
                        ver_match = re.match(r'version\s+"([^"]+)"', stripped)
                        if ver_match:
                            version = ver_match.group(1)
                    j += 1

                deps.append(
                    Dependency(
                        name=name,
                        version=None,
                        resolved_version=version,
                        ecosystem=Ecosystem.JAVASCRIPT,
                        scope=DependencyScope.PRODUCTION,
                        is_direct=False,
                        source_file=dep_file.path,
                        line_number=i + 1,
                    )
                )
            i += 1

        dep_file.dependencies = deps
        logger.info(
            "yarn.lock: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # Java / Maven parsers
    # ==================================================================

    def _parse_pom_xml(self, content: str, dep_file: DependencyFile) -> None:
        """Parse pom.xml for <dependencies> and <dependencyManagement>."""
        deps: List[Dependency] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            dep_file.parse_errors.append(f"Invalid XML in pom.xml: {exc}")
            return

        ns = ""
        if root.tag.startswith("{"):
            ns_match = re.match(r"\{([^}]+)\}", root.tag)
            if ns_match:
                ns = "{" + ns_match.group(1) + "}"

        # Parse <dependencies> (direct)
        deps_elem = root.find(f".//{ns}dependencies")
        if deps_elem is not None:
            self._parse_maven_dependencies(
                deps_elem, ns, deps, dep_file.path, DependencyScope.PRODUCTION,
            )

        # Parse <dependencyManagement><dependencies>
        dm_elem = root.find(f".//{ns}dependencyManagement/{ns}dependencies")
        if dm_elem is not None:
            self._parse_maven_dependencies(
                dm_elem, ns, deps, dep_file.path, DependencyScope.PRODUCTION,
            )

        dep_file.dependencies = deps
        logger.info(
            "pom.xml: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    def _parse_maven_dependencies(
        self,
        parent_elem,
        ns: str,
        deps: List[Dependency],
        source_file: str,
        scope: DependencyScope,
    ) -> None:
        """Parse <dependency> elements under a parent element."""
        for dep_elem in parent_elem.findall(f"{ns}dependency"):
            group_id = self._get_xml_text(dep_elem, f"{ns}groupId")
            artifact_id = self._get_xml_text(dep_elem, f"{ns}artifactId")
            version = self._get_xml_text(dep_elem, f"{ns}version")
            dep_scope_xml = self._get_xml_text(dep_elem, f"{ns}scope")
            optional = self._get_xml_text(dep_elem, f"{ns}optional")

            if not artifact_id:
                continue

            name = f"{group_id}:{artifact_id}" if group_id else artifact_id

            # Map Maven scope to our scope
            if dep_scope_xml == "test":
                actual_scope = DependencyScope.TEST
            elif dep_scope_xml == "provided" or dep_scope_xml == "runtime":
                actual_scope = DependencyScope.PRODUCTION
            else:
                actual_scope = scope

            is_opt = optional and optional.lower() == "true"

            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.JAVA,
                    scope=actual_scope if not is_opt else DependencyScope.OPTIONAL,
                    is_direct=True,
                    source_file=source_file,
                )
            )

    @staticmethod
    def _get_xml_text(element, tag: str) -> Optional[str]:
        """Safely get text content of a child XML element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return None

    # ==================================================================
    # Go parsers
    # ==================================================================

    def _parse_go_mod(self, content: str, dep_file: DependencyFile) -> None:
        """Parse go.mod for require blocks."""
        deps: List[Dependency] = []
        lines = content.splitlines()

        in_require_block = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue

            if in_require_block or line.startswith("require "):
                # Single require: require module v1.2.3
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    if parts[0] == "require":
                        parts = parts[1:]
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        # Strip comment if any
                        if "//" in version:
                            version = version.split("//")[0].strip()
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem=Ecosystem.GO,
                                scope=DependencyScope.PRODUCTION,
                                is_direct=True,
                                source_file=dep_file.path,
                                line_number=line_no,
                            )
                        )

        dep_file.dependencies = deps
        logger.info(
            "go.mod: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # go.sum
    # ------------------------------------------------------------------

    def _parse_go_sum(self, content: str, dep_file: DependencyFile) -> None:
        """Parse go.sum for module versions (each line: module version hash)."""
        deps: List[Dependency] = []
        seen: set = set()

        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            parts = raw_line.strip().split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                key = (name, version)
                if key not in seen:
                    seen.add(key)
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            resolved_version=version,
                            ecosystem=Ecosystem.GO,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=False,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )

        dep_file.dependencies = deps
        logger.info(
            "go.sum: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # .NET parsers
    # ==================================================================

    def _parse_csproj(self, content: str, dep_file: DependencyFile) -> None:
        """Parse a .csproj file for <PackageReference> elements."""
        deps: List[Dependency] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            dep_file.parse_errors.append(f"Invalid XML in csproj: {exc}")
            return

        ns = ""
        if root.tag.startswith("{"):
            ns_match = re.match(r"\{([^}]+)\}", root.tag)
            if ns_match:
                ns = "{" + ns_match.group(1) + "}"

        for item_group in root.iter(f"{ns}ItemGroup"):
            for pkg_ref in item_group.findall(f"{ns}PackageReference"):
                name = pkg_ref.get("Include", "")
                version = pkg_ref.get("Version")
                if not version:
                    ver_elem = pkg_ref.find(f"{ns}Version")
                    if ver_elem is not None and ver_elem.text:
                        version = ver_elem.text.strip()

                if name:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.DOTNET,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=True,
                            source_file=dep_file.path,
                        )
                    )

        dep_file.dependencies = deps
        logger.info(
            "csproj: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # packages.config
    # ------------------------------------------------------------------

    def _parse_packages_config(self, content: str, dep_file: DependencyFile) -> None:
        """Parse packages.config for <package> elements."""
        deps: List[Dependency] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            dep_file.parse_errors.append(f"Invalid XML in packages.config: {exc}")
            return

        for pkg_elem in root.findall("package"):
            id_attr = pkg_elem.get("id", "")
            version = pkg_elem.get("version")
            if id_attr:
                deps.append(
                    Dependency(
                        name=id_attr,
                        version=version,
                        resolved_version=version,
                        ecosystem=Ecosystem.DOTNET,
                        scope=DependencyScope.PRODUCTION,
                        is_direct=True,
                        source_file=dep_file.path,
                    )
                )

        dep_file.dependencies = deps
        logger.info(
            "packages.config: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # PHP / Composer parsers
    # ==================================================================

    def _parse_composer_json(self, content: str, dep_file: DependencyFile) -> None:
        """Parse composer.json for require and require-dev."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            dep_file.parse_errors.append(f"Invalid JSON in composer.json: {exc}")
            return

        deps: List[Dependency] = []

        for field, scope in [
            ("require", DependencyScope.PRODUCTION),
            ("require-dev", DependencyScope.DEVELOPMENT),
        ]:
            section = data.get(field)
            if not isinstance(section, dict):
                continue
            for name, version in section.items():
                # Skip php version requirement
                if name.lower() == "php":
                    continue
                deps.append(
                    Dependency(
                        name=name,
                        version=str(version) if version else None,
                        ecosystem=Ecosystem.PHP,
                        scope=scope,
                        is_dev=(scope == DependencyScope.DEVELOPMENT),
                        is_direct=True,
                        source_file=dep_file.path,
                    )
                )

        dep_file.dependencies = deps
        logger.info(
            "composer.json: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # composer.lock
    # ------------------------------------------------------------------

    def _parse_composer_lock(self, content: str, dep_file: DependencyFile) -> None:
        """Parse composer.lock for resolved package versions."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            dep_file.parse_errors.append(f"Invalid JSON in composer.lock: {exc}")
            return

        deps: List[Dependency] = []
        for pkg in data.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version")
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    resolved_version=version,
                    ecosystem=Ecosystem.PHP,
                    scope=DependencyScope.PRODUCTION,
                    is_direct=False,
                    source_file=dep_file.path,
                )
            )
        for pkg in data.get("packages-dev", []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version")
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    resolved_version=version,
                    ecosystem=Ecosystem.PHP,
                    scope=DependencyScope.DEVELOPMENT,
                    is_dev=True,
                    is_direct=False,
                    source_file=dep_file.path,
                )
            )

        dep_file.dependencies = deps
        logger.info(
            "composer.lock: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # Ruby / Bundler parsers
    # ==================================================================

    def _parse_gemfile(self, content: str, dep_file: DependencyFile) -> None:
        """Parse Gemfile for gem declarations."""
        deps: List[Dependency] = []
        lines = content.splitlines()

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip comments, empty lines, and non-gem lines
            if not line or line.startswith("#") or line.startswith("source") or line.startswith("group") or line.startswith("end"):
                continue

            # Match gem "name", "version" or gem "name", "~> 1.0" etc.
            m = re.match(
                r"""gem\s+['"](?P<name>[^'"]+)['"]"""
                r"""(?:\s*,\s*['"](?P<version>[^'"]+)['"])?""",
                line,
            )
            if not m:
                # Try gem :group => ... do style
                m2 = re.match(
                    r"""gem\s+['"](?P<name>[^'"]+)['"]""",
                    line,
                )
                if m2:
                    deps.append(
                        Dependency(
                            name=m2.group("name"),
                            version=None,
                            ecosystem=Ecosystem.RUBY,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=True,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )
                continue

            name = m.group("name")
            version = m.group("version")

            # Determine scope from context
            scope = DependencyScope.PRODUCTION
            if ":group" in line and ("test" in line or "development" in line):
                scope = DependencyScope.DEVELOPMENT

            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.RUBY,
                    scope=scope,
                    is_direct=True,
                    source_file=dep_file.path,
                    line_number=line_no,
                )
            )

        dep_file.dependencies = deps
        logger.info(
            "Gemfile: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # Gemfile.lock
    # ------------------------------------------------------------------

    def _parse_gemfile_lock(self, content: str, dep_file: DependencyFile) -> None:
        """Parse Gemfile.lock for resolved gem versions."""
        deps: List[Dependency] = []
        lines = content.splitlines()

        in_specs = False
        in_deps = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Detect section headers
            if line == "specs:":
                in_specs = True
                in_deps = False
                continue
            if line == "dependencies:":
                in_deps = True
                in_specs = False
                continue
            if line and not line.startswith(" ") and not line.startswith("-") and not line.startswith("#"):
                # New top-level section
                in_specs = False
                in_deps = False
                if re.match(r"^[A-Z]", line):
                    continue

            if in_specs:
                # specs section lines like:  name (version)
                m = re.match(r"^\s+(?P<name>\S+)\s+\((?P<version>[^)]+)\)", line)
                if m:
                    deps.append(
                        Dependency(
                            name=m.group("name"),
                            version=m.group("version"),
                            resolved_version=m.group("version"),
                            ecosystem=Ecosystem.RUBY,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=False,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )

            if in_deps:
                # dependencies section lines like:  name (= version)
                m = re.match(r"^\s+(?P<name>\S+)(?:\s+\((?P<version>[^)]+)\))?", line)
                if m:
                    deps.append(
                        Dependency(
                            name=m.group("name"),
                            version=m.group("version"),
                            resolved_version=m.group("version"),
                            ecosystem=Ecosystem.RUBY,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=True,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )

        dep_file.dependencies = deps
        logger.info(
            "Gemfile.lock: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # Rust / Cargo parsers
    # ==================================================================

    def _parse_cargo_toml(self, content: str, dep_file: DependencyFile) -> None:
        """Parse Cargo.toml for [dependencies] and [dev-dependencies]."""
        deps: List[Dependency] = []

        # [dependencies]
        section = self._extract_toml_section(content, "dependencies")
        if section is not None:
            for line_no_offset, entry in enumerate(section):
                dep = self._parse_toml_dependency_entry(
                    entry, line_no_offset, dep_file.path, Ecosystem.RUST,
                    DependencyScope.PRODUCTION,
                )
                if dep is not None:
                    deps.append(dep)

        # [dev-dependencies]
        section = self._extract_toml_section(content, "dev-dependencies")
        if section is not None:
            for line_no_offset, entry in enumerate(section):
                dep = self._parse_toml_dependency_entry(
                    entry, line_no_offset, dep_file.path, Ecosystem.RUST,
                    DependencyScope.DEVELOPMENT,
                )
                if dep is not None:
                    deps.append(dep)

        dep_file.dependencies = deps
        logger.info(
            "Cargo.toml: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ------------------------------------------------------------------
    # Cargo.lock
    # ------------------------------------------------------------------

    def _parse_cargo_lock(self, content: str, dep_file: DependencyFile) -> None:
        """Parse Cargo.lock for resolved package versions."""
        deps: List[Dependency] = []
        lines = content.splitlines()
        in_package = False
        current_name = None
        current_version = None

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if line == "[[package]]":
                if current_name:
                    deps.append(
                        Dependency(
                            name=current_name,
                            version=current_version,
                            resolved_version=current_version,
                            ecosystem=Ecosystem.RUST,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=False,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )
                in_package = True
                current_name = None
                current_version = None
                continue

            if in_package and line.startswith("["):
                in_package = False
                if current_name:
                    deps.append(
                        Dependency(
                            name=current_name,
                            version=current_version,
                            resolved_version=current_version,
                            ecosystem=Ecosystem.RUST,
                            scope=DependencyScope.PRODUCTION,
                            is_direct=False,
                            source_file=dep_file.path,
                            line_number=line_no,
                        )
                    )
                current_name = None
                current_version = None
                continue

            if in_package:
                if line.startswith("name = "):
                    m = re.match(r'name\s*=\s*"([^"]+)"', line)
                    if m:
                        current_name = m.group(1)
                elif line.startswith("version = "):
                    m = re.match(r'version\s*=\s*"([^"]+)"', line)
                    if m:
                        current_version = m.group(1)

        # Don't forget the last package
        if current_name:
            deps.append(
                Dependency(
                    name=current_name,
                    version=current_version,
                    resolved_version=current_version,
                    ecosystem=Ecosystem.RUST,
                    scope=DependencyScope.PRODUCTION,
                    is_direct=False,
                    source_file=dep_file.path,
                )
            )

        dep_file.dependencies = deps
        logger.info(
            "Cargo.lock: parsed %d dependency/ies from '%s'",
            len(deps),
            dep_file.path,
        )

    # ==================================================================
    # Shared TOML / INI helpers
    # ==================================================================

    @staticmethod
    def _extract_toml_section(content: str, *section_path: str) -> Optional[List[str]]:
        """Extract lines belonging to a TOML section.

        Parameters
        ----------
        content:
            Full file content.
        *section_path:
            Section name components, e.g. ("project", "dependencies") for
            ``[project.dependencies]``.

        Returns
        -------
        List of stripped lines inside the section, or *None* if not found.
        """
        section_header = "[" + ".".join(section_path) + "]"
        # Also handle alternative: [project.dependencies] vs [project]\n[dependencies]
        lines = content.splitlines()
        start = None
        end = len(lines)

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == section_header:
                start = i + 1
                break

        if start is None:
            return None

        # Find next section header
        for i in range(start, len(lines)):
            stripped = lines[i].strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                # Could be a sub-section header like [extras-name]
                # We stop at a new top-level or same-level section
                if not section_path:
                    end = i
                    break
                # Check if this is a new section at the same or higher level
                new_header = stripped[1:-1]
                new_parts = new_header.split(".")
                if len(new_parts) <= len(section_path):
                    end = i
                    break

        return [lines[i].strip() for i in range(start, end)]

    @staticmethod
    def _parse_toml_dependency_entry(
        entry: str,
        line_no: int,
        source_file: str,
        ecosystem: Ecosystem,
        scope: DependencyScope,
    ) -> Optional[Dependency]:
        """Parse a single TOML dependency entry.

        Supports:
          - Simple: name = "1.2.3"
          - Complex: name = { version = "1.2.3" }
        """
        entry = entry.strip()
        if not entry or entry.startswith("#") or entry.startswith("["):
            return None

        # Simple: name = "version"
        m = re.match(
            r'^(?P<name>[A-Za-z0-9_][A-Za-z0-9_.-]*)\s*=\s*"(?P<version>[^"]*)"',
            entry,
        )
        if m:
            version = m.group("version")
            return Dependency(
                name=m.group("name"),
                version=version if version and version != "*" else None,
                ecosystem=ecosystem,
                scope=scope,
                is_direct=True,
                source_file=source_file,
                line_number=line_no,
            )

        # Complex: name = { version = "1.2.3", ... }
        m = re.match(
            r'^(?P<name>[A-Za-z0-9_][A-Za-z0-9_.-]*)\s*=\s*\{',
            entry,
        )
        if m:
            name = m.group("name")
            # Look for version in the same line or following lines
            ver_match = re.search(r'version\s*=\s*"([^"]*)"', entry)
            version = ver_match.group(1) if ver_match else None
            return Dependency(
                name=name,
                version=version if version and version != "*" else None,
                ecosystem=ecosystem,
                scope=scope,
                is_direct=True,
                source_file=source_file,
                line_number=line_no,
            )

        return None

    @staticmethod
    def _extract_ini_section(content: str, section_name: str) -> Optional[List[str]]:
        """Extract lines from an INI-style section.

        Parameters
        ----------
        content:
            Full file content.
        section_name:
            Section name (e.g. "options" or "options.extras_require").

        Returns
        -------
        List of lines inside the section, or *None* if not found.
        """
        lines = content.splitlines()
        header = f"[{section_name}]"
        start = None
        end = len(lines)

        for i, line in enumerate(lines):
            if line.strip() == header:
                start = i + 1
                break

        if start is None:
            return None

        for i in range(start, len(lines)):
            stripped = lines[i].strip()
            if stripped.startswith("["):
                end = i
                break

        return lines[start:end]
