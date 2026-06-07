"""
Comprehensive tests for the supply_chain security module.

Covers DependencyParser, SBOMGenerator, SupplyChainAttackDetector,
CVEMatcher, and SupplyChainAnalyzer with full isolation (no network).
"""

import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from supply_chain.models import (
    Dependency, DependencyFile, DependencyScope, Ecosystem,
    SeverityLevel, AttackType, VulnerabilityInfo, CVEMatch,
    SBOMDocument, SBOMComponent, SupplyChainScanResult,
    AttackIndicator,
)
from supply_chain.dep_parser import DependencyParser
from supply_chain.sbom_generator import SBOMGenerator
from supply_chain.attack_detector import SupplyChainAttackDetector
from supply_chain.cve_matcher import CVEMatcher
from supply_chain.analyzer import SupplyChainAnalyzer


# ======================================================================
# 1. DependencyParser Tests
# ======================================================================


class TestDependencyParser:
    """Tests for DependencyParser covering all supported file formats."""

    def test_parse_requirements_txt(self, tmp_path):
        """Parse requirements.txt with various version constraints, comments, and blank lines."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "# Project dependencies\n"
            "\n"
            "requests==2.31.0\n"
            "numpy>=1.24.0\n"
            "pandas~=2.0.0\n"
            "flask>=1.0,<3.0\n"
            "django\n"
            "pytest>=7.0; python_version>='3.8'\n"
            "\n"
            "--index-url https://pypi.org/simple\n"
            "# another comment\n"
            "scipy!=1.11.0\n"
            "celery[redis]>=5.3.0\n"
            "-r other-requirements.txt\n"
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            req_file, Ecosystem.PYTHON, "requirements.txt", False,
        )

        assert dep_file.file_type == "requirements.txt"
        assert dep_file.ecosystem == Ecosystem.PYTHON
        assert not dep_file.is_lockfile

        names = {d.name for d in dep_file.dependencies}
        assert "requests" in names
        assert "numpy" in names
        assert "pandas" in names
        assert "flask" in names
        assert "django" in names
        assert "pytest" in names
        assert "scipy" in names
        assert "celery" in names

        # requests should have pinned version
        req_dep = next(d for d in dep_file.dependencies if d.name == "requests")
        assert req_dep.version == "==2.31.0"
        assert req_dep.ecosystem == Ecosystem.PYTHON

        # django has no version
        django_dep = next(d for d in dep_file.dependencies if d.name == "django")
        assert django_dep.version is None

        # celery[redis] - extras are part of the parsed name
        assert "celery" in names

        # -r lines and -- options should be skipped
        assert len(dep_file.dependencies) == 8

    def test_parse_package_json(self, tmp_path):
        """Parse package.json with dependencies and devDependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "name": "my-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "4.17.21",
                "axios": "^1.5.0",
            },
            "devDependencies": {
                "jest": "^29.0.0",
                "typescript": "^5.0.0",
            },
            "peerDependencies": {
                "react": ">=17.0.0",
            },
            "optionalDependencies": {
                "fsevents": "^2.3.0",
            },
        }))

        parser = DependencyParser()
        dep_file = parser._parse_file(
            pkg_file, Ecosystem.JAVASCRIPT, "package.json", False,
        )

        assert dep_file.ecosystem == Ecosystem.JAVASCRIPT
        assert len(dep_file.dependencies) == 7

        prod_names = {d.name for d in dep_file.dependencies if d.scope == DependencyScope.PRODUCTION}
        dev_names = {d.name for d in dep_file.dependencies if d.scope == DependencyScope.DEVELOPMENT}
        peer_names = {d.name for d in dep_file.dependencies if d.scope == DependencyScope.PEER}
        opt_names = {d.name for d in dep_file.dependencies if d.scope == DependencyScope.OPTIONAL}

        assert "express" in prod_names
        assert "lodash" in prod_names
        assert "jest" in dev_names
        assert "typescript" in dev_names
        assert "react" in peer_names
        assert "fsevents" in opt_names

        # dev deps should have is_dev=True
        jest_dep = next(d for d in dep_file.dependencies if d.name == "jest")
        assert jest_dep.is_dev is True

    def test_parse_pom_xml(self, tmp_path):
        """Parse pom.xml with Maven dependencies."""
        pom_file = tmp_path / "pom.xml"
        pom_file.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <groupId>com.example</groupId>\n'
            '  <artifactId>my-app</artifactId>\n'
            '  <version>1.0.0</version>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <groupId>org.apache.struts</groupId>\n'
            '      <artifactId>struts2-core</artifactId>\n'
            '      <version>2.5.33</version>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>junit</groupId>\n'
            '      <artifactId>junit</artifactId>\n'
            '      <version>4.13.2</version>\n'
            '      <scope>test</scope>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>com.google.guava</groupId>\n'
            '      <artifactId>guava</artifactId>\n'
            '      <version>32.0.0</version>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>\n'
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            pom_file, Ecosystem.JAVA, "pom.xml", False,
        )

        assert dep_file.ecosystem == Ecosystem.JAVA
        assert len(dep_file.dependencies) == 3

        names = {d.name for d in dep_file.dependencies}
        assert "org.apache.struts:struts2-core" in names
        assert "junit:junit" in names
        assert "com.google.guava:guava" in names

        # junit should have test scope
        junit_dep = next(d for d in dep_file.dependencies if d.name == "junit:junit")
        assert junit_dep.scope == DependencyScope.TEST

        # struts should have production scope
        struts_dep = next(d for d in dep_file.dependencies if "struts" in d.name)
        assert struts_dep.scope == DependencyScope.PRODUCTION

    def test_parse_go_mod(self, tmp_path):
        """Parse go.mod with require block."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module github.com/example/myproject\n\n"
            "go 1.21\n\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.9.1\n"
            "    github.com/go-sql-driver/mysql v1.7.1\n"
            "    gorm.io/gorm v1.25.5\n"
            ")\n\n"
            "require github.com/stretchr/testify v1.8.4\n"
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            go_mod, Ecosystem.GO, "go.mod", False,
        )

        assert dep_file.ecosystem == Ecosystem.GO
        assert len(dep_file.dependencies) == 4

        names = {d.name for d in dep_file.dependencies}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/go-sql-driver/mysql" in names
        assert "gorm.io/gorm" in names
        assert "github.com/stretchr/testify" in names

        gin_dep = next(d for d in dep_file.dependencies if "gin" in d.name)
        assert gin_dep.version == "v1.9.1"

    def test_parse_gemfile(self, tmp_path):
        """Parse Gemfile with gem declarations."""
        gemfile = tmp_path / "Gemfile"
        gemfile.write_text(
            'source "https://rubygems.org"\n\n'
            'gem "rails", "~> 7.1.0"\n'
            'gem "devise"\n'
            'gem "pundit", "~> 2.3"\n'
            'gem "sidekiq", "~> 7.2"\n'
            '# gem "old-gem"\n'
            '\n'
            'group :test do\n'
            '  gem "rspec"\n'
            'end\n'
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            gemfile, Ecosystem.RUBY, "Gemfile", False,
        )

        assert dep_file.ecosystem == Ecosystem.RUBY
        assert len(dep_file.dependencies) >= 4

        names = {d.name for d in dep_file.dependencies}
        assert "rails" in names
        assert "devise" in names
        assert "pundit" in names
        assert "sidekiq" in names

        rails_dep = next(d for d in dep_file.dependencies if d.name == "rails")
        assert rails_dep.version == "~> 7.1.0"

        # devise has no version
        devise_dep = next(d for d in dep_file.dependencies if d.name == "devise")
        assert devise_dep.version is None

    def test_parse_cargo_toml(self, tmp_path):
        """Parse Cargo.toml with [dependencies] and [dev-dependencies]."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text(
            '[package]\n'
            'name = "my-project"\n'
            'version = "0.1.0"\n'
            'edition = "2021"\n\n'
            '[dependencies]\n'
            'serde = { version = "1.0.195", features = ["derive"] }\n'
            'tokio = "1.35.0"\n'
            'reqwest = "0.11.0"\n\n'
            '[dev-dependencies]\n'
            'mockall = "0.11.0"\n'
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            cargo, Ecosystem.RUST, "Cargo.toml", False,
        )

        assert dep_file.ecosystem == Ecosystem.RUST
        assert len(dep_file.dependencies) >= 4

        names = {d.name for d in dep_file.dependencies}
        assert "serde" in names
        assert "tokio" in names
        assert "reqwest" in names
        assert "mockall" in names

        # serde uses complex format { version = "..." }
        serde_dep = next(d for d in dep_file.dependencies if d.name == "serde")
        assert serde_dep.version == "1.0.195"

        # mockall should be dev scope
        mockall_dep = next(d for d in dep_file.dependencies if d.name == "mockall")
        assert mockall_dep.scope == DependencyScope.DEVELOPMENT

    def test_parse_composer_json(self, tmp_path):
        """Parse composer.json with require and require-dev."""
        composer = tmp_path / "composer.json"
        composer.write_text(json.dumps({
            "name": "my/project",
            "require": {
                "php": "^8.1",
                "laravel/framework": "^10.0",
                "guzzlehttp/guzzle": "^7.5",
            },
            "require-dev": {
                "phpunit/phpunit": "^10.0",
            },
        }))

        parser = DependencyParser()
        dep_file = parser._parse_file(
            composer, Ecosystem.PHP, "composer.json", False,
        )

        assert dep_file.ecosystem == Ecosystem.PHP
        # "php" should be skipped
        assert len(dep_file.dependencies) == 3

        names = {d.name for d in dep_file.dependencies}
        assert "laravel/framework" in names
        assert "guzzlehttp/guzzle" in names
        assert "phpunit/phpunit" in names
        assert "php" not in names

        # phpunit should be dev scope
        phpunit_dep = next(d for d in dep_file.dependencies if d.name == "phpunit/phpunit")
        assert phpunit_dep.scope == DependencyScope.DEVELOPMENT
        assert phpunit_dep.is_dev is True

    def test_parse_csproj(self, tmp_path):
        """Parse .csproj with PackageReference elements."""
        csproj = tmp_path / "MyProject.csproj"
        csproj.write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <PropertyGroup>\n'
            '    <TargetFramework>net8.0</TargetFramework>\n'
            '  </PropertyGroup>\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
            '    <PackageReference Include="Serilog" Version="3.1.0" />\n'
            '    <PackageReference Include="Moq">\n'
            '      <Version>4.20.0</Version>\n'
            '    </PackageReference>\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        )

        parser = DependencyParser()
        dep_file = parser._parse_file(
            csproj, Ecosystem.DOTNET, "csproj", False,
        )

        assert dep_file.ecosystem == Ecosystem.DOTNET
        assert len(dep_file.dependencies) == 3

        names = {d.name for d in dep_file.dependencies}
        assert "Newtonsoft.Json" in names
        assert "Serilog" in names
        assert "Moq" in names

        newton_dep = next(d for d in dep_file.dependencies if d.name == "Newtonsoft.Json")
        assert newton_dep.version == "13.0.3"

    def test_scan_project(self, tmp_path):
        """Scan a directory containing multiple dependency files."""
        # Create requirements.txt
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nflask>=2.0\n"
        )

        # Create package.json
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"express": "^4.18.0"},
        }))

        # Create a subdirectory with go.mod
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.21\n\n"
            "require github.com/gin-gonic/gin v1.9.1\n"
        )

        parser = DependencyParser()
        results = parser.scan_project(str(tmp_path))

        assert len(results) >= 3

        ecosystems = {r.ecosystem for r in results}
        assert Ecosystem.PYTHON in ecosystems
        assert Ecosystem.JAVASCRIPT in ecosystems
        assert Ecosystem.GO in ecosystems

    def test_parse_empty_file(self, tmp_path):
        """Parsing an empty file should return a DependencyFile with no dependencies."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")

        parser = DependencyParser()
        dep_file = parser._parse_file(
            req_file, Ecosystem.PYTHON, "requirements.txt", False,
        )

        assert dep_file.dependencies == []
        assert dep_file.parse_errors == []

    def test_parse_invalid_format(self, tmp_path):
        """Parsing a malformed file should not crash; errors should be recorded."""
        bad_file = tmp_path / "requirements.txt"
        bad_file.write_text("{{{{invalid content}}}}\n")

        parser = DependencyParser()
        dep_file = parser._parse_file(
            bad_file, Ecosystem.PYTHON, "requirements.txt", False,
        )

        # Should not crash; may have zero dependencies
        assert isinstance(dep_file, DependencyFile)

        # Try invalid JSON for package.json
        bad_json = tmp_path / "package.json"
        bad_json.write_text("{invalid json!!!")
        dep_file2 = parser._parse_file(
            bad_json, Ecosystem.JAVASCRIPT, "package.json", False,
        )
        assert isinstance(dep_file2, DependencyFile)
        assert len(dep_file2.parse_errors) > 0

        # Try invalid XML for pom.xml
        bad_xml = tmp_path / "pom.xml"
        bad_xml.write_text("<not valid xml")
        dep_file3 = parser._parse_file(
            bad_xml, Ecosystem.JAVA, "pom.xml", False,
        )
        assert isinstance(dep_file3, DependencyFile)
        assert len(dep_file3.parse_errors) > 0


# ======================================================================
# 2. SBOMGenerator Tests
# ======================================================================


class TestSBOMGenerator:
    """Tests for SBOMGenerator covering CycloneDX, SPDX, purl, and file output."""

    def _make_dep_file(self, deps):
        """Helper to create a DependencyFile from a list of (name, version, ecosystem) tuples."""
        dependencies = []
        for name, version, ecosystem in deps:
            dependencies.append(Dependency(
                name=name,
                version=version,
                resolved_version=version,
                ecosystem=ecosystem,
                scope=DependencyScope.PRODUCTION,
                is_direct=True,
            ))
        return DependencyFile(
            path="test/requirements.txt",
            ecosystem=Ecosystem.PYTHON,
            file_type="requirements.txt",
            dependencies=dependencies,
        )

    def test_generate_cyclonedx(self):
        """Generate CycloneDX format SBOM."""
        gen = SBOMGenerator(project_name="test-project", project_version="1.0.0")
        dep_file = self._make_dep_file([
            ("requests", "2.31.0", Ecosystem.PYTHON),
            ("numpy", "1.24.0", Ecosystem.PYTHON),
        ])

        sbom = gen.generate([dep_file], format_name="cyclonedx")

        assert sbom.format_name == "CycloneDX"
        assert sbom.format_version == "1.5"
        assert sbom.name == "test-project"
        assert sbom.version == "1.0.0"
        assert sbom.total_components == 2
        assert len(sbom.components) == 2

        # Verify CycloneDX JSON structure
        cdx_json = gen.to_cyclonedx_json(sbom)
        assert cdx_json["bomFormat"] == "CycloneDX"
        assert cdx_json["specVersion"] == "1.5"
        assert "$schema" in cdx_json
        assert "metadata" in cdx_json
        assert "components" in cdx_json
        assert len(cdx_json["components"]) == 2

        # Check component structure
        comp = cdx_json["components"][0]
        assert "type" in comp
        assert "name" in comp
        assert "version" in comp
        assert "scope" in comp

    def test_generate_spdx(self):
        """Generate SPDX format SBOM."""
        gen = SBOMGenerator(project_name="test-project", project_version="1.0.0")
        dep_file = self._make_dep_file([
            ("express", "4.18.0", Ecosystem.JAVASCRIPT),
        ])

        sbom = gen.generate([dep_file], format_name="spdx")

        assert sbom.format_name == "SPDX"
        assert sbom.format_version == "2.3"

        spdx_json = gen.to_spdx_json(sbom)
        assert spdx_json["spdxVersion"] == "SPDX-2.3"
        assert spdx_json["dataLicense"] == "CC0-1.0"
        assert "packages" in spdx_json
        assert "relationships" in spdx_json
        assert "creationInfo" in spdx_json
        assert len(spdx_json["packages"]) == 1

        pkg = spdx_json["packages"][0]
        assert "SPDXID" in pkg
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert pkg["primaryPackagePurpose"] == "LIBRARY"

    def test_build_purl(self):
        """Verify purl generation correctness for various ecosystems."""
        gen = SBOMGenerator()

        test_cases = [
            (
                Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYTHON),
                "pkg:pypi/requests@2.31.0",
            ),
            (
                Dependency(name="lodash", version="4.17.21", ecosystem=Ecosystem.JAVASCRIPT),
                "pkg:npm/lodash@4.17.21",
            ),
            (
                # Maven names with ":" use ":" as purl separator (not "/")
                Dependency(name="org.apache.struts:struts2-core", version="2.5.33", ecosystem=Ecosystem.JAVA),
                "pkg:maven/org.apache.struts:struts2-core@2.5.33",
            ),
            (
                Dependency(name="github.com/gin-gonic/gin", version="1.9.1", ecosystem=Ecosystem.GO),
                "pkg:golang/github.com/gin-gonic/gin@1.9.1",
            ),
            (
                Dependency(name="serde", version="1.0.195", ecosystem=Ecosystem.RUST),
                "pkg:cargo/serde@1.0.195",
            ),
            (
                Dependency(name="rails", version="7.1.0", ecosystem=Ecosystem.RUBY),
                "pkg:gem/rails@7.1.0",
            ),
            (
                Dependency(name="laravel/framework", version="10.40.0", ecosystem=Ecosystem.PHP),
                "pkg:composer/laravel/framework@10.40.0",
            ),
            (
                Dependency(name="Newtonsoft.Json", version="13.0.3", ecosystem=Ecosystem.DOTNET),
                "pkg:nuget/Newtonsoft.Json@13.0.3",
            ),
        ]

        for dep, expected_purl in test_cases:
            actual_purl = gen._build_purl(dep)
            assert actual_purl == expected_purl, (
                f"purl mismatch for {dep.name}: expected '{expected_purl}', got '{actual_purl}'"
            )

    def test_empty_dependencies(self):
        """SBOM generation with empty dependency list should produce valid empty SBOM."""
        gen = SBOMGenerator(project_name="empty-project")
        dep_file = DependencyFile(
            path="test/requirements.txt",
            ecosystem=Ecosystem.PYTHON,
            file_type="requirements.txt",
            dependencies=[],
        )

        sbom = gen.generate([dep_file])

        assert sbom.total_components == 0
        assert sbom.components == []

        cdx_json = gen.to_cyclonedx_json(sbom)
        assert len(cdx_json["components"]) == 0

        spdx_json = gen.to_spdx_json(sbom)
        assert len(spdx_json["packages"]) == 0

    def test_save_to_file(self, tmp_path):
        """Save SBOM to a JSON file and verify contents."""
        gen = SBOMGenerator(project_name="save-test", project_version="1.0.0")
        dep_file = self._make_dep_file([
            ("requests", "2.31.0", Ecosystem.PYTHON),
        ])

        sbom = gen.generate([dep_file])
        output_path = str(tmp_path / "sbom.json")
        gen.save_to_file(sbom, output_path, format_name="cyclonedx")

        assert os.path.isfile(output_path)

        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert len(data["components"]) == 1
        assert data["components"][0]["name"] == "requests"

        # Also test SPDX format
        spdx_path = str(tmp_path / "sbom-spdx.json")
        gen.save_to_file(sbom, spdx_path, format_name="spdx")
        with open(spdx_path, "r", encoding="utf-8") as f:
            spdx_data = json.load(f)
        assert spdx_data["spdxVersion"] == "SPDX-2.3"


# ======================================================================
# 3. SupplyChainAttackDetector Tests
# ======================================================================


class TestSupplyChainAttackDetector:
    """Tests for SupplyChainAttackDetector covering typosquatting,
    dependency confusion, suspicious versions, and false positive safety."""

    def _make_dep_file(self, deps):
        """Helper to create a DependencyFile with given Dependency objects."""
        return DependencyFile(
            path="test/requirements.txt",
            ecosystem=Ecosystem.PYTHON,
            file_type="requirements.txt",
            dependencies=deps,
        )

    def test_detect_typosquatting(self):
        """Detect typosquatting packages via Levenshtein distance."""
        detector = SupplyChainAttackDetector()

        # "reqeusts" is 1 edit away from "requests" (transposition)
        dep_file = self._make_dep_file([
            Dependency(name="reqeusts", version="2.0.0", ecosystem=Ecosystem.PYTHON),
        ])

        indicators = detector.detect_typosquatting([dep_file])

        assert len(indicators) > 0
        found = any(
            ind.attack_type == AttackType.TYPOSQUATTING
            and "reqeusts" in ind.title
            and "requests" in ind.title
            for ind in indicators
        )
        assert found, "Should detect 'reqeusts' as typosquatting of 'requests'"

    def test_levenshtein_distance(self):
        """Test the Levenshtein distance algorithm directly."""
        detector = SupplyChainAttackDetector()

        # Identical strings
        assert detector._levenshtein_distance("abc", "abc") == 0

        # One insertion
        assert detector._levenshtein_distance("abc", "abcd") == 1

        # One deletion
        assert detector._levenshtein_distance("abc", "ac") == 1

        # One substitution
        assert detector._levenshtein_distance("abc", "axc") == 1

        # One transposition
        assert detector._levenshtein_distance("ab", "ba") == 2

        # Completely different
        assert detector._levenshtein_distance("abc", "xyz") == 3

        # Empty string
        assert detector._levenshtein_distance("", "abc") == 3
        assert detector._levenshtein_distance("abc", "") == 3

        # Symmetry
        assert detector._levenshtein_distance("kitten", "sitting") == 3
        assert detector._levenshtein_distance("sitting", "kitten") == 3

    def test_generate_typosquat_candidates(self):
        """Verify candidate generation produces expected variations."""
        detector = SupplyChainAttackDetector()
        candidates = detector._generate_typosquat_candidates("requests")

        # Should generate a non-empty list
        assert len(candidates) > 0

        # Should not include the original name
        assert "requests" not in candidates

        # Should include common variations
        assert "reqeusts" in candidates  # transposition
        assert "request" in candidates  # deletion
        assert "equests" in candidates  # deletion (first char)
        assert "requestss" in candidates  # insertion

        # Hyphen/underscore swap
        assert "requests" not in candidates  # original excluded

    def test_detect_dependency_confusion(self):
        """Detect dependency confusion for generic/internal package names."""
        detector = SupplyChainAttackDetector()

        dep_file = self._make_dep_file([
            Dependency(name="utils", version="1.0.0", ecosystem=Ecosystem.PYTHON),
            Dependency(name="core", version="2.0.0", ecosystem=Ecosystem.PYTHON),
        ])

        indicators = detector.detect_dependency_confusion([dep_file])

        assert len(indicators) > 0
        types = {ind.attack_type for ind in indicators}
        assert AttackType.DEPENDENCY_CONFUSION in types

        names_flagged = {ind.dependency.name for ind in indicators}
        assert "utils" in names_flagged
        assert "core" in names_flagged

    def test_detect_suspicious_versions(self):
        """Detect suspicious version patterns."""
        detector = SupplyChainAttackDetector()

        dep_file = self._make_dep_file([
            # Very high version number
            Dependency(name="bad-pkg", version="9999.0.0", ecosystem=Ecosystem.PYTHON, is_dev=False),
            # Date-based version
            Dependency(name="date-pkg", version="2024.01.15", ecosystem=Ecosystem.PYTHON, is_dev=False),
            # All zeros
            Dependency(name="zero-pkg", version="0.0.0", ecosystem=Ecosystem.PYTHON, is_dev=False),
            # Pre-release in production
            Dependency(name="pre-pkg", version="1.0.0-alpha", ecosystem=Ecosystem.PYTHON, is_dev=False),
            # Normal version (should not be flagged)
            Dependency(name="good-pkg", version="2.31.0", ecosystem=Ecosystem.PYTHON, is_dev=False),
        ])

        indicators = detector.detect_suspicious_versions([dep_file])

        flagged_names = {ind.dependency.name for ind in indicators}
        assert "bad-pkg" in flagged_names
        assert "date-pkg" in flagged_names
        assert "zero-pkg" in flagged_names
        assert "pre-pkg" in flagged_names
        assert "good-pkg" not in flagged_names

    def test_no_false_positives_safe_packages(self):
        """Safe, well-known packages should not produce false positive indicators."""
        detector = SupplyChainAttackDetector()

        dep_file = self._make_dep_file([
            Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYTHON),
            Dependency(name="numpy", version="1.24.0", ecosystem=Ecosystem.PYTHON),
            Dependency(name="lodash", version="4.17.21", ecosystem=Ecosystem.JAVASCRIPT),
            Dependency(name="express", version="4.18.0", ecosystem=Ecosystem.JAVASCRIPT),
        ])

        # Run all detection checks
        indicators = detector.scan([dep_file])

        # No typosquatting should be detected for exact popular package names
        typosquat = [i for i in indicators if i.attack_type == AttackType.TYPOSQUATTING]
        assert len(typosquat) == 0, (
            f"Popular packages should not be flagged as typosquatting, but got: "
            f"{[i.title for i in typosquat]}"
        )

        # No dependency confusion for well-named packages
        confusion = [i for i in indicators if i.attack_type == AttackType.DEPENDENCY_CONFUSION]
        assert len(confusion) == 0, (
            f"Well-named packages should not trigger dependency confusion, but got: "
            f"{[i.title for i in confusion]}"
        )

        # No suspicious versions for normal versions
        suspicious = [i for i in indicators if i.attack_type == AttackType.SUSPICIOUS_VERSION]
        assert len(suspicious) == 0, (
            f"Normal versions should not be flagged, but got: "
            f"{[i.title for i in suspicious]}"
        )


# ======================================================================
# 4. CVEMatcher Tests
# ======================================================================


class TestCVEMatcher:
    """Tests for CVEMatcher covering version comparison, normalization,
    version range matching, and CVSS severity mapping."""

    def test_version_comparison(self):
        """Test semantic version comparison logic."""
        matcher = CVEMatcher()

        # Equal versions
        assert matcher._compare_versions("1.0.0", "1.0.0") == 0
        assert matcher._compare_versions("1.0", "1.0.0") == 0

        # Less than
        assert matcher._compare_versions("1.0.0", "2.0.0") == -1
        assert matcher._compare_versions("1.1.0", "1.2.0") == -1
        assert matcher._compare_versions("1.0.1", "1.0.2") == -1

        # Greater than
        assert matcher._compare_versions("2.0.0", "1.0.0") == 1
        assert matcher._compare_versions("1.2.0", "1.1.0") == 1

        # Pre-release handling: _normalize_version strips pre-release suffixes,
        # so "1.0.0-alpha" normalizes to (1,0,0) which equals "1.0.0"
        assert matcher._compare_versions("1.0.0", "1.0.0-alpha") == 0
        assert matcher._compare_versions("1.0.0-beta", "1.0.0") == 0

        # v-prefix stripping
        assert matcher._compare_versions("v1.0.0", "1.0.0") == 0
        assert matcher._compare_versions("V2.0.0", "2.0.0") == 0

    def test_normalize_version(self):
        """Test version string normalization."""
        matcher = CVEMatcher()

        assert matcher._normalize_version("1.2.3") == (1, 2, 3)
        assert matcher._normalize_version("v1.2.3") == (1, 2, 3)
        assert matcher._normalize_version("V1.2.3") == (1, 2, 3)
        assert matcher._normalize_version("1.2.3-alpha") == (1, 2, 3)
        assert matcher._normalize_version("1.2.3+build") == (1, 2, 3)
        assert matcher._normalize_version("1.2") == (1, 2)
        assert matcher._normalize_version("1") == (1,)
        assert matcher._normalize_version("") == (0,)
        assert matcher._normalize_version("0.0.0") == (0, 0, 0)

    def test_version_affected(self):
        """Test version range matching."""
        matcher = CVEMatcher()

        # Simple equality
        assert matcher._version_affected("1.0.0", "=1.0.0") is True
        assert matcher._version_affected("1.0.0", "=2.0.0") is False

        # Greater than / less than
        assert matcher._version_affected("2.0.0", ">=1.0.0") is True
        assert matcher._version_affected("0.9.0", ">=1.0.0") is False
        assert matcher._version_affected("1.5.0", "<2.0.0") is True
        assert matcher._version_affected("2.0.0", "<2.0.0") is False

        # Compound range (comma-separated AND logic)
        assert matcher._version_affected("1.5.0", ">=1.0.0,<2.0.0") is True
        assert matcher._version_affected("2.0.0", ">=1.0.0,<2.0.0") is False
        assert matcher._version_affected("0.9.0", ">=1.0.0,<2.0.0") is False

        # Empty / None inputs
        assert matcher._version_affected("", ">=1.0.0") is False
        assert matcher._version_affected("1.0.0", "") is False

        # Caret range
        assert matcher._version_affected("1.5.0", "^1.2.3") is True
        assert matcher._version_affected("2.0.0", "^1.2.3") is False
        assert matcher._version_affected("1.2.3", "^1.2.3") is True
        assert matcher._version_affected("1.2.2", "^1.2.3") is False

        # Tilde range
        assert matcher._version_affected("1.2.5", "~1.2.3") is True
        assert matcher._version_affected("1.3.0", "~1.2.3") is False
        assert matcher._version_affected("1.2.2", "~1.2.3") is False

    def test_severity_from_cvss(self):
        """Test CVSS score to SeverityLevel mapping."""
        matcher = CVEMatcher()

        assert matcher._severity_from_cvss(10.0) == SeverityLevel.CRITICAL
        assert matcher._severity_from_cvss(9.0) == SeverityLevel.CRITICAL
        assert matcher._severity_from_cvss(9.5) == SeverityLevel.CRITICAL

        assert matcher._severity_from_cvss(8.9) == SeverityLevel.HIGH
        assert matcher._severity_from_cvss(7.0) == SeverityLevel.HIGH
        assert matcher._severity_from_cvss(7.5) == SeverityLevel.HIGH

        assert matcher._severity_from_cvss(6.9) == SeverityLevel.MEDIUM
        assert matcher._severity_from_cvss(4.0) == SeverityLevel.MEDIUM
        assert matcher._severity_from_cvss(5.5) == SeverityLevel.MEDIUM

        assert matcher._severity_from_cvss(3.9) == SeverityLevel.LOW
        assert matcher._severity_from_cvss(0.1) == SeverityLevel.LOW
        assert matcher._severity_from_cvss(1.0) == SeverityLevel.LOW

        assert matcher._severity_from_cvss(0.0) == SeverityLevel.INFO

    def test_match_single_with_mock_osv(self):
        """Test match_single with mocked OSV API (no network)."""
        matcher = CVEMatcher()

        dep = Dependency(
            name="requests",
            version="2.28.0",
            resolved_version="2.28.0",
            ecosystem=Ecosystem.PYTHON,
        )

        mock_osv_response = {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2023-44487"],
                    "summary": "HTTP/2 Rapid Reset Attack",
                    "details": "A vulnerability in HTTP/2",
                    "severity": [],
                    "affected": [
                        {
                            "package": {"name": "requests", "ecosystem": "PyPI"},
                            "versions": ["2.28.0"],
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.31.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                    "references": [],
                }
            ]
        }

        with patch.object(matcher, "query_osv", new_callable=AsyncMock) as mock_osv, \
             patch.object(matcher, "query_nvd", new_callable=AsyncMock, return_value=[]):
            mock_osv.return_value = matcher._parse_osv_response(mock_osv_response)

            matches = asyncio.get_event_loop().run_until_complete(
                matcher.match_single(dep)
            )

            assert len(matches) >= 1
            cve_match = matches[0]
            assert cve_match.dependency.name == "requests"
            assert cve_match.is_affected is True
            assert "CVE-2023-44487" in (cve_match.vulnerability.cve_id or "")


# ======================================================================
# 5. SupplyChainAnalyzer Tests
# ======================================================================


class TestSupplyChainAnalyzer:
    """Tests for SupplyChainAnalyzer covering registration, analysis flow,
    and disabled state."""

    def test_analyzer_registration(self):
        """Analyzer should register correctly with expected attributes."""
        with patch.dict(os.environ, {"SUPPLY_CHAIN_ENABLED": "true"}):
            analyzer = SupplyChainAnalyzer()
            assert analyzer.name == "supply_chain"
            assert "python" in analyzer.supported_languages
            assert "javascript" in analyzer.supported_languages
            assert "java" in analyzer.supported_languages
            assert "go" in analyzer.supported_languages
            assert "rust" in analyzer.supported_languages
            assert "php" in analyzer.supported_languages
            assert "ruby" in analyzer.supported_languages
            assert analyzer.is_available() is True

    def test_analyzer_with_mock_code_units(self, tmp_path):
        """Test the full analysis flow using mock CodeUnits and a temp project dir."""
        # Create a requirements.txt in tmp_path
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nnumpy>=1.24.0\n"
        )

        with patch.dict(os.environ, {
            "SUPPLY_CHAIN_ENABLED": "true",
            "SUPPLY_CHAIN_CVE_MATCH": "false",  # disable CVE matching (no network)
            "SUPPLY_CHAIN_ATTACK_DETECT": "true",
            "SUPPLY_CHAIN_SBOM_GENERATE": "true",
            "SUPPLY_CHAIN_PROJECT_DIR": str(tmp_path),
        }):
            analyzer = SupplyChainAnalyzer()

            # Create mock CodeUnit with absolute_path metadata
            from audit_core.models import CodeUnit
            code_unit = CodeUnit(
                path="test.py",
                language="python",
                content="import requests",
                metadata={"absolute_path": str(tmp_path / "test.py")},
            )

            findings = analyzer.analyze([code_unit])

            # Should produce findings (at minimum from attack detection
            # since we have well-known packages, but should not crash)
            assert isinstance(findings, list)

            # Verify scan result was stored
            result = analyzer.get_last_scan_result()
            assert result is not None
            assert isinstance(result, SupplyChainScanResult)
            assert result.total_dependencies >= 2
            assert "python" in result.ecosystems

    def test_analyzer_disabled(self):
        """When disabled, analyzer should return empty findings."""
        with patch.dict(os.environ, {"SUPPLY_CHAIN_ENABLED": "false"}):
            analyzer = SupplyChainAnalyzer()
            assert analyzer.is_available() is False

            from audit_core.models import CodeUnit
            code_unit = CodeUnit(
                path="test.py",
                language="python",
                content="import requests",
                metadata={"absolute_path": "/tmp/test.py"},
            )

            findings = analyzer.analyze([code_unit])
            assert findings == []
