"""
SBOM (Software Bill of Materials) Generator.

Generates standards-compliant SBOM documents in CycloneDX and SPDX formats.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from supply_chain.models import (
    Dependency, DependencyFile, Ecosystem, SBOMComponent, SBOMDocument,
)

logger = logging.getLogger(__name__)


# purl ecosystem prefix mapping
PURL_ECOSYSTEM_MAP = {
    Ecosystem.PYTHON: "pypi",
    Ecosystem.JAVASCRIPT: "npm",
    Ecosystem.TYPESCRIPT: "npm",
    Ecosystem.JAVA: "maven",
    Ecosystem.GO: "golang",
    Ecosystem.RUST: "cargo",
    Ecosystem.PHP: "composer",
    Ecosystem.RUBY: "gem",
    Ecosystem.DOTNET: "nuget",
    Ecosystem.C: "",
    Ecosystem.CPP: "",
    Ecosystem.UNKNOWN: "",
}


class SBOMGenerator:
    """Generates SBOM documents from dependency data."""

    def __init__(self, project_name: str = "", project_version: str = "0.0.0"):
        self.project_name = project_name
        self.project_version = project_version

    def generate(
        self,
        dependency_files: List[DependencyFile],
        format_name: str = "cyclonedx",
    ) -> SBOMDocument:
        """Generate SBOM from parsed dependency files.

        Args:
            dependency_files: List of parsed dependency files
            format_name: 'cyclonedx' or 'spdx'

        Returns:
            SBOMDocument instance
        """
        components = self._to_components(dependency_files)

        fmt_label = "CycloneDX" if format_name == "cyclonedx" else "SPDX"
        fmt_version = "1.5" if format_name == "cyclonedx" else "2.3"

        sbom = SBOMDocument(
            format_name=fmt_label,
            format_version=fmt_version,
            name=self.project_name,
            version=self.project_version,
            components=components,
            total_components=len(components),
        )
        logger.info(
            "Generated %s SBOM with %d components for project '%s'",
            fmt_label,
            len(components),
            self.project_name,
        )
        return sbom

    def _to_components(
        self, dependency_files: List[DependencyFile]
    ) -> List[SBOMComponent]:
        """Convert dependencies to SBOM components."""
        components: List[SBOMComponent] = []
        seen: set = set()

        for dep_file in dependency_files:
            for dep in dep_file.dependencies:
                key = (dep.name, dep.resolved_version or dep.version)
                if key in seen:
                    continue
                seen.add(key)
                components.append(self._dep_to_component(dep))

        return components

    def _dep_to_component(self, dep: Dependency) -> SBOMComponent:
        """Convert a single Dependency to SBOMComponent."""
        purl = self._build_purl(dep)
        version = dep.resolved_version or dep.version or "0.0.0"

        return SBOMComponent(
            type="library",
            name=dep.name,
            version=version,
            purl=purl,
            ecosystem=dep.ecosystem,
            scope=dep.scope,
            license_name=dep.license_name,
            description=dep.description,
            homepage=dep.homepage,
        )

    def _build_purl(self, dep: Dependency) -> Optional[str]:
        """Build Package URL (purl) for a dependency.

        Format: pkg:<type>/<namespace>/<name>@<version>
        Examples:
          pkg:pypi/requests@2.31.0
          pkg:npm/lodash@4.17.21
          pkg:maven/org.apache.struts/struts2-core@2.5.33
          pkg:golang/github.com/gin-gonic/gin@1.9.1
          pkg:nuget/Newtonsoft.Json@13.0.3
          pkg:cargo/serde@1.0.195
          pkg:gem/rails@7.1.0
          pkg:composer/laravel/framework@10.40.0
        """
        purl_type = PURL_ECOSYSTEM_MAP.get(dep.ecosystem, "")
        if not purl_type:
            return None

        version = dep.resolved_version or dep.version
        name = dep.name

        # For Java (Maven), split namespace/name if present
        if dep.ecosystem == Ecosystem.JAVA and "/" in name:
            namespace, artifact = name.rsplit("/", 1)
            if version:
                return f"pkg:maven/{namespace}/{artifact}@{version}"
            return f"pkg:maven/{namespace}/{artifact}"

        # For Go, PHP, Ruby – names may contain a namespace prefix
        if dep.ecosystem in (Ecosystem.GO, Ecosystem.PHP, Ecosystem.RUBY):
            if "/" in name:
                namespace, artifact = name.rsplit("/", 1)
                if version:
                    return f"pkg:{purl_type}/{namespace}/{artifact}@{version}"
                return f"pkg:{purl_type}/{namespace}/{artifact}"

        if version:
            return f"pkg:{purl_type}/{name}@{version}"
        return f"pkg:{purl_type}/{name}"

    # ------------------------------------------------------------------
    # CycloneDX 1.5 JSON
    # ------------------------------------------------------------------

    def to_cyclonedx_json(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Convert SBOMDocument to CycloneDX 1.5 JSON format.

        Must produce valid CycloneDX JSON with:
        - $schema: http://cyclonedx.org/schema/bom-1.5.schema.json
        - bomFormat: CycloneDX
        - specVersion: "1.5"
        - metadata (with component for the project itself)
        - components list
        """
        bom_serial_number = f"urn:uuid:{uuid.uuid4()}"

        # Build the root metadata component (the project itself)
        metadata_component: Dict[str, Any] = {
            "type": "application",
            "name": sbom.name or "unknown-project",
            "version": sbom.version,
        }

        metadata: Dict[str, Any] = {
            "timestamp": sbom.generated_at,
            "component": metadata_component,
            "tools": [
                {
                    "type": "application",
                    "name": sbom.tool_name,
                    "version": sbom.tool_version,
                }
            ],
        }

        # Build components list
        components: List[Dict[str, Any]] = []
        for comp in sbom.components:
            cdx_comp: Dict[str, Any] = {
                "type": "library",
                "name": comp.name,
                "version": comp.version,
            }

            if comp.purl:
                cdx_comp["purl"] = comp.purl

            if comp.description:
                cdx_comp["description"] = comp.description

            # Scope mapping to CycloneDX scope values
            scope_map = {
                "required": "required",
                "optional": "optional",
                "production": "required",
                "development": "optional",
                "test": "optional",
                "peer": "required",
                "bundled": "required",
                "unknown": "required",
            }
            scope_value = scope_map.get(comp.scope.value, "required")
            cdx_comp["scope"] = scope_value

            # Licenses
            if comp.license_name:
                cdx_comp["licenses"] = [
                    {
                        "license": {
                            "id": comp.license_name,
                        }
                    }
                ]

            # External references (homepage)
            if comp.homepage:
                cdx_comp.setdefault("externalReferences", []).append(
                    {
                        "type": "website",
                        "url": comp.homepage,
                    }
                )

            # Hashes
            if comp.hashes:
                cdx_comp["hashes"] = [
                    {"alg": alg, "content": hash_val}
                    for alg, hash_val in comp.hashes.items()
                ]

            components.append(cdx_comp)

        bom: Dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": bom_serial_number,
            "version": 1,
            "metadata": metadata,
            "components": components,
        }

        return bom

    # ------------------------------------------------------------------
    # SPDX 2.3 JSON
    # ------------------------------------------------------------------

    def to_spdx_json(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Convert SBOMDocument to SPDX 2.3 JSON format.

        Must produce valid SPDX JSON with:
        - spdxVersion: "SPDX-2.3"
        - dataLicense: "CC0-1.0"
        - name, documentNamespace
        - packages list (each with name, versionInfo, licenseConcluded, externalRefs)
        """
        document_namespace = f"urn:uuid:{uuid.uuid4()}"

        packages: List[Dict[str, Any]] = []
        for comp in sbom.components:
            spdx_pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-Package-{comp.name.replace('/', '-').replace('.', '-')}-{comp.version.replace('.', '-')}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
            }

            # License
            if comp.license_name:
                spdx_pkg["licenseConcluded"] = comp.license_name
                spdx_pkg["licenseDeclared"] = comp.license_name
            else:
                spdx_pkg["licenseConcluded"] = "NOASSERTION"
                spdx_pkg["licenseDeclared"] = "NOASSERTION"

            # Description
            if comp.description:
                spdx_pkg["description"] = comp.description

            # Homepage
            if comp.homepage:
                spdx_pkg["homepage"] = comp.homepage

            # External references (purl)
            external_refs: List[Dict[str, Any]] = []
            if comp.purl:
                external_refs.append(
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl,
                    }
                )

            # Homepage as external reference
            if comp.homepage:
                external_refs.append(
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "other",
                        "referenceLocator": comp.homepage,
                        "comment": "Project homepage",
                    }
                )

            if external_refs:
                spdx_pkg["externalRefs"] = external_refs

            # CPE
            if comp.cpe:
                spdx_pkg["externalRefs"].append(
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": comp.cpe,
                    }
                )

            packages.append(spdx_pkg)

        # Build relationships
        relationships: List[Dict[str, Any]] = []
        doc_spdx_id = "SPDXRef-DOCUMENT"
        for pkg in packages:
            relationships.append(
                {
                    "spdxElementId": doc_spdx_id,
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": pkg["SPDXID"],
                }
            )

        document: Dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_spdx_id,
            "name": sbom.name or "unknown-project",
            "documentNamespace": document_namespace,
            "documentDescribes": [pkg["SPDXID"] for pkg in packages],
            "creationInfo": {
                "created": sbom.generated_at,
                "tool": [f"{sbom.tool_name}-{sbom.tool_version}"],
                "comment": "Generated by VulnPatch SupplyChain Analyzer",
            },
            "packages": packages,
            "relationships": relationships,
        }

        return document

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_json_string(
        self, sbom: SBOMDocument, format_name: str = "cyclonedx"
    ) -> str:
        """Serialize SBOM to JSON string."""
        if format_name == "spdx":
            data = self.to_spdx_json(sbom)
        else:
            data = self.to_cyclonedx_json(sbom)

        return json.dumps(data, indent=2, ensure_ascii=False)

    def save_to_file(
        self,
        sbom: SBOMDocument,
        file_path: str,
        format_name: str = "cyclonedx",
    ) -> None:
        """Save SBOM to a JSON file."""
        content = self.to_json_string(sbom, format_name)
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        logger.info("SBOM saved to %s (format: %s)", file_path, format_name)
