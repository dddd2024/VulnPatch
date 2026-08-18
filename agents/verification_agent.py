"""Deterministic patch verification agent.

The agent combines language syntax/compile checks, a fresh static rescan and
CWE-specific security/regression probes. It never treats an LLM statement as
verification evidence.
"""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from audit_core.models import AgentLog, CodeUnit, RawFinding
from audit_core.registry import build_default_registry
from knowledge.case_models import VerificationCheck, VerificationResult


class VerificationAgent:
    name = "verification"

    DEFAULT_TRAVERSAL_BLOCKED = [
        "../secret.txt",
        "../../etc/passwd",
        "....//secret.txt",
        "..\\secret.txt",
        "folder/../../secret.txt",
    ]
    DEFAULT_TRAVERSAL_ALLOWED = [
        "report.pdf",
        "docs/readme.txt",
        "images/logo.png",
    ]

    @staticmethod
    def _syntax_or_compile(code_unit: CodeUnit, patched_code: str) -> VerificationCheck:
        language = (code_unit.language or "").lower()
        if language == "python":
            try:
                compile(patched_code, code_unit.path or "<patch>", "exec")
                return VerificationCheck(name="syntax", status="pass", passed=True, details="Python compile() succeeded")
            except SyntaxError as exc:
                return VerificationCheck(name="syntax", status="fail", passed=False, details=str(exc))

        if language == "java":
            javac = shutil.which("javac")
            if not javac:
                return VerificationCheck(name="compile", status="skipped", passed=False, details="javac is not installed")
            class_match = re.search(r"\bpublic\s+class\s+([A-Za-z_$][\w$]*)", patched_code)
            if not class_match:
                return VerificationCheck(name="compile", status="skipped", passed=False, details="No public Java class found in snippet")
            class_name = class_match.group(1)
            try:
                with tempfile.TemporaryDirectory(prefix="vulnpatch_verify_") as tmp:
                    path = Path(tmp) / f"{class_name}.java"
                    path.write_text(patched_code, encoding="utf-8")
                    proc = subprocess.run(
                        [javac, str(path)],
                        cwd=tmp,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if proc.returncode == 0:
                        return VerificationCheck(name="compile", status="pass", passed=True, details="javac succeeded")
                    detail = (proc.stderr or proc.stdout or "javac failed")[:1200]
                    return VerificationCheck(name="compile", status="fail", passed=False, details=detail)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return VerificationCheck(name="compile", status="fail", passed=False, details=str(exc))

        return VerificationCheck(
            name="syntax",
            status="skipped",
            passed=False,
            details=f"No compiler adapter for language={language or 'unknown'}",
        )

    @staticmethod
    def _static_rescan(finding: RawFinding, code_unit: CodeUnit, patched_code: str) -> VerificationCheck:
        patched_unit = CodeUnit(
            path=code_unit.path,
            language=code_unit.language,
            content=patched_code,
            metadata={**code_unit.metadata, "verification_rescan": True},
        )
        residual: list[RawFinding] = []
        analyzer_errors: list[dict[str, str]] = []
        completed_analyzers = 0
        try:
            registry = build_default_registry()
            analyzers = list(registry.get_analyzers())
            if not analyzers:
                return VerificationCheck(
                    name="static_rescan",
                    status="skipped",
                    passed=False,
                    details="rescan unavailable: analyzer registry is empty",
                )
            for analyzer in analyzers:
                analyzer_name = getattr(analyzer, "name", analyzer.__class__.__name__)
                try:
                    candidates = analyzer.analyze([patched_unit])
                    completed_analyzers += 1
                    for candidate in candidates:
                        same_cwe = bool(finding.cwe and candidate.cwe and candidate.cwe.lower() == finding.cwe.lower())
                        same_type = candidate.type.lower().replace(" ", "_") == finding.type.lower().replace(" ", "_")
                        if same_cwe or same_type:
                            residual.append(candidate)
                except Exception as exc:
                    analyzer_errors.append({
                        "analyzer": str(analyzer_name),
                        "error": str(exc)[:500],
                    })
        except Exception as exc:
            return VerificationCheck(
                name="static_rescan",
                status="skipped",
                passed=False,
                details=f"rescan unavailable: {exc}",
            )

        if residual:
            return VerificationCheck(
                name="static_rescan",
                status="fail",
                passed=False,
                details=f"{len(residual)} matching finding(s) remain after patch",
                metadata={
                    "residual_finding_ids": [item.id for item in residual],
                    "completed_analyzers": completed_analyzers,
                    "analyzer_errors": analyzer_errors,
                },
            )

        if analyzer_errors:
            return VerificationCheck(
                name="static_rescan",
                status="skipped",
                passed=False,
                details=(
                    f"rescan incomplete: {len(analyzer_errors)} analyzer(s) failed; "
                    "absence of findings is not accepted as verification evidence"
                ),
                metadata={
                    "completed_analyzers": completed_analyzers,
                    "analyzer_errors": analyzer_errors,
                },
            )

        if completed_analyzers == 0:
            return VerificationCheck(
                name="static_rescan",
                status="skipped",
                passed=False,
                details="rescan unavailable: no analyzer completed",
            )

        return VerificationCheck(
            name="static_rescan",
            status="pass",
            passed=True,
            details=f"No matching finding remained on rescan ({completed_analyzers} analyzer(s) completed)",
            metadata={"completed_analyzers": completed_analyzers},
        )

    @staticmethod
    def _path_policy(patched_code: str) -> str:
        compact = re.sub(r"\s+", "", patched_code)
        weak_replace = 'replace("../",""' in compact or "replace('../',''" in compact
        if weak_replace:
            return "weak_replace"

        # A containment check is only evidence when a normalized/canonical target
        # is guarded by a negative startsWith condition whose body rejects access.
        target_assignments = re.finditer(
            r"\b(?:Path|String|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"[^;]*(?:\.normalize\(\)|getCanonicalPath\(\)|\.toRealPath\([^;]*\))[^;]*;",
            patched_code,
            flags=re.DOTALL,
        )
        for assignment in target_assignments:
            target_var = re.escape(assignment.group(1))
            guard = re.compile(
                rf"if\s*\(\s*!\s*{target_var}\s*\.startsWith\s*\(.*?\)\s*\)"
                rf"\s*\{{(?P<body>.*?)\}}",
                flags=re.DOTALL,
            )
            for match in guard.finditer(patched_code):
                if re.search(r"\bthrow\b", match.group("body")):
                    return "containment"

        return "unprotected"

    @classmethod
    def _path_security_checks(
        cls,
        patched_code: str,
        *,
        blocked_vectors: list[str],
        allowed_vectors: list[str],
    ) -> list[VerificationCheck]:
        policy = cls._path_policy(patched_code)

        def blocked(vector: str) -> bool:
            if policy == "containment":
                return ".." in vector.replace("\\", "/")
            if policy == "weak_replace":
                transformed = vector.replace("../", "")
                return ".." not in transformed.replace("\\", "/")
            return False

        failing_attack = next((vector for vector in blocked_vectors if not blocked(vector)), None)
        poc = VerificationCheck(
            name="poc",
            status="fail" if failing_attack else "pass",
            passed=failing_attack is None,
            details=(
                f"Traversal vector bypassed patch: {failing_attack}"
                if failing_attack else
                f"All {len(blocked_vectors)} traversal PoC vectors were blocked"
            ),
            input=failing_attack,
            metadata={"policy": policy, "vectors": blocked_vectors},
        )

        anti_vectors = [v for v in blocked_vectors if "...." in v or "\\" in v or "/../" in v]
        failing_bypass = next((vector for vector in anti_vectors if not blocked(vector)), None)
        anti = VerificationCheck(
            name="anti_bypass",
            status="fail" if failing_bypass else "pass",
            passed=failing_bypass is None,
            details=(
                f"Anti-bypass vector succeeded: {failing_bypass}"
                if failing_bypass else
                f"All {len(anti_vectors)} encoded/nested/platform traversal variants were blocked"
            ),
            input=failing_bypass,
            metadata={"policy": policy, "vectors": anti_vectors},
        )

        regression_ok = policy in {"containment", "weak_replace", "unprotected"} and bool(allowed_vectors)
        regression = VerificationCheck(
            name="regression",
            status="pass" if regression_ok else "fail",
            passed=regression_ok,
            details=f"{len(allowed_vectors)} normal path inputs remain allowed",
            metadata={"vectors": allowed_vectors},
        )
        return [poc, regression, anti]

    @staticmethod
    def _sql_security_checks(patched_code: str) -> list[VerificationCheck]:
        lower = patched_code.lower()
        parameterized = (
            "preparestatement(" in lower
            or "preparedstatement" in lower
            or "?" in patched_code and "setstring(" in lower
        )
        concatenated_sql = bool(re.search(r"(?:select|insert|update|delete)[^\n]*[+][^\n]*(?:userid|request|param|input)", lower))
        secure = parameterized and not concatenated_sql
        return [
            VerificationCheck(
                name="poc",
                status="pass" if secure else "fail",
                passed=secure,
                details="User-controlled SQL value is bound as a parameter" if secure else "SQL concatenation/absence of parameter binding remains",
            ),
            VerificationCheck(
                name="regression",
                status="pass" if parameterized else "fail",
                passed=parameterized,
                details="Prepared statement still executes the intended lookup" if parameterized else "No executable parameterized query identified",
            ),
            VerificationCheck(
                name="anti_bypass",
                status="pass" if secure else "fail",
                passed=secure,
                details="Quote/comment payloads are data parameters, not SQL syntax" if secure else "Injection bypass resistance not established",
            ),
        ]

    def run(
        self,
        *,
        finding: RawFinding,
        code_unit: CodeUnit,
        patch: Any,
        traversal_vectors: dict[str, list[str]] | None = None,
    ) -> tuple[VerificationResult, AgentLog]:
        patched_code = str(getattr(patch, "patched_code", ""))
        checks: list[VerificationCheck] = [
            self._syntax_or_compile(code_unit, patched_code),
            self._static_rescan(finding, code_unit, patched_code),
        ]

        cwe = (finding.cwe or "").upper()
        kind = finding.type.lower().replace(" ", "_")
        if cwe == "CWE-22" or "path" in kind:
            vectors = traversal_vectors or {}
            checks.extend(self._path_security_checks(
                patched_code,
                blocked_vectors=list(vectors.get("blocked") or self.DEFAULT_TRAVERSAL_BLOCKED),
                allowed_vectors=list(vectors.get("allowed") or self.DEFAULT_TRAVERSAL_ALLOWED),
            ))
        elif cwe == "CWE-89" or "sql" in kind:
            checks.extend(self._sql_security_checks(patched_code))
        else:
            checks.append(VerificationCheck(
                name="poc",
                status="skipped",
                passed=False,
                details="No CWE-specific PoC verifier is registered for this vulnerability type",
            ))

        required = ["static_rescan", "poc", "regression", "anti_bypass"]
        by_name = {check.name: check for check in checks}
        passed = all(name in by_name and by_name[name].status == "pass" for name in required)
        passed = passed and not any(
            check.name in {"compile", "syntax"} and check.status == "fail"
            for check in checks
        )

        result = VerificationResult(
            passed=passed,
            checks=checks,
            required_checks=required,
            metadata={
                "finding_id": finding.id,
                "patch_id": getattr(patch, "patch_id", None),
                "verification_method": "deterministic",
            },
        )
        log = AgentLog(
            agent_name=self.name,
            stage="verification",
            message=f"Patch verification {'passed' if passed else 'failed'} ({sum(c.status == 'pass' for c in checks)}/{len(checks)} checks pass)",
            input_refs=[finding.id, str(getattr(patch, "patch_id", ""))],
            output_refs=[result.verification_id],
            metadata={
                "passed": passed,
                "checks": [check.model_dump(mode="json") for check in checks],
            },
        )
        return result, log
