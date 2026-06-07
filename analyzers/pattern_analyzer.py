"""
Pattern-based analyzer for detecting common vulnerabilities.

Uses regex patterns to detect issues like SQL injection, path traversal,
and privilege escalation.
"""

import re
from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class PatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities.
    
    Currently supports:
    - SQL Injection (f-string and % formatting in execute calls)
    - Path Traversal (open with request args)
    - Privilege Escalation (missing auth decorators on admin routes)
    """
    
    name = "pattern"
    supported_languages = ["python", "javascript", "typescript", "java", "php"]
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        # f-string in execute: execute(f"SELECT ... {var}")
        (r'\.execute\s*\(\s*f["\']', "SQL Injection", "CWE-89", "ERROR",
         "Possible SQL injection via f-string in SQL execution."),
        # % formatting in execute: execute("SELECT ... %s" % var)
        (r'\.execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']\s*%', "SQL Injection", "CWE-89", "ERROR",
         "Possible SQL injection via string formatting in SQL execution."),
        # .format() in execute
        (r'\.execute\s*\([^)]*\.format\s*\(', "SQL Injection", "CWE-89", "ERROR",
         "Possible SQL injection via format() in SQL execution."),
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        # open(request.args.get(...))
        (r'open\s*\(\s*request\.(args|form|json)\.get', "Path Traversal", "CWE-22", "WARN",
         "Possible path traversal via user-controlled input in file open."),
        # open with request directly
        (r'open\s*\(\s*request\.', "Path Traversal", "CWE-22", "WARN",
         "Possible path traversal via request data in file open."),
    ]
    
    # Privilege Escalation patterns (simplified)
    PRIVILEGE_PATTERNS = [
        # @app.route("/admin") without @login_required
        (r'@app\.route\s*\(\s*["\'][^"\']*admin[^"\']*["\']\s*\)', "Privilege Escalation", "CWE-269", "INFO",
         "Admin route detected. Verify authentication is enforced."),
    ]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze code units using regex patterns.
        
        Args:
            code_units: List of code units to analyze
            
        Returns:
            List of RawFinding objects for detected vulnerabilities
        """
        findings = []
        
        for unit in code_units:
            # Skip non-Python files for now (can be extended)
            if unit.language != "python":
                continue
            
            findings.extend(self._analyze_sql_injection(unit))
            findings.extend(self._analyze_path_traversal(unit))
            findings.extend(self._analyze_privilege_escalation(unit))
        
        return findings
    
    def _analyze_sql_injection(self, unit: CodeUnit) -> list[RawFinding]:
        """Analyze for SQL injection vulnerabilities."""
        findings = []
        lines = unit.content.split("\n")
        
        for i, line in enumerate(lines, start=1):
            for pattern, vuln_type, cwe, severity, message in self.SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(RawFinding(
                        rule_id=f"PATTERN_{vuln_type.upper().replace(' ', '_')}_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity=severity,
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + i - 1,
                        message=message,
                        engine=self.name,
                        evidence={
                            "matched_line": line.strip(),
                            "pattern": pattern
                        }
                    ))
        
        return findings
    
    def _analyze_path_traversal(self, unit: CodeUnit) -> list[RawFinding]:
        """Analyze for path traversal vulnerabilities."""
        findings = []
        lines = unit.content.split("\n")
        
        for i, line in enumerate(lines, start=1):
            for pattern, vuln_type, cwe, severity, message in self.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(RawFinding(
                        rule_id=f"PATTERN_{vuln_type.upper().replace(' ', '_')}_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity=severity,
                        confidence="medium",
                        file_path=unit.path,
                        start_line=unit.start_line + i - 1,
                        message=message,
                        engine=self.name,
                        evidence={
                            "matched_line": line.strip(),
                            "pattern": pattern
                        }
                    ))
        
        return findings
    
    def _analyze_privilege_escalation(self, unit: CodeUnit) -> list[RawFinding]:
        """Analyze for privilege escalation vulnerabilities."""
        findings = []
        lines = unit.content.split("\n")
        
        for i, line in enumerate(lines, start=1):
            for pattern, vuln_type, cwe, severity, message in self.PRIVILEGE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if next few lines have login_required
                    context = "\n".join(lines[i:i+5])
                    if "login_required" not in context and "admin_required" not in context:
                        findings.append(RawFinding(
                            rule_id=f"PATTERN_{vuln_type.upper().replace(' ', '_')}_001",
                            type=vuln_type,
                            cwe=cwe,
                            severity=severity,
                            confidence="low",
                            file_path=unit.path,
                            start_line=unit.start_line + i - 1,
                            message=message,
                            engine=self.name,
                            evidence={
                                "matched_line": line.strip(),
                                "pattern": pattern
                            }
                        ))
        
        return findings
