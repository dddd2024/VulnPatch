"""
JavaScript/TypeScript pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like XSS, eval usage, command injection,
and SQL injection in JavaScript and TypeScript code.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class JSPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in JavaScript/TypeScript.
    
    Detects:
    - Cross-Site Scripting (XSS) via innerHTML/outerHTML assignment
    - XSS via Express response sinks with user input
    - Code Injection via eval() / Function()
    - Command Injection via exec() / spawn()
    - SQL Injection via query() with string concatenation
    - Prototype Pollution via Object.assign / lodash merge/extend
    - Path Traversal via fs operations with user input
    - Hardcoded Secrets / Credentials
    - Server-Side Request Forgery (SSRF)
    - Insecure CORS Configuration
    - Regular Expression Denial of Service (ReDoS)
    - Unsafe Deserialization
    """
    
    name = "js_pattern"
    supported_languages = ["javascript", "typescript"]
    
    # XSS patterns
    XSS_HTML_PATTERNS = [
        (r'\.\s*(innerHTML|outerHTML)\s*=', "Cross-Site Scripting (XSS)", "CWE-79",
         "medium", "Potential XSS: HTML assignment with unsanitized content"),
    ]
    
    # Express XSS source pattern
    EXPRESS_XSS_SOURCE = re.compile(r'req(?:uest)?\.(?:query|body|params)', re.IGNORECASE)
    
    # Eval patterns
    EVAL_PATTERNS = [
        (r'\b(eval|Function)\s*\(', "Code Injection / Eval Usage", "CWE-95",
         "medium", "Dangerous dynamic code execution"),
    ]
    
    # Command Injection patterns
    COMMAND_PATTERNS = [
        (r'\b(exec|execSync|execFileSync|spawn|spawnSync)\s*\(', "Command Injection", "CWE-78",
         "medium", "Potential command injection"),
    ]
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        (r'\.(query|execute|raw|sql)\s*\(', "SQL Injection", "CWE-89",
         "medium", "Potential SQL injection with string concatenation"),
    ]
    
    # Prototype Pollution patterns
    PROTO_POLLUTION_PATTERNS = [
        (r'\bObject\.assign\s*\(', "Prototype Pollution", "CWE-1321",
         "medium", "Object.assign() with potentially unsafe source"),
        (r'_\.\s*(merge|extend|deepMerge|defaultsDeep)\s*\(', "Prototype Pollution", "CWE-1321",
         "medium", "Lodash merge/extend with potentially unsafe source"),
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r'\bfs\.\s*(readFile|writeFile|readFileSync|writeFileSync|open|openSync|unlink|unlinkSync|mkdir|mkdirSync|readdir|readdirSync|stat|statSync|createReadStream|createWriteStream)\s*\(',
         "Path Traversal", "CWE-22",
         "medium", "File system operation with potentially user-controlled path"),
    ]
    
    # Hardcoded Secrets patterns
    HARDCODED_SECRETS_PATTERNS = [
        (r'\b(?:password|passwd|pwd|secret|api_key|apikey|apiSecret|access_key|secret_key|private_key|auth_token|bearer_token|token)\s*=\s*["\'][^"\']{4,}["\']',
         "Hardcoded Secret", "CWE-798",
         "high", "Hardcoded secret/credential detected"),
    ]
    
    # SSRF patterns
    SSRF_PATTERNS = [
        (r'\b(?:axios|got|needle|superagent|request|fetch|http\.get|https\.get|http\.request|https\.request)\s*\(\s*',
         "Server-Side Request Forgery (SSRF)", "CWE-918",
         "medium", "HTTP request with potentially user-controlled URL"),
    ]
    
    # Insecure CORS patterns
    INSECURE_CORS_PATTERNS = [
        (r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*["\']?',
         "Insecure CORS Configuration", "CWE-942",
         "high", "CORS origin set to wildcard '*'"),
        (r'["\']Access-Control-Allow-Origin["\']\s*:\s*["\']\*["\']',
         "Insecure CORS Configuration", "CWE-942",
         "high", "Access-Control-Allow-Origin header set to wildcard '*'"),
    ]
    
    # ReDoS patterns
    REDOS_PATTERNS = [
        (r'\b(?:new\s+)?RegExp\s*\(\s*(?:req(?:uest)?\.(?:query|body|params|headers)|userInput|input|params|data)',
         "Regular Expression Denial of Service (ReDoS)", "CWE-1333",
         "medium", "RegExp constructed with user-controlled input"),
    ]
    
    # Unsafe Deserialization patterns
    UNSAFE_DESERIALIZATION_PATTERNS = [
        (r'\b(?:unserialize|serialize|node-serialize|deserialize)\s*\(',
         "Unsafe Deserialization", "CWE-502",
         "high", "Unsafe deserialization of untrusted data"),
    ]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze JavaScript/TypeScript code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language not in ("javascript", "typescript"):
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # XSS: innerHTML / outerHTML
            findings.extend(self._detect_xss_html(unit, source, lines))
            
            # XSS: Express response sinks
            findings.extend(self._detect_xss_express(unit, source, lines))
            
            # Eval usage
            findings.extend(self._detect_eval(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # SQL Injection
            findings.extend(self._detect_sql_injection(unit, source, lines))
            
            # Prototype Pollution
            findings.extend(self._detect_proto_pollution(unit, source, lines))
            
            # Path Traversal
            findings.extend(self._detect_path_traversal(unit, source, lines))
            
            # Hardcoded Secrets
            findings.extend(self._detect_hardcoded_secrets(unit, source, lines))
            
            # SSRF
            findings.extend(self._detect_ssrf(unit, source, lines))
            
            # Insecure CORS
            findings.extend(self._detect_insecure_cors(unit, source, lines))
            
            # ReDoS
            findings.extend(self._detect_redos(unit, source, lines))
            
            # Unsafe Deserialization
            findings.extend(self._detect_unsafe_deserialization(unit, source, lines))
        
        return findings
    
    def _detect_xss_html(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XSS via innerHTML/outerHTML assignment."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.XSS_HTML_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id=f"JS_XSS_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_xss_express(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XSS via Express response sinks with user input."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\bres\.\s*(send|write|end|render)\s*\(', source):
            sink_name = f"res.{m.group(1)}"
            
            # Check context for user input
            ctx_start = max(0, m.start() - 300)
            ctx_end = min(len(source), m.end() + 100)
            ctx = source[ctx_start:ctx_end]
            
            has_user_input = bool(self.EXPRESS_XSS_SOURCE.search(ctx))
            has_concat = '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx)
            
            if has_user_input or has_concat:
                line_num = source[:m.start()].count("\n") + 1
                confidence = "high" if has_user_input else "medium"
                findings.append(RawFinding(
                    rule_id="JS_XSS_002",
                    type="Cross-Site Scripting (XSS)",
                    cwe="CWE-79",
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Express XSS: {sink_name}() with {'user input' if has_user_input else 'string concatenation'}",
                    engine=self.name,
                    evidence={
                        "symbol": sink_name,
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_eval(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect eval() / Function() usage."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.EVAL_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_EVAL_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{message}: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via exec/spawn."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.COMMAND_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_CMD_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{message}: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_sql_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SQL injection via query() with concatenation."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.SQL_PATTERNS:
            for m in re.finditer(pattern, source):
                # Check context for string concatenation
                ctx = source[max(0, m.start() - 100):m.end() + 100]
                if '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx):
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="JS_SQL_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity="ERROR",
                        confidence=confidence,
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"{message}: {m.group(1)}()",
                        engine=self.name,
                        evidence={
                            "symbol": m.group(1),
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_proto_pollution(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect prototype pollution via Object.assign or lodash merge/extend."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.PROTO_POLLUTION_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_PP_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_path_traversal(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect path traversal via fs operations with user input."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.PATH_TRAVERSAL_PATTERNS:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                has_user_input = bool(self.EXPRESS_XSS_SOURCE.search(ctx))
                has_concat = '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx)
                
                if has_user_input or has_concat:
                    line_num = source[:m.start()].count("\n") + 1
                    confidence_level = "high" if has_user_input else "medium"
                    findings.append(RawFinding(
                        rule_id="JS_PT_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity="ERROR",
                        confidence=confidence_level,
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"{message} with {'user input' if has_user_input else 'string concatenation'}",
                        engine=self.name,
                        evidence={
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_hardcoded_secrets(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect hardcoded secrets/credentials in source code."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.HARDCODED_SECRETS_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_HS_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_ssrf(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SSRF via HTTP client calls with user-controlled URL."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.SSRF_PATTERNS:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                has_user_input = bool(self.EXPRESS_XSS_SOURCE.search(ctx))
                has_concat = '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx)
                
                if has_user_input or has_concat:
                    line_num = source[:m.start()].count("\n") + 1
                    confidence_level = "high" if has_user_input else "medium"
                    findings.append(RawFinding(
                        rule_id="JS_SSRF_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity="ERROR",
                        confidence=confidence_level,
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"{message} with {'user input' if has_user_input else 'string concatenation'}",
                        engine=self.name,
                        evidence={
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_insecure_cors(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect insecure CORS configuration with wildcard origin."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.INSECURE_CORS_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_CORS_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_redos(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect ReDoS via RegExp constructed with user input."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.REDOS_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_REDOS_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_unsafe_deserialization(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect unsafe deserialization of untrusted data."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.UNSAFE_DESERIALIZATION_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_DESER_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings