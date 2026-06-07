"""
Java pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like SQL injection, command injection,
path traversal, XXE, insecure deserialization, hardcoded secrets, SSRF,
insecure random, LDAP injection, Spring Security misconfiguration,
unsafe reflection, log injection, and JWT issues.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class JavaPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in Java.
    
    Detects:
    - SQL Injection via executeQuery/executeUpdate with string concatenation
    - Command Injection via Runtime.exec / ProcessBuilder
    - Path Traversal via new File(user input)
    - XXE via DocumentBuilderFactory without secure config
    - Insecure Deserialization via ObjectInputStream.readObject
    - Hardcoded Secrets
    - SSRF via HttpURLConnection/RestTemplate/WebClient/OkHttpClient/URL with user input
    - Path Traversal (extended) via FileInputStream/FileOutputStream/FileReader/FileWriter
    - Insecure Random via new Random() / Math.random() in security contexts
    - LDAP Injection via searchControls/DirContext.search with user input
    - Spring Security Misconfiguration via csrf disable / permitAll
    - Unsafe Reflection via Class.forName / getMethod with user input
    - Log Injection via logger with unescaped user input
    - JWT Issues via missing signature verification / weak signing key
    """
    
    name = "java_pattern"
    supported_languages = ["java"]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze Java code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language != "java":
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # SQL Injection
            findings.extend(self._detect_sql_injection(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # Path Traversal
            findings.extend(self._detect_path_traversal(unit, source, lines))
            
            # XXE
            findings.extend(self._detect_xxe(unit, source, lines))
            
            # Insecure Deserialization
            findings.extend(self._detect_deserialization(unit, source, lines))
            
            # Hardcoded Secrets
            findings.extend(self._detect_hardcoded_secret(unit, source, lines))
            
            # SSRF
            findings.extend(self._detect_ssrf(unit, source, lines))
            
            # Path Traversal (extended)
            findings.extend(self._detect_path_traversal_extended(unit, source, lines))
            
            # Insecure Random
            findings.extend(self._detect_insecure_random(unit, source, lines))
            
            # LDAP Injection
            findings.extend(self._detect_ldap_injection(unit, source, lines))
            
            # Spring Security Misconfiguration
            findings.extend(self._detect_spring_security_misconfig(unit, source, lines))
            
            # Unsafe Reflection
            findings.extend(self._detect_unsafe_reflection(unit, source, lines))
            
            # Log Injection
            findings.extend(self._detect_log_injection(unit, source, lines))
            
            # JWT Issues
            findings.extend(self._detect_jwt_issues(unit, source, lines))
        
        return findings
    
    def _detect_sql_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SQL injection via executeQuery with string concatenation."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'(executeQuery|executeUpdate|execute)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 50]
            if '+' in ctx and any(kw in ctx.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SQL_001",
                    type="SQL Injection",
                    cwe="CWE-89",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"SQL query uses string concatenation: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via Runtime.exec / ProcessBuilder."""
        findings: list[RawFinding] = []
        
        # Runtime.exec pattern 1: direct call
        for m in re.finditer(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_CMD_001",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="Command execution via Runtime.exec with potential user input",
                engine=self.name,
                evidence={
                    "symbol": "Runtime.exec",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        # Runtime.exec pattern 2: getRuntime followed by exec
        for m in re.finditer(r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)', source):
            ctx = source[m.start():m.end() + 300]
            if re.search(r'\.\s*exec\s*\(', ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_CMD_002",
                    type="Command Injection",
                    cwe="CWE-78",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="Command execution via Runtime.exec with potential user input",
                    engine=self.name,
                    evidence={
                        "symbol": "Runtime.exec",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # ProcessBuilder
        for m in re.finditer(r'ProcessBuilder\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_CMD_003",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="ProcessBuilder with potential user input",
                engine=self.name,
                evidence={
                    "symbol": "ProcessBuilder",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_path_traversal(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect path traversal via new File(user input)."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'new\s+File\s*\(', source):
            ctx = source[max(0, m.start() - 50):m.end() + 100]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_PT_001",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="File operation with user-controlled path parameter",
                    engine=self.name,
                    evidence={
                        "symbol": "File",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_xxe(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XXE via DocumentBuilderFactory without secure config."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)', source):
            ctx = source[m.start():m.end() + 500]
            secure_keywords = ["disallow-doctype-decl", "setFeature", "secure-processing", "setXIncludeAware"]
            if not any(kw in ctx for kw in secure_keywords):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_XXE_001",
                    type="XML External Entity (XXE)",
                    cwe="CWE-611",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="XML parser without secure configuration (external entities enabled)",
                    engine=self.name,
                    evidence={
                        "symbol": "DocumentBuilderFactory",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_deserialization(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect insecure deserialization via ObjectInputStream.readObject."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'ObjectInputStream', source):
            ctx = source[m.start():m.start() + 300]
            if "readObject" in ctx:
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_DESER_001",
                    type="Insecure Deserialization",
                    cwe="CWE-502",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="ObjectInputStream.readObject() without type filtering (RCE risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "ObjectInputStream",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_hardcoded_secret(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect hardcoded secrets."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'(password|secret|token|api_key|apikey)\s*=\s*"[^"]{4,}"', source, re.IGNORECASE):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_SECRET_001",
                type="Hardcoded Secret",
                cwe="CWE-798",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Hardcoded secret detected: {m.group(1)}",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_ssrf(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SSRF via HttpURLConnection/RestTemplate/WebClient/OkHttpClient/URL with user-controlled URL."""
        findings: list[RawFinding] = []
        
        ssrf_patterns = [
            r'(HttpURLConnection|RestTemplate|WebClient|OkHttpClient)\s*[\.\(]',
            r'new\s+URL\s*\(',
        ]
        user_input_indicators = [
            "getParameter", "getHeader", "PathVariable", "RequestParam",
            "RequestBody", "request", "url", "uri", "target", "dest",
        ]
        
        for pattern in ssrf_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                if any(ind in ctx for ind in user_input_indicators):
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="JAVA_SSRF_001",
                        type="Server-Side Request Forgery (SSRF)",
                        cwe="CWE-918",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Potential SSRF: {m.group(1) if m.lastindex else m.group(0)} with user-controlled URL",
                        engine=self.name,
                        evidence={
                            "symbol": m.group(1) if m.lastindex else m.group(0),
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_path_traversal_extended(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect path traversal via FileInputStream/FileOutputStream/FileReader/FileWriter with user input."""
        findings: list[RawFinding] = []
        
        io_patterns = [
            r'new\s+FileInputStream\s*\(',
            r'new\s+FileOutputStream\s*\(',
            r'new\s+FileReader\s*\(',
            r'new\s+FileWriter\s*\(',
        ]
        user_input_indicators = [
            "getParameter", "getHeader", "PathVariable", "RequestParam",
            "RequestBody", "request", "filename", "filepath", "path",
        ]
        
        for pattern in io_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                if any(ind in ctx for ind in user_input_indicators):
                    line_num = source[:m.start()].count("\n") + 1
                    symbol = re.search(r'File\w+', pattern).group(0)
                    findings.append(RawFinding(
                        rule_id="JAVA_PT_002",
                        type="Path Traversal (extended)",
                        cwe="CWE-22",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"File I/O operation with user-controlled path: {symbol}",
                        engine=self.name,
                        evidence={
                            "symbol": symbol,
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_insecure_random(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect insecure random via new Random() / Math.random() in security contexts."""
        findings: list[RawFinding] = []
        
        insecure_random_patterns = [
            r'new\s+Random\s*\(\s*\)',
            r'Math\s*\.\s*random\s*\(\s*\)',
        ]
        security_context_keywords = [
            "password", "token", "secret", "key", "salt", "nonce",
            "session", "csrf", "captcha", "otp", "auth",
            "encrypt", "decrypt", "hash", "signature", "certificate",
        ]
        
        for pattern in insecure_random_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 300):m.end() + 300]
                if any(kw in ctx.lower() for kw in security_context_keywords):
                    line_num = source[:m.start()].count("\n") + 1
                    symbol = m.group(0).strip()
                    findings.append(RawFinding(
                        rule_id="JAVA_RAND_001",
                        type="Insecure Random",
                        cwe="CWE-330",
                        severity="WARN",
                        confidence="medium",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Insecure random generator in security context: {symbol}",
                        engine=self.name,
                        evidence={
                            "symbol": symbol,
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_ldap_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect LDAP injection via searchControls/DirContext.search with user input concatenation."""
        findings: list[RawFinding] = []
        
        ldap_patterns = [
            r'(searchControls|SearchControls)',
            r'DirContext\s*\.\s*search\s*\(',
            r'\.search\s*\(\s*"[^"]*"\s*,',
        ]
        user_input_indicators = [
            "getParameter", "getHeader", "PathVariable", "RequestParam",
            "RequestBody", "request", "username", "uid", "cn", "dn",
        ]
        
        for pattern in ldap_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                if any(ind in ctx for ind in user_input_indicators) and '+' in ctx:
                    line_num = source[:m.start()].count("\n") + 1
                    symbol = m.group(1) if m.lastindex else m.group(0)
                    findings.append(RawFinding(
                        rule_id="JAVA_LDAP_001",
                        type="LDAP Injection",
                        cwe="CWE-90",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"LDAP query with user input concatenation: {symbol}",
                        engine=self.name,
                        evidence={
                            "symbol": symbol,
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_spring_security_misconfig(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect Spring Security misconfiguration via csrf disable / permitAll."""
        findings: list[RawFinding] = []
        
        misconfig_patterns = [
            (r'\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)', "JAVA_SEC_001",
             "CSRF protection disabled", "ERROR"),
            (r'\.authorizeRequests\s*\(\s*\)\s*\.\s*anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)',
             "JAVA_SEC_002", "All requests permitted without authentication", "WARN"),
        ]
        
        for pattern, rule_id, message, severity in misconfig_patterns:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id=rule_id,
                    type="Spring Security Misconfiguration",
                    cwe="CWE-942",
                    severity=severity,
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "symbol": m.group(0).strip(),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_unsafe_reflection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect unsafe reflection via Class.forName / getMethod with user input."""
        findings: list[RawFinding] = []
        
        reflection_patterns = [
            r'Class\s*\.\s*forName\s*\(',
            r'\.getMethod\s*\(',
            r'\.getDeclaredMethod\s*\(',
            r'\.newInstance\s*\(',
        ]
        user_input_indicators = [
            "getParameter", "getHeader", "PathVariable", "RequestParam",
            "RequestBody", "request", "className", "methodName", "input",
        ]
        
        for pattern in reflection_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                if any(ind in ctx for ind in user_input_indicators):
                    line_num = source[:m.start()].count("\n") + 1
                    symbol = m.group(0).strip()
                    findings.append(RawFinding(
                        rule_id="JAVA_REFL_001",
                        type="Unsafe Reflection",
                        cwe="CWE-470",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Unsafe reflection with user-controlled input: {symbol}",
                        engine=self.name,
                        evidence={
                            "symbol": symbol,
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_log_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect log injection via logger with unescaped user input."""
        findings: list[RawFinding] = []
        
        log_patterns = [
            r'(?:logger|log)\s*\.\s*(info|warn|error|debug|trace)\s*\(',
        ]
        user_input_indicators = [
            "getParameter", "getHeader", "PathVariable", "RequestParam",
            "RequestBody", "request", "username", "input",
        ]
        escape_indicators = [
            "replace", "sanitize", "escape", "clean", "filter", "encode",
        ]
        
        for pattern in log_patterns:
            for m in re.finditer(pattern, source):
                ctx = source[max(0, m.start() - 200):m.end() + 200]
                if any(ind in ctx for ind in user_input_indicators):
                    if not any(esc in ctx for esc in escape_indicators):
                        line_num = source[:m.start()].count("\n") + 1
                        symbol = m.group(1) if m.lastindex else m.group(0)
                        findings.append(RawFinding(
                            rule_id="JAVA_LOG_001",
                            type="Log Injection",
                            cwe="CWE-117",
                            severity="INFO",
                            confidence="low",
                            file_path=unit.path,
                            start_line=unit.start_line + line_num - 1,
                            message=f"User input logged without escaping: logger.{symbol}()",
                            engine=self.name,
                            evidence={
                                "symbol": f"logger.{symbol}",
                                "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                            }
                        ))
        
        return findings
    
    def _detect_jwt_issues(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect JWT issues: missing signature verification or weak signing key."""
        findings: list[RawFinding] = []
        
        # Jwts.builder() without sign / setSigningKey
        for m in re.finditer(r'Jwts\s*\.\s*builder\s*\(\s*\)', source):
            ctx = source[m.start():m.start() + 500]
            if not re.search(r'\.\s*sign', ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_JWT_001",
                    type="JWT Issues",
                    cwe="CWE-327",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="JWT token built without signature (Jwts.builder without sign)",
                    engine=self.name,
                    evidence={
                        "symbol": "Jwts.builder",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # setSigningKey with hardcoded string
        for m in re.finditer(r'setSigningKey\s*\(\s*"[^"]+"\s*\)', source):
            line_num = source[:m.start()].count("\n") + 1
            key_value = re.search(r'"([^"]+)"', m.group(0)).group(1)
            findings.append(RawFinding(
                rule_id="JAVA_JWT_002",
                type="JWT Issues",
                cwe="CWE-327",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"JWT signing key is a hardcoded string: setSigningKey(\"{key_value}\")",
                engine=self.name,
                evidence={
                    "symbol": "setSigningKey",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings