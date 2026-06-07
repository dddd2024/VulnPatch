"""
C/C++ pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like buffer overflow, format string,
command injection, memory leak, and race conditions.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class CPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in C/C++.
    
    Detects:
    - Buffer Overflow via strcpy/strcat/gets/sprintf
    - Format String via printf with user-controlled format
    - Command Injection via system/popen
    - Memory Leak via malloc without free
    - Race Condition (TOCTOU) via access followed by open
    - Integer Overflow via int multiplication/addition without overflow check
    - Use-After-Free via free(ptr) followed by ptr usage
    - Double Free via multiple free() on same pointer
    - Insecure Random via rand()/srand() usage
    - Hardcoded Secrets via password/secret/key/token string literals
    """
    
    name = "c_pattern"
    supported_languages = ["c", "cpp"]
    
    # Dangerous functions for buffer overflow
    DANGEROUS_FUNCS = {
        "strcpy": "Buffer Overflow",
        "strcat": "Buffer Overflow",
        "gets": "Buffer Overflow",
        "sprintf": "Buffer Overflow",
        "vsprintf": "Buffer Overflow",
        "scanf": "Buffer Overflow",
    }
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze C/C++ code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language not in ("c", "cpp"):
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # Buffer Overflow
            findings.extend(self._detect_buffer_overflow(unit, source, lines))
            
            # Format String
            findings.extend(self._detect_format_string(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # Memory Leak
            findings.extend(self._detect_memory_leak(unit, source, lines))
            
            # Race Condition (TOCTOU)
            findings.extend(self._detect_toctou(unit, source, lines))
            
            # Integer Overflow
            findings.extend(self._detect_integer_overflow(unit, source, lines))
            
            # Use-After-Free
            findings.extend(self._detect_use_after_free(unit, source, lines))
            
            # Double Free
            findings.extend(self._detect_double_free(unit, source, lines))
            
            # Insecure Random
            findings.extend(self._detect_insecure_random(unit, source, lines))
            
            # Hardcoded Secrets
            findings.extend(self._detect_hardcoded_secrets(unit, source, lines))
        
        return findings
    
    def _detect_buffer_overflow(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect buffer overflow via dangerous functions."""
        findings: list[RawFinding] = []
        
        for func_name, vuln_type in self.DANGEROUS_FUNCS.items():
            for m in re.finditer(r'\b' + re.escape(func_name) + r'\s*\(', source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="C_BOF_001",
                    type=vuln_type,
                    cwe="CWE-120",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Use of unsafe function {func_name}() - potential buffer overflow",
                    engine=self.name,
                    evidence={
                        "symbol": func_name,
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_format_string(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect format string vulnerability via printf with variable format."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\bprintf\s*\(\s*(?!")(\w+)', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_FMT_001",
                type="Format String Vulnerability",
                cwe="CWE-134",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="printf with potentially user-controlled format string",
                engine=self.name,
                evidence={
                    "symbol": "printf",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via system/popen."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\b(system|popen)\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_CMD_001",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Use of {m.group(1)}() with potential user input",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_memory_leak(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential memory leak via malloc without free."""
        findings: list[RawFinding] = []
        
        # Find all malloc assignments
        alloc_vars: set[str] = set()
        for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
            alloc_vars.add(m.group(1))
        
        # Find all free calls
        free_vars: set[str] = set()
        for m in re.finditer(r'free\s*\(\s*(\w+)', source):
            free_vars.add(m.group(1))
        
        # Report variables that are allocated but not freed
        for var in alloc_vars - free_vars:
            for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
                if m.group(1) == var:
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="C_MEM_001",
                        type="Memory Leak",
                        cwe="CWE-401",
                        severity="WARN",
                        confidence="low",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Variable {var} allocated but not freed",
                        engine=self.name,
                        evidence={
                            "symbol": "malloc",
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
                    break
        
        return findings
    
    def _detect_toctou(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect race condition (TOCTOU) via access followed by open."""
        findings: list[RawFinding] = []
        
        for i, line in enumerate(lines):
            if re.search(r'\baccess\s*\(', line):
                # Check next 10 lines for open()
                for j in range(i + 1, min(i + 10, len(lines))):
                    if re.search(r'\bopen\s*\(', lines[j]):
                        findings.append(RawFinding(
                            rule_id="C_TOCTOU_001",
                            type="Race Condition (TOCTOU)",
                            cwe="CWE-367",
                            severity="WARN",
                            confidence="medium",
                            file_path=unit.path,
                            start_line=unit.start_line + j + 1,
                            message="Time-of-check to time-of-use (TOCTOU) race condition",
                            engine=self.name,
                            evidence={
                                "symbol": "access/open",
                                "matched_line": lines[j].strip(),
                            }
                        ))
                        break
        
        return findings
    
    def _detect_integer_overflow(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect integer overflow via int multiplication/addition without overflow check."""
        findings: list[RawFinding] = []
        
        # Match int variable declarations
        int_vars: set[str] = set()
        for m in re.finditer(r'\bint\s+(\w+)\s*[;=]', source):
            int_vars.add(m.group(1))
        
        # Match unsigned int variable declarations
        for m in re.finditer(r'\bunsigned\s+int\s+(\w+)\s*[;=]', source):
            int_vars.add(m.group(1))
        
        if not int_vars:
            return findings
        
        # Check for multiplication or addition between int variables without overflow guards
        var_pattern = '|'.join(re.escape(v) for v in int_vars)
        for m in re.finditer(
            r'(?<!\w)(' + var_pattern + r')\s*\*\s*(' + var_pattern + r')(?!\s*[;&|])',
            source
        ):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_IOF_001",
                type="Integer Overflow",
                cwe="CWE-190",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Integer multiplication between '{m.group(1)}' and '{m.group(2)}' without overflow check",
                engine=self.name,
                evidence={
                    "symbol": "*",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        for m in re.finditer(
            r'(?<!\w)(' + var_pattern + r')\s*\+\s*(' + var_pattern + r')(?!\s*[;&|])',
            source
        ):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_IOF_002",
                type="Integer Overflow",
                cwe="CWE-190",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Integer addition between '{m.group(1)}' and '{m.group(2)}' without overflow check",
                engine=self.name,
                evidence={
                    "symbol": "+",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_use_after_free(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect use-after-free via free(ptr) followed by continued use of ptr."""
        findings: list[RawFinding] = []
        
        # Find all free(ptr) calls and their line numbers
        free_events: list[tuple[str, int]] = []
        for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', source):
            ptr_name = m.group(1)
            line_num = source[:m.start()].count("\n") + 1
            free_events.append((ptr_name, line_num))
        
        # For each free event, check if the pointer is used in subsequent lines
        for ptr_name, free_line in free_events:
            for i in range(free_line, len(lines)):
                if i < free_line:
                    continue
                line = lines[i]
                # Skip the free line itself and NULL/0 assignments (safe patterns)
                if i == free_line - 1:
                    continue
                if re.search(r'\b' + re.escape(ptr_name) + r'\s*=\s*(NULL|0|nullptr)\s*;', line):
                    break  # Pointer set to NULL after free - safe
                # Check if pointer is used (dereferenced, passed to function, etc.)
                if re.search(r'\b' + re.escape(ptr_name) + r'\b', line):
                    # Exclude comments
                    stripped = line.lstrip()
                    if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                        continue
                    findings.append(RawFinding(
                        rule_id="C_UAF_001",
                        type="Use-After-Free",
                        cwe="CWE-416",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + i,
                        message=f"Pointer '{ptr_name}' used after being freed at line {free_line}",
                        engine=self.name,
                        evidence={
                            "symbol": ptr_name,
                            "matched_line": line.strip(),
                        }
                    ))
                    break  # Only report once per free event
        
        return findings
    
    def _detect_double_free(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect double free via multiple free() calls on the same pointer."""
        findings: list[RawFinding] = []
        
        # Find all free(ptr) calls with their line numbers
        free_calls: dict[str, list[int]] = {}
        for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', source):
            ptr_name = m.group(1)
            line_num = source[:m.start()].count("\n") + 1
            if ptr_name not in free_calls:
                free_calls[ptr_name] = []
            free_calls[ptr_name].append(line_num)
        
        # Report pointers freed more than once
        for ptr_name, line_nums in free_calls.items():
            if len(line_nums) > 1:
                for line_num in line_nums[1:]:  # Report subsequent frees
                    findings.append(RawFinding(
                        rule_id="C_DFR_001",
                        type="Double Free",
                        cwe="CWE-415",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Pointer '{ptr_name}' freed again at line {line_num} (previously freed at line {line_nums[0]})",
                        engine=self.name,
                        evidence={
                            "symbol": "free",
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings
    
    def _detect_insecure_random(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect insecure random number generation via rand()/srand()."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\b(rand|srand)\s*\(', source):
            func_name = m.group(1)
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_IRND_001",
                type="Insecure Random",
                cwe="CWE-330",
                severity="WARN",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Use of insecure {func_name}() - use a cryptographically secure RNG instead",
                engine=self.name,
                evidence={
                    "symbol": func_name,
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_hardcoded_secrets(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect hardcoded secrets via password/secret/key/token string literals."""
        findings: list[RawFinding] = []
        
        secret_pattern = re.compile(
            r'\b(password|passwd|secret|api_key|apikey|access_key|secret_key|token|auth_token)\s*'
            r'=\s*"([^"]+)"',
            re.IGNORECASE
        )
        
        for m in secret_pattern.finditer(source):
            field_name = m.group(1)
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_SEC_001",
                type="Hardcoded Secret",
                cwe="CWE-798",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Hardcoded secret detected: '{field_name}' is assigned a string literal",
                engine=self.name,
                evidence={
                    "symbol": field_name,
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings