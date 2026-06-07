"""
Tests for C/C++ pattern analyzer.

Verifies detection of:
- Buffer Overflow
- Format String
- Command Injection
- Memory Leak
- Race Condition (TOCTOU)
"""

import pytest
from audit_core.models import CodeUnit, RawFinding
from analyzers.c_cpp.c_pattern_analyzer import CPatternAnalyzer


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

BUFFER_OVERFLOW_CODE = '''
#include <string.h>

void copy_data(char *dest, char *src) {
    strcpy(dest, src);
    strcat(dest, "extra");
    gets(dest);
    sprintf(dest, "Value: %s", src);
}
'''

FORMAT_STRING_CODE = '''
#include <stdio.h>

void print_message(char *fmt, char *arg) {
    printf(fmt, arg);
    printf(user_format);
}
'''

COMMAND_INJECTION_CODE = '''
#include <stdlib.h>

void run_command(char *cmd) {
    system(cmd);
    popen(cmd, "r");
}
'''

MEMORY_LEAK_CODE = '''
#include <stdlib.h>

void allocate_memory() {
    char *buffer = malloc(1024);
    char *data = malloc(512);
    // No free() calls
}
'''

TOCTOU_CODE = '''
#include <unistd.h>
#include <fcntl.h>

void check_and_open(char *path) {
    if (access(path, R_OK) == 0) {
        int fd = open(path, O_RDONLY);
        // Race condition between access and open
    }
}
'''

CLEAN_CODE = '''
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

void safe_copy(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
}
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.c", lang: str = "c") -> CodeUnit:
    return CodeUnit(path=path, language=lang, content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerBasic:

    def test_analyzer_name(self):
        assert CPatternAnalyzer().name == "c_pattern"

    def test_supported_languages(self):
        analyzer = CPatternAnalyzer()
        assert "c" in analyzer.supported_languages
        assert "cpp" in analyzer.supported_languages

    def test_skips_non_c(self):
        analyzer = CPatternAnalyzer()
        unit = CodeUnit(path="test.py", language="python", content="eval(code)", start_line=1)
        results = analyzer.analyze([unit])
        assert results == []

    def test_empty_code_units(self):
        analyzer = CPatternAnalyzer()
        results = analyzer.analyze([])
        assert results == []

    def test_clean_code_no_findings(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        results = analyzer.analyze([unit])
        # strncpy is safe, so no findings
        assert len(results) == 0


class TestCPatternAnalyzerBufferOverflow:

    def test_detects_strcpy(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) > 0

        finding = bof_findings[0]
        assert finding.cwe == "CWE-120"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"

    def test_detects_multiple_dangerous_funcs(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        symbols = [f.evidence.get("symbol") for f in results if "Buffer Overflow" in f.type]
        assert "strcpy" in symbols
        assert "strcat" in symbols
        assert "gets" in symbols

    def test_detects_sprintf(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        sprintf_findings = [f for f in results if f.evidence.get("symbol") == "sprintf"]
        assert len(sprintf_findings) > 0


class TestCPatternAnalyzerFormatString:

    def test_detects_format_string(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(FORMAT_STRING_CODE)
        results = analyzer.analyze([unit])

        fmt_findings = [f for f in results if "Format String" in f.type]
        assert len(fmt_findings) > 0

        finding = fmt_findings[0]
        assert finding.cwe == "CWE-134"
        assert finding.severity == "ERROR"


class TestCPatternAnalyzerCommandInjection:

    def test_detects_system(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) > 0

        finding = cmd_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.severity == "ERROR"

    def test_detects_popen(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        popen_findings = [f for f in results if f.evidence.get("symbol") == "popen"]
        assert len(popen_findings) > 0


class TestCPatternAnalyzerMemoryLeak:

    def test_detects_memory_leak(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(MEMORY_LEAK_CODE)
        results = analyzer.analyze([unit])

        leak_findings = [f for f in results if "Memory Leak" in f.type]
        assert len(leak_findings) > 0

        finding = leak_findings[0]
        assert finding.cwe == "CWE-401"
        assert finding.severity == "WARN"
        assert finding.confidence == "low"


class TestCPatternAnalyzerTOCTOU:

    def test_detects_toctou(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(TOCTOU_CODE)
        results = analyzer.analyze([unit])

        toctou_findings = [f for f in results if "TOCTOU" in f.type or "Race Condition" in f.type]
        assert len(toctou_findings) > 0

        finding = toctou_findings[0]
        assert finding.cwe == "CWE-367"
        assert finding.severity == "WARN"


class TestCPatternAnalyzerCpp:

    def test_analyzes_cpp(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE, path="test.cpp", lang="cpp")
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) > 0


class TestCPatternAnalyzerFindingFormat:

    def test_findings_are_raw_finding(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        for finding in results:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.engine == "c_pattern"

    def test_file_path_preserved(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE, path="src/utils/strings.c")
        results = analyzer.analyze([unit])

        for finding in results:
            assert finding.file_path == "src/utils/strings.c"