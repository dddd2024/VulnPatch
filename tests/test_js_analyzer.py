"""
Tests for JavaScript/TypeScript pattern analyzer.

Verifies detection of:
- XSS via innerHTML/outerHTML
- XSS via Express response sinks
- Eval usage
- Command Injection
- SQL Injection
"""

import pytest
from audit_core.models import CodeUnit, RawFinding
from analyzers.javascript.js_pattern_analyzer import JSPatternAnalyzer


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

XSS_HTML_CODE = '''
document.getElementById("output").innerHTML = userInput;
document.body.outerHTML = "<div>" + data + "</div>";
'''

XSS_EXPRESS_CODE = '''
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    res.send(req.query.content);
    res.render('template', { data: req.body.data });
});
'''

EVAL_CODE = '''
function runCode(code) {
    eval(code);
    new Function(code)();
}
'''

COMMAND_INJECTION_CODE = '''
const { exec, spawn } = require('child_process');

function run(cmd) {
    exec(cmd, (err, stdout, stderr) => { console.log(stdout); });
    spawn('ls', [userInput]);
}
'''

SQL_INJECTION_CODE = '''
const mysql = require('mysql');
const connection = mysql.createConnection({ host: 'localhost' });

function search(name) {
    connection.query('SELECT * FROM users WHERE name = "' + name + '"');
}
'''

CLEAN_CODE = '''
function add(a, b) {
    return a + b;
}

const greet = (name) => `Hello, ${name}!`;
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.js", lang: str = "javascript") -> CodeUnit:
    return CodeUnit(path=path, language=lang, content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJSPatternAnalyzerBasic:

    def test_analyzer_name(self):
        assert JSPatternAnalyzer().name == "js_pattern"

    def test_supported_languages(self):
        analyzer = JSPatternAnalyzer()
        assert "javascript" in analyzer.supported_languages
        assert "typescript" in analyzer.supported_languages

    def test_skips_non_js(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit("eval(code)", lang="python")
        results = analyzer.analyze([unit])
        assert results == []

    def test_empty_code_units(self):
        analyzer = JSPatternAnalyzer()
        results = analyzer.analyze([])
        assert results == []

    def test_clean_code_no_findings(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        results = analyzer.analyze([unit])
        assert len(results) == 0


class TestJSPatternAnalyzerXSS:

    def test_detects_innerHTML_xss(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(XSS_HTML_CODE)
        results = analyzer.analyze([unit])

        xss_findings = [f for f in results if "XSS" in f.type]
        assert len(xss_findings) > 0

        finding = xss_findings[0]
        assert finding.cwe == "CWE-79"
        assert finding.severity == "ERROR"
        assert finding.evidence.get("symbol") in ("innerHTML", "outerHTML")

    def test_detects_express_xss_with_user_input(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(XSS_EXPRESS_CODE)
        results = analyzer.analyze([unit])

        xss_findings = [f for f in results if "XSS" in f.type]
        assert len(xss_findings) > 0

        # Should have high confidence for req.query/req.body
        high_conf = [f for f in xss_findings if f.confidence == "high"]
        assert len(high_conf) > 0


class TestJSPatternAnalyzerEval:

    def test_detects_eval_usage(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(EVAL_CODE)
        results = analyzer.analyze([unit])

        eval_findings = [f for f in results if "Eval" in f.type or "Code Injection" in f.type]
        assert len(eval_findings) > 0

        finding = eval_findings[0]
        assert finding.cwe == "CWE-95"
        assert finding.evidence.get("symbol") in ("eval", "Function")


class TestJSPatternAnalyzerCommandInjection:

    def test_detects_command_injection(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) > 0

        finding = cmd_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.severity == "ERROR"


class TestJSPatternAnalyzerSQLInjection:

    def test_detects_sql_injection(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        sql_findings = [f for f in results if "SQL" in f.type]
        assert len(sql_findings) > 0

        finding = sql_findings[0]
        assert finding.cwe == "CWE-89"


class TestJSPatternAnalyzerTypeScript:

    def test_analyzes_typescript(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(EVAL_CODE, path="test.ts", lang="typescript")
        results = analyzer.analyze([unit])

        eval_findings = [f for f in results if "Eval" in f.type or "Code Injection" in f.type]
        assert len(eval_findings) > 0


class TestJSPatternAnalyzerFindingFormat:

    def test_findings_are_raw_finding(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(XSS_HTML_CODE)
        results = analyzer.analyze([unit])

        for finding in results:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.engine == "js_pattern"

    def test_file_path_preserved(self):
        analyzer = JSPatternAnalyzer()
        unit = _make_unit(XSS_HTML_CODE, path="src/components/output.js")
        results = analyzer.analyze([unit])

        for finding in results:
            assert finding.file_path == "src/components/output.js"