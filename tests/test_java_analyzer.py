"""
Tests for Java pattern analyzer.

Verifies detection of:
- SQL Injection
- Command Injection
- Path Traversal
- XXE
- Insecure Deserialization
- Hardcoded Secret
"""

import pytest
from audit_core.models import CodeUnit, RawFinding
from analyzers.java.java_pattern_analyzer import JavaPatternAnalyzer


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

SQL_INJECTION_CODE = '''
import java.sql.*;

public class UserDao {
    public ResultSet search(String name) {
        String query = "SELECT * FROM users WHERE name = " + name;
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }
}
'''

COMMAND_INJECTION_CODE = '''
import java.io.*;

public class CommandRunner {
    public void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.start();
    }
}
'''

PATH_TRAVERSAL_CODE = '''
import java.io.File;

public class FileReader {
    public File getFile(HttpServletRequest request) {
        String filename = request.getParameter("file");
        return new File(filename);
    }
}
'''

XXE_CODE = '''
import javax.xml.parsers.*;

public class XmlParser {
    public void parse(String xml) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xml);
    }
}
'''

DESERIALIZATION_CODE = '''
import java.io.*;

public class DataLoader {
    public Object load(InputStream in) {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
'''

HARDCODED_SECRET_CODE = '''
public class Config {
    private String password = "admin123";
    private String api_key = "sk-abc123xyz";
}
'''

CLEAN_CODE = '''
public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
}
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "Test.java") -> CodeUnit:
    return CodeUnit(path=path, language="java", content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJavaPatternAnalyzerBasic:

    def test_analyzer_name(self):
        assert JavaPatternAnalyzer().name == "java_pattern"

    def test_supported_languages(self):
        analyzer = JavaPatternAnalyzer()
        assert "java" in analyzer.supported_languages

    def test_skips_non_java(self):
        analyzer = JavaPatternAnalyzer()
        unit = CodeUnit(path="test.py", language="python", content="eval(code)", start_line=1)
        results = analyzer.analyze([unit])
        assert results == []

    def test_empty_code_units(self):
        analyzer = JavaPatternAnalyzer()
        results = analyzer.analyze([])
        assert results == []

    def test_clean_code_no_findings(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        results = analyzer.analyze([unit])
        assert len(results) == 0


class TestJavaPatternAnalyzerSQLInjection:

    def test_detects_sql_injection(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        sql_findings = [f for f in results if "SQL" in f.type]
        assert len(sql_findings) > 0

        finding = sql_findings[0]
        assert finding.cwe == "CWE-89"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"

    def test_sql_injection_has_symbol(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        sql_findings = [f for f in results if "SQL" in f.type]
        assert len(sql_findings) > 0
        assert sql_findings[0].evidence.get("symbol") in ("executeQuery", "executeUpdate", "execute")


class TestJavaPatternAnalyzerCommandInjection:

    def test_detects_runtime_exec(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) > 0

        finding = cmd_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.severity == "ERROR"

    def test_detects_process_builder(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        pb_findings = [f for f in results if "ProcessBuilder" in f.evidence.get("symbol", "")]
        assert len(pb_findings) > 0


class TestJavaPatternAnalyzerPathTraversal:

    def test_detects_path_traversal(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(PATH_TRAVERSAL_CODE)
        results = analyzer.analyze([unit])

        pt_findings = [f for f in results if "Path Traversal" in f.type]
        assert len(pt_findings) > 0

        finding = pt_findings[0]
        assert finding.cwe == "CWE-22"
        assert finding.evidence.get("symbol") == "File"


class TestJavaPatternAnalyzerXXE:

    def test_detects_xxe(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(XXE_CODE)
        results = analyzer.analyze([unit])

        xxe_findings = [f for f in results if "XXE" in f.type]
        assert len(xxe_findings) > 0

        finding = xxe_findings[0]
        assert finding.cwe == "CWE-611"
        assert finding.severity == "ERROR"


class TestJavaPatternAnalyzerDeserialization:

    def test_detects_insecure_deserialization(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(DESERIALIZATION_CODE)
        results = analyzer.analyze([unit])

        deser_findings = [f for f in results if "Deserialization" in f.type]
        assert len(deser_findings) > 0

        finding = deser_findings[0]
        assert finding.cwe == "CWE-502"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"


class TestJavaPatternAnalyzerHardcodedSecret:

    def test_detects_hardcoded_secret(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(HARDCODED_SECRET_CODE)
        results = analyzer.analyze([unit])

        secret_findings = [f for f in results if "Secret" in f.type or "secret" in f.type.lower()]
        assert len(secret_findings) > 0

        finding = secret_findings[0]
        assert finding.cwe == "CWE-798"


class TestJavaPatternAnalyzerFindingFormat:

    def test_findings_are_raw_finding(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE)
        results = analyzer.analyze([unit])

        for finding in results:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.engine == "java_pattern"

    def test_file_path_preserved(self):
        analyzer = JavaPatternAnalyzer()
        unit = _make_unit(SQL_INJECTION_CODE, path="src/main/java/UserDao.java")
        results = analyzer.analyze([unit])

        for finding in results:
            assert finding.file_path == "src/main/java/UserDao.java"