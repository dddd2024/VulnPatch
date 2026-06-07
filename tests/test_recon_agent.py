"""
Tests for ReconAgent attack surface extraction.

Verifies:
- ReconAgent extracts routes, requests, file ops, SQL, commands, deserialization
- ReconAgent generates hypotheses and logs
- ReconAgent does not read files directly
"""

import pytest
from audit_core.models import CodeUnit, AgentHypothesis, AgentLog
from agents.recon_agent import ReconAgent


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

PYTHON_WEB_CODE = '''
from flask import Flask, request
import sqlite3
import os
import pickle

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()

@app.route("/run")
def run_cmd():
    cmd = request.form.get("cmd")
    os.system(cmd)
    return "done"

@app.route("/load")
def load_data():
    data = request.data
    obj = pickle.loads(data)
    return str(obj)
'''

JAVASCRIPT_WEB_CODE = '''
const express = require('express');
const fs = require('fs');
const app = express();

app.get('/search', (req, res) => {
    const name = req.query.name;
    db.query('SELECT * FROM users WHERE name = "' + name + '"');
    res.send(results);
});

app.post('/write', (req, res) => {
    const filename = req.body.filename;
    fs.writeFile(filename, req.body.content);
    res.send('done');
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd);
    res.send('done');
});
'''

JAVA_WEB_CODE = '''
import java.io.*;
import javax.servlet.http.*;

public class UserController {
    @RequestMapping("/search")
    public String search(HttpServletRequest request) {
        String name = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = " + name;
        statement.executeQuery(query);
        return results;
    }
    
    @GetMapping("/file")
    public String readFile(HttpServletRequest request) {
        String filename = request.getParameter("file");
        File file = new File(filename);
        return file.getAbsolutePath();
    }
    
    @PostMapping("/load")
    public Object loadData(InputStream in) {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}

class CommandRunner {
    public void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
'''

C_CODE = '''
#include <stdio.h>
#include <stdlib.h>

void read_file(char *path) {
    FILE *f = fopen(path, "r");
    char buffer[1024];
    fgets(buffer, 1024, f);
    fclose(f);
}

void run_command(char *cmd) {
    system(cmd);
}

void write_file(char *path, char *data) {
    FILE *f = fopen(path, "w");
    fprintf(f, data);
    fclose(f);
}
'''

CLEAN_CODE = '''
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.py", lang: str = "python") -> CodeUnit:
    return CodeUnit(path=path, language=lang, content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests: Basic functionality
# ---------------------------------------------------------------------------

class TestReconAgentBasic:

    def test_agent_name(self):
        assert ReconAgent().name == "recon"

    def test_empty_code_units(self):
        """ReconAgent should handle empty input."""
        agent = ReconAgent()
        hypotheses, logs = agent.run([])
        assert hypotheses == []
        assert len(logs) == 1

    def test_clean_code_no_surfaces(self):
        """Clean code should have no attack surfaces."""
        agent = ReconAgent()
        unit = _make_unit(CLEAN_CODE)
        hypotheses, logs = agent.run([unit])
        
        # Clean code has no attack surfaces
        assert len(hypotheses) == 0


# ---------------------------------------------------------------------------
# Tests: Python attack surfaces
# ---------------------------------------------------------------------------

class TestReconAgentPython:

    def test_detects_routes(self):
        """Should detect Flask routes."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        assert len(hypotheses) > 0
        
        # Check surfaces include routes
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        routes = [s for s in surfaces if s["type"] == "route"]
        assert len(routes) > 0

    def test_detects_request_params(self):
        """Should detect request parameters."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        requests = [s for s in surfaces if s["type"] == "request"]
        assert len(requests) > 0

    def test_detects_sql_operations(self):
        """Should detect SQL operations."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        sqls = [s for s in surfaces if s["type"] == "sql"]
        assert len(sqls) > 0

    def test_detects_command_execution(self):
        """Should detect command execution."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        commands = [s for s in surfaces if s["type"] == "command"]
        assert len(commands) > 0

    def test_detects_deserialization(self):
        """Should detect deserialization."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        desers = [s for s in surfaces if s["type"] == "deserialization"]
        assert len(desers) > 0


# ---------------------------------------------------------------------------
# Tests: JavaScript attack surfaces
# ---------------------------------------------------------------------------

class TestReconAgentJavaScript:

    def test_detects_js_routes(self):
        """Should detect Express routes."""
        agent = ReconAgent()
        unit = _make_unit(JAVASCRIPT_WEB_CODE, "test.js", "javascript")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        routes = [s for s in surfaces if s["type"] == "route"]
        assert len(routes) > 0

    def test_detects_js_request_params(self):
        """Should detect Express request params."""
        agent = ReconAgent()
        unit = _make_unit(JAVASCRIPT_WEB_CODE, "test.js", "javascript")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        requests = [s for s in surfaces if s["type"] == "request"]
        assert len(requests) > 0

    def test_detects_js_file_ops(self):
        """Should detect fs operations."""
        agent = ReconAgent()
        unit = _make_unit(JAVASCRIPT_WEB_CODE, "test.js", "javascript")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        files = [s for s in surfaces if s["type"] == "file"]
        assert len(files) > 0


# ---------------------------------------------------------------------------
# Tests: Java attack surfaces
# ---------------------------------------------------------------------------

class TestReconAgentJava:

    def test_detects_java_routes(self):
        """Should detect Spring routes."""
        agent = ReconAgent()
        unit = _make_unit(JAVA_WEB_CODE, "Test.java", "java")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        routes = [s for s in surfaces if s["type"] == "route"]
        assert len(routes) > 0

    def test_detects_java_request_params(self):
        """Should detect HttpServletRequest params."""
        agent = ReconAgent()
        unit = _make_unit(JAVA_WEB_CODE, "Test.java", "java")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        requests = [s for s in surfaces if s["type"] == "request"]
        assert len(requests) > 0

    def test_detects_java_command_execution(self):
        """Should detect Runtime.exec."""
        agent = ReconAgent()
        unit = _make_unit(JAVA_WEB_CODE, "Test.java", "java")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        commands = [s for s in surfaces if s["type"] == "command"]
        assert len(commands) > 0


# ---------------------------------------------------------------------------
# Tests: C attack surfaces
# ---------------------------------------------------------------------------

class TestReconAgentC:

    def test_detects_c_file_ops(self):
        """Should detect fopen."""
        agent = ReconAgent()
        unit = _make_unit(C_CODE, "test.c", "c")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        files = [s for s in surfaces if s["type"] == "file"]
        assert len(files) > 0

    def test_detects_c_command_execution(self):
        """Should detect system()."""
        agent = ReconAgent()
        unit = _make_unit(C_CODE, "test.c", "c")
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        commands = [s for s in surfaces if s["type"] == "command"]
        assert len(commands) > 0


# ---------------------------------------------------------------------------
# Tests: Output structure
# ---------------------------------------------------------------------------

class TestReconAgentOutputStructure:

    def test_hypothesis_has_required_fields(self):
        """Hypothesis should have required fields."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        if hypotheses:
            h = hypotheses[0]
            assert h.agent_name == "recon"
            assert h.vulnerability_type == "Attack Surface"
            assert h.reasoning_summary

    def test_log_has_required_fields(self):
        """Log should have required fields."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        log = logs[0]
        assert log.agent_name == "recon"
        assert log.stage == "recon"
        assert log.message

    def test_log_metadata_has_totals(self):
        """Log metadata should have totals."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        log = logs[0]
        assert "total_attack_surfaces" in log.metadata
        assert "files_with_surfaces" in log.metadata

    def test_surface_has_line_number(self):
        """Attack surfaces should have line numbers."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        for surface in surfaces:
            assert surface.get("line") > 0

    def test_surface_has_risk_level(self):
        """Attack surfaces should have risk levels."""
        agent = ReconAgent()
        unit = _make_unit(PYTHON_WEB_CODE)
        hypotheses, logs = agent.run([unit])
        
        surfaces = hypotheses[0].metadata.get("attack_surfaces", [])
        for surface in surfaces:
            assert surface.get("risk") in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Tests: Does not read files
# ---------------------------------------------------------------------------

class TestReconAgentNoFileAccess:

    def test_agent_only_uses_code_unit_content(self):
        """Agent should only use CodeUnit.content, not read files."""
        # This test verifies that ReconAgent doesn't try to read from file system
        # by using a CodeUnit with a fake path but real content
        agent = ReconAgent()
        unit = CodeUnit(
            path="/nonexistent/path/file.py",
            language="python",
            content=PYTHON_WEB_CODE,
            start_line=1,
        )
        
        # Should work without errors even though path doesn't exist
        hypotheses, logs = agent.run([unit])
        assert len(hypotheses) > 0  # Should still find attack surfaces