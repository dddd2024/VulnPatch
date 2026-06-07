// JavaScript vulnerable code for multi-language detection tests

const express = require('express');
const app = express();

// SQL Injection - string concatenation in query
app.get('/user', (req, res) => {
    const name = req.query.name;
    const sql = "SELECT * FROM users WHERE name='" + name + "'";
    db.query(sql, (err, results) => {
        res.json(results);
    });
});

// Command Injection - exec with user input
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const { exec } = require('child_process');
    exec('ping -c 3 ' + host, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS - innerHTML assignment
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send('<div id="output"></div><script>document.getElementById("output").innerHTML = "' + name + '";</script>');
});

// Eval usage
app.get('/calc', (req, res) => {
    const expr = req.query.expr;
    const result = eval(expr);
    res.send(String(result));
});

// Path Traversal
const fs = require('fs');
app.get('/file', (req, res) => {
    const filename = req.query.file;
    const content = fs.readFileSync(filename, 'utf-8');
    res.send(content);
});

app.listen(3000);
