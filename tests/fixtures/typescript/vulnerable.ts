// TypeScript vulnerable code for multi-language detection tests

import express, { Request, Response } from 'express';

const app = express();

// SQL Injection - string concatenation in query
app.get('/user', (req: Request, res: Response) => {
    const name: string = req.query.name as string;
    const sql: string = "SELECT * FROM users WHERE name='" + name + "'";
    db.query(sql, (err: Error | null, results: any[]) => {
        res.json(results);
    });
});

// Command Injection - execSync with user input
app.get('/ping', (req: Request, res: Response) => {
    const host: string = req.query.host as string;
    const { execSync } = require('child_process');
    const output: Buffer = execSync('ping -c 3 ' + host);
    res.send(output.toString());
});

// XSS - innerHTML assignment
app.get('/greet', (req: Request, res: Response) => {
    const name: string = req.query.name as string;
    res.send(`<div id="output"></div><script>document.getElementById("output").innerHTML = "${name}";</script>`);
});

// Eval usage
app.get('/calc', (req: Request, res: Response) => {
    const expr: string = req.query.expr as string;
    const result: any = eval(expr);
    res.send(String(result));
});

// Path Traversal
import * as fs from 'fs';
app.get('/file', (req: Request, res: Response) => {
    const filename: string = req.query.file as string;
    const content: string = fs.readFileSync(filename, 'utf-8');
    res.send(content);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
