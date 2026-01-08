/**
 * Vulnerable Node.js Application for Security Testing
 * WARNING: This code contains intentional security vulnerabilities for testing purposes only.
 * DO NOT use in production!
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const serialize = require('node-serialize');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'testdb'
});

// Vulnerability 1: SQL Injection
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// CVE-2021-41773: Apache HTTP Server Path Traversal (example reference)
app.get('/api/user', (req, res) => {
    const userId = req.query.id;
    
    // VULNERABLE: SQL Injection - directly concatenating user input into query
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    
    db.query(query, (error, results) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json(results);
    });
});

// Vulnerability 2: Command Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// CVE-2021-44228: Log4Shell (example reference)
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    
    // VULNERABLE: Command Injection - unsanitized user input in system command
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// Vulnerability 3: Cross-Site Scripting (XSS)
// CWE-79: Improper Neutralization of Input During Web Page Generation
// CVE-2020-5902: F5 BIG-IP TMUI RCE (example reference)
app.get('/welcome', (req, res) => {
    const username = req.query.name || 'Guest';
    
    // VULNERABLE: XSS - unsanitized user input rendered in HTML
    const html = `
        <!DOCTYPE html>
        <html>
        <head><title>Welcome</title></head>
        <body>
            <h1>Welcome, ${username}!</h1>
            <p>Your user agent is: ${req.headers['user-agent']}</p>
        </body>
        </html>
    `;
    res.send(html);
});

// Vulnerability 4: Insecure Deserialization
// CWE-502: Deserialization of Untrusted Data
// CVE-2017-5638: Apache Struts Remote Code Execution (example reference)
app.post('/api/profile', (req, res) => {
    const serializedData = req.body.data;
    
    // VULNERABLE: Insecure deserialization - can execute arbitrary code
    try {
        const profile = serialize.unserialize(serializedData);
        res.json({ message: 'Profile loaded', profile: profile });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Vulnerability 5: Path Traversal
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
// CVE-2019-0708: BlueKeep RDP Remote Code Execution (example reference)
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    
    // VULNERABLE: Path Traversal - no validation of file path
    const filepath = path.join(__dirname, 'public', filename);
    
    fs.readFile(filepath, 'utf8', (error, data) => {
        if (error) {
            return res.status(404).json({ error: 'File not found' });
        }
        res.send(data);
    });
});

// Additional vulnerability: Hardcoded credentials
// CWE-798: Use of Hard-coded Credentials
const API_KEY = 'sk-1234567890abcdef';
const ADMIN_PASSWORD = 'admin123';

app.listen(3000, () => {
    console.log('Vulnerable server running on http://localhost:3000');
    console.log('WARNING: This server contains intentional vulnerabilities for testing!');
});
