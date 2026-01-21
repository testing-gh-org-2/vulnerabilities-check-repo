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
const JWT_SECRET = 'my-super-secret-key';
const DB_PASSWORD = 'P@ssw0rd123';

// Vulnerability 6: Regular Expression Denial of Service (ReDoS)
// CWE-1333: Inefficient Regular Expression Complexity
app.post('/api/validate-email', (req, res) => {
    const email = req.body.email;
    
    // VULNERABLE: ReDoS - catastrophic backtracking
    const emailRegex = /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z]{2,})+$/;
    
    if (emailRegex.test(email)) {
        res.json({ valid: true });
    } else {
        res.json({ valid: false });
    }
});

// Vulnerability 7: Unvalidated Redirect
// CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // VULNERABLE: Open redirect - no validation
    res.redirect(url);
});

// Vulnerability 8: Server-Side Request Forgery (SSRF)
// CWE-918: Server-Side Request Forgery (SSRF)
const http = require('http');
app.get('/api/fetch', (req, res) => {
    const url = req.query.url;
    
    // VULNERABLE: SSRF - fetches arbitrary URLs
    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => { res.send(data); });
    }).on('error', (e) => {
        res.status(500).send(e.message);
    });
});

// Vulnerability 9: Missing Authentication
// CWE-306: Missing Authentication for Critical Function
app.delete('/api/admin/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // VULNERABLE: No authentication check for critical operation
    db.query(`DELETE FROM users WHERE id = ${userId}`, (error, results) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ message: 'User deleted', userId: userId });
    });
});

// Vulnerability 10: Information Exposure
// CWE-209: Generation of Error Message Containing Sensitive Information
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: Detailed error messages expose sensitive information
    db.query(
        `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`,
        (error, results) => {
            if (error) {
                return res.status(500).json({ 
                    error: error.message,
                    stack: error.stack,
                    query: error.sql
                });
            }
            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            res.json({ 
                message: 'Login successful',
                user: results[0],
                sessionId: Math.random().toString(36)
            });
        }
    );
});

// Vulnerability 11: Weak Cryptography
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
const crypto = require('crypto');
app.post('/api/encrypt', (req, res) => {
    const data = req.body.data;
    
    // VULNERABLE: Using weak MD5 hashing
    const hash = crypto.createHash('md5').update(data).digest('hex');
    
    res.json({ hash: hash });
});

// Vulnerability 12: Prototype Pollution
// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
app.post('/api/config', (req, res) => {
    const config = {};
    const userInput = req.body;
    
    // VULNERABLE: Prototype pollution through object merge
    function merge(target, source) {
        for (let key in source) {
            if (typeof source[key] === 'object') {
                target[key] = merge(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    
    merge(config, userInput);
    res.json({ message: 'Config updated', config: config });
});

// Vulnerability 13: Race Condition
// CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
let balance = 1000;
app.post('/api/withdraw', (req, res) => {
    const amount = parseInt(req.body.amount);
    
    // VULNERABLE: Race condition - no locking mechanism
    if (balance >= amount) {
        setTimeout(() => {
            balance -= amount;
            res.json({ success: true, newBalance: balance });
        }, 100);
    } else {
        res.status(400).json({ error: 'Insufficient funds' });
    }
});

// Vulnerability 14: XML External Entity (XXE) Injection
// CWE-611: Improper Restriction of XML External Entity Reference
const libxmljs = require('libxmljs');
app.post('/api/xml', (req, res) => {
    const xmlData = req.body.xml;
    
    // VULNERABLE: XXE - parsing untrusted XML without disabling external entities
    try {
        const xmlDoc = libxmljs.parseXml(xmlData);
        res.json({ message: 'XML parsed', data: xmlDoc.toString() });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Vulnerability 15: Insecure Random Number Generation
// CWE-330: Use of Insufficiently Random Values
app.get('/api/token', (req, res) => {
    // VULNERABLE: Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2, 15);
    
    res.json({ token: token });
});

// Vulnerability 16: Missing Rate Limiting
// CWE-770: Allocation of Resources Without Limits or Throttling
app.post('/api/send-email', (req, res) => {
    const email = req.body.email;
    const message = req.body.message;
    
    // VULNERABLE: No rate limiting - can be abused for spam
    // Simulating email send
    console.log(`Sending email to ${email}: ${message}`);
    res.json({ message: 'Email sent' });
});

// Vulnerability 17: Improper Input Validation
// CWE-20: Improper Input Validation
app.post('/api/age', (req, res) => {
    const age = req.body.age;
    
    // VULNERABLE: No validation of input type or range
    const yearsToRetirement = 65 - age;
    
    res.json({ 
        age: age,
        yearsToRetirement: yearsToRetirement
    });
});

// Vulnerability 18: Directory Listing
// CWE-548: Exposure of Information Through Directory Listing
app.use('/uploads', express.static('uploads', { 
    dotfiles: 'allow',
    index: false  // VULNERABLE: Allows directory listing
}));

// Vulnerability 19: Cleartext Storage of Sensitive Information
// CWE-312: Cleartext Storage of Sensitive Information
const sessions = {};
app.post('/api/session', (req, res) => {
    const sessionId = req.body.sessionId;
    const creditCard = req.body.creditCard;
    
    // VULNERABLE: Storing sensitive data in cleartext
    sessions[sessionId] = {
        creditCard: creditCard,
        ssn: req.body.ssn,
        password: req.body.password
    };
    
    res.json({ message: 'Session created' });
});

// Vulnerability 20: Use of Eval
// CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
app.post('/api/calculate', (req, res) => {
    const expression = req.body.expression;
    
    // VULNERABLE: Using eval with user input
    try {
        const result = eval(expression);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.listen(3000, () => {
    console.log('Vulnerable server running on http://localhost:3000');
    console.log('WARNING: This server contains intentional vulnerabilities for testing!');
});
