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
app.get('/api/search', (req, res) => {
    const searchTerm = req.query.q;
    
    // VULNERABLE: Reflected XSS - user input directly rendered in HTML
    res.send(`<html><body>
        <h1>Search Results for: ${searchTerm}</h1>
        <p>No results found.</p>
    </body></html>`);
});

// Vulnerability 4: Insecure Deserialization
// CWE-502: Deserialization of Untrusted Data
app.post('/api/deserialize', (req, res) => {
    const data = req.body.data;
    
    // VULNERABLE: Deserializing untrusted user input (RCE possible)
    const obj = serialize.unserialize(data);
    res.json({ result: obj });
});

// Vulnerability 5: Path Traversal / Directory Traversal
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    
    // VULNERABLE: Path traversal - no validation on filename
    const filePath = path.join(__dirname, 'uploads', filename);
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).json({ error: 'File not found' });
        }
        res.send(data);
    });
});

// Vulnerability 6: Sensitive Data Exposure / Hardcoded Credentials
// CWE-798: Use of Hard-coded Credentials
const API_KEY = "sk-1234567890abcdef";
const SECRET_TOKEN = "super_secret_password_123";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Vulnerability 7: Weak Cryptography
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
const crypto = require('crypto');

function weakHash(password) {
    // VULNERABLE: Using MD5 for password hashing (weak algorithm)
    return crypto.createHash('md5').update(password).digest('hex');
}

function weakEncryption(data) {
    // VULNERABLE: Using DES encryption (weak algorithm)
    const key = 'weakkey1';
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Vulnerability 8: Open Redirect
// CWE-601: URL Redirection to Untrusted Site
app.get('/api/redirect', (req, res) => {
    const url = req.query.url;
    
    // VULNERABLE: Open redirect - redirecting to user-supplied URL
    res.redirect(url);
});

// Vulnerability 9: Server-Side Request Forgery (SSRF)
// CWE-918: Server-Side Request Forgery
const axios = require('axios');

app.get('/api/fetch', async (req, res) => {
    const url = req.query.url;
    
    // VULNERABLE: SSRF - fetching arbitrary URLs from user input
    try {
        const response = await axios.get(url);
        res.json({ data: response.data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Vulnerability 10: Prototype Pollution
// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
const _ = require('lodash');

app.post('/api/merge', (req, res) => {
    const baseObj = { name: 'default' };
    const userInput = req.body;
    
    // VULNERABLE: Prototype pollution via lodash merge with untrusted input
    const merged = _.merge(baseObj, userInput);
    res.json(merged);
});

// Vulnerability 11: XML External Entity (XXE) Injection
// CWE-611: Improper Restriction of XML External Entity Reference
const libxmljs = require('libxmljs');

app.post('/api/parse-xml', (req, res) => {
    const xmlData = req.body.xml;
    
    // VULNERABLE: XXE - parsing XML without disabling external entities
    try {
        const doc = libxmljs.parseXmlString(xmlData, { noent: true });
        res.json({ result: doc.toString() });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Vulnerability 12: NoSQL Injection
// CWE-943: Improper Neutralization of Special Elements in Data Query Logic
const mongoose = require('mongoose');

app.get('/api/users', async (req, res) => {
    const username = req.query.username;
    
    // VULNERABLE: NoSQL injection - user input directly in query
    const users = await mongoose.connection.collection('users').find({
        username: username
    }).toArray();
    
    res.json(users);
});

// Vulnerability 13: Insecure Cookie Configuration
// CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
app.get('/api/login', (req, res) => {
    // VULNERABLE: Cookie without Secure, HttpOnly, SameSite flags
    res.cookie('sessionId', 'abc123', { 
        httpOnly: false,
        secure: false 
    });
    res.json({ message: 'Logged in' });
});

// Vulnerability 14: Regex DoS (ReDoS)
// CWE-1333: Inefficient Regular Expression Complexity
app.get('/api/validate-email', (req, res) => {
    const email = req.query.email;
    
    // VULNERABLE: ReDoS - evil regex pattern
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    
    if (emailRegex.test(email)) {
        res.json({ valid: true });
    } else {
        res.json({ valid: false });
    }
});

// Vulnerability 15: Insufficient Logging & Missing Error Handling
// CWE-778: Insufficient Logging
app.post('/api/transfer', (req, res) => {
    const { amount, toAccount } = req.body;
    
    // VULNERABLE: No logging of sensitive operation, no input validation
    // Simulating a money transfer without proper checks
    res.json({ 
        message: `Transferred ${amount} to ${toAccount}`,
        success: true 
    });
});

// Vulnerability 16: Unsafe eval() usage
// CWE-94: Improper Control of Generation of Code
app.post('/api/calculate', (req, res) => {
    const expression = req.body.expression;
    
    // VULNERABLE: Code injection via eval
    try {
        const result = eval(expression);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});

// Vulnerability 17: Information Exposure Through Error Messages
// CWE-209: Generation of Error Message Containing Sensitive Information
app.get('/api/debug', (req, res) => {
    try {
        throw new Error('Database connection failed: user=admin, password=secret123, host=192.168.1.100');
    } catch (error) {
        // VULNERABLE: Exposing sensitive error details
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Vulnerability 18: Timing Attack Vulnerable Comparison
// CWE-208: Observable Timing Discrepancy
app.post('/api/verify-token', (req, res) => {
    const userToken = req.body.token;
    const secretToken = 'supersecrettoken123';
    
    // VULNERABLE: Non-constant time comparison
    if (userToken === secretToken) {
        res.json({ valid: true });
    } else {
        res.json({ valid: false });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable app running on port ${PORT}`);
});