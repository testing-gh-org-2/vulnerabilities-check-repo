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