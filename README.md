# Secure Coding Review - CodeAlpha Task 3

## Overview

This project demonstrates a security audit of a vulnerable web application with complete remediation.

## Files

| File | Description |
|------|-------------|
| `vulnerable_app.py` | Original code with 10 vulnerabilities |
| `secure_app.py` | Fixed version with security controls |
| `SECURITY_AUDIT_REPORT.md` | Detailed audit findings |

## Vulnerabilities Found

- SQL Injection
- Command Injection
- Path Traversal
- XSS (Cross-Site Scripting)
- Hardcoded Credentials
- Weak Password Hashing
- Missing Authentication
- Information Disclosure
- No Rate Limiting
- Debug Mode Enabled

## How to Test

### Run Vulnerable App
```bash
pip install flask
python vulnerable_app.py
