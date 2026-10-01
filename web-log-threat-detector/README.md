# Real-time Web Log Threat Detector

A lightweight Security Information and Event Management (SIEM) log analysis tool written in Python. It parses Nginx and Apache access log files to detect common web application attack vectors and brute force attempts.

## Features

- **Attack Detection**: Identifies SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and Sensitive File Access attempts.
- **Brute Force Detection**: Tracks repeated failed login requests per IP address.
- **Regex Rule Engine**: Flexible threat signature detection.
- **Structured Export**: Saves security alerts to structured JSON reports.
- **Rich Terminal UI**: Displays findings in clean colored tables.

## Installation

```bash
git clone [https://github.com/YOUR_USERNAME/web-log-threat-detector.git](https://github.com/YOUR_USERNAME/web-log-threat-detector.git)
cd web-log-threat-detector
pip install -r requirements.txt