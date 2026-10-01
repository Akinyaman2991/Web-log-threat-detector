# Real-time Web Log Threat Detector

A lightweight Security Information and Event Management (SIEM) log analysis tool written in Python. It parses Nginx and Apache access log files to detect common web application attack vectors and brute-force login attempts.

## Features

- **Attack Detection Engine**: Identifies SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and Sensitive File Access attempts using custom regular expressions.
- **Brute Force Detection**: Tracks high-frequency failed login attempts per IP address to detect automated brute-force attacks.
- **Structured Export**: Exports security alerts to clean, structured JSON files for further SOC analysis.
- **Interactive Terminal UI**: Utilizes `rich` for beautifully formatted tables and real-time terminal output.

## Project Structure

```text
web-log-threat-detector/
├── log_detector.py      # Main detection script
├── sample_access.log    # Sample log file with attack payloads
├── requirements.txt     # Python dependencies
├── .gitignore           # File exclusions
└── README.md            # Documentation
