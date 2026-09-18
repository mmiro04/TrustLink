# LinkTrust

> URL Security & Threat Analysis Platform

LinkTrust is a cybersecurity web application that analyzes URLs and evaluates their potential security risk using multiple signals.

The project combines URL structure analysis, DNS inspection, TLS/SSL analysis, redirect tracking, and threat intelligence to produce a risk score from 0 to 100.

## Live Demo

🚀 **Try LinkTrust:**  
[Live Demo](#)

> The live demo will be added after deployment.

## Features

### URL Analysis

LinkTrust analyzes the structure of submitted URLs and detects indicators such as:

- HTTP instead of HTTPS
- IP addresses used instead of domains
- Suspicious top-level domains
- Punycode domains
- Encoded characters
- Excessive URL length
- Unusually long hostnames
- Multiple subdomains
- Multiple hyphens
- Embedded credentials
- Unusual ports
- Suspicious URL path structures

### DNS Analysis

The application performs DNS lookups for:

- A records
- AAAA records
- CNAME records
- MX records
- NS records

### TLS / SSL Analysis

For HTTPS websites, LinkTrust checks:

- TLS connection
- TLS version
- Certificate issuer
- Certificate expiration
- Days remaining until certificate expiration

### Redirect Analysis

LinkTrust follows HTTP redirects and records:

- Number of redirects
- Redirect chain
- HTTP status codes
- Final destination
- Cross-domain redirects

Normal redirects such as:

`example.com → www.example.com`

are treated as the same registered domain.

### Threat Intelligence

LinkTrust integrates with VirusTotal to check submitted URLs against external threat intelligence.

The application reports:

- Malicious detections
- Suspicious detections
- Harmless results
- Undetected results

The VirusTotal API key is stored as an environment variable and is never committed to the repository.

## Risk Scoring

LinkTrust produces a risk score between **0 and 100**.

| Score | Classification |
|------:|----------------|
| 0–20 | Low Risk |
| 21–50 | Suspicious |
| 51–75 | High Risk |
| 76–100 | Dangerous |

The score is based on multiple independent signals rather than a single indicator.

Examples of signals include:

- URL structure
- HTTPS usage
- IP-based URLs
- Suspicious TLDs
- Punycode
- DNS results
- TLS certificate status
- Redirect behavior
- VirusTotal detections

## Architecture

```text
                    ┌─────────────────────┐
                    │       User          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Frontend       │
                    │   HTML / CSS / JS   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     FastAPI API     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
       │ URL Analyzer│  │ DNS Analyzer│  │ SSL Analyzer│
       └─────────────┘  └─────────────┘  └─────────────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Redirect Analyzer   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Threat Intelligence │
                    │     VirusTotal      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Risk Scoring     │
                    │      0 – 100        │
                    └─────────────────────┘
