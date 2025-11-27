# Vulnerability Triage Tool

A simple Python tool that parses vulnerability scanner output (JSON format), normalizes key fields, and highlights the issues that require immediate attention. This project was built to practice early-stage triage automation and learn how scanner data is structured.

## Features
- Loads JSON scan results from tools like Nessus, OpenVAS, or custom scans.
- Extracts severity, affected asset, description, and CVE data.
- Prioritizes findings based on severity.
- Flags critical and high-risk items for quick review.
- Outputs a clean summary to the console.

## How It Works
Run the script and provide a JSON file containing scan results.  
Example input format:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "severity": "critical",
      "asset": "10.0.0.14",
      "description": "Sample vulnerability description"
    }
  ]
}
