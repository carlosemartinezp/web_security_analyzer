# Web Security Analyzer

A CLI tool developed in Python to analyze HTTP security headers, identify potential security misconfigurations, and generate structured reports for security assessment.


---

## 🚀 Features

- Analysis of common HTTP security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
- Detection of exposed `Server` header
- Severity classification:
  - HIGH
  - MEDIUM
  - LOW
  - OK
- Findings sorted by severity
- Summary generation with total findings count
- Export of reports in:
  - Human-readable `.txt` format
  - Structured `.json` format for integrations
- Basic input URL validation (CLI)

---

## 🛠️ Technologies

- Python
- requests

---

## ⚙️ Installation

```bash
python -m venv venv
venv\Scripts\activate
pip install requests
```

---

## ▶️ Usage

Run the tool from the command line by providing a valid URL (including the scheme):

```bash
python main.py https://example.com
```

> Note: The URL must start with `http://` or `https://`.


---

## 📄 Example Output


## Console Output

```text
[HIGH] Content-Security-Policy → not found
Risk: Helps prevent XSS attacks
Recommendation: Define a proper CSP policy...

[OK] X-Frame-Options → present

=== SUMMARY ===
TOTAL: 5
HIGH: 2
MEDIUM: 1
LOW: 1
OK: 1
```

---

## JSON Report

```json
{
    "url": "https://example.com",
    "timestamp": "2026-03-27 23:58:10",
    "findings": [
        {
            "header": "Content-Security-Policy",
            "status": "missing",
            "severity": "HIGH",
            "message": "Header not found"
        }
    ],
    "summary": {
        "total": 5,
        "high": 2,
        "medium": 1,
        "low": 1,
        "ok": 1
    }
}
```

The JSON output is designed for integration with other tools or systems.

---

## 📁 Project structure

```text
web_security_analyzer/
│
├── main.py
├── scanner/
│   └── headers.py
├── utils/
│   ├── http_client.py
│   └── report.py
├── reports/
├── project_context.md
└── README.md
```

## 🚧 Roadmap

Planned improvements and future iterations of the project:

### 🔹 Short-term improvements (V1.x)
- Improve URL validation and error handling
- Enhance report formatting for better readability
- Expand analysis to include additional security headers
- Add more detailed risk descriptions and recommendations

### 🔹 Mid-term improvements (V2)
- Implement deeper analysis of header configurations (e.g., CSP validation)
- Add support for exporting reports in additional formats (e.g., HTML)
- Improve modularity for easier extension of analysis rules
- Introduce basic automated tests

### 🔹 Long-term improvements
- Develop a Java version of the tool for comparison and scalability
- Build a web interface to visualize analysis results
- Enable API-based usage for integration with other systems
- Add support for batch analysis of multiple URLs

---

## 👤 Author

Carlos Martinez  
Cybersecurity Analyst & Software Developer

---