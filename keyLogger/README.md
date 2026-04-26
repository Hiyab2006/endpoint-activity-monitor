# 🛡️ Endpoint Activity Monitor
**Author:** Hiyab Hailu  
**Purpose:** Defensive cybersecurity tool for monitoring system activity, detecting threats, and generating AI-powered incident reports.

---

## What It Does
- Scans running processes and flags suspicious activity
- Monitors network connections for suspicious ports
- Detects high CPU/memory usage (possible crypto-mining or injection)
- Tracks new processes started after baseline
- Auto-generates professional incident reports
- Uses **Claude AI** to provide intelligent threat analysis and recommendations

---

## Project Structure
```
endpoint-monitor/
├── monitor.py          # Main scanner — runs endpoint scans
├── ai_analyzer.py      # Claude AI integration — analyzes scan data
├── requirements.txt    # Python dependencies
├── activity_log.json   # Auto-generated scan data (gitignored)
├── endpoint_report.md  # Auto-generated baseline report
├── ai_threat_report.md # AI-generated threat analysis
└── README.md
```

---

## Setup

### 1. Install dependencies
```bash
pip install psutil anthropic
```

### 2. Set your Claude API key
```bash
export ANTHROPIC_API_KEY=your_key_here
```
Get a free API key at: https://console.anthropic.com

### 3. Run a scan
```bash
python monitor.py
```

### 4. Run AI analysis on scan data
```bash
python ai_analyzer.py
```

---

## How to Keep Training It
Every time you run more scans, the AI gets more data to analyze:
1. Run `monitor.py` regularly (daily, weekly)
2. Run `ai_analyzer.py` after each session
3. Review the AI recommendations and note what was a false positive
4. Over time your `activity_log.json` builds a rich dataset

---

## Skills Demonstrated
- Python scripting for security automation
- Endpoint monitoring & process analysis
- Network connection monitoring
- Threat detection & classification
- AI API integration (Anthropic Claude)
- Incident report generation
- Defensive security engineering

---

## Legal Notice
This tool monitors only the local machine it runs on. It is intended for defensive security purposes only. Do not deploy on systems you do not own or have explicit permission to monitor.
