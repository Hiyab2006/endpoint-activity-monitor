"""
Endpoint Activity Monitor
Author: Hiyab Hailu
Description: Monitors system processes, flags suspicious activity, and sends alerts.
Legal: Monitors only the local machine it runs on. For defensive security use only.
"""

import psutil
import datetime
import json
import os
import time
import smtplib
import platform
from email.mime.text import MIMEText
from collections import defaultdict

# ─── CONFIG ───────────────────────────────────────────────────────────────────

LOG_FILE = "activity_log.json"
REPORT_FILE = "endpoint_report.md"
SCAN_INTERVAL = 5  # seconds between scans
ALERT_EMAIL = ""   # optional: add your email to receive alerts

# Processes commonly associated with suspicious activity
SUSPICIOUS_PROCESSES = [
    "netcat", "nc", "ncat", "nmap", "mimikatz", "meterpreter",
    "powershell", "cmd", "wscript", "cscript", "regsvr32",
    "certutil", "bitsadmin", "mshta", "rundll32"
]

# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = [4444, 1337, 31337, 6666, 9999, 8080, 4545]

# Baseline: processes running at startup (populated on first scan)
BASELINE_PROCESSES = set()

# ─── LOGGING ──────────────────────────────────────────────────────────────────

def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    return {"scans": [], "alerts": [], "summary": {}}

def save_log(data):
    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ─── SCANNING ─────────────────────────────────────────────────────────────────

def get_running_processes():
    """Returns a list of currently running processes with details."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            processes.append({
                "pid": info['pid'],
                "name": info['name'],
                "username": info['username'],
                "status": info['status'],
                "cpu_percent": info['cpu_percent'],
                "memory_percent": round(info['memory_percent'], 2) if info['memory_percent'] else 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def get_network_connections():
    """Returns all active network connections."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            connections.append({
                "pid": conn.pid,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_ip": conn.raddr.ip if conn.raddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
                "status": conn.status
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    return connections

def get_system_stats():
    """Returns CPU, memory, and disk usage."""
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }

# ─── THREAT DETECTION ─────────────────────────────────────────────────────────

def check_suspicious_processes(processes):
    """Flags processes matching known suspicious names."""
    alerts = []
    for proc in processes:
        name = proc['name'].lower()
        for sus in SUSPICIOUS_PROCESSES:
            if sus in name:
                alerts.append({
                    "type": "SUSPICIOUS_PROCESS",
                    "severity": "HIGH",
                    "detail": f"Suspicious process detected: {proc['name']} (PID {proc['pid']})",
                    "recommendation": f"Investigate process {proc['name']} immediately. Terminate if unauthorized."
                })
    return alerts

def check_suspicious_ports(connections):
    """Flags connections on known suspicious ports."""
    alerts = []
    for conn in connections:
        if conn['remote_port'] in SUSPICIOUS_PORTS or conn['local_port'] in SUSPICIOUS_PORTS:
            alerts.append({
                "type": "SUSPICIOUS_PORT",
                "severity": "HIGH",
                "detail": f"Connection on suspicious port {conn['remote_port'] or conn['local_port']} to {conn['remote_ip'] or 'local'}",
                "recommendation": "Review this connection. May indicate a backdoor or C2 communication."
            })
    return alerts

def check_high_resource_usage(processes):
    """Flags processes consuming unusually high CPU or memory."""
    alerts = []
    for proc in processes:
        if proc['cpu_percent'] and proc['cpu_percent'] > 80:
            alerts.append({
                "type": "HIGH_CPU",
                "severity": "MEDIUM",
                "detail": f"{proc['name']} (PID {proc['pid']}) using {proc['cpu_percent']}% CPU",
                "recommendation": "High CPU may indicate crypto-mining malware or runaway process."
            })
        if proc['memory_percent'] and proc['memory_percent'] > 50:
            alerts.append({
                "type": "HIGH_MEMORY",
                "severity": "MEDIUM",
                "detail": f"{proc['name']} (PID {proc['pid']}) using {proc['memory_percent']}% memory",
                "recommendation": "Investigate high memory usage — may indicate memory injection."
            })
    return alerts

def check_new_processes(processes, baseline):
    """Flags processes that weren't running at startup."""
    alerts = []
    current_names = {p['name'] for p in processes}
    new_processes = current_names - baseline
    for name in new_processes:
        alerts.append({
            "type": "NEW_PROCESS",
            "severity": "LOW",
            "detail": f"New process started since baseline: {name}",
            "recommendation": "Verify this process is expected and authorized."
        })
    return alerts

# ─── SCAN ─────────────────────────────────────────────────────────────────────

def run_scan(log_data, scan_number):
    """Runs a full endpoint scan and stores results."""
    global BASELINE_PROCESSES

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{timestamp}] Running scan #{scan_number}...")

    processes = get_running_processes()
    connections = get_network_connections()
    stats = get_system_stats()

    # Set baseline on first scan
    if not BASELINE_PROCESSES:
        BASELINE_PROCESSES = {p['name'] for p in processes}
        print(f"  ✔ Baseline set: {len(BASELINE_PROCESSES)} processes recorded")

    # Run all threat checks
    alerts = []
    alerts += check_suspicious_processes(processes)
    alerts += check_suspicious_ports(connections)
    alerts += check_high_resource_usage(processes)
    if scan_number > 1:
        alerts += check_new_processes(processes, BASELINE_PROCESSES)

    # Severity summary
    high = sum(1 for a in alerts if a['severity'] == 'HIGH')
    medium = sum(1 for a in alerts if a['severity'] == 'MEDIUM')
    low = sum(1 for a in alerts if a['severity'] == 'LOW')

    scan_result = {
        "scan_number": scan_number,
        "timestamp": timestamp,
        "process_count": len(processes),
        "connection_count": len(connections),
        "system_stats": stats,
        "alerts": alerts,
        "alert_summary": {"HIGH": high, "MEDIUM": medium, "LOW": low}
    }

    log_data["scans"].append(scan_result)
    log_data["alerts"].extend(alerts)

    print(f"  ✔ Processes: {len(processes)} | Connections: {len(connections)}")
    print(f"  ⚠ Alerts → HIGH: {high} | MEDIUM: {medium} | LOW: {low}")

    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['detail']}")

    return log_data, scan_result

# ─── REPORT ───────────────────────────────────────────────────────────────────

def generate_report(log_data):
    """Generates a professional markdown incident report."""
    scans = log_data["scans"]
    all_alerts = log_data["alerts"]

    total_high = sum(1 for a in all_alerts if a['severity'] == 'HIGH')
    total_medium = sum(1 for a in all_alerts if a['severity'] == 'MEDIUM')
    total_low = sum(1 for a in all_alerts if a['severity'] == 'LOW')

    alert_types = defaultdict(int)
    for a in all_alerts:
        alert_types[a['type']] += 1

    report = f"""# ENDPOINT ACTIVITY MONITOR — INCIDENT REPORT
**Generated:** {datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S")}  
**System:** {platform.node()} | {platform.system()} {platform.release()}  
**Total Scans Completed:** {len(scans)}  

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 HIGH  | {total_high} |
| 🟡 MEDIUM | {total_medium} |
| 🟢 LOW   | {total_low} |
| **TOTAL** | **{len(all_alerts)}** |

---

## Alert Breakdown by Type

"""
    for alert_type, count in alert_types.items():
        report += f"- **{alert_type}**: {count} occurrence(s)\n"

    report += "\n---\n\n## Detailed Findings\n\n"

    for severity in ["HIGH", "MEDIUM", "LOW"]:
        filtered = [a for a in all_alerts if a['severity'] == severity]
        if filtered:
            report += f"### {severity} Severity\n\n"
            for i, alert in enumerate(filtered, 1):
                report += f"**{i}. {alert['type']}**  \n"
                report += f"- **Detail:** {alert['detail']}  \n"
                report += f"- **Recommendation:** {alert['recommendation']}  \n\n"

    report += "---\n\n## System Statistics (Latest Scan)\n\n"
    if scans:
        stats = scans[-1]["system_stats"]
        report += f"- **CPU Usage:** {stats['cpu_percent']}%\n"
        report += f"- **Memory Usage:** {stats['memory_percent']}%\n"
        report += f"- **Disk Usage:** {stats['disk_percent']}%\n"
        report += f"- **Last Boot:** {stats['boot_time']}\n"

    report += "\n---\n\n## Scan History\n\n"
    report += "| Scan # | Timestamp | Processes | Alerts |\n"
    report += "|--------|-----------|-----------|--------|\n"
    for scan in scans:
        total_alerts = sum(scan['alert_summary'].values())
        report += f"| {scan['scan_number']} | {scan['timestamp']} | {scan['process_count']} | {total_alerts} |\n"

    report += "\n---\n*Report generated by Endpoint Activity Monitor — Hiyab Hailu*\n"

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n✔ Report saved to {REPORT_FILE}")
    return report

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   ENDPOINT ACTIVITY MONITOR")
    print("   Defensive Security Tool | Hiyab Hailu")
    print("=" * 55)

    scans_to_run = int(input("\nHow many scans would you like to run? (e.g. 3): "))
    log_data = load_log()
    scan_number = len(log_data["scans"]) + 1

    for i in range(scans_to_run):
        log_data, _ = run_scan(log_data, scan_number)
        save_log(log_data)
        scan_number += 1
        if i < scans_to_run - 1:
            print(f"\n  Next scan in {SCAN_INTERVAL} seconds...")
            time.sleep(SCAN_INTERVAL)

    print("\n" + "=" * 55)
    print("Generating incident report...")
    generate_report(log_data)
    print("=" * 55)
    print("\nDone! Check these files:")
    print(f"  → {LOG_FILE}    (raw scan data)")
    print(f"  → {REPORT_FILE} (incident report)")

if __name__ == "__main__":
    main()
