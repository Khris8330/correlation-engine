import time
from database import (
    get_anomaly_devices,
    get_anomaly_alerts,
    get_latest_scan,
    save_correlation,
    get_all_correlations,
    create_database
)
from attack_surface import scan_all_devices, score_to_threat_level

# -----------------------------
# CORRELATION SCORING WEIGHTS
# These determine how much each
# factor contributes to the final
# threat score
# -----------------------------
WEIGHTS = {
    "NEW_DEVICE":           10,
    "MISSING_DEVICE":        5,
    "IP_SPOOF":             40,
    "attack_surface_score": 0.5,  # scaled down since it's already 0-100
    "reconnect_penalty":     5,   # per reconnect above threshold
    "unknown_device":       10,
}

# -----------------------------
# THREAT LEVEL FROM SCORE
# -----------------------------
def score_to_threat_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    elif score >= 10:
        return "LOW"
    else:
        return "NONE"

# -----------------------------
# CORRELATE A SINGLE DEVICE
# -----------------------------
def correlate_device(device):
    ip = device["ip"]
    mac = device["mac"]
    is_known = device["is_known"]
    reconnect_count = device["reconnect_count"]

    score = 0
    findings = []
    anomaly_alert_list = []

    # ── STEP 1: Pull anomaly alerts for this device ──────────
    alerts = get_anomaly_alerts(mac)
    alert_types = [a["alert_type"] for a in alerts]

    for alert in alerts:
        anomaly_alert_list.append(
            f"[{alert['timestamp']}] {alert['alert_type']} — {alert['message']}"
        )

    # ── STEP 2: Score based on anomaly alert types ───────────
    if "IP_SPOOF" in alert_types:
        score += WEIGHTS["IP_SPOOF"]
        findings.append("IP spoofing detected on this device")

    if "NEW_DEVICE" in alert_types:
        score += WEIGHTS["NEW_DEVICE"]
        findings.append("Device was flagged as new when first seen")

    if "MISSING_DEVICE" in alert_types:
        score += WEIGHTS["MISSING_DEVICE"]
        findings.append("Device has disappeared from the network before")

    # ── STEP 3: Score based on device behaviour ──────────────
    if not is_known:
        score += WEIGHTS["unknown_device"]
        findings.append("Device is not yet established as a known device")

    if reconnect_count > 3:
        penalty = (reconnect_count - 3) * WEIGHTS["reconnect_penalty"]
        score += penalty
        findings.append(
            f"Device has reconnected {reconnect_count} times — "
            f"added {penalty} points to threat score"
        )

    # ── STEP 4: Pull attack surface scan results ─────────────
    scan = get_latest_scan(mac)
    attack_surface_findings = []

    if scan:
        surface_score = scan["attack_surface_score"]
        score += int(surface_score * WEIGHTS["attack_surface_score"])

        if scan["open_ports"]:
            findings.append(
                f"{len(scan['open_ports'])} open ports found: "
                f"{', '.join(str(p) for p in scan['open_ports'])}"
            )

        if scan["os_guess"] and scan["os_guess"] != "Unknown":
            findings.append(f"OS detected: {scan['os_guess']}")

        for m in scan["misconfigurations"]:
            attack_surface_findings.append(
                f"[{m['severity']}] {m['type']}: {m['detail']}"
            )
            findings.append(f"Misconfiguration: {m['type']} ({m['severity']})")

    # ── STEP 5: Cap score and determine threat level ─────────
    score = min(score, 100)
    threat_level = score_to_threat_level(score)

    # ── STEP 6: Build threat summary ─────────────────────────
    if findings:
        summary = f"{threat_level} threat detected on {ip}. " + " | ".join(findings)
    else:
        summary = f"No significant threats detected on {ip}"

    # ── STEP 7: Save correlation to database ─────────────────
    save_correlation(
        ip, mac,
        anomaly_alert_list,
        attack_surface_findings,
        score,
        threat_level,
        summary
    )

    return {
        "ip": ip,
        "mac": mac,
        "score": score,
        "threat_level": threat_level,
        "summary": summary,
        "findings": findings,
        "attack_surface_findings": attack_surface_findings
    }

# -----------------------------
# CORRELATE ALL DEVICES
# -----------------------------
def correlate_all_devices():
    print("\n[CORRELATION ENGINE] Starting correlation analysis...\n")

    # Step 1: Get all devices from anomaly detector
    devices = get_anomaly_devices()
    if not devices:
        print("[WARN] No devices found in anomaly detector database.")
        print("       Make sure the anomaly detector has run at least once.")
        return []

    print(f"[+] Found {len(devices)} devices from anomaly detector")

    # Step 2: Run attack surface scan on all devices
    scan_all_devices(devices)

    # Step 3: Correlate each device
    print("\n[CORRELATION ENGINE] Correlating findings...\n")
    results = []
    for device in devices:
        result = correlate_device(device)
        results.append(result)
        print(f"  [{result['threat_level']}] {result['ip']} — score: {result['score']}")

    print(f"\n[DONE] Correlated {len(results)} devices\n")
    return results

# -----------------------------
# CONTINUOUS RUN LOOP
# -----------------------------
def run():
    print("Correlation Engine Running...\n")
    while True:
        correlate_all_devices()
        print("[CORRELATION ENGINE] Sleeping for 5 minutes...\n")
        time.sleep(300)  # run every 5 minutes

if __name__ == "__main__":
    create_database()
    correlate_all_devices()
