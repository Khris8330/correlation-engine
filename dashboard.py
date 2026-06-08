import threading
from flask import Flask, render_template
from database import (
    create_database,
    get_all_correlations,
    get_all_scan_results,
    get_correlation_stats,
    get_anomaly_devices,
    get_anomaly_alerts
)
from correlation_engine import run as start_correlation

app = Flask(__name__)


@app.route("/")
def home():
    stats = get_correlation_stats()
    correlations = get_all_correlations()
    devices = get_anomaly_devices()
    alerts = get_anomaly_alerts()

    return render_template(
        "index.html",
        stats=stats,
        correlations=correlations,
        devices=devices,
        alerts=alerts
    )


@app.route("/scans")
def scans():
    scan_results = get_all_scan_results()
    return render_template(
        "scans.html",
        scan_results=scan_results
    )


if __name__ == "__main__":
    create_database()

    correlation_thread = threading.Thread(target=start_correlation, daemon=True)
    correlation_thread.start()

    app.run(
        host="0.0.0.0",
        port=5001,  # port 5001 so it doesn't clash with anomaly detector on 5000
        debug=False
    )
