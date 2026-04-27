import time
import threading
import yaml
import os
from collections import defaultdict
from datetime import datetime

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard


def load_config(path='/app/config.yaml'):
    """Load configuration from config.yaml."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def format_duration(seconds):
    """Convert seconds to human readable string."""
    if seconds == -1:
        return 'permanent'
    return f'{seconds}s'


def baseline_feeder(baseline, second_bucket, error_bucket, lock):
    """
    Background thread that feeds completed seconds into the baseline.
    Runs every second, picks up all completed second buckets and
    records them into the baseline tracker.
    
    Runs separately from the main log-reading loop to ensure
    baseline gets fed even during quiet periods.
    """
    print("[feeder] Baseline feeder started")
    while True:
        time.sleep(1)
        now = int(time.time())
        with lock:
            # Get all completed seconds (anything older than current second)
            completed = [ts for ts in list(second_bucket.keys()) if ts < now]
            for ts in completed:
                count = second_bucket.pop(ts)
                error_count = error_bucket.pop(ts, 0)
                baseline.record(
                    timestamp=float(ts),
                    count=count,
                    error_count=error_count,
                )
                print(f"[feeder] Fed second {ts} → count={count} errors={error_count}")


def main():
    print("[main] Starting HNG Anomaly Detector...")

    # Load config
    config = load_config()
    print("[main] Config loaded")

    # Initialize all modules
    baseline = BaselineTracker(config)
    detector = AnomalyDetector(config, baseline)
    blocker = Blocker(config)
    notifier = Notifier(config)
    unbanner = Unbanner(config, blocker, notifier)
    dashboard = Dashboard(config, detector, blocker, baseline)

    print("[main] All modules initialized")

    # Start dashboard in background thread
    dashboard.run()

    # Start unbanner in background thread
    unban_thread = threading.Thread(target=unbanner.run, daemon=True)
    unban_thread.start()

    # Shared per-second buckets and lock
    second_bucket = defaultdict(int)
    error_bucket = defaultdict(int)
    lock = threading.Lock()

    # Start baseline feeder in background thread
    feeder_thread = threading.Thread(
        target=baseline_feeder,
        args=(baseline, second_bucket, error_bucket, lock),
        daemon=True,
    )
    feeder_thread.start()

    # Track recently alerted IPs to avoid alert spam
    recently_alerted = {}
    alert_cooldown = 30  # seconds between alerts for same IP

    log_file = config.get('log_file', '/var/log/nginx/hng-access.log')
    print(f"[main] Tailing log file: {log_file}")

    # Main loop — process log lines as they arrive
    for log_entry in tail_log(log_file):

        ip = log_entry['source_ip']
        status = log_entry['status']
        now = time.time()
        bucket_key = int(now)

        # Skip empty or invalid IPs
        if not ip or ip == '-':
            continue

        print(f"[main] Request from {ip} → {log_entry['method']} {log_entry['path']} {status}")

        # Record into sliding windows
        detector.record_request(log_entry)

        # Count requests per second for baseline feeding
        with lock:
            second_bucket[bucket_key] += 1
            if status >= 400:
                error_bucket[bucket_key] += 1

        # Skip detection for already banned IPs
        if blocker.is_banned(ip):
            continue

        # Check for IP anomaly
        ip_result = detector.check_ip(ip)
        if ip_result:
            now_ts = time.time()
            last_alert = recently_alerted.get(ip, 0)

            if now_ts - last_alert > alert_cooldown:
                recently_alerted[ip] = now_ts

                # Determine ban count for backoff schedule
                ban_info = blocker.banned_ips.get(ip, {})
                ban_count = ban_info.get('ban_count', 0) + 1

                # Get duration from backoff schedule
                schedule_index = min(ban_count - 1, len(config['ban_schedule']) - 1)
                duration_seconds = config['ban_schedule'][schedule_index]
                duration_str = format_duration(duration_seconds)

                # Ban the IP
                banned = blocker.ban(
                    ip=ip,
                    condition=ip_result['condition'],
                    rate=ip_result['rate'],
                    baseline=ip_result['mean'],
                    duration=duration_seconds,
                )

                if banned:
                    # Schedule auto-unban
                    unbanner.schedule_unban(ip, ban_count)

                    # Send Slack alert
                    notifier.send_ban_alert(
                        ip=ip,
                        condition=ip_result['condition'],
                        rate=ip_result['rate'],
                        baseline=ip_result['mean'],
                        duration=duration_str,
                        timestamp=ip_result['timestamp'],
                    )

        # Check for global anomaly
        global_result = detector.check_global()
        if global_result:
            last_global_alert = recently_alerted.get('__global__', 0)
            if time.time() - last_global_alert > alert_cooldown:
                recently_alerted['__global__'] = time.time()
                notifier.send_global_alert(
                    condition=global_result['condition'],
                    rate=global_result['rate'],
                    baseline=global_result['mean'],
                    timestamp=global_result['timestamp'],
                )

    print("[main] Log tail ended — exiting")


if __name__ == '__main__':
    main()
