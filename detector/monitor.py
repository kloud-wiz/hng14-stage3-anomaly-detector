import json
import time
import os
from datetime import datetime


def tail_log(log_file):
    """
    Continuously tail a log file line by line.
    Opens the file, seeks to the end, then yields new lines as they arrive.
    This mimics the behavior of 'tail -f' in Linux.
    """
    # Wait until the log file exists before starting
    while not os.path.exists(log_file):
        print(f"[monitor] Waiting for log file: {log_file}")
        time.sleep(2)

    with open(log_file, 'r') as f:
        # Seek to the end of the file so we only read new lines
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                # No new line yet, wait a short time and try again
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            parsed = parse_line(line)
            if parsed:
                yield parsed


def parse_line(line):
    """
    Parse a single JSON log line from Nginx.
    Returns a dict with the fields we care about, or None if parsing fails.

    Expected fields from nginx.conf:
    - source_ip, timestamp, method, path, status, response_size
    """
    try:
        data = json.loads(line)

        # Extract source IP - use x-forwarded-for if available, fall back to direct IP
        source_ip = data.get('source_ip', '')
        if source_ip and ',' in source_ip:
            # X-Forwarded-For can contain multiple IPs - take the first (real client)
            source_ip = source_ip.split(',')[0].strip()

        return {
            'source_ip': source_ip,
            'timestamp': data.get('timestamp', datetime.utcnow().isoformat()),
            'method': data.get('method', ''),
            'path': data.get('path', ''),
            'status': int(data.get('status', 0)),
            'response_size': int(data.get('response_size', 0)),
        }

    except (json.JSONDecodeError, ValueError) as e:
        # Skip malformed lines silently
        return None
