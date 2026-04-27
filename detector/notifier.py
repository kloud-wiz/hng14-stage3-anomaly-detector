import requests
import json
from datetime import datetime


class Notifier:
    """
    Sends Slack alerts for ban, unban, and global anomaly events.
    All alerts include: condition, current rate, baseline, timestamp,
    and ban duration where applicable.
    """

    def __init__(self, config):
        self.webhook_url = config.get('slack_webhook_url', '')
        if not self.webhook_url:
            print("[notifier] WARNING: No Slack webhook URL configured")

    def send_ban_alert(self, ip, condition, rate, baseline, duration, timestamp):
        """
        Send a Slack alert when an IP is banned.

        ip: the banned IP address
        condition: what triggered the ban (zscore, rate multiplier, etc.)
        rate: request rate at time of ban (req/s)
        baseline: current baseline mean (req/s)
        duration: ban duration string (e.g. '600s' or 'permanent')
        timestamp: ISO format timestamp
        """
        message = {
            "text": "🚨 *IP BANNED — Anomaly Detected*",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Banned IP", "value": ip, "short": True},
                        {"title": "Ban Duration", "value": duration, "short": True},
                        {"title": "Condition", "value": condition, "short": False},
                        {"title": "Current Rate", "value": f"{rate:.2f} req/s", "short": True},
                        {"title": "Baseline Mean", "value": f"{baseline:.2f} req/s", "short": True},
                        {"title": "Timestamp", "value": timestamp, "short": False},
                    ]
                }
            ]
        }
        self._send(message)

    def send_unban_alert(self, ip, ban_count, duration, timestamp):
        """
        Send a Slack alert when an IP is automatically unbanned.

        ip: the unbanned IP address
        ban_count: how many times this IP has been banned
        duration: how long it was banned
        timestamp: ISO format timestamp
        """
        message = {
            "text": "✅ *IP UNBANNED — Ban Lifted*",
            "attachments": [
                {
                    "color": "#36a64f",
                    "fields": [
                        {"title": "Unbanned IP", "value": ip, "short": True},
                        {"title": "Ban Count", "value": str(ban_count), "short": True},
                        {"title": "Was Banned For", "value": duration, "short": True},
                        {"title": "Timestamp", "value": timestamp, "short": False},
                    ]
                }
            ]
        }
        self._send(message)

    def send_global_alert(self, condition, rate, baseline, timestamp):
        """
        Send a Slack alert when a global traffic anomaly is detected.
        No IP ban for global anomalies — alert only.

        condition: what triggered the alert
        rate: current global request rate (req/s)
        baseline: current baseline mean (req/s)
        timestamp: ISO format timestamp
        """
        message = {
            "text": "⚠️ *GLOBAL TRAFFIC ANOMALY DETECTED*",
            "attachments": [
                {
                    "color": "#FFA500",
                    "fields": [
                        {"title": "Condition", "value": condition, "short": False},
                        {"title": "Global Rate", "value": f"{rate:.2f} req/s", "short": True},
                        {"title": "Baseline Mean", "value": f"{baseline:.2f} req/s", "short": True},
                        {"title": "Timestamp", "value": timestamp, "short": False},
                    ]
                }
            ]
        }
        self._send(message)

    def _send(self, message):
        """
        Send a message payload to the Slack webhook URL.
        Fails silently with a log if the request fails —
        we never want a Slack error to crash the daemon.
        """
        if not self.webhook_url:
            return

        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(message),
                headers={'Content-Type': 'application/json'},
                timeout=5,
            )
            if response.status_code != 200:
                print(f"[notifier] Slack error {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"[notifier] Failed to send Slack alert: {e}")
