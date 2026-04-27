import time
import threading
from datetime import datetime


class Unbanner:
    """
    Manages automatic unbanning of IPs on a backoff schedule.

    Backoff schedule (from config):
    - 1st ban: unban after 10 minutes
    - 2nd ban: unban after 30 minutes
    - 3rd ban: unban after 2 hours
    - 4th ban and beyond: permanent (never auto-unban)

    Each time an IP gets rebanned, it moves to the next slot
    in the backoff schedule, making bans progressively longer.
    """

    def __init__(self, config, blocker, notifier):
        self.ban_schedule = config.get('ban_schedule', [600, 1800, 7200, -1])
        self.blocker = blocker
        self.notifier = notifier

        # Track pending unbans
        # Structure: { ip: { 'unban_at': timestamp, 'ban_count': int } }
        self.pending_unbans = {}
        self.lock = threading.Lock()

    def schedule_unban(self, ip, ban_count):
        """
        Schedule an unban for an IP based on its ban count.

        ban_count: how many times this IP has been banned (1-indexed)
        Uses ban_count - 1 as index into ban_schedule list.
        If ban_count exceeds schedule length, ban is permanent.
        """
        # Get the duration for this ban count
        # ban_count=1 → index 0 → 600s (10 min)
        # ban_count=2 → index 1 → 1800s (30 min)
        # ban_count=3 → index 2 → 7200s (2 hours)
        # ban_count=4+ → index 3 → -1 (permanent)
        schedule_index = min(ban_count - 1, len(self.ban_schedule) - 1)
        duration = self.ban_schedule[schedule_index]

        if duration == -1:
            # Permanent ban - never schedule unban
            print(f"[unbanner] {ip} is permanently banned (ban #{ban_count})")
            return duration

        unban_at = time.time() + duration

        with self.lock:
            self.pending_unbans[ip] = {
                'unban_at': unban_at,
                'ban_count': ban_count,
                'duration': duration,
            }

        print(f"[unbanner] Scheduled unban for {ip} in {duration}s (ban #{ban_count})")
        return duration

    def run(self):
        """
        Main loop that checks for IPs due to be unbanned.
        Runs in a separate thread, checks every 10 seconds.
        """
        print("[unbanner] Started")
        while True:
            self._check_unbans()
            time.sleep(10)

    def _check_unbans(self):
        """
        Check all pending unbans and release any that are due.
        """
        now = time.time()
        to_unban = []

        with self.lock:
            for ip, info in self.pending_unbans.items():
                if now >= info['unban_at']:
                    to_unban.append((ip, info))

            for ip, _ in to_unban:
                del self.pending_unbans[ip]

        # Process unbans outside the lock
        for ip, info in to_unban:
            duration_str = f"{info['duration']}s"
            success = self.blocker.unban(ip, condition="auto_unban_backoff")

            if success:
                # Send Slack notification for every unban
                self.notifier.send_unban_alert(
                    ip=ip,
                    ban_count=info['ban_count'],
                    duration=duration_str,
                    timestamp=datetime.utcnow().isoformat(),
                )

    def get_pending_unbans(self):
        """Return current pending unbans for dashboard display."""
        with self.lock:
            return dict(self.pending_unbans)
