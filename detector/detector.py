import time
from collections import deque
from datetime import datetime


class AnomalyDetector:
    """
    Detects anomalies in HTTP traffic using two sliding windows:
    - Per-IP window: tracks request rate for each individual IP
    - Global window: tracks overall request rate across all IPs

    Detection fires when either:
    1. Z-score exceeds 3.0  (statistical deviation from baseline)
    2. Rate exceeds 5x the baseline mean (absolute multiplier check)
    whichever fires first.

    For IPs with high error rates, thresholds are tightened automatically.
    """

    def __init__(self, config, baseline_tracker):
        self.window_seconds = config.get('sliding_window_seconds', 60)
        self.zscore_threshold = config.get('zscore_threshold', 3.0)
        self.rate_multiplier = config.get('rate_multiplier_threshold', 5.0)
        self.error_rate_multiplier = config.get('error_rate_multiplier', 3.0)
        self.baseline = baseline_tracker

        # Per-IP sliding windows
        # Structure: { ip: deque([(timestamp, 1), ...]) }
        # Each entry is a tuple of (timestamp, 1) representing one request
        self.ip_windows = {}

        # Per-IP error windows
        # Structure: { ip: deque([(timestamp, 1), ...]) }
        self.ip_error_windows = {}

        # Global sliding window
        # Stores timestamps of every request in the last 60 seconds
        self.global_window = deque()

        # Global error window
        self.global_error_window = deque()

    def record_request(self, log_entry):
        """
        Record an incoming request into the sliding windows.
        Called for every log line parsed by monitor.py.

        log_entry: dict with source_ip, timestamp, status, etc.
        """
        now = time.time()
        ip = log_entry['source_ip']
        status = log_entry['status']
        is_error = status >= 400

        # --- Per-IP window ---
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
            self.ip_error_windows[ip] = deque()

        self.ip_windows[ip].append(now)
        if is_error:
            self.ip_error_windows[ip].append(now)

        # Evict entries outside the window for this IP
        # Pop from the left while the oldest entry is too old
        cutoff = now - self.window_seconds
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()
        while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
            self.ip_error_windows[ip].popleft()

        # --- Global window ---
        self.global_window.append(now)
        if is_error:
            self.global_error_window.append(now)

        # Evict old entries from global window
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
        while self.global_error_window and self.global_error_window[0] < cutoff:
            self.global_error_window.popleft()

    def get_ip_rate(self, ip):
        """
        Return the current request rate (requests per second)
        for a specific IP over the last 60 seconds.
        """
        if ip not in self.ip_windows:
            return 0.0
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_global_rate(self):
        """
        Return the current global request rate (requests per second)
        across all IPs over the last 60 seconds.
        """
        return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Return the current error rate for a specific IP."""
        if ip not in self.ip_error_windows:
            return 0.0
        return len(self.ip_error_windows[ip]) / self.window_seconds

    def _has_error_surge(self, ip):
        """
        Check if an IP has a high error rate compared to baseline.
        Returns True if IP's error rate is 3x the baseline error rate.
        """
        error_mean, _ = self.baseline.get_error_baseline()
        if error_mean <= 0:
            return False
        ip_error_rate = self.get_ip_error_rate(ip)
        return ip_error_rate >= (error_mean * self.error_rate_multiplier)

    def _compute_zscore(self, rate, mean, stddev):
        """
        Compute z-score: how many standard deviations is the
        current rate away from the baseline mean?

        z = (current_rate - mean) / stddev

        A z-score > 3.0 means the rate is statistically anomalous —
        it would naturally occur less than 0.3% of the time.
        """
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def check_ip(self, ip):
        """
        Check if an IP's request rate is anomalous.
        Returns a dict with detection result or None if normal.

        Tightens thresholds if the IP has an error surge.
        """
        mean, stddev = self.baseline.get_baseline()
        ip_rate = self.get_ip_rate(ip)

        # Tighten thresholds if IP has error surge
        error_surge = self._has_error_surge(ip)
        zscore_thresh = self.zscore_threshold * (0.5 if error_surge else 1.0)
        rate_thresh = self.rate_multiplier * (0.5 if error_surge else 1.0)

        zscore = self._compute_zscore(ip_rate, mean, stddev)
        rate_exceeded = ip_rate >= (mean * rate_thresh)
        zscore_exceeded = zscore >= zscore_thresh

        if zscore_exceeded or rate_exceeded:
            condition = []
            if zscore_exceeded:
                condition.append(f"zscore={zscore:.2f}>={zscore_thresh}")
            if rate_exceeded:
                condition.append(f"rate={ip_rate:.2f}>={mean * rate_thresh:.2f}")
            if error_surge:
                condition.append("error_surge=True")

            return {
                'type': 'ip',
                'ip': ip,
                'rate': ip_rate,
                'zscore': zscore,
                'mean': mean,
                'stddev': stddev,
                'condition': ' | '.join(condition),
                'timestamp': datetime.utcnow().isoformat(),
                'error_surge': error_surge,
            }
        return None

    def check_global(self):
        """
        Check if the global request rate is anomalous.
        Returns a dict with detection result or None if normal.
        """
        mean, stddev = self.baseline.get_baseline()
        global_rate = self.get_global_rate()

        zscore = self._compute_zscore(global_rate, mean, stddev)
        rate_exceeded = global_rate >= (mean * self.rate_multiplier)
        zscore_exceeded = zscore >= self.zscore_threshold

        if zscore_exceeded or rate_exceeded:
            condition = []
            if zscore_exceeded:
                condition.append(f"zscore={zscore:.2f}>={self.zscore_threshold}")
            if rate_exceeded:
                condition.append(f"rate={global_rate:.2f}>={mean * self.rate_multiplier:.2f}")

            return {
                'type': 'global',
                'rate': global_rate,
                'zscore': zscore,
                'mean': mean,
                'stddev': stddev,
                'condition': ' | '.join(condition),
                'timestamp': datetime.utcnow().isoformat(),
            }
        return None

    def get_top_ips(self, n=10):
        """
        Return the top N IPs by current request rate.
        Used by the dashboard to show the most active sources.
        """
        ip_rates = {
            ip: self.get_ip_rate(ip)
            for ip in self.ip_windows
        }
        sorted_ips = sorted(ip_rates.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:n]
