import time
import math
from collections import deque
from datetime import datetime


class BaselineTracker:
    """
    Tracks a rolling baseline of per-second request counts.
    
    How it works:
    - Maintains a 30-minute rolling window of per-second request counts
    - Recalculates mean and stddev every 60 seconds
    - Maintains per-hour slots and prefers the current hour's data
      when it has enough samples
    - Never lets mean or stddev drop below floor values to avoid
      false positives on very quiet traffic
    """

    def __init__(self, config):
        self.window_minutes = config.get('baseline_window_minutes', 30)
        self.recalc_interval = config.get('baseline_recalc_interval_seconds', 60)
        self.min_samples = config.get('baseline_min_samples', 10)
        self.floor_mean = config.get('baseline_floor_mean', 1.0)
        self.floor_stddev = config.get('baseline_floor_stddev', 0.5)

        # Rolling window of (timestamp, count) tuples
        # Stores one entry per second for the last 30 minutes
        self.window_seconds = self.window_minutes * 60
        self.rolling_window = deque()

        # Per-hour slots: { hour_key: [counts] }
        # hour_key is a string like "2026-04-27-14" (YYYY-MM-DD-HH)
        self.hourly_slots = {}

        # Current computed baseline values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # Error rate baseline
        self.error_mean = 0.0
        self.error_stddev = 0.0
        self.error_window = deque()

        # Timestamp of last recalculation
        self.last_recalc = time.time()

        # Audit log entries for baseline recalculations
        self.recalc_log = []

    def record(self, timestamp, count, error_count=0):
        """
        Record a per-second request count into the rolling window.
        Called once per second by the main loop.
        
        timestamp: unix timestamp (float)
        count: number of requests in that second
        error_count: number of 4xx/5xx requests in that second
        """
        now = timestamp

        # Add to rolling window
        self.rolling_window.append((now, count))

        # Add to error window
        self.error_window.append((now, error_count))

        # Evict entries older than the window size
        # This is the deque eviction logic - we pop from the left
        # when the oldest entry is outside our 30-minute window
        cutoff = now - self.window_seconds
        while self.rolling_window and self.rolling_window[0][0] < cutoff:
            self.rolling_window.popleft()

        while self.error_window and self.error_window[0][0] < cutoff:
            self.error_window.popleft()

        # Add to per-hour slot
        hour_key = datetime.utcfromtimestamp(now).strftime('%Y-%m-%d-%H')
        if hour_key not in self.hourly_slots:
            self.hourly_slots[hour_key] = []
        self.hourly_slots[hour_key].append(count)

        # Keep only last 3 hours of slots to save memory
        all_keys = sorted(self.hourly_slots.keys())
        if len(all_keys) > 3:
            for old_key in all_keys[:-3]:
                del self.hourly_slots[old_key]

        # Recalculate baseline if interval has passed
        if now - self.last_recalc >= self.recalc_interval:
            self._recalculate(now)

    def _recalculate(self, now):
        """
        Recompute mean and stddev from available data.
        Prefers current hour's data if it has enough samples,
        otherwise falls back to the full rolling window.
        """
        self.last_recalc = now
        hour_key = datetime.utcfromtimestamp(now).strftime('%Y-%m-%d-%H')
        current_hour_data = self.hourly_slots.get(hour_key, [])

        # Prefer current hour data if we have enough samples
        if len(current_hour_data) >= self.min_samples:
            counts = current_hour_data
            source = f"hour:{hour_key}"
        elif len(self.rolling_window) >= self.min_samples:
            counts = [c for _, c in self.rolling_window]
            source = "rolling_window"
        else:
            # Not enough data yet, keep floor values
            return

        mean = self._mean(counts)
        stddev = self._stddev(counts, mean)

        # Apply floor values - never go below these
        # This prevents division by zero and avoids hair-trigger alerts
        # on very quiet periods
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Recalculate error baseline
        if len(self.error_window) >= self.min_samples:
            error_counts = [c for _, c in self.error_window]
            self.error_mean = max(self._mean(error_counts), 0.1)
            self.error_stddev = max(self._stddev(error_counts, self.error_mean), 0.1)

        # Log the recalculation
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'BASELINE_RECALC',
            'source': source,
            'samples': len(counts),
            'effective_mean': round(self.effective_mean, 4),
            'effective_stddev': round(self.effective_stddev, 4),
        }
        self.recalc_log.append(entry)

        print(f"[baseline] Recalculated — mean={self.effective_mean:.4f} "
              f"stddev={self.effective_stddev:.4f} source={source} "
              f"samples={len(counts)}")

    def _mean(self, values):
        """Calculate arithmetic mean of a list of values."""
        if not values:
            return 0.0
        return sum(values) / len(values)

    def _stddev(self, values, mean):
        """
        Calculate population standard deviation.
        stddev = sqrt( mean of squared differences from mean )
        """
        if len(values) < 2:
            return 0.0
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def get_baseline(self):
        """Return current effective mean and stddev."""
        return self.effective_mean, self.effective_stddev

    def get_error_baseline(self):
        """Return current error rate mean and stddev."""
        return self.error_mean, self.error_stddev
