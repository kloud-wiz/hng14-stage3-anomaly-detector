import subprocess
import os
from datetime import datetime


class Blocker:
    """
    Manages iptables bans for anomalous IPs.
    
    How it works:
    - Adds an iptables DROP rule for a given IP
    - Writes a structured entry to the audit log
    - Tracks which IPs are currently banned
    """

    def __init__(self, config):
        self.audit_log_path = config.get('audit_log', '/var/log/detector/audit.log')
        self.banned_ips = {}  # { ip: { 'banned_at': timestamp, 'duration': seconds, 'ban_count': int } }

        # Ensure audit log directory exists
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)

    def ban(self, ip, condition, rate, baseline, duration):
        """
        Add an iptables DROP rule for the given IP.

        ip: the IP address to ban
        condition: string describing why it was banned
        rate: current request rate at time of ban
        baseline: current baseline mean
        duration: ban duration in seconds (-1 for permanent)
        """
        # Check if already banned
        if ip in self.banned_ips:
            return False

        # Add iptables DROP rule
        # This tells the kernel to silently drop all packets from this IP
        success = self._add_iptables_rule(ip)
        if not success:
            return False

        banned_at = datetime.utcnow()
        self.banned_ips[ip] = {
            'banned_at': banned_at,
            'duration': duration,
            'ban_count': self.banned_ips.get(ip, {}).get('ban_count', 0) + 1,
            'condition': condition,
            'rate': rate,
            'baseline': baseline,
        }

        # Write audit log entry
        duration_str = 'permanent' if duration == -1 else f'{duration}s'
        self._write_audit_log(
            action='BAN',
            ip=ip,
            condition=condition,
            rate=rate,
            baseline=baseline,
            duration=duration_str,
            timestamp=banned_at.isoformat(),
        )

        print(f"[blocker] Banned {ip} | {condition} | rate={rate:.2f} | duration={duration_str}")
        return True

    def unban(self, ip, condition="auto_unban"):
        """
        Remove the iptables DROP rule for the given IP.
        Called by unbanner.py on the backoff schedule.
        """
        if ip not in self.banned_ips:
            return False

        success = self._remove_iptables_rule(ip)
        if not success:
            return False

        ban_info = self.banned_ips.pop(ip)
        unbanned_at = datetime.utcnow()

        self._write_audit_log(
            action='UNBAN',
            ip=ip,
            condition=condition,
            rate=ban_info.get('rate', 0),
            baseline=ban_info.get('baseline', 0),
            duration='0',
            timestamp=unbanned_at.isoformat(),
        )

        print(f"[blocker] Unbanned {ip} | {condition}")
        return True

    def is_banned(self, ip):
        """Check if an IP is currently banned."""
        return ip in self.banned_ips

    def get_banned_ips(self):
        """Return dict of all currently banned IPs with their info."""
        return dict(self.banned_ips)

    def _add_iptables_rule(self, ip):
        """
        Run iptables command to DROP all packets from an IP.
        
        iptables -I INPUT 1 -s <ip> -j DROP
        
        -I INPUT 1  — insert at the top of the INPUT chain (highest priority)
        -s <ip>     — match packets from this source IP
        -j DROP     — silently drop matched packets (no response sent to attacker)
        """
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables ban failed for {ip}: {e.stderr.decode()}")
            return False

    def _remove_iptables_rule(self, ip):
        """
        Run iptables command to remove the DROP rule for an IP.
        
        iptables -D INPUT -s <ip> -j DROP
        
        -D INPUT    — delete from the INPUT chain
        -s <ip>     — match the rule for this source IP
        -j DROP     — match the DROP action
        """
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables unban failed for {ip}: {e.stderr.decode()}")
            return False

    def _write_audit_log(self, action, ip, condition, rate, baseline, duration, timestamp):
        """
        Write a structured audit log entry.
        
        Format: [timestamp] ACTION ip | condition | rate | baseline | duration
        """
        log_entry = (
            f"[{timestamp}] {action} {ip} | "
            f"condition={condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline:.2f} | "
            f"duration={duration}\n"
        )

        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[blocker] Failed to write audit log: {e}")
