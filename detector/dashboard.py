import psutil
import time
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string

START_TIME = time.time()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kloudwiz Anomaly Detector — Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        h1 {
            color: #58a6ff;
            margin-bottom: 5px;
            font-size: 1.4em;
        }
        .subtitle {
            color: #8b949e;
            font-size: 0.85em;
            margin-bottom: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }
        .card h2 {
            font-size: 0.75em;
            text-transform: uppercase;
            color: #8b949e;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #58a6ff;
        }
        .metric.danger { color: #f85149; }
        .metric.warn { color: #d29922; }
        .metric.ok { color: #3fb950; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        th {
            text-align: left;
            color: #8b949e;
            border-bottom: 1px solid #30363d;
            padding: 6px 8px;
            font-weight: normal;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
        }
        td {
            padding: 6px 8px;
            border-bottom: 1px solid #21262d;
        }
        tr:last-child td { border-bottom: none; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
        }
        .badge.banned { background: #f8514933; color: #f85149; }
        .badge.active { background: #3fb95033; color: #3fb950; }
        .last-updated {
            color: #8b949e;
            font-size: 0.75em;
            margin-top: 16px;
        }
        #status-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #3fb950;
            border-radius: 50%;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <h1><span id="status-dot"></span>Kloudwiz Anomaly Detector</h1>
    <div class="subtitle">Live traffic monitoring dashboard — auto-refreshes every 3 seconds</div>

    <div class="grid">
        <div class="card">
            <h2>Global Req/s</h2>
            <div class="metric" id="global-rate">—</div>
        </div>
        <div class="card">
            <h2>Baseline Mean</h2>
            <div class="metric" id="baseline-mean">—</div>
        </div>
        <div class="card">
            <h2>Baseline StdDev</h2>
            <div class="metric" id="baseline-stddev">—</div>
        </div>
        <div class="card">
            <h2>Banned IPs</h2>
            <div class="metric danger" id="banned-count">—</div>
        </div>
        <div class="card">
            <h2>CPU Usage</h2>
            <div class="metric" id="cpu">—</div>
        </div>
        <div class="card">
            <h2>Memory Usage</h2>
            <div class="metric" id="memory">—</div>
        </div>
        <div class="card">
            <h2>Uptime</h2>
            <div class="metric ok" id="uptime">—</div>
        </div>
    </div>

    <div class="grid">
        <div class="card" style="grid-column: span 2;">
            <h2>Top 10 Source IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Req/s</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="top-ips"></tbody>
            </table>
        </div>

        <div class="card">
            <h2>Banned IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Banned At</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody id="banned-ips"></tbody>
            </table>
        </div>
    </div>

    <div class="last-updated">Last updated: <span id="last-updated">—</span></div>

    <script>
        async function refresh() {
            try {
                const res = await fetch('/api/metrics');
                const d = await res.json();

                document.getElementById('global-rate').textContent = d.global_rate.toFixed(2) + ' req/s';
                document.getElementById('baseline-mean').textContent = d.baseline_mean.toFixed(4);
                document.getElementById('baseline-stddev').textContent = d.baseline_stddev.toFixed(4);
                document.getElementById('banned-count').textContent = d.banned_count;
                document.getElementById('cpu').textContent = d.cpu_percent.toFixed(1) + '%';
                document.getElementById('memory').textContent = d.memory_percent.toFixed(1) + '%';
                document.getElementById('uptime').textContent = d.uptime;
                document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();

                // Top IPs table
                const topIpsBody = document.getElementById('top-ips');
                topIpsBody.innerHTML = '';
                d.top_ips.forEach((item, i) => {
                    const banned = d.banned_ips_list.includes(item.ip);
                    topIpsBody.innerHTML += `
                        <tr>
                            <td>${i + 1}</td>
                            <td>${item.ip}</td>
                            <td>${item.rate.toFixed(2)}</td>
                            <td><span class="badge ${banned ? 'banned' : 'active'}">${banned ? 'BANNED' : 'ACTIVE'}</span></td>
                        </tr>`;
                });

                // Banned IPs table
                const bannedBody = document.getElementById('banned-ips');
                bannedBody.innerHTML = '';
                if (d.banned_ips.length === 0) {
                    bannedBody.innerHTML = '<tr><td colspan="3" style="color:#8b949e">No banned IPs</td></tr>';
                } else {
                    d.banned_ips.forEach(item => {
                        bannedBody.innerHTML += `
                            <tr>
                                <td>${item.ip}</td>
                                <td>${item.banned_at}</td>
                                <td>${item.duration === -1 ? 'permanent' : item.duration + 's'}</td>
                            </tr>`;
                    });
                }
            } catch(e) {
                console.error('Refresh error:', e);
            }
        }

        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>
"""


class Dashboard:
    """
    Serves a live web dashboard showing real-time metrics.
    Runs Flask in a background thread on port 8080.
    Refreshes every 3 seconds via a JavaScript polling loop.
    """

    def __init__(self, config, detector, blocker, baseline):
        self.host = config.get('dashboard_host', '0.0.0.0')
        self.port = config.get('dashboard_port', 8080)
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        """Register Flask URL routes."""

        @self.app.route('/')
        def index():
            return render_template_string(HTML_TEMPLATE)

        @self.app.route('/api/metrics')
        def metrics():
            """
            JSON endpoint polled by the dashboard every 3 seconds.
            Returns all live metrics in one response.
            """
            mean, stddev = self.baseline.get_baseline()
            banned = self.blocker.get_banned_ips()
            top_ips = self.detector.get_top_ips(10)

            # Format uptime
            uptime_seconds = int(time.time() - START_TIME)
            hours, remainder = divmod(uptime_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

            # Format banned IPs for display
            banned_list = []
            for ip, info in banned.items():
                banned_list.append({
                    'ip': ip,
                    'banned_at': info['banned_at'].strftime('%H:%M:%S'),
                    'duration': info['duration'],
                })

            return jsonify({
                'global_rate': self.detector.get_global_rate(),
                'baseline_mean': mean,
                'baseline_stddev': stddev,
                'banned_count': len(banned),
                'banned_ips': banned_list,
                'banned_ips_list': list(banned.keys()),
                'top_ips': [{'ip': ip, 'rate': rate} for ip, rate in top_ips],
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory_percent': psutil.virtual_memory().percent,
                'uptime': uptime_str,
            })

    def run(self):
        """Start the Flask dashboard server in a background thread."""
        thread = threading.Thread(
            target=lambda: self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
            ),
            daemon=True,
        )
        thread.start()
        print(f"[dashboard] Started at http://{self.host}:{self.port}")
