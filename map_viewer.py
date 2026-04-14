#!/usr/bin/env python3
"""
WiFi Mapper — Map Viewer
=========================
Reads wifi_data.json and generates an interactive map.html
using Leaflet.js + OpenStreetMap (free, no API key).

Usage:
    python3 map_viewer.py [--data wifi_data.json] [--out map.html]
"""

import argparse
import json
import os
import sys
from collections import defaultdict

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()


def load_data(filepath):
    """Load and validate the JSON data file."""
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[✗] File not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)
    
    with open(filepath, "r") as f:
        data = json.load(f)
    
    if not isinstance(data, list) or len(data) == 0:
        print(f"{Fore.RED}[✗] No scan data found in {filepath}{Style.RESET_ALL}")
        sys.exit(1)
    
    return data


def generate_map(data, output_file):
    """Generate a self-contained interactive HTML map."""
    
    # ── Aggregate networks by location cluster ──
    # Group scan entries and compute stats
    all_networks = []
    location_scans = []
    
    for scan in data:
        loc = scan.get("location", {})
        lat = loc.get("lat", 0)
        lon = loc.get("lon", 0)
        ts = scan.get("timestamp", "?")
        
        if lat == 0 and lon == 0:
            continue
        
        networks = scan.get("networks", [])
        location_scans.append({
            "lat": lat,
            "lon": lon,
            "timestamp": ts,
            "source": loc.get("source", "unknown"),
            "accuracy_m": loc.get("accuracy_m", -1),
            "networks": networks
        })
        all_networks.extend(networks)
    
    if not location_scans:
        print(f"{Fore.RED}[✗] No valid location data to map.{Style.RESET_ALL}")
        sys.exit(1)
    
    # ── Stats ──
    total_scans = len(location_scans)
    total_networks = len(all_networks)
    unique_bssids = len(set(n.get("bssid", "") for n in all_networks))
    open_count = sum(1 for n in all_networks if n.get("encryption") == "Open")
    hidden_count = sum(1 for n in all_networks if n.get("hidden", False))
    
    # Center map on average location
    avg_lat = sum(s["lat"] for s in location_scans) / len(location_scans)
    avg_lon = sum(s["lon"] for s in location_scans) / len(location_scans)
    
    # ── Serialize data for JS ──
    js_data = json.dumps(location_scans, ensure_ascii=False)
    
    # ── Generate HTML ──
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Mapper — Network Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            overflow: hidden;
            height: 100vh;
        }}

        #map {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
        }}

        /* ── Stats Panel ── */
        .stats-panel {{
            position: absolute;
            top: 16px;
            right: 16px;
            z-index: 1000;
            background: rgba(10, 10, 20, 0.92);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(100, 200, 255, 0.15);
            border-radius: 16px;
            padding: 20px 24px;
            min-width: 260px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5),
                        inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }}

        .stats-panel h2 {{
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #64d2ff;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .stats-panel h2::before {{
            content: '📡';
            font-size: 18px;
        }}

        .stat-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .stat-row:last-child {{
            border-bottom: none;
        }}

        .stat-label {{
            font-size: 13px;
            color: #8899aa;
            font-weight: 400;
        }}

        .stat-value {{
            font-size: 15px;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }}

        .stat-value.open {{ color: #30d158; }}
        .stat-value.secured {{ color: #ff9f0a; }}
        .stat-value.hidden {{ color: #ff453a; }}
        .stat-value.total {{ color: #64d2ff; }}

        /* ── Legend ── */
        .legend {{
            position: absolute;
            bottom: 24px;
            right: 16px;
            z-index: 1000;
            background: rgba(10, 10, 20, 0.92);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(100, 200, 255, 0.15);
            border-radius: 12px;
            padding: 14px 18px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }}

        .legend-title {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8899aa;
            margin-bottom: 10px;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 5px;
            font-size: 12px;
            color: #cccccc;
        }}

        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
        }}

        .dot-open {{ background: #30d158; box-shadow: 0 0 8px #30d15888; }}
        .dot-wpa {{ background: #ff9f0a; box-shadow: 0 0 8px #ff9f0a88; }}
        .dot-wpa3 {{ background: #ff453a; box-shadow: 0 0 8px #ff453a88; }}
        .dot-scan {{ background: #64d2ff; box-shadow: 0 0 8px #64d2ff88; }}

        /* ── Title bar ── */
        .title-bar {{
            position: absolute;
            top: 16px;
            left: 16px;
            z-index: 1000;
            background: rgba(10, 10, 20, 0.92);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(100, 200, 255, 0.15);
            border-radius: 12px;
            padding: 12px 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }}

        .title-bar h1 {{
            font-size: 18px;
            font-weight: 700;
            background: linear-gradient(135deg, #64d2ff, #5e5ce6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .title-bar .subtitle {{
            font-size: 11px;
            color: #667788;
            margin-top: 2px;
        }}

        /* ── Popup styling ── */
        .leaflet-popup-content-wrapper {{
            background: rgba(15, 15, 25, 0.95) !important;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(100, 200, 255, 0.2) !important;
            border-radius: 12px !important;
            color: #e0e0e0 !important;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6) !important;
        }}

        .leaflet-popup-tip {{
            background: rgba(15, 15, 25, 0.95) !important;
            border: 1px solid rgba(100, 200, 255, 0.2) !important;
        }}

        .leaflet-popup-content {{
            margin: 12px 14px !important;
            font-family: 'Inter', sans-serif !important;
            max-height: 350px;
            overflow-y: auto;
        }}

        .popup-header {{
            font-size: 13px;
            font-weight: 600;
            color: #64d2ff;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(100, 200, 255, 0.15);
        }}

        .popup-network {{
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .popup-network:last-child {{
            border-bottom: none;
        }}

        .popup-ssid {{
            font-size: 13px;
            font-weight: 600;
            color: #ffffff;
        }}

        .popup-detail {{
            font-size: 11px;
            color: #8899aa;
            margin-top: 2px;
        }}

        .popup-enc {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            margin-left: 6px;
        }}

        .enc-open {{ background: rgba(48, 209, 88, 0.2); color: #30d158; }}
        .enc-wpa {{ background: rgba(255, 159, 10, 0.2); color: #ff9f0a; }}
        .enc-wpa3 {{ background: rgba(255, 69, 58, 0.2); color: #ff453a; }}

        .signal-bar {{
            display: inline-block;
            height: 6px;
            border-radius: 3px;
            margin-right: 4px;
            vertical-align: middle;
        }}

        /* Scrollbar */
        .leaflet-popup-content::-webkit-scrollbar {{
            width: 4px;
        }}
        .leaflet-popup-content::-webkit-scrollbar-track {{
            background: transparent;
        }}
        .leaflet-popup-content::-webkit-scrollbar-thumb {{
            background: rgba(100, 200, 255, 0.3);
            border-radius: 2px;
        }}

        /* ── Click hint ── */
        .click-hint {{
            position: absolute;
            bottom: 24px;
            left: 16px;
            z-index: 1000;
            background: rgba(10, 10, 20, 0.88);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(100, 210, 255, 0.2);
            border-radius: 10px;
            padding: 10px 16px;
            font-size: 12px;
            color: #99aabb;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.35);
            pointer-events: none;
        }}

        .click-hint .hint-icon {{
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div id="map"></div>

    <div class="title-bar">
        <h1>WiFi Mapper</h1>
        <div class="subtitle">Reconnaissance Network Map</div>
    </div>

    <div class="stats-panel">
        <h2>Network Stats</h2>
        <div class="stat-row">
            <span class="stat-label">Total Scans</span>
            <span class="stat-value total">{total_scans}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Total Networks</span>
            <span class="stat-value total">{total_networks}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Unique BSSIDs</span>
            <span class="stat-value total">{unique_bssids}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Open Networks</span>
            <span class="stat-value open">{open_count}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Secured</span>
            <span class="stat-value secured">{total_networks - open_count}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Hidden SSIDs</span>
            <span class="stat-value hidden">{hidden_count}</span>
        </div>
    </div>

    <div class="legend">
        <div class="legend-title">Encryption</div>
        <div class="legend-item"><span class="legend-dot dot-open"></span> Open</div>
        <div class="legend-item"><span class="legend-dot dot-wpa"></span> WPA / WPA2</div>
        <div class="legend-item"><span class="legend-dot dot-wpa3"></span> WPA3 / WEP</div>
        <div class="legend-item"><span class="legend-dot dot-scan"></span> Scan Location</div>
    </div>

    <div class="click-hint">
        <span class="hint-icon">👆</span>
        <span>Click anywhere on the map to see nearby WiFi networks</span>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
    <script>
        const scanData = {js_data};

        // ── Init map ──
        const map = L.map('map', {{
            center: [{avg_lat}, {avg_lon}],
            zoom: 15,
            zoomControl: false
        }});

        L.control.zoom({{ position: 'bottomleft' }}).addTo(map);

        // CartoDB Dark Matter tiles (matches dark theme, no referer issues)
        L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
            attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>',
            maxZoom: 20,
            subdomains: 'abcd'
        }}).addTo(map);

        // ── Color helpers ──
        function encColor(enc) {{
            if (!enc || enc === 'Open') return '#30d158';
            if (enc.includes('WPA3') || enc === 'WEP') return '#ff453a';
            return '#ff9f0a';
        }}

        function encClass(enc) {{
            if (!enc || enc === 'Open') return 'enc-open';
            if (enc.includes('WPA3') || enc === 'WEP') return 'enc-wpa3';
            return 'enc-wpa';
        }}

        function signalToWidth(dbm) {{
            if (dbm === null || dbm === undefined) return 20;
            // -30 dBm = excellent, -90 dBm = terrible
            const pct = Math.max(0, Math.min(100, ((dbm + 90) / 60) * 100));
            return Math.max(10, pct * 0.8);
        }}

        function signalColor(dbm) {{
            if (dbm === null || dbm === undefined) return '#555';
            if (dbm > -50) return '#30d158';
            if (dbm > -70) return '#ff9f0a';
            return '#ff453a';
        }}

        // ── Heatmap data ──
        const heatPoints = [];

        // ── Haversine distance (meters) ──
        function haversine(lat1, lon1, lat2, lon2) {{
            const R = 6371000;
            const dLat = (lat2 - lat1) * Math.PI / 180;
            const dLon = (lon2 - lon1) * Math.PI / 180;
            const a = Math.sin(dLat/2)**2 +
                      Math.cos(lat1 * Math.PI/180) * Math.cos(lat2 * Math.PI/180) *
                      Math.sin(dLon/2)**2;
            return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        }}

        // ── Place static markers (no click handlers on markers) ──
        scanData.forEach((scan, idx) => {{
            const lat = scan.lat;
            const lon = scan.lon;
            const networks = scan.networks || [];

            if (lat === 0 && lon === 0) return;

            heatPoints.push([lat, lon, Math.min(networks.length / 5, 1)]);

            // Static scan location marker (no animation, not interactive)
            L.circleMarker([lat, lon], {{
                radius: 10,
                fillColor: '#64d2ff',
                fillOpacity: 0.6,
                color: '#a0e0ff',
                weight: 2,
                opacity: 0.8,
                interactive: false
            }}).addTo(map);

            // Static network dots around scan point
            networks.forEach(net => {{
                const jitter = 0.00012;
                const nlat = lat + (Math.random() - 0.5) * jitter;
                const nlon = lon + (Math.random() - 0.5) * jitter;
                L.circleMarker([nlat, nlon], {{
                    radius: 4,
                    fillColor: encColor(net.encryption),
                    fillOpacity: 0.7,
                    color: encColor(net.encryption),
                    weight: 1,
                    opacity: 0.4,
                    interactive: false
                }}).addTo(map);
            }});
        }});

        // ── Click anywhere → find nearest scan → show popup ──
        const SEARCH_RADIUS_M = 5000; // 5km max search radius

        map.on('click', function(e) {{
            const clickLat = e.latlng.lat;
            const clickLon = e.latlng.lng;

            // Find all scans within radius, sorted by distance
            const nearby = scanData
                .map((scan, idx) => ({{
                    ...scan,
                    idx: idx,
                    dist: haversine(clickLat, clickLon, scan.lat, scan.lon)
                }}))
                .filter(s => s.dist <= SEARCH_RADIUS_M && (s.lat !== 0 || s.lon !== 0))
                .sort((a, b) => a.dist - b.dist);

            if (nearby.length === 0) {{
                L.popup()
                    .setLatLng(e.latlng)
                    .setContent('<div class="popup-header">📡 No scan data nearby</div><div style="font-size:12px;color:#8899aa;padding:6px 0;">No WiFi scans found within 5 km of this point.<br>Run <code style="color:#64d2ff;">sudo python3 scanner.py</code> at this location to add data.</div>')
                    .openOn(map);
                return;
            }}

            // Collect all unique networks from nearby scans
            const seenBssids = new Set();
            const allNetworks = [];

            nearby.forEach(scan => {{
                (scan.networks || []).forEach(net => {{
                    if (!seenBssids.has(net.bssid)) {{
                        seenBssids.add(net.bssid);
                        allNetworks.push({{ ...net, scanIdx: scan.idx, scanDist: scan.dist, scanTs: scan.timestamp }});
                    }}
                }});
            }});

            // Sort: open first, then by signal
            allNetworks.sort((a, b) => {{
                if (a.encryption === 'Open' && b.encryption !== 'Open') return -1;
                if (b.encryption === 'Open' && a.encryption !== 'Open') return 1;
                return (b.signal_dbm || -100) - (a.signal_dbm || -100);
            }});

            const closestDist = nearby[0].dist;
            const distLabel = closestDist < 1000
                ? `${{Math.round(closestDist)}} m away`
                : `${{(closestDist / 1000).toFixed(1)}} km away`;

            let html = `<div class="popup-header">📡 ${{allNetworks.length}} network${{allNetworks.length !== 1 ? 's' : ''}} nearby<br><span style="font-size:10px;color:#667788;">Nearest scan: ${{distLabel}} · ${{nearby.length}} scan${{nearby.length !== 1 ? 's' : ''}} in range</span></div>`;

            allNetworks.forEach(net => {{
                const sig = net.signal_dbm !== null && net.signal_dbm !== undefined ? `${{net.signal_dbm}} dBm` : 'N/A';
                const ch = net.channel > 0 ? net.channel : '?';
                const band = net.channel > 14 ? '5GHz' : '2.4GHz';
                const barW = signalToWidth(net.signal_dbm);
                const barC = signalColor(net.signal_dbm);

                html += `
                <div class="popup-network">
                    <div>
                        <span class="popup-ssid">${{net.hidden ? '🔒 Hidden' : net.ssid}}</span>
                        <span class="popup-enc ${{encClass(net.encryption)}}">${{net.encryption}}</span>
                    </div>
                    <div class="popup-detail">
                        ${{net.bssid}} · Ch ${{ch}} (${{band}}) · ${{sig}}
                        <br>
                        <span class="signal-bar" style="width:${{barW}}px;background:${{barC}};"></span>
                    </div>
                </div>`;
            }});

            L.popup({{ maxWidth: 400, minWidth: 300 }})
                .setLatLng(e.latlng)
                .setContent(html)
                .openOn(map);
        }});

        // ── Heatmap layer ──
        if (heatPoints.length > 0) {{
            L.heatLayer(heatPoints, {{
                radius: 35,
                blur: 20,
                maxZoom: 17,
                gradient: {{
                    0.0: '#0a0a2e',
                    0.3: '#5e5ce6',
                    0.6: '#64d2ff',
                    0.8: '#30d158',
                    1.0: '#ff9f0a'
                }}
            }}).addTo(map);
        }}

        // ── Fit bounds ──
        if (scanData.length > 1) {{
            const bounds = scanData
                .filter(s => s.lat !== 0 || s.lon !== 0)
                .map(s => [s.lat, s.lon]);
            if (bounds.length > 1) {{
                map.fitBounds(bounds, {{ padding: [60, 60] }});
            }}
        }}
    </script>
</body>
</html>"""
    
    with open(output_file, "w") as f:
        f.write(html)
    
    print(f"{Fore.GREEN}[✓] Map generated → {output_file}{Style.RESET_ALL}")
    print(f"    Open in browser: file://{os.path.abspath(output_file)}")
    print(f"\n{Fore.CYAN}┌─ Map Stats ────────────────────────────────┐")
    print(f"│  Scan locations  : {total_scans:<24}│")
    print(f"│  Total networks  : {total_networks:<24}│")
    print(f"│  Unique BSSIDs   : {unique_bssids:<24}│")
    print(f"│  Open networks   : {Fore.GREEN}{open_count:<24}{Fore.CYAN}│")
    print(f"│  Secured         : {Fore.YELLOW}{total_networks - open_count:<24}{Fore.CYAN}│")
    print(f"│  Hidden SSIDs    : {Fore.RED}{hidden_count:<24}{Fore.CYAN}│")
    print(f"│  Center          : {avg_lat:.4f}, {avg_lon:.4f}{'':>12}│")
    print(f"└────────────────────────────────────────────┘{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="WiFi Mapper — Generate interactive map from scan data",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data", type=str, default="wifi_data.json",
                        help="Input JSON data file (default: wifi_data.json)")
    parser.add_argument("--out", type=str, default="map.html",
                        help="Output HTML map file (default: map.html)")
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗")
    print(f"║  {Fore.WHITE}WiFi Mapper — Map Viewer{Fore.CYAN}                     ║")
    print(f"╚══════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    data = load_data(args.data)
    generate_map(data, args.out)


if __name__ == "__main__":
    main()
