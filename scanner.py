#!/usr/bin/env python3
"""
WiFi Mapper — Reconnaissance Scanner
=====================================
Scans nearby WiFi networks (open + private) using monitor mode,
records SSID, BSSID, channel, signal, encryption type, and GPS/IP
location to a rolling JSON file.

Requires: root/sudo, wireless interface that supports monitor mode.

Usage:
    sudo python3 scanner.py [options]

Options:
    --iface IFACE       Wireless interface (auto-detects wlan* if omitted)
    --timeout SECONDS   Scan duration in seconds (default: 30)
    --lat LAT           Manual latitude override
    --lon LON           Manual longitude override
    --out FILE          Output JSON file (default: wifi_data.json)
"""

import argparse
import atexit
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    from scapy.all import sniff, conf
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy>=2.5.0")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Fallback: no colors
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()

try:
    import requests
except ImportError:
    requests = None


# ── Globals ──────────────────────────────────────────────────────────────────

ORIGINAL_IFACE = None       # To restore managed mode on exit
MONITOR_IFACE = None        # The monitor-mode interface name
DISCOVERED = {}             # BSSID -> network dict (dedup within a single run)


# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  {Fore.WHITE}WiFi Mapper — Reconnaissance Scanner{Fore.CYAN}                    ║
║  {Fore.YELLOW}Passive scan · All networks · JSON logging{Fore.CYAN}              ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


# ── Interface helpers ────────────────────────────────────────────────────────

def find_wireless_iface():
    """Auto-detect the first wlan* or wlp* interface."""
    try:
        output = subprocess.check_output(["iw", "dev"], text=True)
        match = re.search(r"Interface\s+(wl\S+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass

    # Fallback: check /sys/class/net
    for iface in os.listdir("/sys/class/net"):
        if iface.startswith(("wlan", "wlp")):
            return iface
    return None


def enable_monitor_mode(iface):
    """Put interface into monitor mode. Returns the monitor iface name."""
    global ORIGINAL_IFACE, MONITOR_IFACE
    ORIGINAL_IFACE = iface

    print(f"{Fore.YELLOW}[*] Enabling monitor mode on {iface}...{Style.RESET_ALL}")

    # Kill processes that might interfere
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)

    # Try airmon-ng first
    try:
        result = subprocess.run(
            ["airmon-ng", "start", iface],
            capture_output=True, text=True, timeout=10
        )
        # airmon-ng may rename interface to wlan0mon or similar
        output = result.stdout + result.stderr
        mon_match = re.search(r"\(monitor mode.*enabled.*on\s+(\S+)\)", output, re.IGNORECASE)
        if mon_match:
            MONITOR_IFACE = mon_match.group(1)
        else:
            # Check if <iface>mon exists now
            candidate = iface + "mon"
            if os.path.exists(f"/sys/class/net/{candidate}"):
                MONITOR_IFACE = candidate
            else:
                MONITOR_IFACE = iface
        print(f"{Fore.GREEN}[✓] Monitor mode enabled → {MONITOR_IFACE}{Style.RESET_ALL}")
        return MONITOR_IFACE
    except FileNotFoundError:
        pass  # airmon-ng not available, try manual

    # Manual fallback with iw
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
        subprocess.run(["iw", iface, "set", "monitor", "control"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
        MONITOR_IFACE = iface
        print(f"{Fore.GREEN}[✓] Monitor mode enabled → {MONITOR_IFACE} (via iw){Style.RESET_ALL}")
        return MONITOR_IFACE
    except Exception as e:
        print(f"{Fore.RED}[✗] Failed to enable monitor mode: {e}{Style.RESET_ALL}")
        sys.exit(1)


def disable_monitor_mode():
    """Restore managed mode on the original interface."""
    if not ORIGINAL_IFACE:
        return
    print(f"\n{Fore.YELLOW}[*] Restoring managed mode on {ORIGINAL_IFACE}...{Style.RESET_ALL}")

    # Try airmon-ng stop first
    iface_to_stop = MONITOR_IFACE or ORIGINAL_IFACE
    try:
        subprocess.run(["airmon-ng", "stop", iface_to_stop], capture_output=True, timeout=10)
        print(f"{Fore.GREEN}[✓] Managed mode restored.{Style.RESET_ALL}")
        # Restart NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
        return
    except (FileNotFoundError, Exception):
        pass

    # Manual restore
    try:
        subprocess.run(["ip", "link", "set", iface_to_stop, "down"], capture_output=True)
        subprocess.run(["iw", iface_to_stop, "set", "type", "managed"], capture_output=True)
        subprocess.run(["ip", "link", "set", ORIGINAL_IFACE, "up"], capture_output=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
        print(f"{Fore.GREEN}[✓] Managed mode restored.{Style.RESET_ALL}")
    except Exception:
        print(f"{Fore.RED}[!] Could not restore managed mode. Run manually:{Style.RESET_ALL}")
        print(f"    sudo airmon-ng stop {iface_to_stop}")


# ── Location helpers ─────────────────────────────────────────────────────────

def get_location_ip():
    """Get approximate location via IP geolocation (ip-api.com, free)."""
    if requests is None:
        return None
    try:
        r = requests.get("http://ip-api.com/json/?fields=lat,lon,city,query", timeout=5)
        data = r.json()
        if "lat" in data and "lon" in data:
            return {
                "lat": round(data["lat"], 6),
                "lon": round(data["lon"], 6),
                "accuracy_m": 5000,  # IP geolocation is coarse
                "source": "ip_geolocation",
                "note": f"IP: {data.get('query', '?')}, City: {data.get('city', '?')}"
            }
    except Exception:
        pass
    return None


def get_location_gpsd():
    """Get location via gpsd (if running)."""
    try:
        import gps
        session = gps.gps(mode=gps.WATCH_ENABLE)
        for _ in range(10):
            report = session.next()
            if report["class"] == "TPV":
                lat = getattr(report, "lat", None)
                lon = getattr(report, "lon", None)
                if lat and lon:
                    return {
                        "lat": round(lat, 6),
                        "lon": round(lon, 6),
                        "accuracy_m": 10,
                        "source": "gpsd"
                    }
    except Exception:
        pass
    return None


def get_location_termux():
    """Get location via Termux API (Android)."""
    try:
        result = subprocess.run(
            ["termux-location", "-p", "gps", "-r", "once"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        return {
            "lat": round(data["latitude"], 6),
            "lon": round(data["longitude"], 6),
            "accuracy_m": round(data.get("accuracy", 50)),
            "source": "termux_gps"
        }
    except Exception:
        pass
    return None


def get_location(manual_lat=None, manual_lon=None):
    """Try all location sources in order of accuracy."""
    if manual_lat is not None and manual_lon is not None:
        return {
            "lat": round(manual_lat, 6),
            "lon": round(manual_lon, 6),
            "accuracy_m": 0,
            "source": "manual"
        }

    # Try GPS first
    loc = get_location_gpsd()
    if loc:
        return loc

    # Try Termux
    loc = get_location_termux()
    if loc:
        return loc

    # Fallback to IP
    loc = get_location_ip()
    if loc:
        return loc

    print(f"{Fore.RED}[!] Could not determine location. Use --lat and --lon flags.{Style.RESET_ALL}")
    return {"lat": 0.0, "lon": 0.0, "accuracy_m": -1, "source": "unknown"}


# ── Encryption detection ────────────────────────────────────────────────────

def get_encryption(packet):
    """Parse Dot11Elt layers to determine encryption type."""
    crypto = set()
    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                         "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").strip()

    if "privacy" not in cap:
        return "Open"

    # Walk through information elements
    elt = packet.getlayer(Dot11Elt)
    while elt:
        # RSN (WPA2/WPA3) — tag 48
        if elt.ID == 48:
            crypto.add("WPA2")
            # Check for SAE (WPA3) in AKM suites
            if elt.info and b"\x00\x0f\xac\x08" in elt.info:
                crypto.add("WPA3")
        # WPA — vendor specific tag 221 with Microsoft OUI
        if elt.ID == 221 and elt.info and elt.info.startswith(b"\x00\x50\xf2\x01"):
            crypto.add("WPA")
        elt = elt.payload.getlayer(Dot11Elt)

    if not crypto:
        crypto.add("WEP")  # privacy bit set but no RSN/WPA → WEP

    return "/".join(sorted(crypto))


# ── Channel / frequency helpers ─────────────────────────────────────────────

CHANNEL_FREQ_MAP = {
    1: 2.412, 2: 2.417, 3: 2.422, 4: 2.427, 5: 2.432,
    6: 2.437, 7: 2.442, 8: 2.447, 9: 2.452, 10: 2.457,
    11: 2.462, 12: 2.467, 13: 2.472, 14: 2.484,
    36: 5.180, 40: 5.200, 44: 5.220, 48: 5.240,
    52: 5.260, 56: 5.280, 60: 5.300, 64: 5.320,
    100: 5.500, 104: 5.520, 108: 5.540, 112: 5.560,
    116: 5.580, 120: 5.600, 124: 5.620, 128: 5.640,
    132: 5.660, 136: 5.680, 140: 5.700, 144: 5.720,
    149: 5.745, 153: 5.765, 157: 5.785, 161: 5.805, 165: 5.825,
}


def get_channel(packet):
    """Extract WiFi channel from Dot11Elt DS Parameter Set (tag 3)."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) == 1:  # DS Parameter Set
            return int(elt.info[0])
        elt = elt.payload.getlayer(Dot11Elt)

    # Fallback: try RadioTap Channel field
    if packet.haslayer(RadioTap):
        try:
            freq = packet[RadioTap].Channel
            if freq:
                # Reverse lookup
                for ch, f_ghz in CHANNEL_FREQ_MAP.items():
                    if abs(freq - f_ghz * 1000) < 5:
                        return ch
        except Exception:
            pass
    return -1


def get_signal(packet):
    """Extract signal strength (dBm) from RadioTap header."""
    if packet.haslayer(RadioTap):
        try:
            return packet[RadioTap].dBm_AntSignal
        except Exception:
            pass
    return None


# ── Channel hopping ─────────────────────────────────────────────────────────

HOPPING = True

def channel_hopper(iface):
    """Hop through WiFi channels 1-14 (2.4GHz) and 36-165 (5GHz)."""
    channels_2g = list(range(1, 15))
    channels_5g = [36, 40, 44, 48, 52, 56, 60, 64,
                   100, 104, 108, 112, 116, 120, 124, 128,
                   132, 136, 140, 144, 149, 153, 157, 161, 165]
    all_channels = channels_2g + channels_5g

    while HOPPING:
        for ch in all_channels:
            if not HOPPING:
                return
            try:
                subprocess.run(
                    ["iw", "dev", iface, "set", "channel", str(ch)],
                    capture_output=True, timeout=2
                )
            except Exception:
                pass
            time.sleep(0.15)


# ── Packet handler ───────────────────────────────────────────────────────────

def packet_handler(packet):
    """Process each captured Dot11 Beacon / ProbeResp frame."""
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    bssid = packet[Dot11].addr2
    if not bssid:
        return

    # Deduplicate within this run
    if bssid in DISCOVERED:
        return

    # Extract SSID
    ssid = ""
    elt = packet.getlayer(Dot11Elt)
    if elt and elt.ID == 0:
        try:
            ssid = elt.info.decode("utf-8", errors="replace")
        except Exception:
            ssid = ""

    hidden = (ssid == "" or ssid == "\x00" * len(ssid.encode()))
    if hidden:
        ssid = "<Hidden>"

    channel = get_channel(packet)
    signal = get_signal(packet)
    encryption = get_encryption(packet)
    freq = CHANNEL_FREQ_MAP.get(channel, 0)

    network = {
        "ssid": ssid,
        "bssid": bssid.upper(),
        "channel": channel,
        "frequency_ghz": freq,
        "signal_dbm": signal,
        "encryption": encryption,
        "hidden": hidden
    }

    DISCOVERED[bssid] = network

    # Pretty print
    enc_color = Fore.GREEN if encryption == "Open" else (Fore.RED if "WPA3" in encryption else Fore.YELLOW)
    sig_str = f"{signal} dBm" if signal is not None else "N/A"
    band = "5GHz" if channel > 14 else "2.4GHz"

    print(
        f"  {Fore.WHITE}[{len(DISCOVERED):>3}] "
        f"{Fore.CYAN}{ssid:<32} "
        f"{Fore.WHITE}{bssid}  "
        f"{Fore.MAGENTA}Ch {channel:<3} ({band})  "
        f"{Fore.BLUE}{sig_str:<10} "
        f"{enc_color}{encryption}{Style.RESET_ALL}"
    )


# ── JSON persistence ────────────────────────────────────────────────────────

def save_results(output_file, location):
    """Append scan results to the JSON data file."""
    if not DISCOVERED:
        print(f"{Fore.RED}[!] No networks discovered. Nothing to save.{Style.RESET_ALL}")
        return

    # Load existing data
    existing = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except (json.JSONDecodeError, IOError):
            existing = []

    # Build new scan entry
    scan_entry = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "location": location,
        "networks": list(DISCOVERED.values())
    }

    existing.append(scan_entry)

    # Write back
    with open(output_file, "w") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    total_networks = sum(len(e["networks"]) for e in existing)
    print(f"\n{Fore.GREEN}[✓] Saved {len(DISCOVERED)} networks to {output_file}")
    print(f"    Total entries in file: {len(existing)} scans, {total_networks} network records{Style.RESET_ALL}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global HOPPING

    parser = argparse.ArgumentParser(
        description="WiFi Mapper — Reconnaissance Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  sudo python3 scanner.py --timeout 60 --out wifi_data.json"
    )
    parser.add_argument("--iface", type=str, help="Wireless interface (auto-detects if omitted)")
    parser.add_argument("--timeout", type=int, default=30, help="Scan duration in seconds (default: 30)")
    parser.add_argument("--lat", type=float, help="Manual latitude override")
    parser.add_argument("--lon", type=float, help="Manual longitude override")
    parser.add_argument("--out", type=str, default="wifi_data.json", help="Output JSON file (default: wifi_data.json)")
    args = parser.parse_args()

    print(BANNER)

    # ── Check root ──
    if os.geteuid() != 0:
        print(f"{Fore.RED}[✗] This script requires root privileges.")
        print(f"    Run with: sudo python3 scanner.py{Style.RESET_ALL}")
        sys.exit(1)

    # ── Find interface ──
    iface = args.iface or find_wireless_iface()
    if not iface:
        print(f"{Fore.RED}[✗] No wireless interface found. Specify with --iface{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.WHITE}[i] Interface: {Fore.CYAN}{iface}{Style.RESET_ALL}")

    # ── Get location ──
    print(f"{Fore.WHITE}[i] Acquiring location...{Style.RESET_ALL}")
    location = get_location(args.lat, args.lon)
    print(f"{Fore.WHITE}[i] Location: {Fore.CYAN}{location['lat']}, {location['lon']} "
          f"{Fore.WHITE}(source: {location['source']}, accuracy: {location['accuracy_m']}m){Style.RESET_ALL}")

    # ── Monitor mode ──
    mon_iface = enable_monitor_mode(iface)

    # Register cleanup
    atexit.register(disable_monitor_mode)
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # ── Start channel hopping in background ──
    import threading
    hop_thread = threading.Thread(target=channel_hopper, args=(mon_iface,), daemon=True)
    hop_thread.start()

    # ── Scan ──
    print(f"\n{Fore.WHITE}[i] Scanning for {args.timeout}s on {mon_iface} (all channels)...")
    print(f"{'─' * 100}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{'#':>5}  {'SSID':<32} {'BSSID':<19} {'Channel':<15} {'Signal':<10} Encryption{Style.RESET_ALL}")
    print(f"{'─' * 100}")

    try:
        sniff(
            iface=mon_iface,
            prn=packet_handler,
            timeout=args.timeout,
            store=0  # Don't store packets in memory
        )
    except PermissionError:
        print(f"{Fore.RED}[✗] Permission denied. Are you running as root?{Style.RESET_ALL}")
        sys.exit(1)
    except OSError as e:
        print(f"{Fore.RED}[✗] Interface error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # ── Stop hopping ──
    HOPPING = False
    print(f"{'─' * 100}")
    print(f"\n{Fore.WHITE}[i] Scan complete. Found {Fore.GREEN}{len(DISCOVERED)}{Fore.WHITE} unique networks.{Style.RESET_ALL}")

    # ── Save ──
    save_results(args.out, location)

    # ── Summary ──
    open_count = sum(1 for n in DISCOVERED.values() if n["encryption"] == "Open")
    secured_count = len(DISCOVERED) - open_count
    print(f"\n{Fore.CYAN}┌─ Summary ────────────────────────────────┐")
    print(f"│  Total networks : {len(DISCOVERED):<22}│")
    print(f"│  Open           : {Fore.GREEN}{open_count:<22}{Fore.CYAN}│")
    print(f"│  Secured        : {Fore.YELLOW}{secured_count:<22}{Fore.CYAN}│")
    print(f"│  Location       : {location['lat']}, {location['lon']:<10}│")
    print(f"└──────────────────────────────────────────┘{Style.RESET_ALL}")
    print(f"\n{Fore.WHITE}[i] Generate map: python3 map_viewer.py --data {args.out}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
