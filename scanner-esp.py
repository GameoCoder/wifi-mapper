"""
WiFi Mapper — ESP32 Serial Scanner
=====================================
Reads raw promiscuous mode data from an ESP32 via USB Serial,
records MAC, channel, signal, and GPS/IP location to a rolling JSON file.

Usage:
    python3 esp_scanner.py --port /dev/ttyUSB0 [options]
"""

import argparse
import json
import os
import re
import sys
import time
import serial
from datetime import datetime, timezone

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()

try:
    import requests
except ImportError:
    requests = None

# ── Globals ──────────────────────────────────────────────────────────────────
DISCOVERED = {}  # BSSID/MAC -> network dict 

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  {Fore.WHITE}WiFi Mapper — ESP32 Serial Scanner{Fore.CYAN}                      ║
║  {Fore.YELLOW}Hardware Promiscuous Mode · JSON logging{Fore.CYAN}                ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""



# ── Location helpers ─────────────────────────────────────────────────────────

def get_location_termux():
    """Get location via Termux API (Android) — primary source for ESP32+phone setup."""
    import subprocess
    try:
        result = subprocess.run(
            ["termux-location", "-p", "gps", "-r", "once"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is not None and lon is not None:
            print(f"{Fore.GREEN}[✓] GPS fix from Termux: {lat:.6f}, {lon:.6f}{Style.RESET_ALL}")
            return {
                "lat": round(lat, 6),
                "lon": round(lon, 6),
                "accuracy_m": round(data.get("accuracy", 50)),
                "source": "termux_gps"
            }
    except FileNotFoundError:
        pass  # Not on Termux / termux-api not installed
    except json.JSONDecodeError:
        print(f"{Fore.YELLOW}[!] Termux GPS returned invalid data{Style.RESET_ALL}")
    except subprocess.TimeoutExpired:
        print(f"{Fore.YELLOW}[!] Termux GPS timed out (no fix in 30s){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Termux GPS error: {e}{Style.RESET_ALL}")
    return None


def get_location_gpsd():
    """Get location via gpsd (Linux with GPS hardware or phone tethering)."""
    try:
        import gps
        session = gps.gps(mode=gps.WATCH_ENABLE)
        for _ in range(10):
            report = session.next()
            if report["class"] == "TPV":
                lat = getattr(report, "lat", None)
                lon = getattr(report, "lon", None)
                if lat is not None and lon is not None:
                    print(f"{Fore.GREEN}[✓] GPS fix from gpsd: {lat:.6f}, {lon:.6f}{Style.RESET_ALL}")
                    return {
                        "lat": round(lat, 6),
                        "lon": round(lon, 6),
                        "accuracy_m": 10,
                        "source": "gpsd"
                    }
    except ImportError:
        pass  # gps module not installed
    except Exception:
        pass  # gpsd not running or no fix
    return None


def get_location_ip():
    """Get approximate location via IP geolocation (ip-api.com, free)."""
    if requests is None:
        return None
    try:
        r = requests.get("http://ip-api.com/json/?fields=lat,lon,city,query", timeout=5)
        data = r.json()
        if "lat" in data and "lon" in data:
            print(f"{Fore.GREEN}[✓] Location from IP: {data['lat']:.4f}, {data['lon']:.4f} "
                  f"({data.get('city', '?')}){Style.RESET_ALL}")
            return {
                "lat": round(data["lat"], 6),
                "lon": round(data["lon"], 6),
                "accuracy_m": 5000,
                "source": "ip_geolocation",
                "note": f"IP: {data.get('query', '?')}, City: {data.get('city', '?')}"
            }
    except Exception:
        pass
    return None


def get_location(manual_lat=None, manual_lon=None):
    """Try all location sources in priority order."""
    # 1. Manual override
    if manual_lat is not None and manual_lon is not None:
        print(f"{Fore.GREEN}[✓] Using manual coordinates: {manual_lat}, {manual_lon}{Style.RESET_ALL}")
        return {
            "lat": round(manual_lat, 6),
            "lon": round(manual_lon, 6),
            "accuracy_m": 0,
            "source": "manual"
        }

    # 2. Termux GPS (primary — this is an Android+ESP32 setup)
    loc = get_location_termux()
    if loc:
        return loc

    # 3. gpsd (Linux with GPS dongle)
    loc = get_location_gpsd()
    if loc:
        return loc

    # 4. IP geolocation fallback
    loc = get_location_ip()
    if loc:
        return loc

    # 5. Nothing worked
    print(f"{Fore.RED}[!] Could not determine location. Use --lat and --lon flags.{Style.RESET_ALL}")
    return {"lat": 0.0, "lon": 0.0, "accuracy_m": -1, "source": "unknown"}

# ── Channel / frequency helpers ─────────────────────────────────────────────
CHANNEL_FREQ_MAP = {
    1: 2.412, 2: 2.417, 3: 2.422, 4: 2.427, 5: 2.432,
    6: 2.437, 7: 2.442, 8: 2.447, 9: 2.452, 10: 2.457,
    11: 2.462, 12: 2.467, 13: 2.472, 14: 2.484,
}

# ── JSON persistence ────────────────────────────────────────────────────────
def save_results(output_file, location):
    if not DISCOVERED:
        print(f"{Fore.RED}[!] No packets discovered. Nothing to save.{Style.RESET_ALL}")
        return

    existing = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                existing = json.load(f)
        except:
            existing = []

    scan_entry = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "location": location,
        "networks": list(DISCOVERED.values())
    }

    existing.append(scan_entry)
    with open(output_file, "w") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    print(f"\n{Fore.GREEN}[✓] Saved {len(DISCOVERED)} devices to {output_file}{Style.RESET_ALL}")

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WiFi Mapper — ESP32 Scanner")
    parser.add_argument("--port", type=str, required=True, help="Serial port (e.g., /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--timeout", type=int, default=30, help="Scan duration in seconds")
    parser.add_argument("--lat", type=float, help="Manual latitude override")
    parser.add_argument("--lon", type=float, help="Manual longitude override")
    parser.add_argument("--out", type=str, default="wifi_data.json", help="Output JSON file")
    args = parser.parse_args()

    print(BANNER)

    print(f"{Fore.WHITE}[i] Acquiring location...{Style.RESET_ALL}")
    location = get_location(args.lat, args.lon)
    print(f"{Fore.WHITE}[i] Location: {Fore.CYAN}{location['lat']}, {location['lon']} "
          f"{Fore.WHITE}(source: {location['source']}, accuracy: {location['accuracy_m']}m){Style.RESET_ALL}")

    print(f"\n{Fore.WHITE}[i] Listening to ESP32 on {args.port} for {args.timeout}s...")
    print(f"{'─' * 80}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{'#':>5}  {'MAC Address':<19} {'Channel':<15} {'Signal':<10}{Style.RESET_ALL}")
    print(f"{'─' * 80}")

    # Regex to match: "1: TP-Link_2.4G_17A4D2 (-46 dBm) MAC: AC:84:C6:17:A4:D2 | Ch: 6 | Enc: 0"
    # Loosened regex to tolerate extra/missing spaces
    regex = re.compile(r"^\d+:\s*(.*?)\s*\((-?\d+)\s*dBm\)\s*MAC:\s*([a-fA-F0-9:]+)\s*\|\s*Ch:\s*(\d+)\s*\|\s*Enc:\s*(\d+)")

    start_time = time.time()
    
    try:
        # explicitly configure serial to PREVENT the ESP32 from resetting
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = 1
        ser.dtr = False  # Crucial for ESP32
        ser.rts = False  # Crucial for ESP32
        ser.open()
        
        with ser:
            while (time.time() - start_time) < args.timeout:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                
                # Ignore empty lines, dividers, and status messages
                if not line or "Scanning" in line or "networks found" in line or "---" in line:
                    continue

                match = regex.search(line)
                if match:
                    ssid = match.group(1).strip()
                    signal = int(match.group(2))
                    mac = match.group(3).upper()
                    channel = int(match.group(4))
                    enc_raw = int(match.group(5))

                    enc_str = "Open"
                    if enc_raw == 1: enc_str = "WEP"
                    elif enc_raw == 2: enc_str = "WPA"
                    elif enc_raw in [3, 4, 5]: enc_str = "WPA2"
                    elif enc_raw >= 6: enc_str = "WPA3"

                    if mac not in DISCOVERED:
                        freq = CHANNEL_FREQ_MAP.get(channel, 0)
                        
                        DISCOVERED[mac] = {
                            "ssid": ssid,
                            "bssid": mac,
                            "channel": channel,
                            "frequency_ghz": freq,
                            "signal_dbm": signal,
                            "encryption": enc_str,
                            "hidden": (ssid == "" or ssid.startswith("<Hidden>"))
                        }
                        
                        band = "5GHz" if channel > 14 else "2.4GHz"
                        enc_color = Fore.GREEN if enc_str == "Open" else (Fore.RED if "WPA3" in enc_str else Fore.YELLOW)
                        
                        print(f"  {Fore.WHITE}[{len(DISCOVERED):>3}] "
                              f"{Fore.CYAN}{ssid[:22]:<22} "
                              f"{Fore.WHITE}{mac:<18} "
                              f"{Fore.MAGENTA}Ch {channel:<3} "
                              f"{Fore.BLUE}{signal:<4} dBm  "
                              f"{enc_color}{enc_str}{Style.RESET_ALL}")
                else:
                    # DEBUG: If Python gets data but the regex fails, it will print here
                    print(f"{Fore.YELLOW}[DEBUG] Ignored/Unmatched Line: {line}{Style.RESET_ALL}")

    except serial.SerialException as e:
        print(f"{Fore.RED}[✗] Serial Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")

    print(f"{'─' * 80}")
    print(f"\n{Fore.WHITE}[i] Scan complete. Found {Fore.GREEN}{len(DISCOVERED)}{Fore.WHITE} unique MACs.{Style.RESET_ALL}")
    save_results(args.out, location)

if __name__ == "__main__":
    main()