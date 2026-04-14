# WiFi Mapper 📡

A cross-platform WiFi reconnaissance tool that passively scans nearby networks, logs them with GPS coordinates to a rolling JSON file, and generates an interactive dark-themed map.

**No API keys needed.** Uses OpenStreetMap + Leaflet.js (free).

**🚀 NEW: Hardware Bypass Mode!** WiFi Mapper now supports offloading packet capture to an ESP32 microcontroller, completely bypassing Android/MediaTek monitor mode driver restrictions via USB OTG.

---

## Features

- 🔍 **Passive WiFi Scanning** — Captures raw 802.11 frames via native monitor mode OR ESP32 hardware promiscuous mode.
- 🔐 **All Networks** — Open, WPA, WPA2, WPA3, WEP — everything gets logged.
- 📍 **Location Tracking** — GPS (gpsd), Termux GPS API, IP geolocation, or manual coordinates.
- 📊 **Rolling JSON Log** — Each scan appends to `wifi_data.json`. Persists across reboots/sessions.
- 🗺️ **Interactive Map** — Dark-themed Leaflet.js map with color-coded markers, heatmap overlay, and network popups.
- 📱 **True Cross-Platform** — Runs on Linux (native) or Android (Termux + USB OTG).
- 📶 **Channel Hopping** — Automatically sweeps Wi-Fi channels to ensure maximum coverage.

---

## Architecture Modes

### Mode 1: Native Linux Scanner (`scanner.py`)
Uses standard Linux networking tools to put your Wi-Fi card into monitor mode.
* **Requires:** Linux OS, Root/Sudo, a Wi-Fi adapter supporting monitor mode (e.g., Atheros, RTL8812AU), `aircrack-ng` or `iw`.

### Mode 2: ESP32 Hardware Bypass (`scanner-esp.py`)
Uses an ESP32 (like the DOIT DevKit V1) programmed in C++ to sniff packets out of the air. The ESP32 connects to your phone/PC via USB and streams parsed network data to Python over serial.
* **Requires:** ESP32 Board, USB data cable (and OTG adapter for Android), Termux/Linux. Root is **not** strictly required for the Wi-Fi capture part!

---

## Installation & Requirements

### Python Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `scapy`, `colorama`, `requests`, `pyserial`)*

### Android (Termux) ESP32 Setup
1. Install Termux and Termux:API from F-Droid.
2. Connect your ESP32 to your phone via USB-C OTG.
3. Install packages:
```bash
pkg install python root-repo termux-api
pip install pyserial colorama requests
```

---

## Quick Start

### 1. Scan Networks

**If using the ESP32 (Plugged in via USB):**
```bash
# Basic scan (30 seconds, adjust port as needed)
sudo python3 scanner-esp.py --port /dev/ttyUSB0

# Custom duration and manual GPS
sudo python3 scanner-esp.py --port /dev/ttyACM0 --timeout 60 --lat 17.385 --lon 78.486
```

**If using Native Linux (Monitor Mode):**
```bash
# Basic scan (auto-detect interface)
sudo python3 scanner.py

# Custom interface
sudo python3 scanner.py --iface wlan0 --timeout 60
```

### 2. Generate Map

```bash
python3 map_viewer.py

# Or with custom files
python3 map_viewer.py --data wifi_data.json --out map.html
```

Then open the newly generated `map.html` in any web browser.

---

## Data Format

Each scan is appended as an entry in a JSON array (`wifi_data.json`):

```json
{
  "timestamp": "2026-04-14T21:31:00+05:30",
  "location": {
    "lat": 17.385,
    "lon": 78.486,
    "accuracy_m": 50,
    "source": "ip_geolocation"
  },
  "networks": [
    {
      "ssid": "MyNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "channel": 6,
      "frequency_ghz": 2.437,
      "signal_dbm": -67,
      "encryption": "WPA2",
      "hidden": false
    }
  ]
}
```

---

## Map Features

| Feature | Description |
|---------|-------------|
| 🔵 Pulsing blue circles | Scan locations (click for network details) |
| 🟢 Green dots | Open networks |
| 🟡 Yellow dots | WPA/WPA2 secured |
| 🔴 Red dots | WPA3/WEP |
| 🌡️ Heatmap overlay | Network density visualization |
| 📊 Stats panel | Total networks, open vs secured, hidden SSIDs |

---

## CLI Reference

### `scanner-esp.py` (Hardware Bypass)
| Flag | Default | Description |
|------|---------|-------------|
| `--port` | **Required** | Serial port of ESP32 (e.g. `/dev/ttyUSB0`) |
| `--baud` | `115200` | Baud rate for serial connection |
| `--timeout` | `30` | Scan duration (seconds) |
| `--out` | `wifi_data.json` | Output JSON file path |

### `scanner.py` (Native Linux)
| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | auto-detect | Wireless interface name |
| `--timeout` | `30` | Scan duration (seconds) |
| `--out` | `wifi_data.json` | Output JSON file path |

### `map_viewer.py`
| Flag | Default | Description |
|------|---------|-------------|
| `--data` | `wifi_data.json` | Input JSON data file |
| `--out` | `map.html` | Output HTML map file |

---

## Project Structure

```text
wifi-mapper-ag/
├── scanner-esp.py       # Serial scanner (Bypasses Android driver limits via ESP32)
├── scanner.py           # Native Linux WiFi scanner (airmon-ng + Scapy)
├── map_viewer.py        # Interactive HTML map generator
├── wifi_data.json       # Rolling scan data (created on first run)
├── map.html             # Generated map (open in browser)
├── requirements.txt     # Python dependencies
└── README.md
```

---

## Disclaimer

This tool is for **authorized security research and educational purposes only**. Only scan networks you own or have explicit permission to analyze. Monitor mode scanning may be subject to local laws — check your jurisdiction.