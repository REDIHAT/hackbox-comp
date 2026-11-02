# HackBox Compliant Firmware (`hackbox-comp`)

<p align="center">
  <img src="assets/hackbox-brand.jpg" alt="HackBox Branding" width="420" />
</p>

**HackBox Compliant (`hackbox-comp`)** is an educational cybersecurity research and RF auditing firmware for ESP32 devices. 

This repository provides the official source code and build configuration for devices shipped to users, built specifically to meet **strict RF compliance standards (FCC / Tindie Community Guidelines)**.

---

## RF Compliance & Design Assurance

This firmware build intentionally excludes and eliminates all forms of signal disruption, carrier generation, and offensive transmission tools:

- **NO RF Jamming / Continuous Carrier Generation:** All calls to `startConstCarrier()`, `stopConstCarrier()`, and intentional noise/jamming routines have been permanently removed.
- **NO MouseJack or RF Packet Injection:** The `mousejack` module and keystroke injection attacks have been permanently deleted from both the source tree and the menu hierarchy.
- **NO Replay Attack Module:** The `replay_attack` module has been completely removed.
- **Passive & Diagnostic Only:** Features are restricted to passive RF signal analysis, packet logging, BLE scanning/tag detection, WiFi security analysis (handshake analysis for network owners), and educational cybersecurity demonstrations.

---

## Included Modules

- **RF & Spectrum Tools:** RF Analyzer, Channel Analyzer, 2.4GHz Spectrum Scanner, Signal Wars scanner.
- **Environmental Detectors:** Camera Detector, Drone Detector, Flock Detector, Flipper Zero Detector, Meshtastic/MeshCore Detector, Pwnagotchi Detector, Ray-Ban Meta Detector, SmartTag & AirTag Detector.
- **WiFi Security & Diagnostics:** WiFi Scanner, Hidden Network Detector, Deauth Scanner (passive monitor), WPS Scanner, Wardriving, Packet Hunter & Packet Logger.
- **Bluetooth Low Energy (BLE):** BLE Scanner, BLE Inspector, Apple/Android device scout, HoneyBLE.
- **Hardware & System:** NeoPixel LED status indicators, OLED display manager, battery monitoring, sleep management, session logging.

---

## Build Instructions

### Prerequisites
- Python 3.8+
- PlatformIO Core:
  ```bash
  pip install platformio
  ```

### Compiling Firmware
To build the standard compliant firmware binary for ESP32:
```bash
platformio run -e hackbox-main
```

### Flashing to Hardware
Connect your ESP32 board via USB, then run:
```bash
platformio run -e hackbox-main -t upload
```

---

## Merged Binary Flashing (ESP Web Tools / esptool)

For web flashing or automated manufacturing, the firmware can be flashed using the pre-merged single binary or individual partition offsets:

| Binary Component | Flash Offset | Description |
| :--- | :--- | :--- |
| `bootloader.bin` | `0x1000` | ESP32 Second Stage Bootloader |
| `partitions.bin` | `0x8000` | Partition Table (`huge_app.csv`) |
| `boot_app0.bin` | `0xe000` | OTA Data Initialization |
| `firmware.bin` | `0x10000` | Main Application Binary |

Merged single-file binary:
- **`firmware/hackbox-comp-merged.bin`** (Flashed at offset `0x0000`)

---

## License

MIT License. See [LICENSE](LICENSE).

Developed and maintained by REDIHAT LABS for cybersecurity research, education, and authorized diagnostic auditing.
