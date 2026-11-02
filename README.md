# HackBox Compliant Firmware (`hackbox-comp`)

<p align="center">
  <img src="assets/hackbox-brand.jpg" alt="HackBox Branding" width="420" />
</p>

[![Build HackBox Compliant Firmware](https://github.com/REDIHAT/hackbox-comp/actions/workflows/build.yml/badge.svg)](https://github.com/REDIHAT/hackbox-comp/actions/workflows/build.yml)
[![GitHub Release](https://img.shields.io/github/v/release/REDIHAT/hackbox-comp?color=brightgreen)](https://github.com/REDIHAT/hackbox-comp/releases/latest)

**HackBox Compliant (`hackbox-comp`)** is an educational cybersecurity research and RF auditing firmware for ESP32 devices. 

This repository provides the official source code and build configuration for devices shipped to customers, built specifically to meet **strict RF compliance standards (FCC & Tindie Community Guidelines)**.

---

## RF Compliance & Design Assurance

This firmware build intentionally excludes and eliminates all forms of signal disruption, carrier generation, and offensive transmission tools:

- **NO RF Jamming / Continuous Carrier Generation:** All calls to `startConstCarrier()`, `stopConstCarrier()`, and intentional noise/jamming routines have been permanently removed.
- **NO MouseJack or RF Packet Injection:** The `mousejack` module and keystroke injection attacks have been permanently deleted from both the source tree and the menu hierarchy.
- **NO Replay Attack Module:** The `replay_attack` module has been completely removed.
- **Passive & Diagnostic Only:** Features are restricted to passive RF signal analysis, packet logging, BLE scanning/tag detection, WiFi security analysis (handshake analysis for network owners), and educational cybersecurity demonstrations.

---

## Precompiled Compliant Binaries (Release v1.0.0-compliant)

Official prebuilt binaries can be downloaded directly from the [Latest Release](https://github.com/REDIHAT/hackbox-comp/releases/latest):

| Binary Asset | Flash Offset | Description | Direct Download |
| :--- | :--- | :--- | :--- |
| **`hackbox-comp-merged.bin`** | `0x0000` | **Merged single-file binary** (Plug & Flash) | [Download](https://github.com/REDIHAT/hackbox-comp/releases/download/v1.0.0-compliant/hackbox-comp-merged.bin) |
| `firmware.bin` | `0x10000` | Main application firmware | [Download](https://github.com/REDIHAT/hackbox-comp/releases/download/v1.0.0-compliant/firmware.bin) |
| `bootloader.bin` | `0x1000` | ESP32 secondary bootloader | [Download](https://github.com/REDIHAT/hackbox-comp/releases/download/v1.0.0-compliant/bootloader.bin) |
| `partitions.bin` | `0x8000` | Partition table (`huge_app.csv`) | [Download](https://github.com/REDIHAT/hackbox-comp/releases/download/v1.0.0-compliant/partitions.bin) |

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
  pip install platformio esptool
  ```

### Compiling Firmware
To build the standard compliant firmware binary for ESP32:
```bash
platformio run -e hackbox-main
```

### Merging Binaries
To build the single-file merged binary:
```bash
python -m esptool --chip esp32 merge_bin -o hackbox-comp-merged.bin --flash_mode dio --flash_size 4MB 0x1000 .pio/build/hackbox-main/bootloader.bin 0x8000 .pio/build/hackbox-main/partitions.bin 0xe000 $BOOT_APP0 0x10000 .pio/build/hackbox-main/firmware.bin
```

### Flashing to Hardware
Connect your ESP32 board via USB, then run:
```bash
platformio run -e hackbox-main -t upload
```

Or flash the merged binary directly using `esptool`:
```bash
python -m esptool --chip esp32 write_flash 0x0 hackbox-comp-merged.bin
```

---

## License

MIT License. See [LICENSE](LICENSE).

Developed and maintained by REDIHAT LABS for cybersecurity research, education, and authorized diagnostic auditing.
