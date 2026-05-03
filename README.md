# hackbox_ck42x

CK42X-themed ESP32 firmware based on the hackbox/hackbox lineage, with selected
hackbox improvements brought into a fresh PlatformIO project layout.

This repository is source-only: prebuilt firmware binaries from the donor tree
were intentionally left out so releases can be rebuilt from the sanitized source.

## Included

- Root-level PlatformIO project layout from hackbox
- CK42X themed WiFi and BLE name sets
- Camera Detector and AIO Find Mode
- Packet Logger and Traffic Monitor
- Wardriving, probe logging, RSSI tooling, and session logging
- Remote control dashboard
- Theme, menu, and UI updates from hackbox
- Existing hackbox tools carried forward from hackbox where still referenced

## Omitted

- The RF-jamming module and menu entry from the donor firmware
- Prebuilt donor firmware binaries

Use this firmware only on hardware and networks you own or have explicit
permission to test.

## Build

Install PlatformIO, then build the main target:

```bash
pip install platformio
platformio run -e hackbox-main
```

Build and upload to a connected board:

```bash
platformio run -e hackbox-main -t upload --upload-port COM4
```

Optional targets:

```bash
platformio run -e hackbox-scout
platformio run -e hackbox-s3-local
platformio run -e hardware-test
```

## Project Layout

```text
include/        Header files
src/            Firmware sources
assets/         README and project media
boards/         Custom PlatformIO board definitions
scripts/        PlatformIO helper scripts
platformio.ini  Build targets
```

## License

MIT. See [LICENSE](LICENSE).

Based on hackbox by jbohack and zr_crackiin, with compliance-oriented cleanup
from hackbox and selected CK42X additions from hackbox.
