/*
    hackbox
    hackbox custom firmware

    Wardriver - Continuous WiFi network scanner with SPIFFS logging in
    WiGle-v1.4 CSV format, ready for upload to wigle.net.

    GPS integration (optional):
      Any NMEA-0183 GPS module (NEO-6M, BN-220, etc.) wired to
      GPS_UART_RX_PIN on UART2 at 9600 baud. No TX pin needed -- wardriver
      never sends commands to the module, it just reads NMEA.
      Without a GPS module, entries log with 0.0,0.0 coords and empty
      FirstSeen timestamps so tracks can be merged post-hoc.

    - OLED: title, total/unique networks, scan count, GPS lock status, SPIFFS usage
    - UP/DOWN scrolls through recent findings
    - RIGHT toggles serial CSV mirror output
    - Max 100 unique networks in memory (ring buffer)
    - /warlog.csv on SPIFFS, appended, survives reboots
    - Awards 1 XP per 10 new unique networks
*/

#include "../include/wardriver.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include "../include/about.h"
#include <SPIFFS.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <HardwareSerial.h>
#include <TinyGPSPlus.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== GPS (optional, UART2) =====

TinyGPSPlus gps;
HardwareSerial gpsSerial(2);

// ===== Data Structures =====

struct WardriveEntry {
    unsigned long timestamp;
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint8_t encType;  // wifi_auth_mode_t
};

// GPS snapshot captured at first-seen time. Kept OUT of WardriveEntry so
// the in-memory ring buffer stays small -- GPS data is written directly
// to SPIFFS and never displayed on the OLED, so there's no reason to
// carry it in RAM.
struct WardriveGPS {
    double  lat;
    double  lon;
    float   altitude_m;
    float   accuracy_m;
    char    firstSeenDate[20];  // "YYYY-MM-DD HH:MM:SS"
};

const int MAX_NETWORKS = 90;
WardriveEntry networks[MAX_NETWORKS];
int networkCount = 0;
int ringHead = 0;  // next write position when full

// ===== State =====
int scanCount = 0;
int scrollOffset = 0;
bool serialOutput = false;
bool needsRedraw = true;
bool scanning = false;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 3000;
int newSinceLastXP = 0;

bool spiffsReady = false;

// ===== Helpers =====

void bssidToStr(const uint8_t *bssid, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

int findByBSSID(const uint8_t *bssid) {
    int count = (networkCount < MAX_NETWORKS) ? networkCount : MAX_NETWORKS;
    for (int i = 0; i < count; i++) {
        if (memcmp(networks[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

const char* encTypeStr(uint8_t t) {
    switch (t) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "ENT";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        default:                        return "???";
    }
}

// WiGle expects its own AuthMode format, e.g. "[WPA2-PSK-CCMP][ESS]". We
// emit a minimal-but-valid form that the uploader accepts.
const char* wigleAuthStr(uint8_t t) {
    switch (t) {
        case WIFI_AUTH_OPEN:            return "[ESS]";
        case WIFI_AUTH_WEP:             return "[WEP][ESS]";
        case WIFI_AUTH_WPA_PSK:         return "[WPA-PSK-CCMP][ESS]";
        case WIFI_AUTH_WPA2_PSK:        return "[WPA2-PSK-CCMP][ESS]";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "[WPA-PSK-CCMP+WPA2-PSK-CCMP][ESS]";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "[WPA2-EAP-CCMP][ESS]";
        case WIFI_AUTH_WPA3_PSK:        return "[WPA3-SAE-CCMP][ESS]";
        default:                        return "[ESS]";
    }
}

// Snapshot the current GPS fix. When no fix is available the snapshot
// is zeroed and firstSeenDate is empty so the row is easy to filter out
// at upload time.
void snapshotGPS(WardriveGPS &snap) {
    snap.lat = 0.0;
    snap.lon = 0.0;
    snap.altitude_m = 0.0f;
    snap.accuracy_m = 0.0f;
    snap.firstSeenDate[0] = '\0';

    if (gps.location.isValid()) {
        snap.lat = gps.location.lat();
        snap.lon = gps.location.lng();
    }
    if (gps.altitude.isValid()) {
        snap.altitude_m = (float)gps.altitude.meters();
    }
    if (gps.hdop.isValid()) {
        // WiGle "AccuracyMeters" is a rough horizontal precision estimate.
        // HDOP * 5m is the common rule of thumb for consumer GPS modules.
        snap.accuracy_m = (float)(gps.hdop.hdop() * 5.0);
    }
    if (gps.date.isValid() && gps.time.isValid()) {
        snprintf(snap.firstSeenDate, sizeof(snap.firstSeenDate),
                 "%04u-%02u-%02u %02u:%02u:%02u",
                 gps.date.year(), gps.date.month(), gps.date.day(),
                 gps.time.hour(), gps.time.minute(), gps.time.second());
    }
}

void appendToSPIFFS(const WardriveEntry &entry, const WardriveGPS &snap) {
    if (!spiffsReady) return;
    File f = SPIFFS.open("/warlog.csv", FILE_APPEND);
    if (!f) return;

    char bssidStr[18];
    bssidToStr(entry.bssid, bssidStr);

    // SSID is arbitrary user data (802.11 allows commas, newlines, etc).
    // Sanitize into a local copy so one funky network name can't corrupt
    // the warlog.csv file.
    char safeSSID[33];
    strncpy(safeSSID, entry.ssid, sizeof(safeSSID) - 1);
    safeSSID[sizeof(safeSSID) - 1] = '\0';
    for (char *s = safeSSID; *s; ++s) {
        if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
    }

    // WiGle v1.4 row:
    // MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,Lat,Lon,Alt,Acc,Type
    char line[256];
    snprintf(line, sizeof(line),
             "%s,%s,%s,%s,%u,%d,%.6f,%.6f,%.1f,%.1f,WIFI\n",
             bssidStr, safeSSID, wigleAuthStr(entry.encType),
             snap.firstSeenDate, entry.channel, entry.rssi,
             snap.lat, snap.lon, snap.altitude_m, snap.accuracy_m);
    f.print(line);
    f.close();
}

void addNetwork(const WardriveEntry &entry) {
    if (networkCount < MAX_NETWORKS) {
        networks[networkCount] = entry;
        networkCount++;
    } else {
        // Ring buffer: overwrite oldest
        networks[ringHead] = entry;
        ringHead = (ringHead + 1) % MAX_NETWORKS;
    }
}

int getUniqueCount() {
    return (networkCount < MAX_NETWORKS) ? networkCount : MAX_NETWORKS;
}

// Get entry by display index (newest first)
WardriveEntry* getEntryByIndex(int displayIdx) {
    int count = getUniqueCount();
    if (displayIdx < 0 || displayIdx >= count) return nullptr;
    // Show newest first
    int realIdx;
    if (networkCount < MAX_NETWORKS) {
        realIdx = networkCount - 1 - displayIdx;
    } else {
        // Ring buffer: head points to oldest, so newest is head-1
        realIdx = ((ringHead - 1 - displayIdx) + MAX_NETWORKS) % MAX_NETWORKS;
    }
    return &networks[realIdx];
}

void processScanResults() {
    int n = WiFi.scanComplete();
    if (n <= 0) return;

    scanCount++;
    unsigned long now = millis();

    for (int i = 0; i < n; i++) {
        uint8_t *bssid = WiFi.BSSID(i);
        if (!bssid) continue;

        int existing = findByBSSID(bssid);
        if (existing >= 0) {
            // Update RSSI if seen again
            networks[existing].rssi = WiFi.RSSI(i);
            networks[existing].timestamp = now;
            continue;
        }

        // New network
        WardriveEntry entry = {};
        entry.timestamp = now;
        String ssid = WiFi.SSID(i);
        strncpy(entry.ssid, ssid.c_str(), 32);
        entry.ssid[32] = '\0';
        memcpy(entry.bssid, bssid, 6);
        entry.channel = WiFi.channel(i);
        entry.rssi = WiFi.RSSI(i);
        entry.encType = WiFi.encryptionType(i);

        // GPS snapshot is a per-call local -- we never need to keep it
        // around in the in-memory ring buffer, only write it to SPIFFS.
        WardriveGPS snap;
        snapshotGPS(snap);

        addNetwork(entry);
        appendToSPIFFS(entry, snap);

        newSinceLastXP++;
        if (newSinceLastXP >= 10) {
            addXP(1);
            newSinceLastXP = 0;
        }

        if (serialOutput) {
            char bssidStr[18];
            bssidToStr(entry.bssid, bssidStr);

            // Mirror appendToSPIFFS()'s SSID sanitization so a comma or
            // newline in a real AP name can't corrupt the serial-mirror
            // CSV stream that tools on the host tail alongside warlog.csv.
            char safeSSID[33];
            strncpy(safeSSID, entry.ssid, sizeof(safeSSID) - 1);
            safeSSID[sizeof(safeSSID) - 1] = '\0';
            for (char *s = safeSSID; *s; ++s) {
                if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
            }

            Serial.printf("%s,%s,%s,%s,%u,%d,%.6f,%.6f,%.1f,%.1f,WIFI\n",
                bssidStr, safeSSID, wigleAuthStr(entry.encType),
                snap.firstSeenDate, entry.channel, entry.rssi,
                snap.lat, snap.lon, snap.altitude_m, snap.accuracy_m);
        }
    }

    WiFi.scanDelete();
    needsRedraw = true;
}

// ===== Display =====

void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Wardriving");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    int unique = getUniqueCount();
    char statsLine[40];
    snprintf(statsLine, sizeof(statsLine), "Unique:%d  Scans:%d", unique, scanCount);
    u8g2.drawStr(0, 22, statsLine);

    // SPIFFS usage
    if (spiffsReady) {
        size_t total = SPIFFS.totalBytes();
        size_t used = SPIFFS.usedBytes();
        int pct = (total > 0) ? (int)((used * 100) / total) : 0;
        char spiffsLine[32];
        snprintf(spiffsLine, sizeof(spiffsLine), "SPIFFS:%d%%", pct);
        u8g2.drawStr(80, 22, spiffsLine);
    }

    // GPS lock indicator -- shows the current fix state and sat count so
    // users know whether rows are being geotagged.
    char gpsLine[24];
    if (gps.location.isValid()) {
        snprintf(gpsLine, sizeof(gpsLine), "GPS:FIX %u sat",
                 (unsigned)gps.satellites.value());
    } else if (gps.satellites.isValid() && gps.satellites.value() > 0) {
        snprintf(gpsLine, sizeof(gpsLine), "GPS:%u sat",
                 (unsigned)gps.satellites.value());
    } else {
        snprintf(gpsLine, sizeof(gpsLine), "GPS:-");
    }
    u8g2.drawStr(0, 30, gpsLine);

    // Scrollable list of recent findings. 3 rows instead of 4 to leave
    // room for the GPS status line above.
    int displayRows = 3;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        WardriveEntry *e = getEntryByIndex(idx);
        if (!e) break;

        char ssidShort[13];
        if (e->ssid[0] == '\0') {
            strlcpy(ssidShort, "<hidden>", sizeof(ssidShort));
        } else {
            strlcpy(ssidShort, e->ssid, sizeof(ssidShort));
        }

        char line[30];
        snprintf(line, sizeof(line), "%.12s %d %s", ssidShort, e->rssi, encTypeStr(e->encType));
        u8g2.drawStr(0, 40 + (i * 8), line);
    }

    // Footer
    char footer[32];
    snprintf(footer, sizeof(footer), "U/D=Scrl R=%s", serialOutput ? "CSV:ON" : "CSV:OFF");
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void wardriverSetup() {
    networkCount = 0;
    ringHead = 0;
    scanCount = 0;
    scrollOffset = 0;
    serialOutput = false;
    needsRedraw = true;
    scanning = false;
    lastScanTime = 0;
    newSinceLastXP = 0;

    // Init SPIFFS
    if (SPIFFS.begin(true)) {
        spiffsReady = true;
    } else {
        spiffsReady = false;
        Serial.println("# SPIFFS mount failed");
    }

    // Start optional GPS UART (RX only, TX unused). Safe to start even if
    // nothing is wired in -- the UART will just read zero bytes and
    // gps.location.isValid() will stay false. Smaller-than-default RX
    // buffer (128 vs 256) to save DRAM; NMEA sentences are tiny and the
    // main loop drains the buffer every iteration.
    gpsSerial.setRxBufferSize(128);
    gpsSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_UART_RX_PIN, -1);

    initWiFi(WIFI_MODE_STA);
    WiFi.disconnect();

    Serial.println();
    Serial.println("# hackbox Wardriver v1.1 (WiGle-compatible)");
    Serial.println("# Press RIGHT to toggle CSV output");
    Serial.println("# MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,Lat,Lon,Alt,Acc,Type");

    // Re-create the SPIFFS file with the WiGle v1.4 preamble + column header
    // on every setup so the schema never drifts. Previous log lines in the
    // old timestamp-only format are discarded -- they could not be uploaded
    // to WiGle anyway.
    if (spiffsReady) {
        File f = SPIFFS.open("/warlog.csv", FILE_WRITE);
        if (f) {
            f.printf("WigleWifi-1.4,appRelease=%s,model=hackbox,release=%s,device=ESP32,display=hackbox,board=hackbox,brand=ck42x\n",
                     HACKBOX_VERSION_NUMBER, HACKBOX_VERSION_NUMBER);
            f.println("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type");
            f.close();
        }
    }

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    // Start first scan
    WiFi.scanNetworks(true);
    scanning = true;
    lastScanTime = millis();

    drawScreen();
}

void wardriverLoop() {
    unsigned long now = millis();

    // Drain any pending GPS bytes and feed them to TinyGPSPlus. Must run
    // every iteration or the UART RX buffer fills and NMEA sentences stall.
    while (gpsSerial.available()) {
        gps.encode(gpsSerial.read());
    }

    // Check scan results
    int result = WiFi.scanComplete();
    if (result >= 0) {
        processScanResults();
        scanning = false;
    }

    // Start new scan periodically
    if (!scanning && (now - lastScanTime >= SCAN_INTERVAL)) {
        WiFi.scanNetworks(true);
        scanning = true;
        lastScanTime = now;
    }

    // --- Button handling ---
    static bool upPrev = false, downPrev = false, rightPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;

    int unique = getUniqueCount();

    if (upNow && !upPrev && scrollOffset > 0) {
        scrollOffset--;
        needsRedraw = true;
        delay(150);
    }

    if (downNow && !downPrev && scrollOffset < unique - 3) {
        scrollOffset++;
        needsRedraw = true;
        delay(150);
    }

    if (rightNow && !rightPrev) {
        serialOutput = !serialOutput;
        needsRedraw = true;
        delay(200);
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupWardriver() {
    // Print summary
    int unique = getUniqueCount();
    Serial.println();
    Serial.println("# Wardriver Summary");
    Serial.printf("# Total scans: %d\n", scanCount);
    Serial.printf("# Unique networks: %d\n", unique);
    if (spiffsReady) {
        Serial.printf("# Log saved to /warlog.csv on SPIFFS\n");
    }
    Serial.println();

    WiFi.scanDelete();
    cleanupWiFi();
    if (spiffsReady) {
        SPIFFS.end();
        spiffsReady = false;
    }
}
