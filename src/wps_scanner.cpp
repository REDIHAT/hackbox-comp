/*
    hackbox
    hackbox custom firmware

    WPS Auditor ,Scans for WPS-enabled networks, computes
    default PINs from BSSID using known vendor algorithms, and flags
    vulnerable targets.

    Phase 1: Beacon parsing for WPS Information Elements (IE 221, WPS OUI)
    Phase 2: Algorithmic PIN computation (ComputePIN, easybox, Belkin, etc.)
    Phase 3: Display results with vulnerability assessment

    - OLED: WPS network list with computed PINs, lock status, vendor
    - Serial: CSV output (bssid,ssid,channel,wps_version,locked,pin1,pin2,...)
    - Rescans every 5 seconds
    - Awards 5 XP per WPS network found, 15 XP per PIN computed
*/

#include "../include/wps_scanner.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include <WiFi.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== WPS OUI and Tag Constants =====

const uint8_t WPS_OUI[] = {0x00, 0x50, 0xF2, 0x04}; // Microsoft WPS OUI + type

// WPS Data Element IDs (big-endian in frames)
const uint16_t WPS_ATTR_VERSION       = 0x104A;
const uint16_t WPS_ATTR_WPS_STATE     = 0x1044;
const uint16_t WPS_ATTR_AP_LOCKED     = 0x1057;
const uint16_t WPS_ATTR_DEVICE_NAME   = 0x1011;
const uint16_t WPS_ATTR_MANUFACTURER  = 0x1021;
const uint16_t WPS_ATTR_MODEL_NAME    = 0x1023;
const uint16_t WPS_ATTR_MODEL_NUMBER  = 0x1024;
const uint16_t WPS_ATTR_CONFIG_METHODS = 0x1008;

// ===== Data Structures =====

struct ComputedPIN {
    uint32_t pin;
    const char *algorithm;
};

struct WPSNetwork {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint8_t wpsVersion;
    uint8_t wpsState;       // 1=not configured, 2=configured
    bool locked;
    char deviceName[33];
    char manufacturer[33];
    char modelName[33];
    uint16_t configMethods;

    ComputedPIN pins[6];
    int pinCount;
    bool pinned;            // PINs have been computed
};

const int MAX_WPS = 30;
WPSNetwork networks[MAX_WPS];
int networkCount = 0;

// ===== State =====
int scrollOffset = 0;
int selectedIndex = 0;
bool serialOutput = false;
bool needsRedraw = true;
bool scanning = false;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 5000;
int newSinceLastXP = 0;

enum WPSView {
    VIEW_LIST,      // scrollable network list
    VIEW_DETAIL     // selected network detail with PINs
};
WPSView currentView = VIEW_LIST;

// ===== WPS PIN Checksum =====
// WPS PIN is 8 digits. Last digit is checksum of first 7.

uint32_t wpsChecksum(uint32_t pin7) {
    uint32_t accum = 0;
    uint32_t t = pin7;
    t *= 10;  // make room for checksum digit
    accum += 3 * (t % 10); t /= 10;
    accum += 1 * (t % 10); t /= 10;
    accum += 3 * (t % 10); t /= 10;
    accum += 1 * (t % 10); t /= 10;
    accum += 3 * (t % 10); t /= 10;
    accum += 1 * (t % 10); t /= 10;
    accum += 3 * (t % 10);
    uint32_t digit = (10 - (accum % 10)) % 10;
    return pin7 * 10 + digit;
}

// ===== Algorithmic PIN Generators =====

// ComputePIN: Used by many Atheros/Ralink chipsets.
// PIN = last 7 digits of (BSSID as int) with WPS checksum appended.
uint32_t computePIN_generic(const uint8_t *bssid) {
    uint32_t mac = ((uint32_t)bssid[2] << 24) |
                   ((uint32_t)bssid[3] << 16) |
                   ((uint32_t)bssid[4] << 8)  |
                   ((uint32_t)bssid[5]);
    uint32_t pin7 = mac % 10000000;
    return wpsChecksum(pin7);
}

// Variant: nibble-swap then compute. Some Realtek chipsets.
uint32_t computePIN_nibbleswap(const uint8_t *bssid) {
    uint32_t mac = ((uint32_t)bssid[2] << 24) |
                   ((uint32_t)bssid[3] << 16) |
                   ((uint32_t)bssid[4] << 8)  |
                   ((uint32_t)bssid[5]);
    // Nibble swap: reverse nibble order of lower 28 bits
    uint32_t swapped = 0;
    for (int i = 0; i < 7; i++) {
        swapped = (swapped << 4) | (mac & 0xF);
        mac >>= 4;
    }
    uint32_t pin7 = swapped % 10000000;
    return wpsChecksum(pin7);
}

// EasyBox (Arcadyan/Astoria): PIN from BSSID octets 2-5
// Used by Vodafone EasyBox, some Arcadyan OEM routers
uint32_t computePIN_easybox(const uint8_t *bssid) {
    // Take octets as individual values, combine into PIN
    uint32_t s1 = ((bssid[1] & 0x0F) + (bssid[2] & 0x0F)) % 10;
    uint32_t s2 = ((bssid[3] >> 4) + (bssid[3] & 0x0F)) % 10;
    uint32_t s3 = ((bssid[4] >> 4) + (bssid[4] & 0x0F)) % 10;
    uint32_t s4 = ((bssid[5] >> 4) + (bssid[5] & 0x0F)) % 10;
    uint32_t k1 = (s1 * 10 + s2) * 1000 + (s3 * 10 + s4);
    // First half of PIN
    uint32_t p1 = k1 % 10000;
    // Second half from shifted values
    uint32_t s5 = ((bssid[1] >> 4) + (bssid[2] >> 4)) % 10;
    uint32_t s6 = ((bssid[3] >> 4) + (bssid[4] >> 4)) % 10;
    uint32_t s7 = ((bssid[4] & 0x0F) + (bssid[5] >> 4)) % 10;
    uint32_t p2 = (s5 * 100 + s6 * 10 + s7);
    uint32_t pin7 = p1 * 1000 + p2;
    return wpsChecksum(pin7);
}

// Belkin: PIN derived from WAN MAC (usually BSSID+1 or +2)
uint32_t computePIN_belkin(const uint8_t *bssid) {
    // Belkin uses serial-number-based PINs typically,
    // but a common fallback is NIC portion XOR'd
    uint32_t nic = ((uint32_t)bssid[3] << 16) |
                   ((uint32_t)bssid[4] << 8)  |
                   ((uint32_t)bssid[5]);
    uint32_t pin7 = (nic ^ 0x55AA55) % 10000000;
    return wpsChecksum(pin7);
}

// D-Link / TRENDnet: PIN from last 6 hex digits of MAC
uint32_t computePIN_dlink(const uint8_t *bssid) {
    uint32_t nic = ((uint32_t)bssid[3] << 16) |
                   ((uint32_t)bssid[4] << 8)  |
                   ((uint32_t)bssid[5]);
    // D-Link uses: pin = (nic + offset) % 10000000
    // Common offset values found in firmware dumps
    uint32_t pin7 = (nic + 1) % 10000000;
    return wpsChecksum(pin7);
}

// ===== OUI to Vendor Lookup (first 3 bytes of BSSID) =====

struct OUIEntry {
    uint8_t oui[3];
    const char *vendor;
};

// Common WPS-vulnerable OUIs. Not exhaustive but covers the big ones.
const OUIEntry knownOUIs[] = {
    {{0xC8, 0x3A, 0x35}, "Tenda"},
    {{0x00, 0x1D, 0x7E}, "Cisco/Linksys"},
    {{0x00, 0x22, 0x6B}, "Cisco/Linksys"},
    {{0x00, 0x25, 0x9C}, "Cisco/Linksys"},
    {{0x58, 0x6D, 0x8F}, "Cisco/Linksys"},
    {{0xC0, 0xC1, 0xC0}, "Cisco/Linksys"},
    {{0x14, 0xD6, 0x4D}, "D-Link"},
    {{0x1C, 0x7E, 0xE5}, "D-Link"},
    {{0x28, 0x10, 0x7B}, "D-Link"},
    {{0x34, 0x08, 0x04}, "D-Link"},
    {{0x84, 0xC9, 0xB2}, "D-Link"},
    {{0xCC, 0xB2, 0x55}, "D-Link"},
    {{0xFC, 0x75, 0x16}, "D-Link"},
    {{0x00, 0x26, 0x5A}, "D-Link"},
    {{0xC0, 0xA0, 0xBB}, "D-Link"},
    {{0xF0, 0x7D, 0x68}, "D-Link"},
    {{0x08, 0x10, 0x76}, "D-Link"},
    {{0x34, 0x08, 0x04}, "D-Link"},
    {{0x00, 0x22, 0xB0}, "D-Link"},
    {{0xEC, 0x08, 0x6B}, "TP-Link"},
    {{0x50, 0xC7, 0xBF}, "TP-Link"},
    {{0xF4, 0xF2, 0x6D}, "TP-Link"},
    {{0xAC, 0x84, 0xC6}, "TP-Link"},
    {{0xC0, 0x25, 0xE9}, "TP-Link"},
    {{0x14, 0xCC, 0x20}, "TP-Link"},
    {{0x30, 0xB5, 0xC2}, "TP-Link"},
    {{0x64, 0x70, 0x02}, "TP-Link"},
    {{0xB0, 0x48, 0x7A}, "TP-Link"},
    {{0xE8, 0xDE, 0x27}, "TP-Link"},
    {{0x08, 0x86, 0x3B}, "Belkin"},
    {{0x94, 0x44, 0x52}, "Belkin"},
    {{0xC0, 0x56, 0x27}, "Belkin"},
    {{0xEC, 0x1A, 0x59}, "Belkin"},
    {{0xE8, 0xF7, 0x24}, "Belkin"},
    {{0x20, 0xAA, 0x4B}, "Cisco/Linksys"},
    {{0x00, 0x18, 0x01}, "Actiontec"},
    {{0x00, 0x26, 0x62}, "Actiontec"},
    {{0x00, 0x1F, 0x90}, "Actiontec"},
    {{0x08, 0x60, 0x6E}, "ASUSTek"},
    {{0x10, 0xBF, 0x48}, "ASUSTek"},
    {{0x1C, 0x87, 0x2C}, "ASUSTek"},
    {{0x2C, 0x56, 0xDC}, "ASUSTek"},
    {{0x30, 0x85, 0xA9}, "ASUSTek"},
    {{0x50, 0x46, 0x5D}, "ASUSTek"},
    {{0x54, 0x04, 0xA6}, "ASUSTek"},
    {{0x60, 0x45, 0xCB}, "ASUSTek"},
    {{0x00, 0x14, 0x6C}, "NETGEAR"},
    {{0x00, 0x1E, 0x2A}, "NETGEAR"},
    {{0x00, 0x1F, 0x33}, "NETGEAR"},
    {{0x20, 0x4E, 0x7F}, "NETGEAR"},
    {{0x2C, 0xB0, 0x5D}, "NETGEAR"},
    {{0x84, 0x1B, 0x5E}, "NETGEAR"},
    {{0xA4, 0x2B, 0x8C}, "NETGEAR"},
    {{0xC4, 0x04, 0x15}, "NETGEAR"},
    {{0xE0, 0x46, 0x9A}, "NETGEAR"},
    {{0x00, 0x1C, 0xA8}, "AirTies"},
    {{0x00, 0x1A, 0x2B}, "Arcadyan"},
    {{0x00, 0x1D, 0xAA}, "Arcadyan"},
    {{0x88, 0x03, 0x55}, "Arcadyan"},
};
const int OUI_COUNT = sizeof(knownOUIs) / sizeof(knownOUIs[0]);

const char* lookupVendor(const uint8_t *bssid) {
    for (int i = 0; i < OUI_COUNT; i++) {
        if (memcmp(bssid, knownOUIs[i].oui, 3) == 0) {
            return knownOUIs[i].vendor;
        }
    }
    return nullptr;
}

// ===== Compute PINs for a network =====

void computePINs(WPSNetwork &net) {
    if (net.pinned) return;
    net.pinCount = 0;

    const char *vendor = lookupVendor(net.bssid);

    // Always compute generic ComputePIN (works on many chipsets)
    net.pins[net.pinCount++] = { computePIN_generic(net.bssid), "ComputePIN" };

    // Nibble-swap variant
    uint32_t nsPin = computePIN_nibbleswap(net.bssid);
    if (nsPin != net.pins[0].pin) {
        net.pins[net.pinCount++] = { nsPin, "NibbleSwap" };
    }

    // Vendor-specific algorithms
    if (vendor) {
        if (strstr(vendor, "Arcadyan") || strstr(vendor, "AirTies")) {
            net.pins[net.pinCount++] = { computePIN_easybox(net.bssid), "EasyBox" };
        }
        if (strstr(vendor, "Belkin")) {
            net.pins[net.pinCount++] = { computePIN_belkin(net.bssid), "Belkin" };
        }
        if (strstr(vendor, "D-Link") || strstr(vendor, "TRENDnet")) {
            net.pins[net.pinCount++] = { computePIN_dlink(net.bssid), "D-Link" };
        }
    }

    // Common static defaults that some routers ship with
    // Only add if not already computed
    uint32_t commonPins[] = { 12345670, wpsChecksum(0) };  // 12345670, 00000000+checksum
    for (int i = 0; i < 2 && net.pinCount < 6; i++) {
        bool dupe = false;
        for (int j = 0; j < net.pinCount; j++) {
            if (net.pins[j].pin == commonPins[i]) { dupe = true; break; }
        }
        if (!dupe) {
            net.pins[net.pinCount++] = { commonPins[i], "Default" };
        }
    }

    net.pinned = true;
    if (net.pinCount > 0) {
        addXP(15);
    }
}

// ===== Helpers =====

void bssidToStr(const uint8_t *bssid, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

int findByBSSID(const uint8_t *bssid) {
    for (int i = 0; i < networkCount; i++) {
        if (memcmp(networks[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// Parse WPS IE from beacon tagged parameters
// WPS IE: tag 221 (vendor specific), OUI 00:50:F2:04
bool parseWPSIE(const uint8_t *ieData, uint16_t ieLen, WPSNetwork &net) {
    int pos = 0;
    bool foundWPS = false;

    while (pos + 4 <= (int)ieLen) {
        uint16_t attrType = ((uint16_t)ieData[pos] << 8) | ieData[pos + 1];
        uint16_t attrLen  = ((uint16_t)ieData[pos + 2] << 8) | ieData[pos + 3];
        pos += 4;

        if (pos + attrLen > (int)ieLen) break;

        switch (attrType) {
            case WPS_ATTR_VERSION:
                if (attrLen >= 1) net.wpsVersion = ieData[pos];
                foundWPS = true;
                break;
            case WPS_ATTR_WPS_STATE:
                if (attrLen >= 1) net.wpsState = ieData[pos];
                break;
            case WPS_ATTR_AP_LOCKED:
                if (attrLen >= 1) net.locked = (ieData[pos] != 0);
                break;
            case WPS_ATTR_DEVICE_NAME:
                if (attrLen > 0) {
                    int copyLen = (attrLen > 32) ? 32 : attrLen;
                    memcpy(net.deviceName, &ieData[pos], copyLen);
                    net.deviceName[copyLen] = '\0';
                }
                break;
            case WPS_ATTR_MANUFACTURER:
                if (attrLen > 0) {
                    int copyLen = (attrLen > 32) ? 32 : attrLen;
                    memcpy(net.manufacturer, &ieData[pos], copyLen);
                    net.manufacturer[copyLen] = '\0';
                }
                break;
            case WPS_ATTR_MODEL_NAME:
                if (attrLen > 0) {
                    int copyLen = (attrLen > 32) ? 32 : attrLen;
                    memcpy(net.modelName, &ieData[pos], copyLen);
                    net.modelName[copyLen] = '\0';
                }
                break;
            case WPS_ATTR_CONFIG_METHODS:
                if (attrLen >= 2) {
                    net.configMethods = ((uint16_t)ieData[pos] << 8) | ieData[pos + 1];
                }
                break;
        }
        pos += attrLen;
    }
    return foundWPS;
}

// ===== Promiscuous Callback =====
// Parse beacon frames for WPS vendor-specific IEs

volatile int pendingBeaconCount = 0;

struct PendingWPS {
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t ssid[33];
    uint8_t ssidLen;
    uint8_t wpsIEData[256];
    uint16_t wpsIELen;
    bool valid;
};

const int PENDING_MAX = 8;
volatile int pendingHead = 0;
volatile int pendingTail = 0;
PendingWPS pendingQueue[PENDING_MAX];

void IRAM_ATTR wpsSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 36) return;

    uint8_t fsubtype = (frame[0] >> 4) & 0x0F;
    if (fsubtype != 8) return; // beacon only

    const uint8_t *bssid = &frame[16];

    // Parse tagged parameters starting at offset 36
    int pos = 36;
    uint8_t ssid[33] = {0};
    uint8_t ssidLen = 0;
    const uint8_t *wpsIE = nullptr;
    uint16_t wpsIELen = 0;

    while (pos + 2 <= (int)len) {
        uint8_t tagNum = frame[pos];
        uint8_t tagLen = frame[pos + 1];
        if (pos + 2 + tagLen > (int)len) break;

        if (tagNum == 0) {  // SSID
            ssidLen = (tagLen > 32) ? 32 : tagLen;
            memcpy(ssid, &frame[pos + 2], ssidLen);
            ssid[ssidLen] = '\0';
        }

        if (tagNum == 221 && tagLen >= 4) {  // Vendor Specific
            if (memcmp(&frame[pos + 2], WPS_OUI, 4) == 0) {
                wpsIE = &frame[pos + 2 + 4];  // skip OUI+type
                wpsIELen = tagLen - 4;
            }
        }
        pos += 2 + tagLen;
    }

    if (!wpsIE || wpsIELen == 0) return;  // not a WPS beacon

    // Queue for main loop processing (avoid heap ops in callback)
    int next = (pendingHead + 1) % PENDING_MAX;
    if (next == pendingTail) return;  // queue full, drop

    PendingWPS &p = pendingQueue[pendingHead];
    memcpy(p.bssid, bssid, 6);
    p.rssi = pkt->rx_ctrl.rssi;
    p.channel = pkt->rx_ctrl.channel;
    p.ssidLen = ssidLen;
    memcpy(p.ssid, ssid, ssidLen + 1);
    uint16_t copyLen = (wpsIELen > 256) ? 256 : wpsIELen;
    memcpy(p.wpsIEData, wpsIE, copyLen);
    p.wpsIELen = copyLen;
    p.valid = true;
    pendingHead = next;
}

void processPendingBeacons() {
    while (pendingTail != pendingHead) {
        PendingWPS &p = pendingQueue[pendingTail];
        if (!p.valid) {
            pendingTail = (pendingTail + 1) % PENDING_MAX;
            continue;
        }

        int existing = findByBSSID(p.bssid);
        if (existing >= 0) {
            // Update RSSI
            networks[existing].rssi = p.rssi;
        } else if (networkCount < MAX_WPS) {
            // New WPS network
            WPSNetwork &net = networks[networkCount];
            memset(&net, 0, sizeof(WPSNetwork));
            memcpy(net.bssid, p.bssid, 6);
            strncpy(net.ssid, (char*)p.ssid, 32);
            net.ssid[32] = '\0';
            net.rssi = p.rssi;
            net.channel = p.channel;

            if (parseWPSIE(p.wpsIEData, p.wpsIELen, net)) {
                computePINs(net);
                networkCount++;
                newSinceLastXP++;
                if (newSinceLastXP >= 1) {
                    addXP(5);
                    newSinceLastXP = 0;
                }
                needsRedraw = true;

                if (serialOutput) {
                    char bssidStr[18];
                    bssidToStr(net.bssid, bssidStr);
                    const char *vendor = lookupVendor(net.bssid);

                    // SSID can contain commas/newlines ,sanitize a local
                    // copy so a funky AP name can't corrupt the CSV row
                    // that host-side tools tail from the serial console.
                    char safeSSID[33];
                    strncpy(safeSSID, net.ssid, sizeof(safeSSID) - 1);
                    safeSSID[sizeof(safeSSID) - 1] = '\0';
                    for (char *s = safeSSID; *s; ++s) {
                        if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
                    }

                    Serial.printf("%s,%s,%u,0x%02X,%s,%s",
                        bssidStr, safeSSID, net.channel,
                        net.wpsVersion,
                        net.locked ? "LOCKED" : "OPEN",
                        vendor ? vendor : "Unknown");
                    for (int i = 0; i < net.pinCount; i++) {
                        Serial.printf(",%08lu(%s)", net.pins[i].pin, net.pins[i].algorithm);
                    }
                    Serial.println();
                }
            }
        }

        p.valid = false;
        pendingTail = (pendingTail + 1) % PENDING_MAX;
    }
}

// ===== Channel Hopping =====
uint8_t currentChannel = 1;
unsigned long lastHop = 0;
const unsigned long HOP_INTERVAL = 400;

// ===== Display =====

void drawListView() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // Header
    char header[32];
    snprintf(header, sizeof(header), "WPS Scanner  %d found", networkCount);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    // Network list
    int displayRows = 5;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        if (idx >= networkCount) break;

        const WPSNetwork &net = networks[idx];
        char ssidShort[11];
        strncpy(ssidShort, net.ssid, 10);
        ssidShort[10] = '\0';
        if (strlen(net.ssid) == 0) strncpy(ssidShort, "<hidden>", 10);

        char line[32];
        snprintf(line, sizeof(line), "%c%.9s %d %s%s",
                 (idx == selectedIndex) ? '>' : ' ',
                 ssidShort, net.rssi,
                 net.locked ? "LK" : "OK",
                 net.pinCount > 0 ? "*" : "");
        u8g2.drawStr(0, 20 + (i * 8), line);
    }

    // Footer
    char footer[32];
    snprintf(footer, sizeof(footer), "R=PINs C=CSV Ch:%d%s",
             currentChannel, serialOutput ? " *" : "");
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawDetailView() {
    if (selectedIndex >= networkCount) {
        currentView = VIEW_LIST;
        needsRedraw = true;
        return;
    }

    const WPSNetwork &net = networks[selectedIndex];

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // SSID header
    char ssidLine[22];
    strncpy(ssidLine, net.ssid, 21);
    ssidLine[21] = '\0';
    u8g2.drawStr(0, 8, ssidLine);
    u8g2.drawHLine(0, 10, 128);

    // BSSID + vendor
    char bssidStr[18];
    bssidToStr(net.bssid, bssidStr);
    const char *vendor = lookupVendor(net.bssid);

    if (privacyModeEnabled) {
        u8g2.drawStr(0, 20, "XX:XX:XX:XX:XX:XX");
    } else {
        u8g2.drawStr(0, 20, bssidStr);
    }

    char infoLine[32];
    snprintf(infoLine, sizeof(infoLine), "Ch:%d %ddBm %s %s",
             net.channel, net.rssi,
             net.locked ? "LOCKED" : "OPEN",
             vendor ? vendor : "");
    u8g2.drawStr(0, 28, infoLine);

    u8g2.drawHLine(0, 30, 128);

    // PINs
    if (net.pinCount == 0) {
        u8g2.drawStr(0, 40, "No PINs computed");
    } else {
        for (int i = 0; i < net.pinCount && i < 3; i++) {
            char pinLine[32];
            if (privacyModeEnabled) {
                snprintf(pinLine, sizeof(pinLine), "%s: ********", net.pins[i].algorithm);
            } else {
                snprintf(pinLine, sizeof(pinLine), "%s: %08lu",
                         net.pins[i].algorithm, net.pins[i].pin);
            }
            u8g2.drawStr(0, 40 + (i * 8), pinLine);
        }
    }

    // Footer
    u8g2.drawStr(0, 62, "L=Back D=More PINs");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void wpsSetup() {
    networkCount = 0;
    scrollOffset = 0;
    selectedIndex = 0;
    serialOutput = false;
    needsRedraw = true;
    scanning = false;
    lastScanTime = 0;
    newSinceLastXP = 0;
    currentView = VIEW_LIST;
    currentChannel = 1;
    lastHop = 0;
    pendingHead = 0;
    pendingTail = 0;

    memset(networks, 0, sizeof(networks));
    memset(pendingQueue, 0, sizeof(pendingQueue));

    initWiFi(WIFI_MODE_AP);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wpsSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.println();
    Serial.println("# hackbox WPS Auditor v1.0");
    Serial.println("# Scanning for WPS-enabled networks...");
    Serial.println("# Press RIGHT to toggle CSV output");
    Serial.println("# bssid,ssid,channel,wps_ver,lock_state,vendor,pins...");

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawListView();
}

void wpsLoop() {
    unsigned long now = millis();

    // Channel hopping
    if (now - lastHop >= HOP_INTERVAL) {
        lastHop = now;
        currentChannel++;
        if (currentChannel > 13) currentChannel = 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }

    // Process queued beacons from sniffer callback
    processPendingBeacons();

    // --- Button handling ---
    static bool upPrev = false, downPrev = false;
    static bool leftPrev = false, rightPrev = false, centerPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool centerNow = digitalRead(BUTTON_PIN_CENTER) == LOW;

    if (currentView == VIEW_LIST) {
        if (upNow && !upPrev) {
            if (selectedIndex > 0) {
                selectedIndex--;
                if (selectedIndex < scrollOffset) scrollOffset = selectedIndex;
                needsRedraw = true;
            }
            delay(150);
        }
        if (downNow && !downPrev) {
            if (selectedIndex < networkCount - 1) {
                selectedIndex++;
                if (selectedIndex >= scrollOffset + 5) scrollOffset = selectedIndex - 4;
                needsRedraw = true;
            }
            delay(150);
        }
        if (rightNow && !rightPrev) {
            if (networkCount > 0) {
                currentView = VIEW_DETAIL;
                needsRedraw = true;
            }
            delay(200);
        }
        // Toggle serial output via CENTER (OK/select) ,LEFT is now the
        // universal app-exit button and can't be used for an in-app action.
        if (centerNow && !centerPrev) {
            serialOutput = !serialOutput;
            needsRedraw = true;
            delay(200);
        }
    } else if (currentView == VIEW_DETAIL) {
        if (leftNow && !leftPrev) {
            currentView = VIEW_LIST;
            needsRedraw = true;
            // Block until LEFT release so runApp's global LEFT-exit does not
            // also fire on the same edge and kick the user to main menu.
            while (digitalRead(BUTTON_PIN_LEFT) == LOW) delay(5);
            leftNow = false;
        }
        if (downNow && !downPrev) {
            // Cycle through PINs if more than 3 (scroll)
            // For now just go back to list
            delay(200);
        }
        if (rightNow && !rightPrev) {
            // Print full detail to serial
            if (selectedIndex < networkCount) {
                const WPSNetwork &net = networks[selectedIndex];
                char bssidStr[18];
                bssidToStr(net.bssid, bssidStr);
                Serial.println();
                Serial.println("# === WPS Network Detail ===");
                Serial.printf("# SSID: %s\n", net.ssid);
                Serial.printf("# BSSID: %s\n", bssidStr);
                Serial.printf("# Channel: %d  RSSI: %d\n", net.channel, net.rssi);
                Serial.printf("# WPS Version: 0x%02X  State: %d\n", net.wpsVersion, net.wpsState);
                Serial.printf("# Locked: %s\n", net.locked ? "YES" : "NO");
                if (net.deviceName[0]) Serial.printf("# Device: %s\n", net.deviceName);
                if (net.manufacturer[0]) Serial.printf("# Manufacturer: %s\n", net.manufacturer);
                if (net.modelName[0]) Serial.printf("# Model: %s\n", net.modelName);
                const char *vendor = lookupVendor(net.bssid);
                if (vendor) Serial.printf("# OUI Vendor: %s\n", vendor);
                Serial.printf("# Computed PINs (%d):\n", net.pinCount);
                for (int i = 0; i < net.pinCount; i++) {
                    Serial.printf("#   %08lu (%s)\n", net.pins[i].pin, net.pins[i].algorithm);
                }
                Serial.println("# ===========================");
            }
            delay(200);
        }
    }

    upPrev = upNow;
    downPrev = downNow;
    leftPrev = leftNow;
    rightPrev = rightNow;
    centerPrev = centerNow;

    if (needsRedraw) {
        needsRedraw = false;
        if (currentView == VIEW_LIST) {
            drawListView();
        } else {
            drawDetailView();
        }
    }
}

void cleanupWPS() {
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    networkCount = 0;

    Serial.println();
    Serial.println("# WPS Scanner session ended");
}
