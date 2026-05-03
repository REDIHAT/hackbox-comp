/*
    hackbox Rogue AP Detector

    Blue team tool. Scans all WiFi channels for access points, groups
    them by SSID, and flags any SSID that appears on multiple BSSIDs
    or channels -- the signature of an evil twin attack.

    How it works:
    - Runs a full WiFi scan every ~10 seconds
    - Stores up to 64 unique APs (BSSID + SSID + channel + RSSI)
    - Groups APs by SSID after each scan
    - Any SSID with 2+ distinct BSSIDs is flagged as a potential rogue
    - NeoPixel flashes red on new rogue detection
    - Dashboard shows: rogue count, total APs, per-rogue detail

    Controls:
      UP/DOWN - scroll rogue list
      CENTER  - force rescan
      LEFT    - exit (framework)

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#include "../include/rogue_ap.h"
#include "../include/radio_manager.h"
#include "../include/display_mirror.h"
#include <Adafruit_NeoPixel.h>
#include <esp_wifi.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;

// ============================================================
// Data structures
// ============================================================

struct ApRecord {
    char     ssid[33];
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  authmode;   // wifi_auth_mode_t
};

// A rogue group: an SSID seen on multiple BSSIDs
struct RogueGroup {
    char    ssid[33];
    uint8_t bssidCount;      // how many distinct BSSIDs carry this SSID
    uint8_t channels[8];     // up to 8 distinct channels observed
    uint8_t channelCount;
    int8_t  strongestRssi;   // strongest signal among the group
};

static const int MAX_APS = 64;
static const int MAX_ROGUES = 16;
static const unsigned long SCAN_INTERVAL_MS = 10000;
static const unsigned long REDRAW_MS = 300;

struct RogueApState {
    ApRecord aps[MAX_APS];
    int apCount;

    RogueGroup rogues[MAX_ROGUES];
    int rogueCount;
    int prevRogueCount;     // to detect new rogues for NeoPixel

    int totalAps;           // total from last scan (may exceed MAX_APS)
    int scanCount;          // how many scans completed

    bool isScanning;
    unsigned long lastScanStart;
    unsigned long lastRedraw;
    bool needsRedraw;

    int listSelected;
    int listScroll;

    unsigned long lastUp;
    unsigned long lastDown;
    bool centerPrev;
};

static RogueApState *state = nullptr;
static bool wifiInitialized = false;

// ============================================================
// AP storage
// ============================================================

static int findApByBssid(const uint8_t *bssid) {
    if (!state) return -1;
    for (int i = 0; i < state->apCount; i++) {
        if (memcmp(state->aps[i].bssid, bssid, 6) == 0) return i;
    }
    return -1;
}

static void addOrUpdateAp(const wifi_ap_record_t *rec) {
    if (!state) return;
    // Skip hidden SSIDs (empty SSID)
    if (rec->ssid[0] == '\0') return;

    int existing = findApByBssid(rec->bssid);
    if (existing >= 0) {
        // Update RSSI and channel
        state->aps[existing].rssi = rec->rssi;
        state->aps[existing].channel = rec->primary;
        return;
    }
    if (state->apCount >= MAX_APS) return;

    ApRecord &ap = state->aps[state->apCount];
    strlcpy(ap.ssid, (const char *)rec->ssid, sizeof(ap.ssid));
    memcpy(ap.bssid, rec->bssid, 6);
    ap.channel = rec->primary;
    ap.rssi = rec->rssi;
    ap.authmode = (uint8_t)rec->authmode;
    state->apCount++;
}

// ============================================================
// Rogue analysis
// ============================================================

static void analyzeRogues() {
    if (!state) return;
    state->rogueCount = 0;

    // For each unique SSID, count distinct BSSIDs
    for (int i = 0; i < state->apCount && state->rogueCount < MAX_ROGUES; i++) {
        const char *ssid = state->aps[i].ssid;

        // Already in a rogue group?
        bool alreadyGrouped = false;
        for (int r = 0; r < state->rogueCount; r++) {
            if (strcmp(state->rogues[r].ssid, ssid) == 0) {
                alreadyGrouped = true;
                break;
            }
        }
        if (alreadyGrouped) continue;

        // Count BSSIDs and channels for this SSID
        uint8_t bssidCount = 0;
        uint8_t channels[8] = {0};
        uint8_t channelCount = 0;
        int8_t strongest = -127;

        for (int j = i; j < state->apCount; j++) {
            if (strcmp(state->aps[j].ssid, ssid) != 0) continue;
            bssidCount++;
            if (state->aps[j].rssi > strongest) strongest = state->aps[j].rssi;

            // Track unique channels
            bool chSeen = false;
            for (int c = 0; c < channelCount; c++) {
                if (channels[c] == state->aps[j].channel) { chSeen = true; break; }
            }
            if (!chSeen && channelCount < 8) {
                channels[channelCount++] = state->aps[j].channel;
            }
        }

        // 2+ distinct BSSIDs = rogue candidate
        if (bssidCount >= 2) {
            RogueGroup &rg = state->rogues[state->rogueCount];
            strlcpy(rg.ssid, ssid, sizeof(rg.ssid));
            rg.bssidCount = bssidCount;
            memcpy(rg.channels, channels, sizeof(rg.channels));
            rg.channelCount = channelCount;
            rg.strongestRssi = strongest;
            state->rogueCount++;
        }
    }

    // NeoPixel alert on new rogues
    if (state->rogueCount > state->prevRogueCount) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));
        pixels.show();
    }
    state->prevRogueCount = state->rogueCount;
}

// ============================================================
// WiFi scan
// ============================================================

static void startScan() {
    if (!state) return;

    if (!wifiInitialized) {
        initWiFi(WIFI_MODE_STA);
        wifiInitialized = true;
        delay(100);
    }

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };

    state->isScanning = true;
    esp_wifi_scan_start(&scan_config, false);
    state->lastScanStart = millis();
}

static void processScanResults() {
    if (!state) return;

    uint16_t apCount = 0;
    esp_wifi_scan_get_ap_num(&apCount);
    state->totalAps = apCount;

    if (apCount > 0) {
        uint16_t fetchCount = (apCount > MAX_APS) ? MAX_APS : apCount;
        wifi_ap_record_t *records = (wifi_ap_record_t *)malloc(fetchCount * sizeof(wifi_ap_record_t));
        if (records) {
            esp_wifi_scan_get_ap_records(&fetchCount, records);
            // Clear old data each scan for fresh analysis
            state->apCount = 0;
            for (uint16_t i = 0; i < fetchCount; i++) {
                addOrUpdateAp(&records[i]);
            }
            free(records);
        }
    }

    state->scanCount++;
    state->isScanning = false;
    analyzeRogues();
    state->needsRedraw = true;
}

// ============================================================
// Display
// ============================================================

static void drawDisplay() {
    if (!state) return;
    u8g2.clearBuffer();

    // Header
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "ROGUE AP DETECT");

    char status[20];
    snprintf(status, sizeof(status), "%s #%d",
             state->isScanning ? "SCAN" : "IDLE", state->scanCount);
    int sx = 128 - u8g2.getStrWidth(status);
    u8g2.drawStr(sx, 10, status);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (state->rogueCount == 0) {
        // Clean display
        char apLine[28];
        snprintf(apLine, sizeof(apLine), "APs: %d", state->totalAps);
        u8g2.drawStr(0, 24, apLine);

        if (state->scanCount == 0) {
            u8g2.drawStr(0, 36, "Scanning...");
        } else {
            u8g2.drawStr(0, 36, "No rogues detected.");
            u8g2.drawStr(0, 46, "All SSIDs unique.");
        }
    } else {
        // Alert banner
        char alertLine[28];
        snprintf(alertLine, sizeof(alertLine), "!! %d ROGUE%s  APs:%d",
                 state->rogueCount,
                 state->rogueCount > 1 ? "S" : "",
                 state->totalAps);
        // Invert the alert line
        int alertW = u8g2.getStrWidth(alertLine);
        u8g2.drawBox(0, 14, alertW + 2, 9);
        u8g2.setDrawColor(0);
        u8g2.drawStr(1, 22, alertLine);
        u8g2.setDrawColor(1);

        // Rogue list: up to 4 visible rows at y=28, 35, 42, 49
        const int ROWS_VISIBLE = 4;
        int start = state->listScroll;
        for (int r = 0; r < ROWS_VISIBLE; r++) {
            int idx = start + r;
            if (idx >= state->rogueCount) break;
            const RogueGroup &rg = state->rogues[idx];

            // Format: ">SSID_truncated  Bx Chy"
            char row[28];
            char ssidTrunc[14];
            strlcpy(ssidTrunc, rg.ssid, sizeof(ssidTrunc));

            // Build channel list string
            char chStr[12] = "";
            for (int c = 0; c < rg.channelCount && c < 3; c++) {
                char tmp[5];
                snprintf(tmp, sizeof(tmp), "%s%d", c > 0 ? "," : "", rg.channels[c]);
                strlcat(chStr, tmp, sizeof(chStr));
            }
            if (rg.channelCount > 3) strlcat(chStr, "+", sizeof(chStr));

            snprintf(row, sizeof(row), "%c%-13s B%d Ch%s",
                     (idx == state->listSelected) ? '>' : ' ',
                     ssidTrunc, rg.bssidCount, chStr);
            u8g2.drawStr(0, 28 + (r * 7), row);
        }
    }

    // Footer with NeoPixel fade
    u8g2.drawStr(0, 62, "U/D=Scroll C=Scan L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ============================================================
// Public entry points
// ============================================================

void rogueApSetup() {
    if (!state) {
        state = (RogueApState *)calloc(1, sizeof(RogueApState));
    }
    if (state) {
        state->needsRedraw = true;
        state->prevRogueCount = 0;
    }

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "ROGUE AP DETECT");
    u8g2.drawHLine(0, 12, 128);
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 30, state ? "Starting WiFi scan..."
                               : "ERR: out of memory");
    u8g2.drawStr(0, 62, "L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);

    startScan();
}

void rogueApLoop() {
    if (!state) return;
    unsigned long now = millis();
    const unsigned long DEBOUNCE_MS = 150;

    // Check if scan completed
    if (state->isScanning) {
        uint16_t apNum = 0;
        if (esp_wifi_scan_get_ap_num(&apNum) == ESP_OK && apNum > 0) {
            processScanResults();
        }
        // Timeout: if scan takes >15s, force process
        if ((now - state->lastScanStart) > 15000) {
            processScanResults();
        }
    }

    // Auto-rescan every SCAN_INTERVAL_MS
    if (!state->isScanning && (now - state->lastScanStart) > SCAN_INTERVAL_MS) {
        startScan();
    }

    // Buttons
    bool upDown     = digitalRead(BUTTON_PIN_UP)     == LOW;
    bool downDown   = digitalRead(BUTTON_PIN_DOWN)   == LOW;
    bool centerDown = digitalRead(BUTTON_PIN_CENTER)  == LOW;

    bool centerEdge = centerDown && !state->centerPrev;
    state->centerPrev = centerDown;

    // CENTER: force rescan
    if (centerEdge && !state->isScanning) {
        startScan();
        state->needsRedraw = true;
    }

    // UP/DOWN: scroll rogue list
    if (state->rogueCount > 0) {
        const int ROWS_VISIBLE = 4;
        if (upDown && (now - state->lastUp) > DEBOUNCE_MS) {
            state->lastUp = now;
            if (state->listSelected > 0) {
                state->listSelected--;
                if (state->listSelected < state->listScroll)
                    state->listScroll = state->listSelected;
                state->needsRedraw = true;
            }
        }
        if (downDown && (now - state->lastDown) > DEBOUNCE_MS) {
            state->lastDown = now;
            if (state->listSelected < state->rogueCount - 1) {
                state->listSelected++;
                if (state->listSelected >= state->listScroll + ROWS_VISIBLE)
                    state->listScroll = state->listSelected - (ROWS_VISIBLE - 1);
                state->needsRedraw = true;
            }
        }
    }

    // Fade NeoPixel after alert
    static unsigned long lastNeoFade = 0;
    if ((now - lastNeoFade) > 5000) {
        lastNeoFade = now;
        pixels.setPixelColor(0, 0);
        pixels.show();
    }

    // Redraw
    if (state->needsRedraw || (now - state->lastRedraw) > REDRAW_MS) {
        drawDisplay();
        state->lastRedraw = now;
        state->needsRedraw = false;
    }
}

void rogueApCleanup() {
    if (wifiInitialized) {
        esp_wifi_scan_stop();
        cleanupWiFi();
        wifiInitialized = false;
    }
    if (state) {
        free(state);
        state = nullptr;
    }
}
