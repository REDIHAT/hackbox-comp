/*
    hackbox
    hackbox custom firmware

    Probe Logger — Passive WiFi probe request logger
    Captures probe requests in promiscuous mode, extracts MAC + SSID pairs.
    - OLED: scrollable list of unique MAC -> SSID entries
    - Serial: CSV output (timestamp_ms,src_mac,ssid,rssi,channel)
    - Channel hops across 1-13 every 500ms
*/

#include "../include/probe_logger.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include <string.h>
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== Data Structures =====

struct ProbeEntry {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    unsigned long timestamp;
};

const int MAX_PROBES = 100;
std::vector<ProbeEntry> probes;

// ===== State =====
uint8_t currentChannel = 1;
unsigned long lastHop = 0;
const unsigned long HOP_INTERVAL = 500;

int scrollOffset = 0;
bool serialOutput = false;
bool needsRedraw = true;
int lastProbeCount = 0;
int lastScrollOffset = -1;
bool lastSerialOutput = false;

// ===== Helpers =====

void macToStr(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// RFC4180-style CSV field escaping. SSIDs are 1..32 bytes of arbitrary
// payload and can legally contain commas, quotes, and control bytes, so
// printing them raw corrupts the CSV stream the same way evil_portal did
// before its recent integrity fix. Always quote the field and double any
// embedded quotes; strip CR/LF since the log is line-delimited.
// Output buffer must be >= 2 + 2*srcLen + 1 bytes.
void csvEscapeField(const char *src, char *out, size_t outSize) {
    if (outSize == 0) return;
    size_t o = 0;
    if (o + 1 < outSize) out[o++] = '"';
    for (size_t i = 0; src[i] != '\0'; i++) {
        char c = src[i];
        if (c == '\r' || c == '\n') continue;
        if (c == '"') {
            if (o + 2 >= outSize) break;
            out[o++] = '"';
            out[o++] = '"';
        } else {
            if (o + 1 >= outSize) break;
            out[o++] = c;
        }
    }
    if (o + 1 < outSize) out[o++] = '"';
    out[o] = '\0';
}

bool isDuplicate(const uint8_t *mac, const char *ssid) {
    for (size_t i = 0; i < probes.size(); i++) {
        if (memcmp(probes[i].mac, mac, 6) == 0 &&
            strcmp(probes[i].ssid, ssid) == 0) {
            // Update RSSI on re-seen
            return true;
        }
    }
    return false;
}

// ===== Promiscuous Callback =====

void IRAM_ATTR probeSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 38) return;

    // Check frame type: management (0) subtype: probe request (0x04)
    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;
    if (ftype != 0 || fsubtype != 4) return;

    // Source MAC is addr2 at offset 10
    const uint8_t *srcMac = &frame[10];

    // Extract SSID from tagged parameters
    // Frame body starts at offset 24 for management frames
    // Tagged parameters start at offset 24 (no fixed fields for probe request)
    char ssid[33] = {0};
    int pos = 24;
    while (pos + 2 <= len) {
        uint8_t tagNum = frame[pos];
        uint8_t tagLen = frame[pos + 1];
        if (pos + 2 + tagLen > len) break;

        if (tagNum == 0) { // SSID tag
            int copyLen = tagLen;
            if (copyLen > 32) copyLen = 32;
            if (copyLen > 0) {
                memcpy(ssid, &frame[pos + 2], copyLen);
                ssid[copyLen] = '\0';
            } else {
                strncpy(ssid, "<broadcast>", 32);
                ssid[32] = '\0';
            }
            break;
        }
        pos += 2 + tagLen;
    }

    if (ssid[0] == '\0') {
        strncpy(ssid, "<broadcast>", 32);
        ssid[32] = '\0';
    }

    // Check for duplicate MAC+SSID pair
    if (isDuplicate(srcMac, ssid)) return;

    // Enforce max capacity
    if (probes.size() >= MAX_PROBES) return;

    ProbeEntry entry = {};
    memcpy(entry.mac, srcMac, 6);
    strncpy(entry.ssid, ssid, 32);
    entry.ssid[32] = '\0';
    entry.rssi = pkt->rx_ctrl.rssi;
    entry.channel = currentChannel;
    entry.timestamp = millis();

    probes.push_back(entry);
    addXP(1);
    needsRedraw = true;

    // Serial CSV output if enabled
    if (serialOutput) {
        char macStr[18];
        macToStr(srcMac, macStr);
        char ssidCsv[70]; // 2 quotes + up to 2*32 escaped chars + NUL
        csvEscapeField(entry.ssid, ssidCsv, sizeof(ssidCsv));
        Serial.printf("%lu,%s,%s,%d,%u\n",
            entry.timestamp, macStr, ssidCsv, entry.rssi, entry.channel);
    }
}

// ===== Display =====

void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // Header
    char header[32];
    snprintf(header, sizeof(header), "Probe Logger  %d/%d", (int)probes.size(), MAX_PROBES);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    // Show probe entries
    int displayRows = 5;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        if (idx >= (int)probes.size()) break;

        const ProbeEntry &e = probes[idx];
        char macShort[9];
        if (privacyModeEnabled) {
            strncpy(macShort, "XX:XX:XX", sizeof(macShort) - 1);
            macShort[sizeof(macShort) - 1] = '\0';
        } else {
            snprintf(macShort, sizeof(macShort), "%02X%02X%02X",
                     e.mac[3], e.mac[4], e.mac[5]);
        }

        char ssidShort[11];
        strncpy(ssidShort, e.ssid, 10);
        ssidShort[10] = '\0';

        char line[28];
        snprintf(line, sizeof(line), "%s>%.10s %d", macShort, ssidShort, e.rssi);
        u8g2.drawStr(0, 20 + (i * 8), line);
    }

    // Footer
    char footer[32];
    snprintf(footer, sizeof(footer), "U/D=Scrl R=%s Ch:%d",
             serialOutput ? "CSV:ON" : "CSV:OFF", currentChannel);
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void probeLoggerSetup() {
    probes.clear();
    probes.reserve(MAX_PROBES);
    currentChannel = 1;
    lastHop = 0;
    scrollOffset = 0;
    serialOutput = false;
    needsRedraw = true;
    lastProbeCount = 0;
    lastScrollOffset = -1;
    lastSerialOutput = false;

    // Promiscuous RX silently fails on WIFI_MODE_STA across several ESP-IDF
    // builds. The same fix was applied to packet_logger, handshake_capture,
    // and wifi_scan; probe_logger had been quietly broken on those builds.
    initWiFi(WIFI_MODE_AP);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(probeSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.println();
    Serial.println("# hackbox Probe Logger v1.0");
    Serial.println("# Press RIGHT to toggle CSV output");
    Serial.println("# timestamp_ms,src_mac,ssid,rssi,channel");

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScreen();
}

void probeLoggerLoop() {
    unsigned long now = millis();

    // --- Channel hopping ---
    if (now - lastHop >= HOP_INTERVAL) {
        lastHop = now;
        currentChannel++;
        if (currentChannel > 13) currentChannel = 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }

    // --- Button handling ---
    static bool upPrev = false, downPrev = false, rightPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;

    // UP: scroll up
    if (upNow && !upPrev && scrollOffset > 0) {
        scrollOffset--;
        needsRedraw = true;
        delay(150);
    }

    // DOWN: scroll down
    if (downNow && !downPrev && scrollOffset < (int)probes.size() - 5) {
        scrollOffset++;
        needsRedraw = true;
        delay(150);
    }

    // RIGHT: toggle serial CSV output
    if (rightNow && !rightPrev) {
        serialOutput = !serialOutput;
        needsRedraw = true;
        delay(200);
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;

    // --- Display update ---
    if ((int)probes.size() != lastProbeCount ||
        scrollOffset != lastScrollOffset ||
        serialOutput != lastSerialOutput) {
        needsRedraw = true;
        lastProbeCount = (int)probes.size();
        lastScrollOffset = scrollOffset;
        lastSerialOutput = serialOutput;
    }

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupProbeLogger() {
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    probes.clear();
}
