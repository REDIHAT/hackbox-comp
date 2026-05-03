/*
    hackbox
    hackbox custom firmware

    RSSI Snare: single-target WiFi proximity tripwire.

    The operator picks a visible WiFi device from a live promiscuous
    scan. The tool then locks onto that MAC on its last-seen channel,
    streams every matching frame through an exponential moving average
    on the payload RSSI, and drives a hysteresis-buffered state machine
    (ABSENT / FAR / NEAR / CLOSE) that escalates the NeoPixel on each
    proximity change. Serial CSV exports samples for post-op review.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#include "../include/rssi_snare.h"
#include "../include/radio_manager.h"
#include "../include/neopixel.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include <string.h>
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

enum SnareMode : uint8_t {
    MODE_SCAN = 0,
    MODE_LOCK
};

enum SnareState : uint8_t {
    STATE_ABSENT = 0,
    STATE_FAR,
    STATE_NEAR,
    STATE_CLOSE
};

struct ScanEntry {
    uint8_t mac[6];
    int8_t lastRssi;
    uint8_t channel;
    bool hasSsid;
    char ssid[17];
    unsigned long lastSeen;
};

const int MAX_SCAN_ENTRIES = 32;
const int RSSI_RING_SIZE = 32;
const uint8_t HYSTERESIS_SAMPLES = 3;
const unsigned long ABSENT_TIMEOUT_MS = 15000;
const unsigned long CHANNEL_HOP_INTERVAL = 300;
const unsigned long REDRAW_INTERVAL = 200;
const unsigned long PERIODIC_REDRAW_MS = 1000;
const int8_t RSSI_NEAR_THRESHOLD = -80;
const int8_t RSSI_CLOSE_THRESHOLD = -60;
const int8_t RSSI_SENTINEL = -127;

std::vector<ScanEntry> scanEntries;

SnareMode mode = MODE_SCAN;
int selectedIdx = 0;
int scrollOffset = 0;
uint8_t currentChannel = 1;
unsigned long lastHop = 0;

uint8_t targetMac[6] = {0};
uint8_t lockChannel = 1;
bool hasTarget = false;
char targetSsid[17] = {0};
bool targetHasSsid = false;

int8_t ringRssi[RSSI_RING_SIZE] = {0};
uint8_t ringIdx = 0;
uint8_t ringCount = 0;
int16_t emaRssi = RSSI_SENTINEL;
volatile unsigned long lastSampleTime = 0;
volatile unsigned long samplesInLock = 0;

SnareState currentSnareState = STATE_ABSENT;
SnareState candidateState = STATE_ABSENT;
uint8_t candidateCount = 0;

bool serialOutput = false;
volatile bool needsRedraw = true;
unsigned long lastRedraw = 0;

void macToStr(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

SnareState classifyRssi(int8_t rssi) {
    if (rssi >= RSSI_CLOSE_THRESHOLD) return STATE_CLOSE;
    if (rssi >= RSSI_NEAR_THRESHOLD) return STATE_NEAR;
    return STATE_FAR;
}

const char *stateName(SnareState s) {
    switch (s) {
        case STATE_ABSENT: return "ABSENT";
        case STATE_FAR:    return "FAR";
        case STATE_NEAR:   return "NEAR";
        case STATE_CLOSE:  return "CLOSE";
    }
    return "?";
}

void applyStateNeo(SnareState s) {
    switch (s) {
        case STATE_ABSENT: neoSetStatus(NEO_RECON);   break;
        case STATE_FAR:    neoSetStatus(NEO_RECON);   break;
        case STATE_NEAR:   neoSetStatus(NEO_CAPTURE); break;
        case STATE_CLOSE:  neoSetStatus(NEO_ALERT);   break;
    }
}

int findScanEntry(const uint8_t *mac) {
    for (size_t i = 0; i < scanEntries.size(); i++) {
        if (memcmp(scanEntries[i].mac, mac, 6) == 0) return (int)i;
    }
    return -1;
}

// Walking the tagged parameters for beacons / probe responses. Beacon
// fixed fields are 12 bytes (timestamp 8 + beacon interval 2 + capability
// info 2), so tagged IEs start at offset 24 + 12. Probe response has the
// same layout. Anything else is ignored.
bool extractSsidFromBeacon(const uint8_t *frame, uint16_t len,
                           char *out, size_t outSize) {
    if (outSize == 0) return false;
    if (len < 38) return false;
    int pos = 24 + 12;
    while (pos + 2 <= (int)len) {
        uint8_t tagNum = frame[pos];
        uint8_t tagLen = frame[pos + 1];
        if (pos + 2 + tagLen > (int)len) break;
        if (tagNum == 0) {
            int copyLen = tagLen;
            if (copyLen > (int)outSize - 1) copyLen = (int)outSize - 1;
            if (copyLen > 0) {
                memcpy(out, &frame[pos + 2], copyLen);
                out[copyLen] = '\0';
                return true;
            }
            return false;
        }
        pos += 2 + tagLen;
    }
    return false;
}

void updateSnareStateFromSample(int8_t rssi) {
    SnareState classified = classifyRssi(rssi);

    // First contact after absence: jump to classified immediately so the
    // operator sees the tripwire fire on the first frame rather than
    // burning three samples to clear hysteresis.
    if (currentSnareState == STATE_ABSENT) {
        currentSnareState = classified;
        candidateState = classified;
        candidateCount = 0;
        applyStateNeo(currentSnareState);
        return;
    }

    if (classified == currentSnareState) {
        candidateCount = 0;
        return;
    }

    if (classified == candidateState) {
        if (candidateCount < 255) candidateCount++;
        if (candidateCount >= HYSTERESIS_SAMPLES) {
            currentSnareState = candidateState;
            candidateCount = 0;
            applyStateNeo(currentSnareState);
        }
    } else {
        candidateState = classified;
        candidateCount = 1;
    }
}

void IRAM_ATTR snareSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    int8_t rssi = pkt->rx_ctrl.rssi;

    if (len < 16) return;

    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;
    const uint8_t *srcMac = &frame[10];

    // Broadcast / multicast source is illegal in 802.11; treat as noise.
    if (srcMac[0] & 0x01) return;

    if (mode == MODE_LOCK && hasTarget) {
        if (memcmp(srcMac, targetMac, 6) != 0) return;

        uint8_t ri = ringIdx;
        ringRssi[ri] = rssi;
        ringIdx = (ri + 1) % RSSI_RING_SIZE;
        if (ringCount < RSSI_RING_SIZE) ringCount++;
        lastSampleTime = millis();
        samplesInLock++;

        // EMA with alpha = 0.25. Seed on the first sample so we do not
        // spend ~20 samples ramping out of the -127 sentinel.
        if (emaRssi == RSSI_SENTINEL || ringCount == 1) {
            emaRssi = rssi;
        } else {
            emaRssi = (emaRssi * 3 + rssi) / 4;
        }
        updateSnareStateFromSample((int8_t)emaRssi);
        needsRedraw = true;
        return;
    }

    int idx = findScanEntry(srcMac);
    if (idx >= 0) {
        scanEntries[idx].lastRssi = rssi;
        scanEntries[idx].channel = currentChannel;
        scanEntries[idx].lastSeen = millis();
        if (!scanEntries[idx].hasSsid && ftype == 0 &&
            (fsubtype == 8 || fsubtype == 5)) {
            char ssid[17] = {0};
            if (extractSsidFromBeacon(frame, len, ssid, sizeof(ssid)) &&
                ssid[0]) {
                strncpy(scanEntries[idx].ssid, ssid, 16);
                scanEntries[idx].ssid[16] = '\0';
                scanEntries[idx].hasSsid = true;
            }
        }
        return;
    }

    if (scanEntries.size() >= (size_t)MAX_SCAN_ENTRIES) return;

    ScanEntry e = {};
    memcpy(e.mac, srcMac, 6);
    e.lastRssi = rssi;
    e.channel = currentChannel;
    e.hasSsid = false;
    e.lastSeen = millis();
    if (ftype == 0 && (fsubtype == 8 || fsubtype == 5)) {
        char ssid[17] = {0};
        if (extractSsidFromBeacon(frame, len, ssid, sizeof(ssid)) && ssid[0]) {
            strncpy(e.ssid, ssid, 16);
            e.ssid[16] = '\0';
            e.hasSsid = true;
        }
    }
    scanEntries.push_back(e);
    needsRedraw = true;
}

void drawScan() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char header[32];
    snprintf(header, sizeof(header), "RSSI Snare  %d/%d",
             (int)scanEntries.size(), MAX_SCAN_ENTRIES);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    const int displayRows = 5;
    if ((int)scanEntries.size() == 0) {
        u8g2.drawStr(0, 32, "Listening...");
        u8g2.drawStr(0, 42, "Hopping 1-13");
    } else {
        for (int i = 0; i < displayRows; i++) {
            int idx = scrollOffset + i;
            if (idx >= (int)scanEntries.size()) break;
            const ScanEntry &e = scanEntries[idx];
            int topY = 12 + (i * 9);
            int textY = topY + 7;

            if (idx == selectedIdx) {
                u8g2.drawBox(0, topY, 128, 9);
                u8g2.setDrawColor(0);
            }

            char ident[14];
            if (e.hasSsid) {
                strncpy(ident, e.ssid, 13);
                ident[13] = '\0';
            } else if (privacyModeEnabled) {
                strncpy(ident, "XX:XX:XX:XX", sizeof(ident));
                ident[sizeof(ident) - 1] = '\0';
            } else {
                snprintf(ident, sizeof(ident), "%02X%02X%02X%02X%02X%02X",
                         e.mac[0], e.mac[1], e.mac[2],
                         e.mac[3], e.mac[4], e.mac[5]);
            }

            char line[32];
            snprintf(line, sizeof(line), "%-13s %4d ch%-2d",
                     ident, (int)e.lastRssi, (int)e.channel);
            u8g2.drawStr(0, textY, line);

            if (idx == selectedIdx) {
                u8g2.setDrawColor(1);
            }
        }
    }

    char footer[32];
    snprintf(footer, sizeof(footer), "CEN=Lock R=Clr ch%d", (int)currentChannel);
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawLock() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char macStr[18];
    if (privacyModeEnabled) {
        strncpy(macStr, "XX:XX:XX:XX:XX:XX", sizeof(macStr));
    } else {
        macToStr(targetMac, macStr);
    }

    char header[32];
    if (targetHasSsid) {
        snprintf(header, sizeof(header), "SNARE %.16s", targetSsid);
    } else {
        snprintf(header, sizeof(header), "SNARE %s", macStr);
    }
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    bool live = (ringCount > 0 && currentSnareState != STATE_ABSENT);

    u8g2.setFont(u8g2_font_helvB18_tr);
    char rssiBuf[8];
    if (live) {
        snprintf(rssiBuf, sizeof(rssiBuf), "%d", (int)emaRssi);
    } else {
        strncpy(rssiBuf, "---", sizeof(rssiBuf));
    }
    int w = u8g2.getUTF8Width(rssiBuf);
    u8g2.setCursor((128 - w) / 2, 32);
    u8g2.print(rssiBuf);

    u8g2.setFont(u8g2_font_5x8_tr);
    int dbw = u8g2.getUTF8Width("dBm");
    u8g2.drawStr((128 - dbw) / 2, 42, "dBm");

    int bar = 0;
    if (live) {
        int clamped = emaRssi;
        if (clamped < -100) clamped = -100;
        if (clamped > -30)  clamped = -30;
        bar = ((clamped + 100) * 128) / 70;
    }
    u8g2.drawFrame(0, 46, 128, 6);
    if (bar > 0) u8g2.drawBox(0, 46, bar, 6);

    char footer[32];
    const char *csvTag = serialOutput ? "csv" : "---";
    snprintf(footer, sizeof(footer), "%-6s n%lu ch%d %s",
             stateName(currentSnareState),
             (unsigned long)samplesInLock,
             (int)lockChannel,
             csvTag);
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void enterScanMode() {
    mode = MODE_SCAN;
    scanEntries.clear();
    scanEntries.reserve(MAX_SCAN_ENTRIES);
    selectedIdx = 0;
    scrollOffset = 0;
    currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
    hasTarget = false;
    serialOutput = false;
    neoSetStatus(NEO_RECON);
    needsRedraw = true;
}

void enterLockMode(const ScanEntry &e) {
    memcpy(targetMac, e.mac, 6);
    lockChannel = (e.channel >= 1 && e.channel <= 13) ? e.channel : currentChannel;
    hasTarget = true;
    targetHasSsid = e.hasSsid;
    if (e.hasSsid) {
        strncpy(targetSsid, e.ssid, 16);
        targetSsid[16] = '\0';
    } else {
        targetSsid[0] = '\0';
    }

    ringIdx = 0;
    ringCount = 0;
    emaRssi = RSSI_SENTINEL;
    lastSampleTime = 0;
    samplesInLock = 0;
    currentSnareState = STATE_ABSENT;
    candidateState = STATE_ABSENT;
    candidateCount = 0;
    applyStateNeo(currentSnareState);

    esp_wifi_set_channel(lockChannel, WIFI_SECOND_CHAN_NONE);
    mode = MODE_LOCK;
    needsRedraw = true;

    char macStr[18];
    macToStr(targetMac, macStr);
    Serial.println();
    Serial.print("# Snare target ");
    Serial.print(macStr);
    Serial.print(" on channel ");
    Serial.println(lockChannel);
}

} // namespace

void rssiSnareSetup() {
    scanEntries.clear();
    scanEntries.reserve(MAX_SCAN_ENTRIES);
    mode = MODE_SCAN;
    selectedIdx = 0;
    scrollOffset = 0;
    currentChannel = 1;
    hasTarget = false;
    targetHasSsid = false;
    targetSsid[0] = '\0';
    ringIdx = 0;
    ringCount = 0;
    emaRssi = RSSI_SENTINEL;
    lastSampleTime = 0;
    samplesInLock = 0;
    currentSnareState = STATE_ABSENT;
    candidateState = STATE_ABSENT;
    candidateCount = 0;
    serialOutput = false;
    needsRedraw = true;
    lastRedraw = 0;

    // Promiscuous RX silently fails on WIFI_MODE_STA across several
    // ESP-IDF builds; packet_logger and probe_logger both use AP mode
    // for the same reason.
    initWiFi(WIFI_MODE_AP);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(snareSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.println();
    Serial.println("# hackbox RSSI Snare v1.0");
    Serial.println("# SCAN: browse visible MACs, CENTER locks onto one");
    Serial.println("# LOCK: RIGHT toggles CSV, CENTER returns to scan");
    Serial.println("# timestamp_ms,src_mac,rssi_ema,state,channel");

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    lastHop = millis();
    neoSetStatus(NEO_RECON);
    drawScan();
}

void rssiSnareLoop() {
    unsigned long now = millis();

    static bool upPrev = false;
    static bool downPrev = false;
    static bool rightPrev = false;
    static bool centerPrev = false;

    bool upNow     = digitalRead(BUTTON_PIN_UP)     == LOW;
    bool downNow   = digitalRead(BUTTON_PIN_DOWN)   == LOW;
    bool rightNow  = digitalRead(BUTTON_PIN_RIGHT)  == LOW;
    bool centerNow = digitalRead(BUTTON_PIN_CENTER) == LOW;

    if (mode == MODE_SCAN) {
        if (now - lastHop >= CHANNEL_HOP_INTERVAL) {
            lastHop = now;
            currentChannel++;
            if (currentChannel > 13) currentChannel = 1;
            esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            needsRedraw = true;
        }

        if (upNow && !upPrev) {
            if (selectedIdx > 0) selectedIdx--;
            needsRedraw = true;
        }
        if (downNow && !downPrev) {
            if (selectedIdx + 1 < (int)scanEntries.size()) selectedIdx++;
            needsRedraw = true;
        }
        if (rightNow && !rightPrev) {
            enterScanMode();
        }
        if (centerNow && !centerPrev && !scanEntries.empty()) {
            ScanEntry chosen = scanEntries[selectedIdx];
            enterLockMode(chosen);
        }

        if ((int)scanEntries.size() > 0 &&
            selectedIdx >= (int)scanEntries.size()) {
            selectedIdx = (int)scanEntries.size() - 1;
        }
        const int displayRows = 5;
        if (selectedIdx < scrollOffset) scrollOffset = selectedIdx;
        if (selectedIdx >= scrollOffset + displayRows) {
            scrollOffset = selectedIdx - displayRows + 1;
        }
        if (scrollOffset < 0) scrollOffset = 0;

        if (needsRedraw && now - lastRedraw >= REDRAW_INTERVAL) {
            needsRedraw = false;
            lastRedraw = now;
            drawScan();
        }
    } else {
        if (lastSampleTime != 0 &&
            now - lastSampleTime > ABSENT_TIMEOUT_MS &&
            currentSnareState != STATE_ABSENT) {
            currentSnareState = STATE_ABSENT;
            candidateState = STATE_ABSENT;
            candidateCount = 0;
            applyStateNeo(currentSnareState);
            needsRedraw = true;
        }

        if (serialOutput && lastSampleTime != 0) {
            static unsigned long lastEmittedTs = 0;
            if (lastSampleTime != lastEmittedTs) {
                char macStr[18];
                macToStr(targetMac, macStr);
                Serial.printf("%lu,%s,%d,%s,%u\n",
                    (unsigned long)lastSampleTime,
                    macStr,
                    (int)emaRssi,
                    stateName(currentSnareState),
                    (unsigned int)lockChannel);
                lastEmittedTs = lastSampleTime;
            }
        }

        if (rightNow && !rightPrev) {
            serialOutput = !serialOutput;
            needsRedraw = true;
        }
        if (centerNow && !centerPrev) {
            hasTarget = false;
            enterScanMode();
        }

        if (needsRedraw && now - lastRedraw >= REDRAW_INTERVAL) {
            needsRedraw = false;
            lastRedraw = now;
            drawLock();
        } else if (now - lastRedraw >= PERIODIC_REDRAW_MS) {
            lastRedraw = now;
            drawLock();
        }
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;
    centerPrev = centerNow;
}

void rssiSnareCleanup() {
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    scanEntries.clear();
    hasTarget = false;
    serialOutput = false;
    currentSnareState = STATE_ABSENT;
}
