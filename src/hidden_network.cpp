/*
    hackbox
    hackbox custom firmware

    Hidden Network Revealer — Finds and unmasks hidden WiFi networks.
    Captures beacons with empty SSIDs, then cross-references with probe
    responses on the same BSSID to extract the real SSID.
    - OLED: hidden count, revealed count, scrollable network list
    - Serial: CSV output (timestamp_ms,bssid,ssid,rssi,channel,status)
    - Channel hops across 1-13 every 500ms
    - Awards 5 XP per hidden network found, 10 XP per SSID revealed
*/

#include "../include/hidden_network.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== Data Structures =====

struct HiddenNetwork {
    uint8_t bssid[6];
    char ssid[33];          // revealed SSID (empty until unmasked)
    int8_t rssi;
    uint8_t channel;
    bool revealed;           // true once SSID has been unmasked
    unsigned long foundAt;
    unsigned long revealedAt;
};

const int MAX_HIDDEN = 50;
HiddenNetwork networks[MAX_HIDDEN];
int networkCount = 0;
int hiddenCount = 0;
int revealedCount = 0;

// ===== State =====
uint8_t currentChannel = 1;
unsigned long lastHop = 0;
const unsigned long HOP_INTERVAL = 500;

int scrollOffset = 0;
bool serialOutput = false;
bool needsRedraw = true;

// Dirty tracking for efficient redraws
int lastNetworkCount = 0;
int lastRevealedCount = 0;
int lastScrollOffset = -1;
bool lastSerialOutput = false;

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

void addHiddenNetwork(const uint8_t *bssid, int8_t rssi, uint8_t channel) {
    if (findByBSSID(bssid) >= 0) return;  // already tracked
    if (networkCount >= MAX_HIDDEN) return;

    HiddenNetwork &net = networks[networkCount];
    memcpy(net.bssid, bssid, 6);
    net.ssid[0] = '\0';
    net.rssi = rssi;
    net.channel = channel;
    net.revealed = false;
    net.foundAt = millis();
    net.revealedAt = 0;

    networkCount++;
    hiddenCount++;
    addXP(5);
    needsRedraw = true;

    if (serialOutput) {
        char bssidStr[18];
        bssidToStr(bssid, bssidStr);
        Serial.printf("%lu,%s,,,%u,HIDDEN\n", millis(), bssidStr, channel);
    }
}

void revealNetwork(int idx, const char *ssid, int8_t rssi) {
    if (idx < 0 || idx >= networkCount) return;
    if (networks[idx].revealed) return;  // already revealed

    strncpy(networks[idx].ssid, ssid, 32);
    networks[idx].ssid[32] = '\0';
    networks[idx].revealed = true;
    networks[idx].revealedAt = millis();
    // RSSI 0 dBm is a legitimate (very strong) reading, not a sentinel.
    // Always update so the displayed signal matches the probe response.
    networks[idx].rssi = rssi;
    revealedCount++;
    addXP(10);
    needsRedraw = true;

    if (serialOutput) {
        char bssidStr[18];
        bssidToStr(networks[idx].bssid, bssidStr);

        // Sanitize the revealed SSID before emitting. The serial output is
        // documented as CSV (see banner in hiddenNetworkSetup()), so a name
        // containing commas or newlines would corrupt the stream and break
        // any downstream parser consuming it.
        char safeSSID[33];
        strncpy(safeSSID, ssid, sizeof(safeSSID) - 1);
        safeSSID[sizeof(safeSSID) - 1] = '\0';
        for (char *s = safeSSID; *s; ++s) {
            if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
        }

        Serial.printf("%lu,%s,%s,%d,%u,REVEALED\n",
            millis(), bssidStr, safeSSID, rssi, networks[idx].channel);
    }
}

// ===== Promiscuous Callback =====

void IRAM_ATTR hiddenSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 36) return;

    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;

    // Only management frames
    if (ftype != 0) return;

    // Beacon frame (subtype 8): check for hidden SSID
    if (fsubtype == 8) {
        // BSSID is addr3 at offset 16
        const uint8_t *bssid = &frame[16];

        // Tagged parameters start at offset 36 (24 header + 12 fixed fields)
        int pos = 36;
        while (pos + 2 <= (int)len) {
            uint8_t tagNum = frame[pos];
            uint8_t tagLen = frame[pos + 1];
            if (pos + 2 + tagLen > (int)len) break;

            if (tagNum == 0) { // SSID tag
                if (tagLen == 0) {
                    // Empty SSID = hidden network
                    addHiddenNetwork(bssid, pkt->rx_ctrl.rssi, currentChannel);
                } else {
                    // Check for null-padded SSID (some APs send \0\0\0 instead of empty)
                    bool allZeros = true;
                    for (int j = 0; j < tagLen; j++) {
                        if (frame[pos + 2 + j] != 0) {
                            allZeros = false;
                            break;
                        }
                    }
                    if (allZeros) {
                        addHiddenNetwork(bssid, pkt->rx_ctrl.rssi, currentChannel);
                    }
                }
                break;
            }
            pos += 2 + tagLen;
        }
        return;
    }

    // Probe response (subtype 5): may reveal a hidden network's SSID
    if (fsubtype == 5) {
        // BSSID is addr3 at offset 16 (same as source for probe responses)
        const uint8_t *bssid = &frame[16];

        int idx = findByBSSID(bssid);
        if (idx < 0) return;  // not a tracked hidden network
        if (networks[idx].revealed) return;  // already revealed

        // Extract SSID from tagged parameters (offset 36 for probe response)
        int pos = 36;
        while (pos + 2 <= (int)len) {
            uint8_t tagNum = frame[pos];
            uint8_t tagLen = frame[pos + 1];
            if (pos + 2 + tagLen > (int)len) break;

            if (tagNum == 0 && tagLen > 0) {
                char ssid[33] = {0};
                int copyLen = (tagLen > 32) ? 32 : tagLen;
                memcpy(ssid, &frame[pos + 2], copyLen);
                ssid[copyLen] = '\0';

                // Verify it's not all zeros
                bool valid = false;
                for (int j = 0; j < copyLen; j++) {
                    if (ssid[j] != '\0') { valid = true; break; }
                }
                if (valid) {
                    revealNetwork(idx, ssid, pkt->rx_ctrl.rssi);
                }
                break;
            }
            pos += 2 + tagLen;
        }
        return;
    }

    // Probe request (subtype 4): directed probes tell us what hidden SSIDs
    // nearby devices are looking for. If we see a directed probe AND we have
    // a hidden AP that hasn't been revealed yet, a subsequent probe response
    // will be handled above. We can also use directed probes to attempt
    // revealing: if a device probes for "SecretNet" and we have an unrevealed
    // AP, we can't match them yet (no BSSID link), but we log the attempt.
    // This is handled passively; the probe response callback above does the
    // actual matching once the AP responds.
}

// ===== Display =====

void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // Header
    char header[32];
    snprintf(header, sizeof(header), "Hidden Networks  %d/%d",
             hiddenCount, MAX_HIDDEN);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    // Stats line
    char stats[40];
    snprintf(stats, sizeof(stats), "Found:%d Revealed:%d Ch:%d",
             hiddenCount, revealedCount, currentChannel);
    u8g2.drawStr(0, 20, stats);
    u8g2.drawHLine(0, 22, 128);

    // Network list
    int displayRows = 4;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        if (idx >= networkCount) break;

        const HiddenNetwork &net = networks[idx];
        char bssidShort[9];
        if (privacyModeEnabled) {
            strncpy(bssidShort, "XX:XX:XX", sizeof(bssidShort) - 1);
            bssidShort[sizeof(bssidShort) - 1] = '\0';
        } else {
            snprintf(bssidShort, sizeof(bssidShort), "%02X%02X%02X",
                     net.bssid[3], net.bssid[4], net.bssid[5]);
        }

        char line[32];
        if (net.revealed) {
            char ssidShort[11];
            strncpy(ssidShort, net.ssid, 10);
            ssidShort[10] = '\0';
            snprintf(line, sizeof(line), "*%s>%.10s %d",
                     bssidShort, ssidShort, net.rssi);
        } else {
            snprintf(line, sizeof(line), " %s>[hidden] %d",
                     bssidShort, net.rssi);
        }
        u8g2.drawStr(0, 32 + (i * 8), line);
    }

    // Footer
    char footer[32];
    snprintf(footer, sizeof(footer), "U/D=Scrl R=%s",
             serialOutput ? "CSV:ON" : "CSV:OFF");
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void hiddenNetworkSetup() {
    networkCount = 0;
    hiddenCount = 0;
    revealedCount = 0;
    currentChannel = 1;
    lastHop = 0;
    scrollOffset = 0;
    serialOutput = false;
    needsRedraw = true;
    lastNetworkCount = 0;
    lastRevealedCount = 0;
    lastScrollOffset = -1;
    lastSerialOutput = false;

    memset(networks, 0, sizeof(networks));

    initWiFi(WIFI_MODE_AP);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(hiddenSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.println();
    Serial.println("# hackbox Hidden Network Revealer v1.0");
    Serial.println("# Scanning for hidden SSIDs...");
    Serial.println("# Press RIGHT to toggle CSV output");
    Serial.println("# timestamp_ms,bssid,ssid,rssi,channel,status");

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScreen();
}

void hiddenNetworkLoop() {
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

    if (upNow && !upPrev && scrollOffset > 0) {
        scrollOffset--;
        needsRedraw = true;
        delay(150);
    }

    if (downNow && !downPrev && scrollOffset < networkCount - 4) {
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

    // --- Display update ---
    if (networkCount != lastNetworkCount ||
        revealedCount != lastRevealedCount ||
        scrollOffset != lastScrollOffset ||
        serialOutput != lastSerialOutput) {
        needsRedraw = true;
        lastNetworkCount = networkCount;
        lastRevealedCount = revealedCount;
        lastScrollOffset = scrollOffset;
        lastSerialOutput = serialOutput;
    }

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupHiddenNetwork() {
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    networkCount = 0;
    hiddenCount = 0;
    revealedCount = 0;
}
