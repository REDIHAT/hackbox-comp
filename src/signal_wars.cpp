/*
    hackbox - Signal Wars

    WiFi territory control game. Beacon-spam your team's SSIDs to claim
    zones. Scan to see who controls an area. NeoPixel shows team color.

    States: SW_TEAM_SELECT, SW_LOBBY, SW_CLAIMING, SW_SCANNING, SW_SCOREBOARD
    Controls: UP/DOWN = navigate, CENTER = select, RIGHT = start action
    LEFT is reserved globally as the exit-app button by runApp().
*/

#include "../include/signal_wars.h"
#include "../include/level_system.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include "../include/neopixel.h"
#include "../include/radio_manager.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <EEPROM.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== EEPROM =====
#define EEPROM_SW_TERRITORIES 112  // 16-bit total territories claimed
#define EEPROM_SW_TEAM        115  // 1 byte: 0=unset, 1=RED, 2=BLUE

// ===== State Machine =====
enum SWState {
    SW_TEAM_SELECT,
    SW_LOBBY,
    SW_CLAIMING,
    SW_SCANNING
};

SWState swState = SW_TEAM_SELECT;

// ===== Team =====
uint8_t team = 0;  // 1=RED, 2=BLUE
char teamTag[5];    // "RED" or "BLUE"

// ===== Territory Tracking =====
struct Territory {
    char ssid[20];
    uint8_t ownerTeam;  // 1=RED, 2=BLUE
    int8_t rssi;
};

const int MAX_TERRITORIES = 4;
Territory territories[MAX_TERRITORIES];
int territoryCount = 0;
int redCount = 0;
int blueCount = 0;

// ===== UI =====
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
bool claiming = false;
unsigned long claimStartTime = 0;
unsigned long lastBeaconTime = 0;
int claimChannel = 1;
unsigned long lastScanTime = 0;

// ===== Device ID (last 4 of MAC) =====
char deviceId[5];

// ===== Beacon Spam =====

void sendBeacon(const char* ssid, int channel) {
    // Raw 802.11 beacon frame
    uint8_t beacon[] = {
        0x80, 0x00,             // Frame Control: Beacon
        0x00, 0x00,             // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Destination: broadcast
        0xBE, 0xE5, 0x00, 0x00, 0x00, 0x01,  // Source (fake)
        0xBE, 0xE5, 0x00, 0x00, 0x00, 0x01,  // BSSID (same)
        0x00, 0x00,             // Sequence
        // Fixed params (timestamp, interval, capability)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00,             // Beacon interval
        0x31, 0x04,             // Capability
    };

    int ssidLen = strlen(ssid);
    if (ssidLen > 32) ssidLen = 32;

    uint8_t frame[128];
    int pos = 0;
    memcpy(frame, beacon, sizeof(beacon));
    pos = sizeof(beacon);

    // SSID tag
    frame[pos++] = 0x00;  // Tag: SSID
    frame[pos++] = ssidLen;
    memcpy(&frame[pos], ssid, ssidLen);
    pos += ssidLen;

    // Supported rates
    frame[pos++] = 0x01;
    frame[pos++] = 0x08;
    frame[pos++] = 0x82; frame[pos++] = 0x84; frame[pos++] = 0x8b;
    frame[pos++] = 0x96; frame[pos++] = 0x24; frame[pos++] = 0x30;
    frame[pos++] = 0x48; frame[pos++] = 0x6c;

    // DS Parameter Set (channel)
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = channel;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, pos, false);
}

// ===== Drawing =====

void drawTeamSelect() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Signal Wars");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 26, "Choose your team:");

    u8g2.setFont(u8g2_font_6x10_tr);
    if (team == 1) {
        u8g2.drawStr(10, 42, "> RED <");
        u8g2.drawStr(80, 42, "  BLUE");
    } else {
        u8g2.drawStr(10, 42, "  RED");
        u8g2.drawStr(80, 42, "> BLUE <");
    }

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 62, "U/D=Pick  C=Confirm");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawLobby() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Signal Wars");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char teamLine[24];
    snprintf(teamLine, sizeof(teamLine), "Team: %s  [%s]", teamTag, deviceId);
    u8g2.drawStr(0, 24, teamLine);

    uint16_t totalClaims = (EEPROM.read(EEPROM_SW_TERRITORIES + 1) << 8) |
                            EEPROM.read(EEPROM_SW_TERRITORIES);
    char statsLine[28];
    snprintf(statsLine, sizeof(statsLine), "Lifetime claims: %u", totalClaims);
    u8g2.drawStr(0, 36, statsLine);

    u8g2.drawStr(0, 50, "R=Claim Territory");
    u8g2.drawStr(0, 58, "C=Scan Area  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawClaiming() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    char title[20];
    snprintf(title, sizeof(title), "CLAIMING [%s]", teamTag);
    u8g2.drawStr(0, 10, title);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    unsigned long elapsed = (millis() - claimStartTime) / 1000;
    char timeLine[20];
    snprintf(timeLine, sizeof(timeLine), "Active: %lus", elapsed);
    u8g2.drawStr(0, 24, timeLine);

    char chLine[20];
    snprintf(chLine, sizeof(chLine), "Channel: %d", claimChannel);
    u8g2.drawStr(0, 34, chLine);

    // Animated broadcast indicator
    int dots = (millis() / 300) % 4;
    char broadcasting[20] = "Broadcasting";
    for (int i = 0; i < dots; i++) strcat(broadcasting, ".");
    u8g2.drawStr(0, 46, broadcasting);

    u8g2.drawStr(0, 62, "C=Stop  U/D=Channel");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawScanning() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Territory Map");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char scoreLine[28];
    snprintf(scoreLine, sizeof(scoreLine), "RED: %d   BLUE: %d", redCount, blueCount);
    u8g2.drawStr(0, 22, scoreLine);

    // Draw territory bars
    int totalT = redCount + blueCount;
    if (totalT > 0) {
        int barW = 120;
        int redW = (redCount * barW) / totalT;
        u8g2.drawFrame(4, 26, barW, 8);
        if (redW > 0) u8g2.drawBox(4, 26, redW, 8);
    }

    // List territories
    int maxShow = 3;
    for (int i = 0; i < maxShow && i < territoryCount; i++) {
        char line[30];
        snprintf(line, sizeof(line), "%s %s %ddB",
                 territories[i].ownerTeam == 1 ? "R" : "B",
                 territories[i].ssid + 4,  // skip "[SW]"
                 territories[i].rssi);
        u8g2.drawStr(0, 40 + (i * 8), line);
    }

    u8g2.drawStr(0, 62, "R=Rescan  C=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ===== Scanning =====

void scanTerritories() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(50);

    int n = WiFi.scanNetworks(false, false, false, 300);
    territoryCount = 0;
    redCount = 0;
    blueCount = 0;

    for (int i = 0; i < n && territoryCount < MAX_TERRITORIES; i++) {
        String ssid = WiFi.SSID(i);
        if (!ssid.startsWith("[SW]")) continue;

        Territory &t = territories[territoryCount];
        strncpy(t.ssid, ssid.c_str(), 19);
        t.ssid[19] = '\0';
        t.rssi = WiFi.RSSI(i);

        if (ssid.indexOf("RED") >= 0) {
            t.ownerTeam = 1;
            redCount++;
        } else if (ssid.indexOf("BLU") >= 0) {
            t.ownerTeam = 2;
            blueCount++;
        }
        territoryCount++;
    }

    WiFi.scanDelete();
    Serial.printf("# Signal Wars scan: RED=%d BLUE=%d\n", redCount, blueCount);
}

} // namespace

// ===== Public API =====

void signalWarsSetup() {
    // Load saved team
    uint8_t savedTeam = EEPROM.read(EEPROM_SW_TEAM);
    team = (savedTeam == 1 || savedTeam == 2) ? savedTeam : 1;
    strlcpy(teamTag, team == 1 ? "RED" : "BLUE", sizeof(teamTag));

    swState = (savedTeam == 1 || savedTeam == 2) ? SW_LOBBY : SW_TEAM_SELECT;

    // Get device ID from MAC
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(deviceId, sizeof(deviceId), "%02X%02X", mac[4], mac[5]);

    territoryCount = 0;
    redCount = 0;
    blueCount = 0;
    claiming = false;
    needsRedraw = true;
    lastButtonPress = 0;

    Serial.println();
    Serial.println("# hackbox Signal Wars v1.0");

    if (swState == SW_TEAM_SELECT) drawTeamSelect();
    else drawLobby();
}

void signalWarsLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (swState) {
        case SW_TEAM_SELECT: {
            if (now - lastButtonPress > debounceDelay) {
                if (up || down) {
                    team = (team == 1) ? 2 : 1;
                    strlcpy(teamTag, team == 1 ? "RED" : "BLUE", sizeof(teamTag));
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    EEPROM.write(EEPROM_SW_TEAM, team);
                    EEPROM.commit();
                    if (team == 1) blinkColor(255, 0, 0);
                    else blinkColor(0, 0, 255);
                    swState = SW_LOBBY;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawTeamSelect(); }
            break;
        }

        case SW_LOBBY: {
            if (now - lastButtonPress > debounceDelay) {
                if (right) {
                    // AP mode required for promiscuous RX; see initWiFi
                    // in radio_manager.h.
                    initWiFi(WIFI_MODE_AP);
                    esp_wifi_set_promiscuous(true);

                    claimStartTime = millis();
                    claimChannel = 1;
                    claiming = true;
                    swState = SW_CLAIMING;
                    if (team == 1) blinkColor(255, 0, 0);
                    else blinkColor(0, 0, 255);
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    // Scan
                    swState = SW_SCANNING;
                    scanTerritories();
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawLobby(); }
            break;
        }

        case SW_CLAIMING: {
            // Spam beacons every 100ms
            if (now - lastBeaconTime > 100) {
                char ssid1[33], ssid2[33], ssid3[33];
                snprintf(ssid1, sizeof(ssid1), "[SW]%s-%s-A", teamTag, deviceId);
                snprintf(ssid2, sizeof(ssid2), "[SW]%s-%s-B", teamTag, deviceId);
                snprintf(ssid3, sizeof(ssid3), "[SW]%s-%s-C", teamTag, deviceId);

                sendBeacon(ssid1, claimChannel);
                sendBeacon(ssid2, claimChannel);
                sendBeacon(ssid3, claimChannel);
                lastBeaconTime = now;
            }

            // XP every 60s of claiming
            static unsigned long lastClaimXP = 0;
            if (now - lastClaimXP > 60000) {
                addXP(3);
                lastClaimXP = now;
            }

            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    // Stop claiming
                    esp_wifi_set_promiscuous(false);
                    claiming = false;

                    // Update lifetime claims
                    uint16_t total = (EEPROM.read(EEPROM_SW_TERRITORIES + 1) << 8) |
                                      EEPROM.read(EEPROM_SW_TERRITORIES);
                    total++;
                    EEPROM.write(EEPROM_SW_TERRITORIES, total & 0xFF);
                    EEPROM.write(EEPROM_SW_TERRITORIES + 1, (total >> 8) & 0xFF);
                    EEPROM.commit();

                    stopBlinking();
                    swState = SW_LOBBY;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (up && claimChannel < 14) {
                    claimChannel++;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && claimChannel > 1) {
                    claimChannel--;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }

            // Periodic redraw
            static unsigned long lastClaimDraw = 0;
            if (now - lastClaimDraw > 500) {
                lastClaimDraw = now;
                needsRedraw = true;
            }
            if (needsRedraw) { needsRedraw = false; drawClaiming(); }
            break;
        }

        case SW_SCANNING: {
            if (now - lastButtonPress > debounceDelay) {
                if (right) {
                    scanTerritories();
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    swState = SW_LOBBY;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawScanning(); }
            break;
        }
    }
}

void signalWarsCleanup() {
    if (claiming) {
        esp_wifi_set_promiscuous(false);
    }
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    stopBlinking();
    claiming = false;
    Serial.println("# Signal Wars session ended");
}
