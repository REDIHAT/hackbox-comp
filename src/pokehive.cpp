/*
    hackbox - PokeHive

    Pokemon-inspired WiFi broadcast/catch game.
    - Broadcast Mode: Fetch a random Pokemon from ck42x.com, then beacon
      it as a WiFi SSID shaped [PH]Name-SpeciesId-Level-Diff.
    - Catch Mode: Scan WiFi for other hackboxs broadcasting Pokemon
      beacons. Display encounters and attempt catches. Collection stored
      in EEPROM Pokedex.
    - Party View: Your last 6 caught Pokemon.
    - Pokedex: Bit-flag collection of all unique species.

    SSID format: "[PH]Pikachu-25-12-128"

    LEFT is reserved globally as the exit-app button by runApp().
*/

#include "../include/pokehive.h"
#include "../include/level_system.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include "../include/radio_manager.h"
#include <EEPROM.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== EEPROM Addresses =====
#define EEPROM_POKEDEX_START 120   // 132 bytes (bits 0-1055 → species 1-1025)
#define EEPROM_POKEDEX_LEN   132
#define EEPROM_PARTY_START   252   // 6 * 8 = 48 bytes
#define EEPROM_PARTY_LEN     48

// ===== API =====
#define PH_API_SPAWN "https://www.ck42x.com/api/games/pokehive/spawn"

// ===== Manufacturer ID =====
#define POKEHIVE_MFG_ID_LO 0xE5
#define POKEHIVE_MFG_ID_HI 0xBE
#define POKEHIVE_PKT_POKEMON 0x01

// ===== State Machine =====
enum PHiveState {
    PHIVE_MENU,
    PHIVE_CATCH,
    PHIVE_BROADCAST_FETCH,
    PHIVE_BROADCAST,
    PHIVE_PARTY,
    PHIVE_POKEDEX
};

PHiveState phiveState = PHIVE_MENU;

// ===== Pokemon Data =====
struct Pokemon {
    uint16_t speciesId;
    char name[12];
    uint8_t level;
    uint8_t type1;
    uint8_t type2;
    uint8_t catchDiff;
    int8_t rssi;
};

// Party (last 6 caught)
struct PartyMon {
    uint16_t speciesId;
    char name[6];     // 5 chars + null
    uint8_t level;
    uint8_t hp;       // 1-100
};

PartyMon party[6];
int partyCount = 0;

// Scan encounters
const int MAX_ENCOUNTERS = 3;
Pokemon encounters[MAX_ENCOUNTERS];
int encounterCount = 0;

// Broadcasting Pokemon
Pokemon broadcastMon;
bool hasBroadcast = false;

// UI state
int selectedIdx = 0;
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
unsigned long lastScanRestart = 0;
bool wifiScanning = false;
bool wifiBroadcasting = false;

// ===== Pokedex (bit-flag storage) =====

bool pokedexHas(uint16_t speciesId) {
    if (speciesId == 0 || speciesId > 1025) return false;
    int bitIdx = speciesId - 1;
    int byteIdx = bitIdx / 8;
    int bitPos = bitIdx % 8;
    uint8_t val = EEPROM.read(EEPROM_POKEDEX_START + byteIdx);
    return (val >> bitPos) & 1;
}

void pokedexSet(uint16_t speciesId) {
    if (speciesId == 0 || speciesId > 1025) return;
    int bitIdx = speciesId - 1;
    int byteIdx = bitIdx / 8;
    int bitPos = bitIdx % 8;
    uint8_t val = EEPROM.read(EEPROM_POKEDEX_START + byteIdx);
    val |= (1 << bitPos);
    EEPROM.write(EEPROM_POKEDEX_START + byteIdx, val);
    EEPROM.commit();
}

int pokedexCount() {
    int count = 0;
    for (int b = 0; b < EEPROM_POKEDEX_LEN; b++) {
        uint8_t val = EEPROM.read(EEPROM_POKEDEX_START + b);
        while (val) { count += val & 1; val >>= 1; }
    }
    return count;
}

// ===== Party EEPROM =====

void loadParty() {
    partyCount = 0;
    for (int i = 0; i < 6; i++) {
        int addr = EEPROM_PARTY_START + (i * 8);
        uint8_t lo = EEPROM.read(addr);
        uint8_t hi = EEPROM.read(addr + 1);
        uint16_t id = (hi << 8) | lo;
        if (id == 0 || id > 1025) continue;
        party[partyCount].speciesId = id;
        for (int c = 0; c < 5; c++) party[partyCount].name[c] = EEPROM.read(addr + 2 + c);
        party[partyCount].name[5] = '\0';
        party[partyCount].level = EEPROM.read(addr + 7);
        party[partyCount].hp = 100;
        partyCount++;
    }
}

void savePartySlot(int slot, Pokemon &mon) {
    int addr = EEPROM_PARTY_START + (slot * 8);
    EEPROM.write(addr, mon.speciesId & 0xFF);
    EEPROM.write(addr + 1, (mon.speciesId >> 8) & 0xFF);
    for (int c = 0; c < 5; c++) {
        EEPROM.write(addr + 2 + c, (c < (int)strlen(mon.name)) ? mon.name[c] : '\0');
    }
    EEPROM.write(addr + 7, mon.level);
    EEPROM.commit();
}

void addToParty(Pokemon &mon) {
    // Shift party, newest at index 0
    for (int i = 5; i > 0; i--) party[i] = party[i - 1];
    party[0].speciesId = mon.speciesId;
    strncpy(party[0].name, mon.name, 5);
    party[0].name[5] = '\0';
    party[0].level = mon.level;
    party[0].hp = 100;
    if (partyCount < 6) partyCount++;

    // Save all party slots
    for (int i = 0; i < 6; i++) {
        if (i < partyCount) {
            Pokemon tmp;
            tmp.speciesId = party[i].speciesId;
            strncpy(tmp.name, party[i].name, 11);
            tmp.level = party[i].level;
            savePartySlot(i, tmp);
        } else {
            int addr = EEPROM_PARTY_START + (i * 8);
            EEPROM.write(addr, 0);
            EEPROM.write(addr + 1, 0);
        }
    }
    EEPROM.commit();
}

// ===== WiFi Beacon Scan for Pokemon =====
// Pokemon are broadcast as SSIDs: [PH]Name-Species-Lv-Diff
// e.g. "[PH]Pikachu-25-12-128"

void scanForPokemon() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(10);
    int n = WiFi.scanNetworks(false, false, false, 300);

    for (int i = 0; i < n && encounterCount < MAX_ENCOUNTERS; i++) {
        String ssid = WiFi.SSID(i);
        if (!ssid.startsWith("[PH]")) continue;

        // Parse: [PH]Name-SpeciesId-Level-CatchDiff
        String data = ssid.substring(4);
        int d1 = data.indexOf('-');
        if (d1 < 0) continue;
        int d2 = data.indexOf('-', d1 + 1);
        if (d2 < 0) continue;
        int d3 = data.indexOf('-', d2 + 1);
        if (d3 < 0) continue;

        String name = data.substring(0, d1);
        uint16_t specId = data.substring(d1 + 1, d2).toInt();
        uint8_t lvl = data.substring(d2 + 1, d3).toInt();
        uint8_t diff = data.substring(d3 + 1).toInt();

        if (specId == 0 || specId > 1025) continue;

        // Dedup
        bool dupe = false;
        for (int d = 0; d < encounterCount; d++) {
            if (encounters[d].speciesId == specId) { dupe = true; break; }
        }
        if (dupe) continue;

        Pokemon &p = encounters[encounterCount];
        p.speciesId = specId;
        strncpy(p.name, name.c_str(), 11);
        p.name[11] = '\0';
        p.level = lvl;
        p.type1 = 0;
        p.type2 = 0xFF;
        p.catchDiff = diff;
        p.rssi = WiFi.RSSI(i);
        encounterCount++;

        Serial.printf("# PokeHive: found %s (#%d) Lv%d\n", p.name, p.speciesId, p.level);
    }
    WiFi.scanDelete();
    wifiScanning = false;
}

void startWiFiScan() {
    if (wifiScanning) return;
    wifiScanning = true;
    lastScanRestart = millis();
    scanForPokemon();
}

void stopWiFiScan() {
    wifiScanning = false;
}

// ===== WiFi Beacon Broadcast Pokemon =====

void sendPokemonBeacon(const char* ssid, int channel) {
    uint8_t beacon[] = {
        0x80, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xBE, 0xE5, 0xCA, 0xFE, 0x00, 0x01,
        0xBE, 0xE5, 0xCA, 0xFE, 0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x31, 0x04,
    };

    int ssidLen = strlen(ssid);
    if (ssidLen > 32) ssidLen = 32;

    uint8_t frame[96];
    int pos = sizeof(beacon);
    memcpy(frame, beacon, pos);
    frame[pos++] = 0x00;
    frame[pos++] = ssidLen;
    memcpy(&frame[pos], ssid, ssidLen);
    pos += ssidLen;
    frame[pos++] = 0x01; frame[pos++] = 0x02;
    frame[pos++] = 0x82; frame[pos++] = 0x84;
    frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = channel;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, pos, false);
}

void startBroadcast() {
    if (!hasBroadcast) return;

    // AP mode required for promiscuous RX (see initWiFi in radio_manager.h);
    // sendPokemonBeacon's raw TX uses WIFI_IF_AP to match.
    initWiFi(WIFI_MODE_AP);
    esp_wifi_set_promiscuous(true);

    wifiBroadcasting = true;
    Serial.printf("# PokeHive: broadcasting %s (#%d) Lv%d via WiFi beacon\n",
                  broadcastMon.name, broadcastMon.speciesId, broadcastMon.level);
}

void stopBroadcast() {
    if (!wifiBroadcasting) return;
    // cleanupWiFi clears the promiscuous rx_cb before deinit, which avoids
    // the ISR-dispatching-into-unloaded-code crash after 2-3 tool switches.
    cleanupWiFi();
    wifiBroadcasting = false;
}

// ===== Fetch Pokemon from Server =====

bool fetchSpawn() {
    WiFi.mode(WIFI_STA);
    WiFi.begin();
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 10000) {
        delay(100);
    }
    if (WiFi.status() != WL_CONNECTED) {
        WiFi.disconnect(true);
        WiFi.mode(WIFI_OFF);
        return false;
    }

    HTTPClient http;
    http.begin(PH_API_SPAWN);
    http.setTimeout(8000);
    int code = http.GET();

    bool ok = false;
    if (code == 200) {
        String payload = http.getString();
        JsonDocument doc;
        if (!deserializeJson(doc, payload)) {
            broadcastMon.speciesId = doc["speciesId"] | 0;
            const char* n = doc["name"] | "???";
            strncpy(broadcastMon.name, n, 11);
            broadcastMon.name[11] = '\0';
            broadcastMon.level = doc["level"] | 5;
            broadcastMon.type1 = doc["type1"] | 0;
            broadcastMon.type2 = doc["type2"] | 0xFF;
            broadcastMon.catchDiff = doc["catchDifficulty"] | 128;
            hasBroadcast = true;
            ok = true;
        }
    }

    http.end();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return ok;
}

// ===== Catch Attempt =====

bool attemptCatch(Pokemon &mon) {
    // Catch probability: higher level = harder, lower catchDiff = easier
    // Base chance 60%, modified by level difference and catch difficulty
    int myLevel = getCurrentLevel();
    int diff = mon.level - myLevel;
    int chance = 60 - diff * 2 - (mon.catchDiff / 10);
    if (chance < 10) chance = 10;
    if (chance > 95) chance = 95;

    int roll = random(100);
    return roll < chance;
}

// ===== Drawing =====

void drawMenu() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "PokeHive");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    int dex = pokedexCount();
    char dexLine[28];
    snprintf(dexLine, sizeof(dexLine), "Pokedex: %d / 1025", dex);
    u8g2.drawStr(0, 24, dexLine);

    char partyLine[24];
    snprintf(partyLine, sizeof(partyLine), "Party: %d / 6", partyCount);
    u8g2.drawStr(0, 34, partyLine);

    u8g2.drawStr(0, 46, "R=Catch  C=Broadcast");
    u8g2.drawStr(0, 54, "U=Party  D=Pokedex");
    u8g2.drawStr(0, 62, "L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawCatch() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    char title[24];
    snprintf(title, sizeof(title), "Wild Pokemon (%d)", encounterCount);
    u8g2.drawStr(0, 10, title);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (encounterCount == 0) {
        u8g2.drawStr(0, 30, "Scanning for Pokemon...");
        u8g2.drawStr(0, 40, "Need another hackbox");
        u8g2.drawStr(0, 48, "broadcasting nearby!");
    } else {
        for (int i = 0; i < 4 && i < encounterCount; i++) {
            int y = 22 + (i * 10);
            Pokemon &p = encounters[i];
            char line[28];
            bool caught = pokedexHas(p.speciesId);
            snprintf(line, sizeof(line), "%s%-10s Lv%-3d %s",
                     (i == selectedIdx) ? ">" : " ",
                     p.name, p.level,
                     caught ? "[*]" : "");
            u8g2.drawStr(0, y, line);
        }
    }

    u8g2.drawStr(0, 62, "C=Catch  U/D=Sel  L=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawBroadcast() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Broadcasting...");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (hasBroadcast) {
        char nameLine[28];
        snprintf(nameLine, sizeof(nameLine), "Pokemon: %s", broadcastMon.name);
        u8g2.drawStr(0, 24, nameLine);

        char lvLine[20];
        snprintf(lvLine, sizeof(lvLine), "Level: %d", broadcastMon.level);
        u8g2.drawStr(0, 34, lvLine);

        char idLine[20];
        snprintf(idLine, sizeof(idLine), "Species #%d", broadcastMon.speciesId);
        u8g2.drawStr(0, 44, idLine);

        u8g2.drawStr(0, 54, "WiFi beacon active!");
    } else {
        u8g2.drawStr(0, 30, "Fetching Pokemon...");
    }

    u8g2.drawStr(0, 62, "C=New Mon  L=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawParty() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Party");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (partyCount == 0) {
        u8g2.drawStr(0, 30, "No Pokemon caught yet!");
        u8g2.drawStr(0, 40, "Go catch some!");
    } else {
        for (int i = 0; i < partyCount && i < 6; i++) {
            int y = 22 + (i * 8);
            char line[28];
            snprintf(line, sizeof(line), "%d. %-8s Lv%d", i + 1, party[i].name, party[i].level);
            u8g2.drawStr(0, y, line);
        }
    }

    u8g2.drawStr(0, 62, "L=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawPokedex() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Pokedex");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    int count = pokedexCount();
    char countLine[28];
    snprintf(countLine, sizeof(countLine), "Discovered: %d / 1025", count);
    u8g2.drawStr(0, 26, countLine);

    float pct = (count * 100.0f) / 1025.0f;
    char pctLine[20];
    snprintf(pctLine, sizeof(pctLine), "Completion: %.1f%%", pct);
    u8g2.drawStr(0, 38, pctLine);

    // Progress bar
    int barW = 100;
    int filled = (count * barW) / 1025;
    u8g2.drawFrame(14, 44, barW, 8);
    if (filled > 0) u8g2.drawBox(14, 44, filled, 8);

    u8g2.drawStr(0, 62, "L=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void pokehiveSetup() {
    phiveState = PHIVE_MENU;
    encounterCount = 0;
    selectedIdx = 0;
    needsRedraw = true;
    lastButtonPress = 0;
    wifiScanning = false;
    wifiBroadcasting = false;
    hasBroadcast = false;

    loadParty();

    Serial.println();
    Serial.println("# hackbox PokeHive v1.0");

    drawMenu();
}

void pokehiveLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (phiveState) {
        case PHIVE_MENU: {
            if (now - lastButtonPress > debounceDelay) {
                if (right) {
                    // Enter catch mode
                    encounterCount = 0;
                    selectedIdx = 0;
                    phiveState = PHIVE_CATCH;
                    startWiFiScan();
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    // Enter broadcast mode
                    phiveState = PHIVE_BROADCAST_FETCH;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (up) {
                    phiveState = PHIVE_PARTY;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down) {
                    phiveState = PHIVE_POKEDEX;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawMenu(); }
            break;
        }

        case PHIVE_CATCH: {
            // scanForPokemon() is synchronous; encounters[] populated inline.

            if (now - lastButtonPress > debounceDelay) {
                if (up && selectedIdx > 0) {
                    selectedIdx--;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && selectedIdx < encounterCount - 1) {
                    selectedIdx++;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center && encounterCount > 0 && selectedIdx < encounterCount) {
                    Pokemon &target = encounters[selectedIdx];
                    bool caught = attemptCatch(target);

                    u8g2.clearBuffer();
                    u8g2.setFont(u8g2_font_6x10_tr);
                    if (caught) {
                        char msg[24];
                        snprintf(msg, sizeof(msg), "Caught %s!", target.name);
                        u8g2.drawStr(4, 30, msg);

                        bool isNew = !pokedexHas(target.speciesId);
                        pokedexSet(target.speciesId);
                        addToParty(target);
                        addXP(5);
                        if (isNew) {
                            addXP(20);
                            u8g2.drawStr(4, 42, "NEW POKEDEX ENTRY!");
                        }
                    } else {
                        char msg[24];
                        snprintf(msg, sizeof(msg), "%s broke free!", target.name);
                        u8g2.drawStr(4, 30, msg);
                    }
                    u8g2.sendBuffer();
                    displayMirrorSend(u8g2);
                    delay(1500);
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right) {
                    // Back to menu
                    stopWiFiScan();
                    phiveState = PHIVE_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }

            // Periodic redraw
            static unsigned long lastCatchDraw = 0;
            if (now - lastCatchDraw > 2000) {
                lastCatchDraw = now;
                needsRedraw = true;
            }

            if (needsRedraw) { needsRedraw = false; drawCatch(); }
            break;
        }

        case PHIVE_BROADCAST_FETCH: {
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawStr(0, 30, "Connecting to server...");
            u8g2.sendBuffer();
            displayMirrorSend(u8g2);

            bool ok = fetchSpawn();
            if (!ok) {
                broadcastMon.speciesId = random(1, 152);
                snprintf(broadcastMon.name, 12, "Mon#%d", broadcastMon.speciesId);
                broadcastMon.level = random(1, 30);
                broadcastMon.type1 = random(0, 18);
                broadcastMon.type2 = 0xFF;
                broadcastMon.catchDiff = 128;
                hasBroadcast = true;
            }
            startBroadcast();
            phiveState = PHIVE_BROADCAST;
            needsRedraw = true;
            lastButtonPress = now;
            break;
        }

        case PHIVE_BROADCAST: {
            // Send beacon every 200ms
            static unsigned long lastBeacon = 0;
            if (wifiBroadcasting && now - lastBeacon > 200) {
                char ssid[33];
                snprintf(ssid, sizeof(ssid), "[PH]%.6s-%d-%d-%d",
                         broadcastMon.name, broadcastMon.speciesId,
                         broadcastMon.level, broadcastMon.catchDiff);
                sendPokemonBeacon(ssid, 6);
                lastBeacon = now;
            }

            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    stopBroadcast();
                    phiveState = PHIVE_BROADCAST_FETCH;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right) {
                    stopBroadcast();
                    phiveState = PHIVE_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }

            static unsigned long lastBroadcastXP = 0;
            if (now - lastBroadcastXP > 60000) {
                addXP(2);
                lastBroadcastXP = now;
            }

            if (needsRedraw) { needsRedraw = false; drawBroadcast(); }
            break;
        }

        case PHIVE_PARTY: {
            if (now - lastButtonPress > debounceDelay) {
                if (right || center) {
                    phiveState = PHIVE_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawParty(); }
            break;
        }

        case PHIVE_POKEDEX: {
            if (now - lastButtonPress > debounceDelay) {
                if (right || center) {
                    phiveState = PHIVE_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawPokedex(); }
            break;
        }
    }
}

void pokehiveCleanup() {
    stopWiFiScan();
    stopBroadcast();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    Serial.println("# PokeHive session ended");
}
