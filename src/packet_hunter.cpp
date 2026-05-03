/*
    hackbox - Pollen Patrol

    WiFi flower collection game. Every unique SSID is a flower species.
    Scan to discover flowers and collect pollen. Rarer flowers = more pollen.
    Collection persists in EEPROM. Upload scores to the global leaderboard.

    Flower rarity tiers:
      Dandelion (common):  default ISP/router SSIDs ,1 pollen
      Clover (uncommon):   named home networks ,3 pollen
      Wildflower (rare):   hidden, long, or special-char SSIDs ,5 pollen
      Orchid (epic):       hacker keywords (kali, pwn, hack, etc.) ,10 pollen
      Ghost Bloom (legend): very weak signal (<-85dBm) ,15 pollen

    Controls: CENTER = scan, UP/DOWN = scroll views, RIGHT = upload, LEFT = exit
*/

#include "../include/packet_hunter.h"
#include "../include/level_system.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include <WiFi.h>
#include <EEPROM.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== EEPROM Layout (105-119) =====
#define PP_MAGIC_ADDR      105
#define PP_MAGIC_VAL       0xBB
#define PP_FLOWERS_LO      106
#define PP_FLOWERS_HI      107
#define PP_POLLEN_LO       108
#define PP_POLLEN_HI       109
#define PP_STREAK          110
#define PP_LAST_DAY        111  // day-of-year mod 256
#define PP_TIER_DANDELION  112
#define PP_TIER_CLOVER     113
// Slot 114 is reserved for the OTA flag, so wildflower lives at 116.
#define PP_TIER_WILDFLOWER 116
#define PP_TIER_ORCHID     117
#define PP_TIER_GHOST      118

// ===== State Machine =====
enum PPState {
    PP_GARDEN,
    PP_COLLECTION,
    PP_RESULTS
};

PPState ppState = PP_GARDEN;

// ===== Persistent Stats =====
uint16_t totalFlowers = 0;
uint16_t totalPollen = 0;
uint8_t streak = 0;
uint8_t tierCounts[5] = {0};  // dandelion, clover, wildflower, orchid, ghost

// ===== Session Stats =====
int sessionFlowers = 0;
int sessionPollen = 0;
int sessionTiers[5] = {0};

// ===== Common SSID patterns (Dandelion tier) =====
const char* commonPatterns[] = {
    "xfinity", "att", "netgear", "linksys", "spectrum", "verizon",
    "tmobile", "t-mobile", "comcast", "cox", "frontier", "century",
    "tp-link", "asus", "dlink", "belkin", "arris", "motorola",
    "direct-", "hp-print", "epson", "chromecast", "roku", "firestick"
};
const int commonCount = 24;

// ===== Hacker keywords (Orchid tier) =====
const char* hackerPatterns[] = {
    "kali", "pwn", "hack", "pentest", "exploit", "metasploit",
    "burp", "nmap", "wireshark", "flipper", "evil", "rogue",
    "deauth", "sniff", "inject", "fbi", "cia", "nsa", "surveil",
    "honeypot", "c2", "beacon", "cobalt", "empire", "hack"
};
const int hackerCount = 25;

// ===== UI =====
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
int viewOffset = 0;  // for collection scroll

// ===== Helpers =====

bool containsInsensitive(const char* haystack, const char* needle) {
    char hLow[33], nLow[24];
    int hLen = strlen(haystack);
    int nLen = strlen(needle);
    if (hLen > 32) hLen = 32;
    if (nLen > 23) nLen = 23;
    for (int i = 0; i < hLen; i++) hLow[i] = tolower(haystack[i]);
    hLow[hLen] = '\0';
    for (int i = 0; i < nLen; i++) nLow[i] = tolower(needle[i]);
    nLow[nLen] = '\0';
    return strstr(hLow, nLow) != nullptr;
}

int classifyFlower(const char* ssid, int rssi) {
    // Ghost Bloom: very weak signal
    if (rssi < -85) return 4;

    // Orchid: hacker keywords
    for (int i = 0; i < hackerCount; i++) {
        if (containsInsensitive(ssid, hackerPatterns[i])) return 3;
    }

    // Wildflower: hidden (empty), very long (>20), or special chars
    int len = strlen(ssid);
    if (len == 0) return 2;
    if (len > 20) return 2;
    for (int i = 0; i < len; i++) {
        char c = ssid[i];
        if (c == '!' || c == '@' || c == '#' || c == '$' || c == '%' ||
            c == '&' || c == '{' || c == '}' || c == '~' || c == '`') return 2;
    }

    // Dandelion: known ISP/router defaults
    for (int i = 0; i < commonCount; i++) {
        if (containsInsensitive(ssid, commonPatterns[i])) return 0;
    }

    // Clover: everything else (named home networks)
    return 1;
}

const int pollenPerTier[] = {1, 3, 5, 10, 15};
const char* tierNames[] = {"Dandelion", "Clover", "Wildflower", "Orchid", "Ghost Bloom"};
const char* tierIcons[] = {".", "o", "*", "#", "~"};

void loadStats() {
    if (EEPROM.read(PP_MAGIC_ADDR) != PP_MAGIC_VAL) {
        // First time ,initialize
        EEPROM.write(PP_MAGIC_ADDR, PP_MAGIC_VAL);
        EEPROM.write(PP_FLOWERS_LO, 0); EEPROM.write(PP_FLOWERS_HI, 0);
        EEPROM.write(PP_POLLEN_LO, 0);  EEPROM.write(PP_POLLEN_HI, 0);
        EEPROM.write(PP_STREAK, 0);
        EEPROM.write(PP_LAST_DAY, 0);
        EEPROM.write(PP_TIER_DANDELION, 0);
        EEPROM.write(PP_TIER_CLOVER, 0);
        EEPROM.write(PP_TIER_WILDFLOWER, 0);
        EEPROM.write(PP_TIER_ORCHID, 0);
        EEPROM.write(PP_TIER_GHOST, 0);
        EEPROM.commit();
        totalFlowers = 0; totalPollen = 0; streak = 0;
        memset(tierCounts, 0, sizeof(tierCounts));
        return;
    }
    totalFlowers = EEPROM.read(PP_FLOWERS_LO) | (EEPROM.read(PP_FLOWERS_HI) << 8);
    totalPollen = EEPROM.read(PP_POLLEN_LO) | (EEPROM.read(PP_POLLEN_HI) << 8);
    streak = EEPROM.read(PP_STREAK);
    tierCounts[0] = EEPROM.read(PP_TIER_DANDELION);
    tierCounts[1] = EEPROM.read(PP_TIER_CLOVER);
    tierCounts[2] = EEPROM.read(PP_TIER_WILDFLOWER);
    tierCounts[3] = EEPROM.read(PP_TIER_ORCHID);
    tierCounts[4] = EEPROM.read(PP_TIER_GHOST);
}

void saveStats() {
    EEPROM.write(PP_FLOWERS_LO, totalFlowers & 0xFF);
    EEPROM.write(PP_FLOWERS_HI, (totalFlowers >> 8) & 0xFF);
    EEPROM.write(PP_POLLEN_LO, totalPollen & 0xFF);
    EEPROM.write(PP_POLLEN_HI, (totalPollen >> 8) & 0xFF);
    EEPROM.write(PP_STREAK, streak);
    EEPROM.write(PP_TIER_DANDELION, tierCounts[0]);
    EEPROM.write(PP_TIER_CLOVER, tierCounts[1]);
    EEPROM.write(PP_TIER_WILDFLOWER, tierCounts[2]);
    EEPROM.write(PP_TIER_ORCHID, tierCounts[3]);
    EEPROM.write(PP_TIER_GHOST, tierCounts[4]);
    EEPROM.commit();
}

// ===== Drawing =====

void drawGarden() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "~ Pollen Patrol ~");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char flowerLine[28];
    snprintf(flowerLine, sizeof(flowerLine), "Flowers: %u", totalFlowers);
    u8g2.drawStr(0, 24, flowerLine);

    char pollenLine[28];
    snprintf(pollenLine, sizeof(pollenLine), "Pollen:  %u", totalPollen);
    u8g2.drawStr(0, 32, pollenLine);

    char streakLine[24];
    snprintf(streakLine, sizeof(streakLine), "Streak:  %u days", streak);
    u8g2.drawStr(0, 40, streakLine);

    // Animated bee (simple)
    unsigned long frame = (millis() / 500) % 2;
    if (frame == 0) {
        u8g2.drawStr(100, 24, "=-=");
        u8g2.drawStr(103, 32, "O");
    } else {
        u8g2.drawStr(98, 24, "=-=");
        u8g2.drawStr(101, 32, "O");
    }

    u8g2.drawStr(0, 54, "C=Scan  U/D=View");
    u8g2.drawStr(0, 62, "R=Upload  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawScanning(int found, int scanned) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Foraging...");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char scanLine[24];
    snprintf(scanLine, sizeof(scanLine), "Networks: %d", scanned);
    u8g2.drawStr(0, 24, scanLine);

    char foundLine[24];
    snprintf(foundLine, sizeof(foundLine), "New flowers: %d", found);
    u8g2.drawStr(0, 32, foundLine);

    char pollenLine[24];
    snprintf(pollenLine, sizeof(pollenLine), "Pollen: +%d", sessionPollen);
    u8g2.drawStr(0, 40, pollenLine);

    // Show last few discoveries by tier
    for (int t = 0; t < 5; t++) {
        if (sessionTiers[t] > 0) {
            char tLine[28];
            snprintf(tLine, sizeof(tLine), " %s %s x%d",
                     tierIcons[t], tierNames[t], sessionTiers[t]);
            u8g2.drawStr(0, 50 + (t > 0 ? 0 : 0), tLine);  // only room for summary
            break;  // just show the best tier found
        }
    }

    // Progress dots
    int dots = (millis() / 300) % 4;
    char dotStr[5] = "";
    for (int i = 0; i < dots; i++) strcat(dotStr, ".");
    u8g2.drawStr(70, 10, dotStr);

    u8g2.drawStr(0, 62, "Scanning...");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawCollection() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Flower Collection");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    for (int t = 0; t < 5; t++) {
        int y = 24 + (t * 8);
        char line[30];
        snprintf(line, sizeof(line), "%s %-11s x%-3d  +%d ea",
                 tierIcons[t], tierNames[t], tierCounts[t], pollenPerTier[t]);
        u8g2.drawStr(0, y, line);
    }

    u8g2.drawStr(0, 62, "U/D=Scroll  C=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawResults() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Forage Complete!");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char fLine[24];
    snprintf(fLine, sizeof(fLine), "Flowers found: %d", sessionFlowers);
    u8g2.drawStr(0, 24, fLine);

    char pLine[24];
    snprintf(pLine, sizeof(pLine), "Pollen earned: %d", sessionPollen);
    u8g2.drawStr(0, 32, pLine);

    // Show tier breakdown
    for (int t = 0; t < 5; t++) {
        if (sessionTiers[t] > 0) {
            char tLine[28];
            snprintf(tLine, sizeof(tLine), " %s %s: %d",
                     tierIcons[t], tierNames[t], sessionTiers[t]);
            u8g2.drawStr(0, 42, tLine);
            break;  // show best
        }
    }

    if (sessionFlowers >= 50) {
        u8g2.drawStr(0, 52, "MEGA FORAGE! +25 XP");
    }

    u8g2.drawStr(0, 62, "C=Again  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ===== Core Scan =====

void doScan() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(50);

    int n = WiFi.scanNetworks(false, true);  // include hidden

    sessionFlowers = 0;
    sessionPollen = 0;
    memset(sessionTiers, 0, sizeof(sessionTiers));

    for (int i = 0; i < n; i++) {
        String ssid = WiFi.SSID(i);
        int rssi = WiFi.RSSI(i);

        int tier = classifyFlower(ssid.c_str(), rssi);
        int pollen = pollenPerTier[tier];

        sessionFlowers++;
        sessionPollen += pollen;
        sessionTiers[tier]++;

        // Update persistent totals
        totalFlowers++;
        totalPollen += pollen;
        if (tierCounts[tier] < 255) tierCounts[tier]++;

        addXP(pollen);
    }

    WiFi.scanDelete();
    WiFi.mode(WIFI_OFF);

    // Bonus for mega forage
    if (sessionFlowers >= 50) addXP(25);

    // Save to EEPROM
    saveStats();

    Serial.printf("# Pollen Patrol: %d flowers, %d pollen\n",
                  sessionFlowers, sessionPollen);
}

} // namespace

// ===== Public API =====

void packetHunterSetup() {
    ppState = PP_GARDEN;
    sessionFlowers = 0;
    sessionPollen = 0;
    memset(sessionTiers, 0, sizeof(sessionTiers));
    viewOffset = 0;
    needsRedraw = true;
    lastButtonPress = 0;

    loadStats();

    Serial.println();
    Serial.println("# hackbox Pollen Patrol v1.0");

    drawGarden();
}

void packetHunterLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (ppState) {
        case PP_GARDEN: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    needsRedraw = true;
                    lastButtonPress = now;
                    drawScanning(0, 0);
                    doScan();
                    ppState = PP_RESULTS;
                    needsRedraw = true;
                } else if (down) {
                    ppState = PP_COLLECTION;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (up) {
                    ppState = PP_COLLECTION;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right) {
                    // Upload-to-server path is intentionally stubbed until a
                    // leaderboard endpoint lands; prompt the user instead.
                    u8g2.clearBuffer();
                    u8g2.setFont(u8g2_font_5x8_tr);
                    u8g2.drawStr(0, 30, "Upload coming soon!");
                    u8g2.drawStr(0, 40, "Need WiFi Setup first");
                    u8g2.sendBuffer();
                    displayMirrorSend(u8g2);
                    delay(1500);
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }

            // Animated garden redraw
            static unsigned long lastGardenDraw = 0;
            if (now - lastGardenDraw > 500) {
                lastGardenDraw = now;
                needsRedraw = true;
            }

            if (needsRedraw) { needsRedraw = false; drawGarden(); }
            break;
        }

        case PP_COLLECTION: {
            if (now - lastButtonPress > debounceDelay) {
                if (center || up || down) {
                    ppState = PP_GARDEN;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawCollection(); }
            break;
        }

        case PP_RESULTS: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    // doScan() is synchronous, so we stay in PP_RESULTS.
                    drawScanning(0, 0);
                    doScan();
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawResults(); }
            break;
        }
    }
}

void packetHunterCleanup() {
    WiFi.scanDelete();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    Serial.println("# Pollen Patrol session ended");
}
