/*
    hackbox
    hackbox custom firmware

    OTA Firmware Update - Connect to WiFi and check for firmware updates.
    - Scan WiFi networks, user selects one
    - Character-by-character password entry
    - Fetch manifest JSON from ck42x.com
    - Compare versions, download and flash OTA
    - Progress bar on OLED during download

    States: SCAN_WIFI, PASSWORD_ENTRY, CONNECTING, CHECKING, UPDATE_AVAILABLE, DOWNLOADING, DONE, ERROR
*/

#include "../include/ota_update.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/about.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <EEPROM.h>
#include <ArduinoJson.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

#define HACKBOX_OTA_VERSION HACKBOX_VERSION_NUMBER
#define OTA_MANIFEST_URL "https://ck42x.com/api/hackbox/ota-manifest"

// EEPROM addresses for OTA password storage (50-114).
//
// This slot is intentionally SHARED with the WiFi Setup tool in
// setting.cpp -- both features store the same kind of data (one
// WiFi STA credential the device should remember) so reusing the
// same bytes gives users a single source of truth. Whichever tool
// was used most recently owns the saved password; the other tool
// picks it up on next run. Mirror any change here in
// setting.cpp's WiFi Setup block and vice versa.
#define EEPROM_OTA_PW_START 50
#define EEPROM_OTA_PW_LEN   64
#define EEPROM_OTA_PW_FLAG  114  // 0xAA means password is stored

// Saved WiFi SSID slot. Also shared with setting.cpp's WiFi Setup
// block -- the captive portal writes the SSID here when the user
// configures a network. OTA Update reads it on scan completion to
// auto-pick the user's home network if it is in range, turning the
// "scan, scroll, select, connect" flow into a one-button update.
#define EEPROM_WIFI_SSID_START 300
#define EEPROM_WIFI_SSID_LEN    33

// ===== State Machine =====
enum OTAState {
    OTA_SCAN_WIFI,
    OTA_PASSWORD_ENTRY,
    OTA_CONNECTING,
    OTA_CHECKING,
    OTA_UPDATE_AVAILABLE,
    OTA_DOWNLOADING,
    OTA_DONE,
    OTA_ERROR
};

OTAState otaState = OTA_SCAN_WIFI;

// WiFi scan results
struct WiFiEntry {
    char ssid[33];
    int8_t rssi;
    uint8_t encType;
};

const int MAX_WIFI = 20;
WiFiEntry wifiList[MAX_WIFI];
int wifiCount = 0;
int wifiSelected = 0;
int wifiScroll = 0;

// Password entry
char password[65];
int passwordLen = 0;
int charIndex = 0;
const char CHARSET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~ ";
const int CHARSET_LEN = 95;

// Update info
char newVersion[16];
char firmwareUrl[128];
int firmwareSize = 0;
int downloadProgress = 0;

// Error message
char errorMsg[64];

// UI state
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
unsigned long connectStartTime = 0;

// Tracks whether we have already tried the one-shot auto-connect to
// the saved SSID in this app invocation. Reset on setup. If the
// auto-connect attempt fails, the state machine drops into the
// normal manual scan-and-pick flow instead of re-trying on every
// scan iteration.
bool autoConnectAttempted = false;

// ===== EEPROM Password =====

void loadSavedPassword() {
    if (EEPROM.read(EEPROM_OTA_PW_FLAG) != 0xAA) {
        password[0] = '\0';
        passwordLen = 0;
        return;
    }
    for (int i = 0; i < EEPROM_OTA_PW_LEN; i++) {
        password[i] = EEPROM.read(EEPROM_OTA_PW_START + i);
        if (password[i] == '\0') break;
    }
    password[EEPROM_OTA_PW_LEN] = '\0';
    passwordLen = strlen(password);
}

// Load the SSID previously saved by WiFi Setup (setting.cpp) into
// `out`. Returns true if a non-empty SSID was loaded, false if the
// slot is empty (e.g. first boot, or the user has never run WiFi
// Setup on this device). `out` must have room for at least
// EEPROM_WIFI_SSID_LEN bytes.
bool loadSavedSSID(char *out, int outSize) {
    if (outSize <= 0 || !out) return false;
    int n = (outSize < EEPROM_WIFI_SSID_LEN) ? outSize : EEPROM_WIFI_SSID_LEN;
    for (int i = 0; i < n; i++) {
        out[i] = (char)EEPROM.read(EEPROM_WIFI_SSID_START + i);
    }
    out[n - 1] = '\0';
    // Treat 0xFF (fresh EEPROM) as empty.
    if ((uint8_t)out[0] == 0xFF || out[0] == '\0') {
        out[0] = '\0';
        return false;
    }
    return true;
}

void savePassword() {
    for (int i = 0; i < EEPROM_OTA_PW_LEN; i++) {
        EEPROM.write(EEPROM_OTA_PW_START + i, (i < passwordLen) ? password[i] : '\0');
    }
    EEPROM.write(EEPROM_OTA_PW_FLAG, 0xAA);
    EEPROM.commit();
}

// ===== Version Comparison =====
// Returns true if newVer is newer than currentVer (simple semver)
bool isNewer(const char* currentVer, const char* newVer) {
    int curMajor = 0, curMinor = 0, curPatch = 0;
    int newMajor = 0, newMinor = 0, newPatch = 0;
    sscanf(currentVer, "%d.%d.%d", &curMajor, &curMinor, &curPatch);
    sscanf(newVer, "%d.%d.%d", &newMajor, &newMinor, &newPatch);

    if (newMajor > curMajor) return true;
    if (newMajor == curMajor && newMinor > curMinor) return true;
    if (newMajor == curMajor && newMinor == curMinor && newPatch > curPatch) return true;
    return false;
}

// ===== Drawing Functions =====

void drawScanWifi() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "OTA: Select WiFi");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (wifiCount == 0) {
        u8g2.drawStr(0, 30, "Scanning...");
    } else {
        int visibleRows = 5;
        for (int i = 0; i < visibleRows; i++) {
            int idx = wifiScroll + i;
            if (idx >= wifiCount) break;

            char line[28];
            char ssidShort[17];
            strncpy(ssidShort, wifiList[idx].ssid, 16);
            ssidShort[16] = '\0';

            snprintf(line, sizeof(line), "%s%s%.14s %d",
                     (idx == wifiSelected) ? ">" : " ",
                     (wifiList[idx].encType == 0) ? " " : "*",
                     ssidShort, wifiList[idx].rssi);
            u8g2.drawStr(0, 22 + (i * 8), line);
        }
    }

    u8g2.drawStr(0, 62, "U/D=Scroll R=Conn L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawPasswordEntry() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "WiFi Password");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    // Show SSID
    char ssidLine[30];
    snprintf(ssidLine, sizeof(ssidLine), "SSID: %.18s", wifiList[wifiSelected].ssid);
    u8g2.drawStr(0, 22, ssidLine);

    // Show password as dots with current char visible
    char display[22];
    int showStart = 0;
    if (passwordLen > 18) showStart = passwordLen - 18;
    for (int i = 0; i < 20 && (showStart + i) < passwordLen; i++) {
        display[i] = '*';
    }
    int displayLen = (passwordLen - showStart);
    if (displayLen > 20) displayLen = 20;
    display[displayLen] = '\0';
    u8g2.drawStr(0, 32, display);

    // Current character selector
    char charLine[28];
    snprintf(charLine, sizeof(charLine), "Char:[%c] Len:%d",
             CHARSET[charIndex], passwordLen);
    u8g2.drawStr(0, 44, charLine);

    u8g2.drawStr(0, 54, "U/D=Char R=Add C=Del");
    u8g2.drawStr(0, 62, "Hold R=Connect L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawConnecting() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Connecting...");
    u8g2.setFont(u8g2_font_5x8_tr);

    char ssidLine[30];
    snprintf(ssidLine, sizeof(ssidLine), "SSID: %.20s", wifiList[wifiSelected].ssid);
    u8g2.drawStr(0, 28, ssidLine);

    // Animated dots
    int dots = ((millis() / 500) % 4);
    char dotStr[5] = "";
    for (int i = 0; i < dots; i++) strcat(dotStr, ".");
    u8g2.drawStr(78, 10, dotStr);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawChecking() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Checking updates...");
    u8g2.setFont(u8g2_font_5x8_tr);

    char curVer[24];
    snprintf(curVer, sizeof(curVer), "Current: %s", HACKBOX_VERSION);
    u8g2.drawStr(0, 30, curVer);

    u8g2.drawStr(0, 44, "Fetching manifest...");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawUpdateAvailable() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Update Available!");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char curLine[30];
    snprintf(curLine, sizeof(curLine), "Current: %s", HACKBOX_VERSION);
    u8g2.drawStr(0, 24, curLine);

    char newLine[30];
    snprintf(newLine, sizeof(newLine), "New:     v%s", newVersion);
    u8g2.drawStr(0, 34, newLine);

    char sizeLine[24];
    float sizeMB = firmwareSize / 1048576.0f;
    snprintf(sizeLine, sizeof(sizeLine), "Size: %.1fMB", sizeMB);
    u8g2.drawStr(0, 46, sizeLine);

    u8g2.drawStr(0, 62, "C=Install  L=Cancel");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawDownloading() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Downloading...");

    u8g2.setFont(u8g2_font_5x8_tr);

    char pctLine[24];
    snprintf(pctLine, sizeof(pctLine), "%d%%", downloadProgress);
    u8g2.drawStr(50, 30, pctLine);

    // Progress bar
    int barX = 4;
    int barY = 36;
    int barW = 120;
    int barH = 10;
    u8g2.drawFrame(barX, barY, barW, barH);
    int fill = (downloadProgress * barW) / 100;
    if (fill > 0) {
        u8g2.drawBox(barX, barY, fill, barH);
    }

    u8g2.drawStr(0, 62, "DO NOT POWER OFF!");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawDone() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Update Complete!");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 30, "Rebooting in 3s...");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawError() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "OTA Error");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 28, errorMsg);
    u8g2.drawStr(0, 62, "L=Back to menu");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawNoUpdate() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Up to date!");
    u8g2.setFont(u8g2_font_5x8_tr);

    char curLine[30];
    snprintf(curLine, sizeof(curLine), "Version: %s", HACKBOX_VERSION);
    u8g2.drawStr(0, 30, curLine);
    u8g2.drawStr(0, 44, "No updates available.");
    u8g2.drawStr(0, 62, "L=Back to menu");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ===== Core Logic =====

void startWifiScan() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    WiFi.scanNetworks(true);
    wifiCount = 0;
    wifiSelected = 0;
    wifiScroll = 0;
    otaState = OTA_SCAN_WIFI;
    needsRedraw = true;
}

// Forward declaration so processWifiScan() can short-circuit into
// connectToWifi() when it finds a saved-SSID auto-connect candidate.
// Both functions live in the same anonymous namespace.
void connectToWifi();

void processWifiScan() {
    int n = WiFi.scanComplete();
    if (n < 0) return;  // still scanning or error

    wifiCount = 0;
    for (int i = 0; i < n && wifiCount < MAX_WIFI; i++) {
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) continue;  // skip hidden

        strncpy(wifiList[wifiCount].ssid, ssid.c_str(), 32);
        wifiList[wifiCount].ssid[32] = '\0';
        wifiList[wifiCount].rssi = WiFi.RSSI(i);
        wifiList[wifiCount].encType = WiFi.encryptionType(i);
        wifiCount++;
    }
    WiFi.scanDelete();
    needsRedraw = true;

    // One-shot auto-connect: if WiFi Setup has a saved SSID and
    // that SSID is currently visible in the scan list, pre-select
    // it. If we also have a saved password (or the network is
    // open), connect immediately without waiting for user input.
    // This turns "open OTA, scroll, press RIGHT, wait" into
    // "open OTA, app connects on its own". LEFT still exits
    // cleanly via the framework if the user wants to bail.
    //
    // The autoConnectAttempted gate makes this a one-shot attempt
    // per app invocation -- a failed connect does not re-trigger on
    // the next processWifiScan() call, so we gracefully fall into
    // the manual flow instead of spinning.
    if (!autoConnectAttempted && wifiCount > 0) {
        char savedSSID[EEPROM_WIFI_SSID_LEN];
        if (loadSavedSSID(savedSSID, sizeof(savedSSID))) {
            for (int i = 0; i < wifiCount; i++) {
                if (strcmp(wifiList[i].ssid, savedSSID) == 0) {
                    wifiSelected = i;
                    if (wifiSelected >= 5) wifiScroll = wifiSelected - 4;
                    // Auto-connect if we can. Open networks go
                    // through the same path with a zero-length
                    // password, same as the manual flow.
                    bool canAutoConnect =
                        (wifiList[i].encType == 0) || (passwordLen > 0);
                    if (canAutoConnect) {
                        autoConnectAttempted = true;
                        Serial.printf("# OTA auto-connect to saved SSID: %s\n",
                                      savedSSID);
                        connectToWifi();
                    }
                    break;
                }
            }
        }
    }
}

void connectToWifi() {
    password[passwordLen] = '\0';
    // Open networks (encType 0 = WIFI_AUTH_OPEN) need no password
    if (wifiList[wifiSelected].encType == 0) {
        WiFi.begin(wifiList[wifiSelected].ssid);
    } else {
        savePassword();
        WiFi.begin(wifiList[wifiSelected].ssid, password);
    }
    connectStartTime = millis();
    otaState = OTA_CONNECTING;
    needsRedraw = true;
}

void checkForUpdate() {
    otaState = OTA_CHECKING;
    needsRedraw = true;
    drawChecking();

    HTTPClient http;
    http.begin(OTA_MANIFEST_URL);
    http.setTimeout(10000);
    int httpCode = http.GET();

    if (httpCode != 200) {
        snprintf(errorMsg, sizeof(errorMsg), "HTTP %d from manifest", httpCode);
        otaState = OTA_ERROR;
        http.end();
        needsRedraw = true;
        return;
    }

    String payload = http.getString();
    http.end();

    // Parse JSON. Use the v7 JsonDocument API (auto-sized) -- the project
    // pins ArduinoJson 7.x and the legacy StaticJsonDocument<size> shim is
    // slated for removal upstream.
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (err) {
        snprintf(errorMsg, sizeof(errorMsg), "JSON parse error");
        otaState = OTA_ERROR;
        needsRedraw = true;
        return;
    }

    const char* ver = doc["version"];
    const char* url = doc["url"];
    int size = doc["size"] | 0;

    if (!ver || !url) {
        snprintf(errorMsg, sizeof(errorMsg), "Invalid manifest format");
        otaState = OTA_ERROR;
        needsRedraw = true;
        return;
    }

    strncpy(newVersion, ver, 15);
    newVersion[15] = '\0';
    strncpy(firmwareUrl, url, 127);
    firmwareUrl[127] = '\0';
    firmwareSize = size;

    if (isNewer(HACKBOX_OTA_VERSION, newVersion)) {
        otaState = OTA_UPDATE_AVAILABLE;
    } else {
        // No update, show no-update screen using ERROR state with custom draw
        otaState = OTA_ERROR;
        // Use a special message that drawNoUpdate will handle
        strncpy(errorMsg, "NO_UPDATE", sizeof(errorMsg));
    }
    needsRedraw = true;
}

void performOTA() {
    otaState = OTA_DOWNLOADING;
    downloadProgress = 0;
    needsRedraw = true;
    drawDownloading();

    HTTPClient http;
    http.begin(firmwareUrl);
    http.setTimeout(30000);
    int httpCode = http.GET();

    if (httpCode != 200) {
        snprintf(errorMsg, sizeof(errorMsg), "Download failed: HTTP %d", httpCode);
        otaState = OTA_ERROR;
        needsRedraw = true;
        return;
    }

    int contentLength = http.getSize();
    if (contentLength <= 0) {
        snprintf(errorMsg, sizeof(errorMsg), "Invalid content length");
        otaState = OTA_ERROR;
        needsRedraw = true;
        http.end();
        return;
    }

    WiFiClient* stream = http.getStreamPtr();

    if (!Update.begin(contentLength)) {
        snprintf(errorMsg, sizeof(errorMsg), "Not enough space for OTA");
        otaState = OTA_ERROR;
        needsRedraw = true;
        http.end();
        return;
    }

    // Stream download with progress and an idle-timeout so we don't spin
    // forever if the server hangs mid-stream without closing the socket.
    uint8_t buf[1024];
    int totalRead = 0;
    unsigned long lastDataAt = millis();
    const unsigned long IDLE_TIMEOUT_MS = 15000;

    while (http.connected() && totalRead < contentLength) {
        size_t available = stream->available();
        if (available) {
            int readBytes = stream->readBytes(buf, min(available, sizeof(buf)));
            Update.write(buf, readBytes);
            totalRead += readBytes;
            lastDataAt = millis();

            int newProgress = (totalRead * 100) / contentLength;
            if (newProgress != downloadProgress) {
                downloadProgress = newProgress;
                drawDownloading();
            }
        } else if (millis() - lastDataAt > IDLE_TIMEOUT_MS) {
            snprintf(errorMsg, sizeof(errorMsg), "Download stalled");
            otaState = OTA_ERROR;
            needsRedraw = true;
            http.end();
            Update.abort();
            return;
        }
        delay(1);
    }

    http.end();

    if (Update.end()) {
        if (Update.isFinished()) {
            otaState = OTA_DONE;
            needsRedraw = true;
            drawDone();
            delay(3000);
            ESP.restart();
        } else {
            snprintf(errorMsg, sizeof(errorMsg), "Update not finished");
            otaState = OTA_ERROR;
            needsRedraw = true;
        }
    } else {
        snprintf(errorMsg, sizeof(errorMsg), "Update error: %d", Update.getError());
        otaState = OTA_ERROR;
        needsRedraw = true;
    }
}

} // namespace

// ===== Public API =====

void otaUpdateSetup() {
    otaState = OTA_SCAN_WIFI;
    wifiCount = 0;
    wifiSelected = 0;
    wifiScroll = 0;
    passwordLen = 0;
    charIndex = 0;
    memset(password, 0, sizeof(password));
    memset(newVersion, 0, sizeof(newVersion));
    memset(firmwareUrl, 0, sizeof(firmwareUrl));
    memset(errorMsg, 0, sizeof(errorMsg));
    firmwareSize = 0;
    downloadProgress = 0;
    needsRedraw = true;
    lastButtonPress = 0;
    autoConnectAttempted = false;

    // Load saved password
    loadSavedPassword();
    charIndex = 0;

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    Serial.println();
    Serial.println("# hackbox OTA Update");

    startWifiScan();
}

void otaUpdateLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool left = digitalRead(BUTTON_PIN_LEFT) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (otaState) {
        case OTA_SCAN_WIFI: {
            processWifiScan();

            if (now - lastButtonPress > debounceDelay) {
                if (up && wifiSelected > 0) {
                    wifiSelected--;
                    if (wifiSelected < wifiScroll) wifiScroll = wifiSelected;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && wifiSelected < wifiCount - 1) {
                    wifiSelected++;
                    if (wifiSelected >= wifiScroll + 5) wifiScroll = wifiSelected - 4;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right && wifiCount > 0) {
                    // Wait for button release before transitioning
                    while (digitalRead(BUTTON_PIN_RIGHT) == LOW) delay(10);
                    delay(200);

                    // Open network: connect immediately, no password needed
                    if (wifiList[wifiSelected].encType == 0) {
                        passwordLen = 0;
                        password[0] = '\0';
                        connectToWifi();
                        lastButtonPress = millis();
                        break;
                    }

                    // Encrypted + saved password: auto-connect
                    if (passwordLen > 0) {
                        connectToWifi();
                        lastButtonPress = millis();
                        break;
                    }

                    // Encrypted + no saved password: enter password
                    otaState = OTA_PASSWORD_ENTRY;
                    charIndex = 0;
                    needsRedraw = true;
                    lastButtonPress = millis();
                }
            }
            // LEFT is the global app-exit. To rescan, exit and re-enter.

            if (needsRedraw) {
                needsRedraw = false;
                drawScanWifi();
            }
            break;
        }

        case OTA_PASSWORD_ENTRY: {
            if (now - lastButtonPress > debounceDelay) {
                if (up) {
                    charIndex = (charIndex + 1) % CHARSET_LEN;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down) {
                    charIndex = (charIndex - 1 + CHARSET_LEN) % CHARSET_LEN;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right) {
                    // Append character
                    if (passwordLen < 64) {
                        password[passwordLen++] = CHARSET[charIndex];
                        password[passwordLen] = '\0';
                        needsRedraw = true;
                    }
                    lastButtonPress = now;
                } else if (center) {
                    // Delete last char. CENTER (not LEFT) is used because LEFT
                    // is the global app-exit button — using it here would throw
                    // away the entire password the moment the user mistypes.
                    if (passwordLen > 0) {
                        passwordLen--;
                        password[passwordLen] = '\0';
                        needsRedraw = true;
                        while (digitalRead(BUTTON_PIN_CENTER) == LOW) delay(5);
                    }
                    lastButtonPress = now;
                }
            }

            // LEFT exits the app via runApp(). Hold RIGHT to connect.
            if (right) {
                delay(400);
                if (digitalRead(BUTTON_PIN_RIGHT) == LOW) {
                    // Still held = long press = connect
                    while (digitalRead(BUTTON_PIN_RIGHT) == LOW) delay(10);
                    connectToWifi();
                    lastButtonPress = millis();
                    break;
                }
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawPasswordEntry();
            }
            break;
        }

        case OTA_CONNECTING: {
            if (WiFi.status() == WL_CONNECTED) {
                Serial.printf("# Connected to %s\n", wifiList[wifiSelected].ssid);
                Serial.printf("# IP: %s\n", WiFi.localIP().toString().c_str());
                checkForUpdate();
                break;
            }

            if (now - connectStartTime > 15000) {
                snprintf(errorMsg, sizeof(errorMsg), "Connection timeout");
                otaState = OTA_ERROR;
                needsRedraw = true;
                break;
            }

            // Redraw periodically for animation
            static unsigned long lastConnDraw = 0;
            if (now - lastConnDraw > 500) {
                lastConnDraw = now;
                drawConnecting();
            }
            break;
        }

        case OTA_CHECKING:
            // Handled synchronously in checkForUpdate
            break;

        case OTA_UPDATE_AVAILABLE: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    // CENTER = confirm install. This matches the global
                    // "CENTER = OK/enter" convention and the on-screen hint.
                    performOTA();
                    lastButtonPress = now;
                }
            }
            // LEFT cancels by falling through to the global app-exit in runApp().

            if (needsRedraw) {
                needsRedraw = false;
                drawUpdateAvailable();
            }
            break;
        }

        case OTA_DOWNLOADING:
            // Handled synchronously in performOTA
            break;

        case OTA_DONE:
            // Should have rebooted already
            break;

        case OTA_ERROR: {
            // LEFT is the global app-exit via runApp; no in-app handler needed.

            if (needsRedraw) {
                needsRedraw = false;
                if (strcmp(errorMsg, "NO_UPDATE") == 0) {
                    drawNoUpdate();
                } else {
                    drawError();
                }
            }
            break;
        }
    }
}

void cleanupOtaUpdate() {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    Serial.println("# OTA Update session ended");
}
