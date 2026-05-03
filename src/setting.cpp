/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include <EEPROM.h>
#include <U8g2lib.h>
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

#include "../include/setting.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/level_system.h"
#include "../include/legal_disclaimer.h"
#include "../include/pindefs.h"
#include "../include/password.h"
#include "../include/themes.h"
#include "../include/livestream.h"

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

#define EEPROM_ADDRESS_NEOPIXEL 0
#define EEPROM_ADDRESS_BRIGHTNESS 1
#define EEPROM_ADDRESS_CONTINUOUS_SCAN 4
#define EEPROM_ADDRESS_PRIVACY_MODE 5
// byte 20 was the dangerous-actions toggle; left unused so an older EEPROM
// state can't accidentally re-surface the removed setting. byte 6 onward
// is reserved for the password sequence.

int currentSetting = 0;
int totalSettings = 11;
bool neoPixelActive = true;
uint8_t oledBrightness = 100;
bool continuousScanEnabled = true;
bool privacyModeEnabled = false;
bool showResetConfirm = false;
uint8_t sleepTimeoutIndex = 3;

static bool needsRedraw = true;
static int lastCurrentSetting = -1;
static bool lastNeoPixelActive = true;
static uint8_t lastOledBrightness = 100;
static bool lastContinuousScanEnabled = true;
static bool lastPrivacyModeEnabled = false;
static bool lastShowResetConfirm = false;
static uint8_t lastSleepTimeoutIndex = 3;

const unsigned long sleepTimeouts[] = {15, 30, 60, 120, 300, 900, 1800, 0};
const char* sleepTimeoutNames[] = {"15s", "30s", "1m", "2m", "5m", "15m", "30m", "Off"};
const int sleepTimeoutCount = 8;

extern unsigned long idleTimeout;
extern void updateSleepTimeout(unsigned long newTimeout);



// ===== WiFi Setup via Captive Portal =====
// EEPROM layout reuses OTA password storage (addr 50-114)
#define EEPROM_WIFI_SSID_START  300
#define EEPROM_WIFI_SSID_LEN     33
#define EEPROM_WIFI_PW_START      50
#define EEPROM_WIFI_PW_LEN        64
#define EEPROM_WIFI_PW_FLAG      114  // 0xAA = saved

static const char WIFI_SETUP_HTML[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html><head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>hackbox WiFi Setup</title>
<style>
body{font-family:sans-serif;background:#111;color:#FFB300;margin:0;padding:20px;text-align:center}
h1{font-size:1.5em}h2{font-size:1em;color:#aaa}
input,select{width:90%;max-width:300px;padding:12px;margin:8px 0;border:2px solid #FFB300;border-radius:8px;background:#222;color:#fff;font-size:16px}
button{width:90%;max-width:300px;padding:14px;margin:16px 0;border:none;border-radius:8px;background:#FFB300;color:#000;font-weight:bold;font-size:18px;cursor:pointer}
button:hover{background:#FFC107}
.ok{color:#0f0;font-size:1.2em}
#nets{max-height:200px;overflow-y:auto;text-align:left;margin:0 auto;max-width:300px}
.net{padding:10px;margin:4px 0;background:#222;border-radius:6px;cursor:pointer;border:1px solid #333}
.net:hover{border-color:#FFB300}
.net .rssi{float:right;color:#888}
</style>
</head><body>
<h1>hackbox</h1>
<h2>WiFi Setup</h2>
<div id='nets'>Scanning...</div>
<form method='POST' action='/save'>
<input id='s' name='s' placeholder='WiFi Name (SSID)' required>
<input id='p' name='p' type='password' placeholder='Password (leave blank if open)'>
<button type='submit'>Save & Connect</button>
</form>
<script>
fetch('/scan').then(r=>r.json()).then(d=>{
let h='';d.forEach(n=>{h+="<div class='net' onclick=\"document.getElementById('s').value='"+n.s.replace(/'/g,"\\'")+"'\">"+n.s+"<span class='rssi'>"+n.r+"dBm</span></div>"});
document.getElementById('nets').innerHTML=h||'No networks found';
});
</script>
</body></html>
)rawhtml";

static const char WIFI_SETUP_OK_HTML[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html><head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>hackbox WiFi Setup</title>
<style>body{font-family:sans-serif;background:#111;color:#FFB300;margin:0;padding:40px;text-align:center}h1{font-size:1.5em}.ok{color:#0f0;font-size:1.2em}</style>
</head><body>
<h1>hackbox</h1>
<p class='ok'>WiFi credentials saved!</p>
<p>You can disconnect from hackbox-Setup now.</p>
<p>The device will auto-connect to your network.</p>
</body></html>
)rawhtml";

void runWiFiSetup() {
    // Show instructions on OLED
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "WiFi Setup");
    u8g2.drawHLine(0, 12, 128);
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 24, "1. On your phone, go to");
    u8g2.drawStr(0, 32, "   WiFi settings");
    u8g2.drawStr(0, 42, "2. Connect to:");
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 54, "   hackbox-Setup");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 64, "3. A page will open");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);

    // Start AP
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("hackbox-Setup");
    delay(500);

    // Scan for networks to show in the portal
    int scanCount = WiFi.scanNetworks();

    // Start DNS (captive portal redirect)
    DNSServer dns;
    dns.start(53, "*", WiFi.softAPIP());

    // Start web server
    WebServer server(80);
    bool saved = false;

    server.on("/", HTTP_GET, [&server]() {
        server.send_P(200, "text/html", WIFI_SETUP_HTML);
    });

    server.on("/scan", HTTP_GET, [&server, &scanCount]() {
        String json = "[";
        for (int i = 0; i < scanCount && i < 20; i++) {
            if (i > 0) json += ",";
            String ssid = WiFi.SSID(i);
            ssid.replace("\"", "\\\"");
            ssid.replace("'", "\\'");
            json += "{\"s\":\"" + ssid + "\",\"r\":" + String(WiFi.RSSI(i)) + "}";
        }
        json += "]";
        server.send(200, "application/json", json);
    });

    server.on("/save", HTTP_POST, [&server, &saved]() {
        String ssid = server.arg("s");
        String pw = server.arg("p");

        if (ssid.length() > 0 && ssid.length() <= 32) {
            // Save SSID to EEPROM (addr 300-332)
            for (int i = 0; i < 33; i++) {
                EEPROM.write(EEPROM_WIFI_SSID_START + i,
                    (i < (int)ssid.length()) ? ssid.charAt(i) : '\0');
            }

            // Save password to EEPROM (addr 50-113, flag at 114)
            for (int i = 0; i < 64; i++) {
                EEPROM.write(EEPROM_WIFI_PW_START + i,
                    (i < (int)pw.length()) ? pw.charAt(i) : '\0');
            }
            EEPROM.write(EEPROM_WIFI_PW_FLAG, 0xAA);
            EEPROM.commit();

            // Also tell the ESP32 WiFi stack to remember this network
            WiFi.begin(ssid.c_str(), pw.length() > 0 ? pw.c_str() : nullptr);

            saved = true;
            Serial.printf("# WiFi Setup: saved SSID=%s\n", ssid.c_str());
        }

        server.send_P(200, "text/html", WIFI_SETUP_OK_HTML);
    });

    // Captive portal: redirect all unknown URLs to root
    server.onNotFound([&server]() {
        server.sendHeader("Location", "http://192.168.4.1/");
        server.send(302, "text/plain", "");
    });

    server.begin();
    Serial.println("# WiFi Setup portal active on 192.168.4.1");

    // Update OLED with connection status
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "WiFi Setup Active");
    u8g2.drawHLine(0, 12, 128);
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 24, "On your phone:");
    u8g2.drawStr(0, 34, "1. Connect WiFi to");
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 46, " hackbox-Setup");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 56, "2. Pick your network");
    u8g2.drawStr(0, 64, "3. Enter password");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);

    // Run portal until user saves or presses a button to cancel
    unsigned long startTime = millis();
    while (!saved) {
        dns.processNextRequest();
        server.handleClient();
        delay(5);

        // Check for LEFT button to cancel
        if (digitalRead(BUTTON_PIN_LEFT) == LOW) {
            while (digitalRead(BUTTON_PIN_LEFT) == LOW) delay(5);
            break;
        }

        // Timeout after 3 minutes
        if (millis() - startTime > 180000) break;
    }

    server.stop();
    dns.stop();
    WiFi.softAPdisconnect(true);

    if (saved) {
        // Show success on OLED
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(15, 30, "WiFi Saved!");
        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(10, 45, "Games will auto-connect");
        u8g2.sendBuffer();
        displayMirrorSend(u8g2);
        delay(2000);
    } else {
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(20, 35, "Cancelled");
        u8g2.sendBuffer();
        displayMirrorSend(u8g2);
        delay(1000);
    }

    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
}

void settingSetup() {
  uint8_t neoPixelValue = EEPROM.read(EEPROM_ADDRESS_NEOPIXEL);
  uint8_t brightnessValue = EEPROM.read(EEPROM_ADDRESS_BRIGHTNESS);
  uint8_t sleepTimeoutValue = EEPROM.read(EEPROM_ADDRESS_SLEEP_TIMEOUT);
  uint8_t continuousScanValue = EEPROM.read(EEPROM_ADDRESS_CONTINUOUS_SCAN);
  uint8_t privacyModeValue = EEPROM.read(EEPROM_ADDRESS_PRIVACY_MODE);

  if (neoPixelValue == 0xFF) {
    neoPixelActive = true;
    EEPROM.write(EEPROM_ADDRESS_NEOPIXEL, 1);
    EEPROM.commit();
  } else {
    neoPixelActive = (neoPixelValue == 1);
  }

  // Treat an erased EEPROM byte (0xFF) as "uninitialized" and fall back to a
  // reasonable mid-brightness default. The previous check (brightnessValue > 255)
  // was dead code because brightnessValue is uint8_t, so a fresh device used to
  // boot at 100%/full glare instead of the 50% default.
  if (brightnessValue == 0xFF) {
    oledBrightness = 128;
    EEPROM.write(EEPROM_ADDRESS_BRIGHTNESS, oledBrightness);
    EEPROM.commit();
  } else {
    oledBrightness = brightnessValue;
  }

  if (sleepTimeoutValue == 0xFF || sleepTimeoutValue >= sleepTimeoutCount) {
    sleepTimeoutIndex = 3;
    EEPROM.write(EEPROM_ADDRESS_SLEEP_TIMEOUT, sleepTimeoutIndex);
    EEPROM.commit();
  } else {
    sleepTimeoutIndex = sleepTimeoutValue;
  }

  if (continuousScanValue == 0xFF) {
    continuousScanEnabled = true;
    EEPROM.write(EEPROM_ADDRESS_CONTINUOUS_SCAN, 1);
    EEPROM.commit();
  } else {
    continuousScanEnabled = (continuousScanValue == 1);
  }

  if (privacyModeValue == 0xFF) {
    privacyModeEnabled = false;
    EEPROM.write(EEPROM_ADDRESS_PRIVACY_MODE, 0);
    EEPROM.commit();
  } else {
    privacyModeEnabled = (privacyModeValue == 1);
  }

  u8g2.setContrast(oledBrightness);

  updateSleepTimeout(sleepTimeouts[sleepTimeoutIndex] * 1000);

  currentSetting = 0;
  showResetConfirm = false;

  needsRedraw = true;
  lastCurrentSetting = -1;
  lastNeoPixelActive = neoPixelActive;
  lastOledBrightness = oledBrightness;
  lastContinuousScanEnabled = continuousScanEnabled;
  lastPrivacyModeEnabled = privacyModeEnabled;
  lastShowResetConfirm = false;
  lastSleepTimeoutIndex = sleepTimeoutIndex;
}

void settingLoop() {
  static bool upPressed = false;
  static bool downPressed = false;
  static bool rightPressed = false;
  static bool leftPressed = false;
  static bool centerPressed = false;
  static unsigned long lastUpPress = 0;
  static unsigned long lastDownPress = 0;
  static unsigned long lastRightPress = 0;
  static unsigned long lastLeftPress = 0;
  static unsigned long lastCenterPress = 0;
  const unsigned long debounceDelay = 200;

  checkIdle();

  unsigned long now = millis();
  bool up = !digitalRead(BUTTON_PIN_UP);
  bool down = !digitalRead(BUTTON_PIN_DOWN);
  bool right = !digitalRead(BUTTON_PIN_RIGHT);
  bool left = !digitalRead(BUTTON_PIN_LEFT);
  bool center = !digitalRead(BUTTON_PIN_CENTER);

  if (up) {
    if (!upPressed && (now - lastUpPress > debounceDelay)) {
      upPressed = true;
      lastUpPress = now;
      if (!showResetConfirm) {
        currentSetting = (currentSetting - 1 + totalSettings) % totalSettings;
        needsRedraw = true;
      }
    }
  } else {
    upPressed = false;
  }

  if (down) {
    if (!downPressed && (now - lastDownPress > debounceDelay)) {
      downPressed = true;
      lastDownPress = now;
      if (!showResetConfirm) {
        currentSetting = (currentSetting + 1) % totalSettings;
        needsRedraw = true;
      }
    }
  } else {
    downPressed = false;
  }

  if (right) {
    if (!rightPressed && (now - lastRightPress > debounceDelay)) {
      rightPressed = true;
      lastRightPress = now;

      if (showResetConfirm) {
        // Reset dialog: RIGHT is a no-op. Confirm is CENTER, cancel is LEFT.
      } else {
        switch (currentSetting) {
          case 0:
            neoPixelActive = !neoPixelActive;
            EEPROM.write(EEPROM_ADDRESS_NEOPIXEL, neoPixelActive ? 1 : 0);
            EEPROM.commit();
            needsRedraw = true;
            break;

          case 1:
            {
              uint8_t percent = map(oledBrightness, 0, 255, 0, 100);
              percent += 10;
              if (percent > 100) percent = 0;
              oledBrightness = map(percent, 0, 100, 0, 255);
              u8g2.setContrast(oledBrightness);
              EEPROM.write(EEPROM_ADDRESS_BRIGHTNESS, oledBrightness);
              EEPROM.commit();
              needsRedraw = true;
            }
            break;

          case 2:
            sleepTimeoutIndex = (sleepTimeoutIndex + 1) % sleepTimeoutCount;
            EEPROM.write(EEPROM_ADDRESS_SLEEP_TIMEOUT, sleepTimeoutIndex);
            EEPROM.commit();
            updateSleepTimeout(sleepTimeouts[sleepTimeoutIndex] * 1000);
            needsRedraw = true;
            break;

          case 3:
            continuousScanEnabled = !continuousScanEnabled;
            EEPROM.write(EEPROM_ADDRESS_CONTINUOUS_SCAN, continuousScanEnabled ? 1 : 0);
            EEPROM.commit();
            needsRedraw = true;
            break;

          case 4:
            privacyModeEnabled = !privacyModeEnabled;
            EEPROM.write(EEPROM_ADDRESS_PRIVACY_MODE, privacyModeEnabled ? 1 : 0);
            EEPROM.commit();
            needsRedraw = true;
            break;

          case 5:
            if (passwordEnabled()) {
              clearPassword();
              needsRedraw = true;
            } else {
              setPasswordInSettings();
              needsRedraw = true;
            }
            break;

          case 6:
            showResetConfirm = true;
            needsRedraw = true;
            break;

          case 7:
            // Full EEPROM wipe
            for (int i = 0; i < 512; i++) {
              EEPROM.write(i, 0xFF);
            }
            EEPROM.commit();
            ESP.restart();
            break;

          case 8:
            runWiFiSetup();
            needsRedraw = true;
            break;

          case 9:
            themeCycle();
            needsRedraw = true;
            break;

          case 10:
            livestreamToggle();
            needsRedraw = true;
            break;
        }
      }
    }
  } else {
    rightPressed = false;
  }

  if (left) {
    if (!leftPressed && (now - lastLeftPress > debounceDelay)) {
      leftPressed = true;
      lastLeftPress = now;
      if (showResetConfirm) {
        // In-app cancel of the reset dialog. Wait for release so the global
        // runApp() LEFT=exit edge detector doesn't also fire and kick us out
        // of the settings app entirely.
        showResetConfirm = false;
        needsRedraw = true;
        while (digitalRead(BUTTON_PIN_LEFT) == LOW) delay(5);
      }
    }
  } else {
    leftPressed = false;
  }

  if (center) {
    if (!centerPressed && (now - lastCenterPress > debounceDelay)) {
      centerPressed = true;
      lastCenterPress = now;
      if (showResetConfirm) {
        resetXPData();
        showResetConfirm = false;
        needsRedraw = true;
      }
    }
  } else {
    centerPressed = false;
  }

  if (lastCurrentSetting != currentSetting) {
    lastCurrentSetting = currentSetting;
    needsRedraw = true;
  }
  if (lastNeoPixelActive != neoPixelActive) {
    lastNeoPixelActive = neoPixelActive;
    needsRedraw = true;
  }
  if (lastOledBrightness != oledBrightness) {
    lastOledBrightness = oledBrightness;
    needsRedraw = true;
  }
  if (lastShowResetConfirm != showResetConfirm) {
    lastShowResetConfirm = showResetConfirm;
    needsRedraw = true;
  }
  if (lastSleepTimeoutIndex != sleepTimeoutIndex) {
    lastSleepTimeoutIndex = sleepTimeoutIndex;
    needsRedraw = true;
  }
  if (lastContinuousScanEnabled != continuousScanEnabled) {
    lastContinuousScanEnabled = continuousScanEnabled;
    needsRedraw = true;
  }
  if (lastPrivacyModeEnabled != privacyModeEnabled) {
    lastPrivacyModeEnabled = privacyModeEnabled;
    needsRedraw = true;
  }

  if (!needsRedraw) {
    return;
  }

  needsRedraw = false;
  u8g2.clearBuffer();

  if (showResetConfirm) {
    u8g2.setFont(u8g2_font_helvB08_tr);
    int titleWidth = u8g2.getUTF8Width("Reset XP Data?");
    u8g2.drawStr((128 - titleWidth) / 2, 20, "Reset XP Data?");

    u8g2.setFont(u8g2_font_6x10_tr);
    int messageWidth = u8g2.getUTF8Width("Reset to Level 1");
    u8g2.drawStr((128 - messageWidth) / 2, 35, "Reset to Level 1");

    u8g2.setFont(u8g2_font_4x6_tr);
    int buttonWidth = u8g2.getUTF8Width("LEFT=Cancel  CENTER=Confirm");
    u8g2.drawStr((128 - buttonWidth) / 2, 55, "LEFT=Cancel  CENTER=Confirm");
  } else {
    u8g2.setFont(u8g2_font_helvB08_tr);
    u8g2.drawStr(45, 12, "Settings");

    u8g2.setFont(u8g2_font_6x10_tr);

    int startIndex = max(0, min(currentSetting - 1, totalSettings - 4));
    int displayIndex = 0;

    for (int i = startIndex; i < min(startIndex + 4, totalSettings); i++) {
      int yPos = 25 + displayIndex * 12;

      if (currentSetting == i) u8g2.drawStr(2, yPos, ">");

      switch (i) {
        case 0:
          u8g2.drawStr(10, yPos, "NeoPixel:");
          u8g2.drawStr(85, yPos, neoPixelActive ? "On" : "Off");
          break;
        case 1:
          u8g2.drawStr(10, yPos, "Brightness:");
          char brightStr[8];
          snprintf(brightStr, sizeof(brightStr), "%d%%", (int)map(oledBrightness, 0, 255, 0, 100));
          u8g2.drawStr(85, yPos, brightStr);
          break;
        case 2:
          u8g2.drawStr(10, yPos, "Sleep:");
          u8g2.drawStr(85, yPos, sleepTimeoutNames[sleepTimeoutIndex]);
          break;
        case 3:
          u8g2.drawStr(10, yPos, "Fast Retry:");
          u8g2.drawStr(85, yPos, continuousScanEnabled ? "On" : "Off");
          break;
        case 4:
          u8g2.drawStr(10, yPos, "Privacy:");
          u8g2.drawStr(85, yPos, privacyModeEnabled ? "On" : "Off");
          break;
        case 5:
          u8g2.drawStr(10, yPos, "Password:");
          u8g2.drawStr(85, yPos, passwordEnabled() ? "On" : "Off");
          break;
        case 6:
          u8g2.drawStr(10, yPos, "Reset XP:");
          char lvlStr[8];
          snprintf(lvlStr, sizeof(lvlStr), "Lv%d", getCurrentLevel());
          u8g2.drawStr(85, yPos, lvlStr);
          break;
        case 7:
          u8g2.drawStr(10, yPos, "Wipe EEPROM");
          u8g2.drawStr(85, yPos, ">>>");
          break;
        case 8:
          u8g2.drawStr(10, yPos, "WiFi Setup");
          u8g2.drawStr(85, yPos, ">>>");
          break;
        case 9:
          u8g2.drawStr(10, yPos, "Theme:");
          u8g2.drawStr(85, yPos, themeCurrentName());
          break;
        case 10:
          u8g2.drawStr(10, yPos, "Livestream:");
          u8g2.drawStr(85, yPos, livestreamEnabled() ? "On" : "Off");
          break;
      }
      displayIndex++;
    }
  }

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

bool isContinuousScanEnabled() {
  return continuousScanEnabled;
}

bool isPrivacyModeEnabled() {
  return privacyModeEnabled;
}

void maskMAC(const char* original, char* masked) {
  if (!privacyModeEnabled || original == nullptr || masked == nullptr) {
    if (original && masked) {
      strncpy(masked, original, 18);
      masked[17] = '\0';
    }
    return;
  }

  // Exclude generic placeholder MAC addresses from masking
  if (strcmp(original, "N/A") == 0) {
    strncpy(masked, original, 18);
    masked[17] = '\0';
    return;
  }

  strncpy(masked, original, 8);
  masked[8] = '\0';

  strcat(masked, ":**:**:**");
}

void maskName(const char* original, char* masked, int maxLen) {
  if (!privacyModeEnabled || original == nullptr || masked == nullptr) {
    if (original && masked) {
      strncpy(masked, original, maxLen);
      masked[maxLen] = '\0';
    }
    return;
  }

  // Exclude generic placeholder names from masking
  if (strcmp(original, "Unknown") == 0 ||
      strcmp(original, "Hidden") == 0 ||
      strcmp(original, "N/A") == 0 ||
      strcmp(original, "AirTag") == 0 ||
      strcmp(original, "SmartTag") == 0 ||
      strcmp(original, "Axon Device") == 0 ||
      strcmp(original, "Flipper Zero") == 0 ||
      strcmp(original, "MeshCore") == 0 ||
      strcmp(original, "Meshtastic") == 0 ||
      strcmp(original, "Tile") == 0 ||
      strcmp(original, "RayBan Device") == 0 ||
      strcmp(original, "Flock Device") == 0) {
    strncpy(masked, original, maxLen);
    masked[maxLen] = '\0';
    return;
  }

  int len = strlen(original);
  if (len == 0) {
    masked[0] = '\0';
    return;
  }

  masked[0] = original[0];

  int asterisks = min(len - 1, maxLen - 1);
  for (int i = 1; i <= asterisks; i++) {
    masked[i] = '*';
  }
  masked[asterisks + 1] = '\0';
}

void maskNameEvilPortal(const char* original, char* masked, int maxLen, const char* customSSIDs[], int customSSIDCount) {
  if (!privacyModeEnabled || original == nullptr || masked == nullptr) {
    if (original && masked) {
      strncpy(masked, original, maxLen);
      masked[maxLen] = '\0';
    }
    return;
  }

  // Exclude custom SSIDs from masking in Evil Portal
  for (int i = 0; i < customSSIDCount; i++) {
    if (strcmp(original, customSSIDs[i]) == 0) {
      strncpy(masked, original, maxLen);
      masked[maxLen] = '\0';
      return;
    }
  }

  int len = strlen(original);
  if (len == 0) {
    masked[0] = '\0';
    return;
  }

  masked[0] = original[0];

  int asterisks = min(len - 1, maxLen - 1);
  for (int i = 1; i <= asterisks; i++) {
    masked[i] = '*';
  }
  masked[asterisks + 1] = '\0';
}