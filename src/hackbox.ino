/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include <Arduino.h>
#include <SPI.h>
#include <U8g2lib.h>
#include <stdint.h>
#include <Adafruit_NeoPixel.h>
#include <EEPROM.h>
#include <esp_wifi.h>
#include "esp_bt_main.h"

#ifdef U8X8_HAVE_HW_I2C
#include <Wire.h>
#endif
#include <RF24.h>

#include "../include/icon.h"
#include "../include/neopixel.h"
#include "../include/setting.h"

#include "../include/scanner.h"
#include "../include/analyzer.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/hivemind.h"
#endif
#include "../include/sourapple.h"
#include "../include/sourdroid.h"
#include "../include/honeyble.h"
#include "../include/blescan.h"
#include "../include/ble_inspector.h"
#include "../include/ble_spammer.h"
#include "../include/ble_spoofer.h"
#include "../include/swiftpair.h"
#include "../include/flipperzero_detector.h"
#include "../include/meshtastic_detector.h"
#include "../include/meshcore_detector.h"
#include "../include/airtag_detector.h"
#include "../include/airtag_spoofer.h"
#include "../include/tile_detector.h"
#include "../include/smarttag_detector.h"
#include "../include/rayban_detector.h"
#include "../include/wifiscan.h"
#include "../include/deauth.h"
#include "../include/deauth_scanner.h"
#include "../include/xbox_hunter.h"
#include "../include/beacon_spam.h"
#include "../include/ck42x_spam.h"
#include "../include/pwnagotchi_detector.h"
#include "../include/pindefs.h"
#include "../include/about.h"
#include "../include/channel_analyzer.h"
#include "../include/camera_detector.h"
#include "../include/pwnagotchi_spam.h"
#include "../include/level_system.h"
#include "../include/hackbox_detector.h"
#include "../include/hackbox_advertiser.h"
#include "../include/themes.h"
#include "../include/livestream.h"
#include "../include/evil_portal.h"
#include "../include/legal_disclaimer.h"
#include "../include/cardskimmer_detector.h"
#include "../include/axon_detector.h"
#include "../include/drone_detector.h"
#include "../include/drone_spoofer.h"
#include "../include/flock_detector.h"
#include "../include/device_scout.h"
#include "../include/aio_find_mode.h"
#include "../include/tracking_sweep.h"
#include "../include/mission_mode.h"
#include "../include/rogue_ap.h"
#include "../include/session_log.h"
#include "../include/pineapple_detector.h"
#include "../include/display_mirror.h"
#include "../include/password.h"
#include "../include/radio_manager.h"
#include "../include/packet_logger.h"
#include "../include/probe_logger.h"
#include "../include/rssi_snare.h"
#include "../include/traffic_portal.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/remote_control.h"
#endif
// battery_probe.h removed: hackbox has no battery ADC pin
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/handshake_capture.h"
#include "../include/pmkid_capture.h"
#endif
#include "../include/bee_spam.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/evil_twin.h"
#endif
#include "../include/hidden_network.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/mousejack.h"
#endif
#include "../include/wardriver.h"
#include "../include/ota_update.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/replay_attack.h"
#endif
#include "../include/wifi_graffiti.h"
#include "../include/engagement_report.h"
#include "../include/wps_scanner.h"
#ifndef HACKBOX_SCOUT_BUILD
#include "../include/ble_mitm.h"
#endif
#include "../include/snake.h"
#include "../include/pokehive.h"
#include "../include/signal_wars.h"
#include "../include/packet_hunter.h"
#include "../include/rf_roulette.h"
#include "../include/bee_cipher.h"
#include "../include/hivepet.h"
#include "../include/sneaker_mode.h"
#include "../include/morse_beacon.h"
#include "../include/hive_listener.h"
#include "../include/honey_flood.h"

RF24 radios[] = {
  RF24(RADIO_CE_PIN_1, RADIO_CSN_PIN_1),
  RF24(RADIO_CE_PIN_2, RADIO_CSN_PIN_2),
  RF24(RADIO_CE_PIN_3, RADIO_CSN_PIN_3)
};

U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
Adafruit_NeoPixel pixels(1, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);
extern uint8_t oledBrightness;

struct MenuItem {
  const char* name;
  const unsigned char* icon;
  void (*setup)();
  void (*loop)();
  void (*cleanup)();
};

const char* hackboxVersion = HACKBOX_VERSION;
// Apps can set this to true to request runApp() exit on a non-LEFT button.
// Cleared when runApp() enters an app and when it exits.
bool hackboxAppExitRequested = false;
unsigned long idleTimeout = 120000;
static unsigned long lastActivity = 0;
static bool displayOff = false;
const unsigned long MAX_XP_IDLE_TIME = 120000;

unsigned long upLastMillis    = 0;
unsigned long upNextRepeat    = 0;
bool         upPressed        = false;
unsigned long upDebounceTime  = 0;

unsigned long downLastMillis  = 0;
unsigned long downNextRepeat  = 0;
bool         downPressed      = false;
unsigned long downDebounceTime = 0;

bool selPrev = false;
bool rightPrev = false;
bool leftPrev = false;
unsigned long selDebounceTime = 0;
unsigned long rightDebounceTime = 0;
unsigned long leftDebounceTime = 0;

const unsigned long initialDelay   = 500;
const unsigned long repeatInterval = 250;
const unsigned long debounceDelay  = 200;

static bool needsRedraw = true;

void updateLastActivity() {
  lastActivity = millis();
}

void updateSleepTimeout(unsigned long newTimeout) {
  idleTimeout = newTimeout;
}

bool anyButtonPressed() {
  return digitalRead(BUTTON_PIN_UP)    == LOW ||
        digitalRead(BUTTON_PIN_DOWN)  == LOW ||
        digitalRead(BUTTON_PIN_CENTER)== LOW ||
        digitalRead(BUTTON_PIN_RIGHT) == LOW ||
        digitalRead(BUTTON_PIN_LEFT)  == LOW;
}


void loadSleepTimeoutFromEEPROM() {
  uint8_t sleepTimeoutValue = EEPROM.read(EEPROM_ADDRESS_SLEEP_TIMEOUT);
  if (sleepTimeoutValue < (uint8_t)sleepTimeoutCount) {
    updateSleepTimeout(sleepTimeouts[sleepTimeoutValue] * 1000);
  } else {
    updateSleepTimeout(120000);
  }
}


void wakeDisplay() {
  u8g2.setPowerSave(0);
  displayOff = false;
  while (anyButtonPressed()) {}

  upDebounceTime = 0;
  downDebounceTime = 0;
  selDebounceTime = 0;
  leftDebounceTime = 0;
  rightDebounceTime = 0;

  upPressed = false;
  downPressed = false;
  selPrev = false;
  leftPrev = false;
  rightPrev = false;

  updateLastActivity();
  needsRedraw = true;
}

void checkIdle() {
  if (idleTimeout == 0) {
    return;
  }

  if (!displayOff && millis() - lastActivity >= idleTimeout) {
    u8g2.setPowerSave(1);
    displayOff = true;
    return;
  }
  if (displayOff && anyButtonPressed()) {
    delay(10);
    if (anyButtonPressed()) {
      wakeDisplay();
    }
  }
}

const int ITEM_HEIGHT = 16;
const int ITEM_SPACING = 2;
const int TEXT_X = 28;
const int SELECTION_X = 4;
const int SELECTION_WIDTH = 120;
const int ICON_X = 8;

void drawSelection(int x, int y, int width, int height, bool selected) {
  if (selected) {
    u8g2.drawBox(x, y+2, 2, height-4);
  }
}

enum AppMenuState { APP_MAIN, APP_BLE, APP_WIFI, APP_OTHER, APP_GAMES, APP_LEVEL };

int getXPAmount(const char* appName) {
  if (isReconApp(appName)) {
    return 3;
  } else if (isOffensiveApp(appName)) {
    return 4;
  } else if (isUtilityApp(appName)) {
    return 2;
  } else {
    return 0;
  }
}

bool isReconApp(const char* appName) {
  return strstr(appName, "Scan") != nullptr || 
         strstr(appName, "Detector") != nullptr ||
         strstr(appName, "Scout") != nullptr ||
         strstr(appName, "Analyzer") != nullptr ||
         strstr(appName, "Inspect") != nullptr;
}

bool isDangerousApp(const char* appName) {
  return false; // hackbox: all tools always visible
}

bool isOffensiveApp(const char* appName) {
  if (isDangerousApp(appName)) {
    return true;
  }

  return strstr(appName, "Deauth") != nullptr ||
         strstr(appName, "Spam") != nullptr ||
         strstr(appName, "Swift Pair") != nullptr ||
         strstr(appName, "Sour Apple") != nullptr ||
         strstr(appName, "Sour Droid") != nullptr ||
         strstr(appName, "Spoofer") != nullptr ||
         strstr(appName, "Evil Portal") != nullptr;
}

bool isUtilityApp(const char* appName) {
  return strstr(appName, "Setting") != nullptr ||
         strstr(appName, "About") != nullptr;
}

bool isCaptureApp(const char* appName) {
  return strstr(appName, "Handshake") != nullptr ||
         strstr(appName, "PMKID") != nullptr ||
         strstr(appName, "Logger") != nullptr ||
         strstr(appName, "Wardriv") != nullptr;
}

bool isGameApp(const char* appName) {
  return strstr(appName, "Snake") != nullptr ||
         strstr(appName, "Cipher") != nullptr ||
         strstr(appName, "PokeHive") != nullptr ||
         strstr(appName, "Roulette") != nullptr ||
         strstr(appName, "Signal Wars") != nullptr ||
         strstr(appName, "Pollen Patrol") != nullptr;
}

AppMenuState currentState = APP_MAIN;
const MenuItem* currentMenuItems = nullptr;
int          currentMenuSize  = 0;
int          item_selected    = 0;

constexpr uint8_t BUTTON_UP    = BUTTON_PIN_UP;
constexpr uint8_t BUTTON_SEL   = BUTTON_PIN_CENTER;
constexpr uint8_t BUTTON_DOWN  = BUTTON_PIN_DOWN;
constexpr uint8_t BUTTON_RIGHT = BUTTON_PIN_RIGHT;
constexpr uint8_t BUTTON_LEFT  = BUTTON_PIN_LEFT;

static unsigned long appStartTime = 0;
static unsigned long lastXPReward = 0;
static const char* currentAppName = "";
static int currentXPAmount = 0;
static bool inApplication = false;
static int pendingXP = 0;
static unsigned long totalActiveMinutes = 0;
const unsigned long XP_REWARD_INTERVAL = 60000;

bool justPressed(uint8_t pin, bool &prev, unsigned long &debounceTime) {
  bool now = digitalRead(pin) == LOW;
  unsigned long currentTime = millis();

  if (now != prev && (currentTime - debounceTime) > debounceDelay) {
    debounceTime = currentTime;
    prev = now;
    return now;
  }

  return false;
}

bool shouldShowApp(const char* appName) {
  return !isDangerousApp(appName);
}

int getVisibleMenuSize() {
  int count = 0;
  for (int i = 0; i < currentMenuSize; i++) {
    if (shouldShowApp(currentMenuItems[i].name)) {
      count++;
    }
  }
  return count;
}

const MenuItem* getVisibleMenuItem(int visibleIndex) {
  int visibleCount = 0;
  for (int i = 0; i < currentMenuSize; i++) {
    if (shouldShowApp(currentMenuItems[i].name)) {
      if (visibleCount == visibleIndex) {
        return &currentMenuItems[i];
      }
      visibleCount++;
    }
  }

  return &currentMenuItems[0];
}


void startAppTracking(const char* appName) {
  currentAppName = appName;
  currentXPAmount = getXPAmount(appName);
  appStartTime = millis();
  lastXPReward = appStartTime;
  totalActiveMinutes = 0;
  inApplication = true;
  livestreamEmit("app_enter", appName);
  sessionLogEvent("app_start", appName);
}

void stopAppTracking() {
  if (inApplication) {
    if (totalActiveMinutes >= 10) {
      pendingXP += 12;
    } else if (totalActiveMinutes >= 5) {
      pendingXP += 4;
    }

    if (pendingXP > 0) {
      addXP(pendingXP);
      pendingXP = 0;
    }

    char detail[32];
    snprintf(detail, sizeof(detail), "%s %lum", currentAppName, totalActiveMinutes);
    livestreamEmit("app_exit", currentAppName);
    sessionLogEvent("app_exit", detail);

    inApplication = false;
    currentAppName = "";
    currentXPAmount = 0;

    updateLastActivity();
  }
}

void updateAppXP() {
  if (!inApplication) return;

  bool currentlyActive = (millis() - lastActivity < MAX_XP_IDLE_TIME);

  if (currentlyActive && millis() - lastXPReward >= XP_REWARD_INTERVAL) {
    totalActiveMinutes++;

    if (currentXPAmount > 0) {
      pendingXP += currentXPAmount;
    }
    lastXPReward = millis();
  }
}

void enterMenu(AppMenuState st);
void runApp(const MenuItem &mi);

void noCleanup() {
}

const MenuItem mainMenu[] = {
  { "WiFi",  bitmap_icon_wifi,    nullptr, nullptr, noCleanup },
  { "BLE",   bitmap_icon_ble,     nullptr, nullptr, noCleanup },
  { "Other", bitmap_icon_analyzer, nullptr, nullptr, noCleanup },
  { "Games", bitmap_icon_gamepad,  nullptr, nullptr, noCleanup }
};
constexpr int MAIN_MENU_SIZE = sizeof(mainMenu) / sizeof(mainMenu[0]);

const MenuItem wifiMenu[] = {
  { "Camera Detector", nullptr, cameraDetectorSetup,      cameraDetectorLoop,     cameraDetectorCleanup },
  { "WiFi Scan",       nullptr, wifiscanSetup,           wifiscanLoop,           wifiscanCleanup },
  { "Channel Analyzer", nullptr, channelAnalyzerSetup,   channelAnalyzerLoop,    cleanupWiFi },
  { "WiFi Deauther",   nullptr, deauthSetup,             deauthLoop,             cleanupWiFi },
#ifndef HACKBOX_SCOUT_BUILD
  { "Handshake Cap",   nullptr, handshakeCaptureSetup,   handshakeCaptureLoop,   cleanupHandshakeCapture },
  { "PMKID Capture",   nullptr, pmkidCaptureSetup,       pmkidCaptureLoop,       cleanupPmkidCapture },
#endif
  { "Deauth Scanner",  nullptr, deauthScannerSetup,      deauthScannerLoop,      cleanupWiFi },
  { "Xbox Hunter",     nullptr, xboxHunterSetup,         xboxHunterLoop,         cleanupWiFi },
  { "Beacon Spam",     nullptr, beaconSpamSetup,         beaconSpamLoop,         cleanupWiFi },
  { "CK42X Spam",      nullptr, ck42xSpamSetup,          ck42xSpamLoop,          cleanupWiFi },
  { "WiFi Graffiti",   nullptr, wifiGraffitiSetup,       wifiGraffitiLoop,       cleanupWifiGraffiti },
  { "Evil Portal",     nullptr, evilPortalSetup,         evilPortalLoop,         cleanupEvilPortal },
#ifndef HACKBOX_SCOUT_BUILD
  { "Evil Twin",       nullptr, evilTwinSetup,           evilTwinLoop,           cleanupEvilTwin },
#endif
  { "Hidden Networks", nullptr, hiddenNetworkSetup, hiddenNetworkLoop, cleanupHiddenNetwork },
  { "Rogue AP Detect", nullptr, rogueApSetup,            rogueApLoop,            rogueApCleanup },
  { "Pineapple Detector", nullptr, pineappleDetectorSetup, pineappleDetectorLoop, cleanupWiFi },
  { "Pwnagotchi Detector", nullptr, pwnagotchiDetectorSetup, pwnagotchiDetectorLoop, cleanupWiFi },
  { "Pwnagotchi Spam", nullptr, pwnagotchiSpamSetup,     pwnagotchiSpamLoop,     cleanupWiFi },
  { "WPS Auditor", nullptr, wpsSetup,                wpsLoop,                cleanupWPS },
  { "Wardriving",      nullptr, wardriverSetup,          wardriverLoop,          cleanupWardriver },
  { "Back",            nullptr, nullptr,                 nullptr,                noCleanup }
};
constexpr int WIFI_MENU_SIZE = sizeof(wifiMenu) / sizeof(wifiMenu[0]);

const MenuItem bleMenu[] = {
  { "BLE Scan",     nullptr, blescanSetup,             blescanLoop,             cleanupBLE },
  { "BLE Inspector",   nullptr, bleInspectorSetup,            bleInspectorLoop,            cleanupBLE },
  { "hackbox Detector", nullptr, hackboxDetectorSetup,         hackboxDetectorLoop,         cleanupBLE },
  { "Flipper Zero Detector", nullptr, flipperZeroDetectorSetup, flipperZeroDetectorLoop, cleanupBLE },
  { "Axon Detector", nullptr, axonDetectorSetup, axonDetectorLoop, cleanupBLE },
  { "Meshtastic Detector", nullptr, meshtasticDetectorSetup, meshtasticDetectorLoop, cleanupBLE },
  { "MeshCore Detector", nullptr, meshcoreDetectorSetup, meshcoreDetectorLoop, cleanupBLE },
  { "Skimmer Detector", nullptr, cardskimmerDetectorSetup, cardskimmerDetectorLoop, cleanupBLE },
  { "AirTag Detector", nullptr, airtagDetectorSetup,   airtagDetectorLoop,      cleanupBLE },
  { "AirTag Spoofer", nullptr, airtagSpooferSetup,     airtagSpooferLoop,       cleanupBLE },
  { "SmartTag Detector", nullptr, smarttagDetectorSetup, smarttagDetectorLoop, cleanupBLE },
  { "Tile Detector", nullptr, tileDetectorSetup,     tileDetectorLoop,       cleanupBLE },
  { "RayBan Detector", nullptr, raybanDetectorSetup, raybanDetectorLoop, cleanupBLE },
  { "BLE Spammer",  nullptr, bleSpamSetup,             bleSpamLoop,             cleanupBLE },
  { "Bee Spam",     nullptr, beeSpamSetup,             beeSpamLoop,             cleanupBLE },
  { "Swift Pair",   nullptr, swiftpairSpamSetup,       swiftpairSpamLoop,       cleanupBLE },
  { "Sour Apple",   nullptr, sourappleSetup,           sourappleLoop,           cleanupBLE },
  { "Sour Droid",    nullptr, sourDroidSetup,          sourDroidLoop,          cleanupBLE },
  { "HoneyBLE",      nullptr, honeybleSetup,           honeybleLoop,            cleanupBLE },
  { "BLE Spoofer",  nullptr, bleSpooferSetup,          bleSpooferLoop,          cleanupBLE },
#ifndef HACKBOX_SCOUT_BUILD
  { "BLE MITM",    nullptr, bleMitmSetup,             bleMitmLoop,             cleanupBleMitm },
#endif
  { "Back",         nullptr, nullptr,                  nullptr,                 noCleanup }
};
constexpr int BLE_MENU_SIZE = sizeof(bleMenu) / sizeof(bleMenu[0]);

const MenuItem otherMenu[] = {
#ifndef HACKBOX_SCOUT_BUILD
  { "MouseJack",      nullptr, mousejackSetup,      mousejackLoop,      cleanupMousejack },
  { "Replay Attack",  nullptr, replayAttackSetup,   replayAttackLoop,   cleanupReplayAttack },
#endif
  { "Drone Detector", nullptr, droneDetectorSetup, droneDetectorLoop, cleanupDroneDetector },
  { "Drone Spoofer", nullptr, droneSpooferSetup, droneSpooferLoop, cleanupDroneSpoofer },
  { "Flock Detector", nullptr, flockDetectorSetup, flockDetectorLoop, cleanupFlockDetector },
  { "Device Scout", nullptr, deviceScoutSetup, deviceScoutLoop, cleanupDeviceScout },
  { "AIO Find Mode", nullptr, aioFindModeSetup, aioFindModeLoop, aioFindModeCleanup },
  { "Tracker Sweep", nullptr, trackingSweepSetup, trackingSweepLoop, trackingSweepCleanup },
  { "RSSI Snare",    nullptr, rssiSnareSetup,     rssiSnareLoop,     rssiSnareCleanup },
  { "Mission Mode",  nullptr, missionModeSetup,   missionModeLoop,   missionModeCleanup },
#ifndef HACKBOX_SCOUT_BUILD
  { "HiveMind",     nullptr, hivemindSetup,   hivemindLoop,   cleanupHivemind },
#endif
  { "Sneaker Mode", nullptr, sneakerModeSetup, sneakerModeLoop, sneakerModeCleanup },
  { "Morse Beacon", nullptr, morseBeaconSetup, morseBeaconLoop, morseBeaconCleanup },
  { "Hive Listener",nullptr, hiveListenerSetup, hiveListenerLoop, hiveListenerCleanup },
  { "Scanner",      nullptr, scannerSetup,    scannerLoop,    cleanupRadio },
  { "Analyzer",     nullptr, analyzerSetup,   analyzerLoop,   cleanupRadio },
  { "Packet Logger", nullptr, packetLoggerSetup, packetLoggerLoop, cleanupWiFi },
  { "Probe Logger", nullptr, probeLoggerSetup, probeLoggerLoop, cleanupProbeLogger },
  { "Traffic Monitor", nullptr, trafficPortalSetup, trafficPortalLoop, cleanupTrafficPortal },
  { "Eng Report",   nullptr, engReportSetup,  engReportLoop,  cleanupEngReport },
  { "OTA Update",   nullptr, otaUpdateSetup,  otaUpdateLoop,  cleanupOtaUpdate },
  { "Session Log",  nullptr, sessionLogSetup, sessionLogLoop, sessionLogCleanup },
  { "Setting",      nullptr, settingSetup,    settingLoop,    noCleanup },
  { "About",        nullptr, aboutSetup,      aboutLoop,      aboutCleanup },
  { "Back",         nullptr, nullptr,         nullptr,        noCleanup }
};
constexpr int OTHER_MENU_SIZE = sizeof(otherMenu) / sizeof(otherMenu[0]);

const MenuItem gamesMenu[] = {
  { "HivePet",       nullptr, hivepetSetup,      hivepetLoop,      hivepetCleanup },
  { "Pollen Patrol", nullptr, packetHunterSetup, packetHunterLoop, packetHunterCleanup },
  { "Bee Cipher",    nullptr, beeCipherSetup,    beeCipherLoop,    beeCipherCleanup },
  { "Snake",         nullptr, snakeSetup,        snakeLoop,        snakeCleanup },
  { "PokeHive",      nullptr, pokehiveSetup,     pokehiveLoop,     pokehiveCleanup },
  { "RF Roulette",   nullptr, rfRouletteSetup,   rfRouletteLoop,   rfRouletteCleanup },
  { "Signal Wars",   nullptr, signalWarsSetup,   signalWarsLoop,   signalWarsCleanup },
  { "Back",          nullptr, nullptr,           nullptr,          noCleanup }
};
constexpr int GAMES_MENU_SIZE = sizeof(gamesMenu) / sizeof(gamesMenu[0]);

void enterMenu(AppMenuState st) {
  currentState = st;

  int previousSelection = item_selected;
  const char* previousAppName = nullptr;

  if (item_selected < getVisibleMenuSize()) {
    previousAppName = getVisibleMenuItem(item_selected)->name;
  }

  if (st == APP_MAIN) {
    startHackboxAdvertiser();
  } else {
    stopHackboxAdvertiser();
  }

  switch (st) {
    case APP_MAIN:
      currentMenuItems = mainMenu;
      currentMenuSize  = MAIN_MENU_SIZE;
      break;
    case APP_WIFI:
      currentMenuItems = wifiMenu;
      currentMenuSize  = WIFI_MENU_SIZE;
      break;
    case APP_BLE:
      currentMenuItems = bleMenu;
      currentMenuSize  = BLE_MENU_SIZE;
      break;
    case APP_OTHER:
      currentMenuItems = otherMenu;
      currentMenuSize  = OTHER_MENU_SIZE;
      break;
    case APP_GAMES:
      currentMenuItems = gamesMenu;
      currentMenuSize  = GAMES_MENU_SIZE;
      break;
  }

  item_selected = 0;
  if (previousAppName && st != APP_MAIN) {
    for (int i = 0; i < getVisibleMenuSize(); i++) {
      if (strcmp(getVisibleMenuItem(i)->name, previousAppName) == 0) {
        item_selected = i;
        break;
      }
    }
  }

  needsRedraw = true;
}

void runApp(const MenuItem &mi) {
  if (!mi.setup) return;

  startAppTracking(mi.name);

  if (isGameApp(mi.name)) {
    neoSetStatus(NEO_GAME);
  } else if (isCaptureApp(mi.name)) {
    neoSetStatus(NEO_CAPTURE);
  } else if (isReconApp(mi.name)) {
    neoSetStatus(NEO_RECON);
  } else if (isOffensiveApp(mi.name)) {
    neoSetStatus(NEO_OFFENSIVE);
  } else {
    neoSetStatus(NEO_RECON);  // default: blue breathe
  }

  mi.setup();
  updateLastActivity();
  displayOff = false;
  u8g2.setPowerSave(0);

  if (!mi.loop) return;
  // User entered the app by pressing CENTER. Wait for release so the first
  // loop iteration doesn't see a still-held CENTER and treat it as an in-app
  // action (CENTER is now free for apps to use as OK/confirm).
  while (digitalRead(BUTTON_SEL) == LOW);

  // Global app-exit trigger: LEFT (back/cancel/stop). Edge-triggered so apps
  // that handle LEFT internally and wait for release before returning from
  // their loop don't cause a spurious exit. Any app that does NOT handle LEFT
  // will be exited by this check on the press edge.
  //
  // Apps that need LEFT for an in-app action (e.g. games with a left arrow)
  // can set hackboxAppExitRequested=true to request exit on a different button.
  bool leftPrev = false;
  unsigned long leftExitDebounceTime = 0;
  hackboxAppExitRequested = false;

  while (true) {
    // App-initiated exit request (e.g. snake's CENTER=exit)
    if (hackboxAppExitRequested) {
      hackboxAppExitRequested = false;
      if (mi.cleanup) {
        mi.cleanup();
      }
      break;
    }

    // Check LEFT before checkIdle so a press that would also wake the display
    // is caught as an exit instead of being consumed by wakeDisplay()'s
    // spin-until-released loop.
    if (justPressed(BUTTON_LEFT, leftPrev, leftExitDebounceTime)) {
      while (digitalRead(BUTTON_LEFT) == LOW) delay(5);
      if (mi.cleanup) {
        mi.cleanup();
      }
      break;
    }

    checkIdle();
    updateAppXP();
    neopixelLoop();

    if (anyButtonPressed()) {
      updateLastActivity();
    }

    mi.loop();
  }

  stopBlinking();
  neoSetStatus(NEO_IDLE);
  stopAppTracking();
  u8g2.clearBuffer();
}

void setup() {
  Serial.begin(115200);

  // Structured boot banner so anyone with a serial console can confirm
  // which firmware and build landed on the device after flash.
  Serial.println();
  Serial.println("================================================");
  Serial.printf ("  hackbox firmware %s\n", hackboxVersion);
  Serial.printf ("  built %s %s\n", __DATE__, __TIME__);
  Serial.println("  repo: lordbuffcloud/hackbox");
  Serial.println("================================================");

  themesSetup();
  livestreamSetup();
  livestreamEmit("boot", hackboxVersion);

  neopixelSetup();
  // Visual boot heartbeat: rainbow cycle signals the firmware is alive
  // even before the OLED finishes its splash. Auto-decays back to IDLE
  // once setup completes, so we don't leave it stuck on LEVEL_UP.
  neoSetStatus(NEO_LEVEL_UP);

  SPI.begin();

  int cePins[] = {RADIO_CE_PIN_1, RADIO_CE_PIN_2, RADIO_CE_PIN_3};
  int csnPins[] = {RADIO_CSN_PIN_1, RADIO_CSN_PIN_2, RADIO_CSN_PIN_3};

  for (int i = 0; i < 3; i++) {
    pinMode(cePins[i], OUTPUT);
    pinMode(csnPins[i], OUTPUT);
    digitalWrite(csnPins[i], HIGH);
    digitalWrite(cePins[i], LOW);
  }
  delay(100);

  int radiosFailed = 0;
  bool radioOk[3] = {false, false, false};
  for (int i = 0; i < 3; i++) {
    bool began = radios[i].begin();
    bool connected = radios[i].isChipConnected();
    if (!began || !connected) {
      radiosFailed++;
      Serial.printf(
        "WARNING: NRF24 radio %d failed (begin=%s, chipConnected=%s)\n",
        i + 1,
        began ? "true" : "false",
        connected ? "true" : "false");
      continue;
    }
    radioOk[i] = true;
    Serial.printf("NRF24 radio %d ok\n", i + 1);
    radios[i].setAutoAck(false);
    radios[i].stopListening();
    radios[i].setRetries(0,0);
    radios[i].setPALevel(RF24_PA_MAX, true);
    radios[i].setDataRate(RF24_2MBPS);
    radios[i].setCRCLength(RF24_CRC_DISABLED);
  }

  EEPROM.begin(512);
  // 0xFF means erased/never-written -- fall back to the same 50% default the
  // settings menu uses so a fresh board doesn't blast the OLED at full
  // brightness during the boot splash.
  uint8_t storedBrightness = EEPROM.read(1);
  oledBrightness = (storedBrightness == 0xFF) ? 128 : storedBrightness;

  loadSleepTimeoutFromEEPROM();

  uint8_t continuousScanValue = EEPROM.read(4);
  if (continuousScanValue == 0xFF) {
    continuousScanEnabled = true;
  } else {
    continuousScanEnabled = (continuousScanValue == 1);
  }

  uint8_t privacyModeValue = EEPROM.read(5);
  if (privacyModeValue == 0xFF) {
    privacyModeEnabled = false;
  } else {
    privacyModeEnabled = (privacyModeValue == 1);
  }

  u8g2.begin();
  u8g2.setContrast(oledBrightness);
  u8g2.setBitmapMode(1);

  updateLastActivity();

  u8g2.clearBuffer();
  
  u8g2.setFont(u8g2_font_helvB14_tr);
  const char* title = "hackbox";
  int16_t titleW = u8g2.getUTF8Width(title);
  u8g2.setCursor((128 - titleW) / 2, 16);
  u8g2.print(title);

  u8g2.setFont(u8g2_font_helvR08_tr);
  const char* url = "buzz buzz";
  int16_t urlW = u8g2.getUTF8Width(url);
  u8g2.setCursor((128 - urlW) / 2, 32);
  u8g2.print(url);

  int16_t creditWidth = u8g2.getUTF8Width("the hive is watching");
  int16_t creditX = (128 - creditWidth) / 2;
  u8g2.setCursor(creditX, 50);
  u8g2.print("the hive is watching");

  int16_t verW = u8g2.getUTF8Width(hackboxVersion);
  u8g2.setCursor((128 - verW) / 2, 62);
  u8g2.print(hackboxVersion);

  u8g2.sendBuffer();
  // Skippable splash: hold up to 2s, but any button cuts it short. Faster
  // reboots for power users, same experience on first flash.
  {
    unsigned long splashStart = millis();
    while (millis() - splashStart < 2000) {
      if (anyButtonPressed()) break;
      delay(50);
    }
  }

  // Logo splash: draw the bee logo with the version string overlaid at
  // the bottom so flashers can confirm firmware version without drilling
  // into the About menu.
  u8g2.clearBuffer();
  u8g2.drawXBMP(0, 0, 128, 64, logo_hackbox);
  u8g2.setFont(u8g2_font_5x8_tr);
  int16_t logoVerW = u8g2.getUTF8Width(hackboxVersion);
  u8g2.setCursor(128 - logoVerW - 2, 62);
  u8g2.print(hackboxVersion);
  u8g2.sendBuffer();
  {
    unsigned long splashStart = millis();
    while (millis() - splashStart < 1500) {
      if (anyButtonPressed()) break;
      delay(50);
    }
  }

  // Show radio status warning if any NRF24 failed
  if (radiosFailed > 0) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 12, "NRF24 Radio Warning");
    u8g2.setFont(u8g2_font_5x8_tr);
    // Build "Radios 1,2 failed" so the user knows which specific chips
    // are bad (easier to field-debug than just a count).
    char failList[20] = {0};
    for (int i = 0; i < 3; i++) {
      if (!radioOk[i]) {
        size_t used = strlen(failList);
        snprintf(failList + used, sizeof(failList) - used, "%s%d", used ? "," : "", i + 1);
      }
    }
    char warnBuf[40];
    snprintf(warnBuf, sizeof(warnBuf), "Radio%s %s failed init",
      radiosFailed == 1 ? "" : "s", failList);
    u8g2.drawStr(0, 28, warnBuf);
    u8g2.drawStr(0, 40, "WiFi & BLE tools will work.");
    u8g2.drawStr(0, 50, "RF tools may not function.");
    u8g2.drawStr(0, 62, "SEL or any button to continue");
    u8g2.sendBuffer();
    // Wait for button press, but timeout after 5 seconds (was 10s; most
    // users do not need that long to read four lines of text).
    unsigned long warnStart = millis();
    while (millis() - warnStart < 5000) {
      if (anyButtonPressed()) break;
      delay(50);
    }
  }

  pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
  pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);
  pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
  pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
  pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);

  levelSystemSetup();

  initHackboxAdvertiser();
  startHackboxAdvertiser();

  if (passwordEnabled()) { checkPasswordOnBoot(); }

  enterMenu(APP_MAIN);
  displayMirrorSetup();
  neoSetStatus(NEO_IDLE);
}

void loop() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "MIRROR_ON") {
      displayMirrorEnable(true);
      needsRedraw = true;
    } else if (cmd == "MIRROR_OFF") {
      displayMirrorEnable(false);
    }
  }

  checkIdle();

  if (displayOff) {
    return;
  }

  updateAppXP();
  neopixelLoop();
  updateHackboxAdvertiser();

  bool upNow = (digitalRead(BUTTON_PIN_UP) == LOW);
  bool downNow = (digitalRead(BUTTON_PIN_DOWN) == LOW);
  unsigned long currentTime = millis();

  if (upNow) {
    updateLastActivity();
    if (!upPressed && (currentTime - upDebounceTime) > debounceDelay) {
      upDebounceTime = currentTime;
      if (honeyFloodPush(HONEY_UP)) { honeyFloodRun(); upPressed = upNow; return; }
      if (item_selected > 0) {
        item_selected--;
      } else {
        item_selected = getVisibleMenuSize() - 1;
      }
      upLastMillis = currentTime;
      upNextRepeat = upLastMillis + initialDelay;
      needsRedraw = true;
    } else if (upPressed && currentTime >= upNextRepeat) {
      if (item_selected > 0) {
        item_selected--;
      } else {
        item_selected = getVisibleMenuSize() - 1;
      }
      upNextRepeat += repeatInterval;
      needsRedraw = true;
    }
  }
  upPressed = upNow;

  if (downNow) {
    updateLastActivity();
    if (!downPressed && (currentTime - downDebounceTime) > debounceDelay) {
      downDebounceTime = currentTime;
      if (honeyFloodPush(HONEY_DOWN)) { honeyFloodRun(); downPressed = downNow; return; }
      if (item_selected < getVisibleMenuSize() - 1) {
        item_selected++;
      } else {
        item_selected = 0;
      }
      downLastMillis = currentTime;
      downNextRepeat = downLastMillis + initialDelay;
      needsRedraw = true;
    } else if (downPressed && currentTime >= downNextRepeat) {
      if (item_selected < getVisibleMenuSize() - 1) {
        item_selected++;
      } else {
        item_selected = 0;
      }
      downNextRepeat += repeatInterval;
      needsRedraw = true;
    }
  }
  downPressed = downNow;

  if (justPressed(BUTTON_SEL, selPrev, selDebounceTime)) {
    updateLastActivity();
    if (honeyFloodPush(HONEY_SELECT)) { honeyFloodRun(); return; }
    if (currentState != APP_LEVEL) {
      const MenuItem *sel = getVisibleMenuItem(item_selected);
      if (currentState == APP_MAIN) {
        if (strcmp(sel->name, "WiFi") == 0) enterMenu(APP_WIFI);
        else if (strcmp(sel->name, "BLE") == 0) enterMenu(APP_BLE);
        else if (strcmp(sel->name, "Other") == 0) enterMenu(APP_OTHER);
        else if (strcmp(sel->name, "Games") == 0) enterMenu(APP_GAMES);
      } else {
        if (strcmp(sel->name, "Back") == 0) {
          enterMenu(APP_MAIN);
        } else {
          runApp(*sel);
          needsRedraw = true;
        }
      }
    }
  }

  if (justPressed(BUTTON_LEFT, leftPrev, leftDebounceTime)) {
    updateLastActivity();
    if (honeyFloodPush(HONEY_LEFT)) { honeyFloodRun(); return; }
    if (currentState == APP_LEVEL ||
        currentState == APP_BLE   ||
        currentState == APP_WIFI  ||
        currentState == APP_OTHER ||
        currentState == APP_GAMES) {
      enterMenu(APP_MAIN);
    }
  }

  if (justPressed(BUTTON_RIGHT, rightPrev, rightDebounceTime)) {
    updateLastActivity();
    if (honeyFloodPush(HONEY_RIGHT)) { honeyFloodRun(); return; }
    if (currentState == APP_MAIN) {
      currentState = APP_LEVEL;
      levelSystemSetup();
      needsRedraw = true;
    }
  }

  if (currentState == APP_LEVEL) {
    levelSystemLoop();
  } else {
    if (currentState == APP_MAIN) {
      updateHackboxAdvertiser();
    }

    if (needsRedraw) {
      u8g2.clearBuffer();

      int start;
      if (item_selected == 0) start = 0;
      else if (item_selected == getVisibleMenuSize() - 1) start = max(0, getVisibleMenuSize() - 3);
      else start = item_selected - 1;

      int highlight = item_selected - start;

      int selectionY = 6 + (highlight * (ITEM_HEIGHT + ITEM_SPACING));
      drawSelection(SELECTION_X, selectionY, SELECTION_WIDTH, ITEM_HEIGHT, true);

      for (int i = 0; i < 3; i++) {
        int idx = start + i;
        if (idx < getVisibleMenuSize()) {
          const MenuItem *item = getVisibleMenuItem(idx);
          int itemY = 6 + (i * (ITEM_HEIGHT + ITEM_SPACING));
          int textY = itemY + 11;

          u8g2.setFont(u8g2_font_helvR08_tr);
          u8g2.drawStr(TEXT_X, textY, item->name);

          if (item->icon) {
            int iconY = itemY;
            u8g2.drawXBMP(ICON_X, iconY, 16, 16, item->icon);
          }
        }
      }

      if (currentState == APP_MAIN) {
        u8g2.setFont(u8g2_font_5x8_tr);
        char levelStr[16];
        snprintf(levelStr, sizeof(levelStr), "Level %d", getCurrentLevel());
        int levelWidth = u8g2.getUTF8Width(levelStr);
        u8g2.drawStr(128 - levelWidth, 8, levelStr);

        const char* rightHint = "Level Menu ->";
        int rightHintWidth = u8g2.getUTF8Width(rightHint);
        u8g2.drawStr(128 - rightHintWidth, 64, rightHint);
      } else {
        int visibleCount = getVisibleMenuSize();
        if (start > 0) {
          u8g2.drawTriangle(122, 5, 127, 5, 124, 1);
        }
        if (start + 3 < visibleCount) {
          u8g2.drawTriangle(122, 58, 127, 58, 124, 62);
        }
      }

      u8g2.sendBuffer();
      displayMirrorSend(u8g2);
      needsRedraw = false;
    }
  }
}
