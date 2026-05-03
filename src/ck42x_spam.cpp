/*
    CK42X.COM Beacon Spammer
    Custom tool for hackbox
*/

#include "../include/ck42x_spam.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "esp_wifi.h"
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

namespace {

const uint8_t channels[] = {1, 6, 11};
uint8_t channelIndex = 0;
uint8_t batchesSinceSwitch = 0;
uint32_t beaconsSent = 0;
unsigned long lastBatch = 0;
bool needsRedraw = true;

const int AP_COUNT = 30;
uint8_t apMACs[AP_COUNT][6];
uint16_t apSeqNums[AP_COUNT];
char apSSIDs[AP_COUNT][33];
uint8_t apSSIDLens[AP_COUNT];

const char* ssidVariants[] = {
  "CK42X.COM",
  "CK42X.COM Hive",
  "CK42X.COM BeeNet",
  "CK42X.COM Honeycomb",
  "CK42X.COM Queen Bee",
  "CK42X.COM Buzz",
  "CK42X.COM Nectar",
  "CK42X.COM Swarm",
  "CK42X.COM Pollen",
  "CK42X.COM Apiary",
  "CK42X.COM Bee Signal",
  "CK42X.COM Drone",
  "CK42X.COM Royal Jelly",
  "CK42X.COM Beekeeper",
  "CK42X.COM Waggle",
  "CK42X.COM Honey",
  "CK42X.COM Colony",
  "CK42X.COM Beeline",
  "CK42X.COM Bumble",
  "CK42X.COM Hexagon",
  "CK42X.COM Propolis",
  "CK42X.COM Worker Bee",
  "CK42X.COM Bee Kind",
  "CK42X.COM Pollinator",
  "CK42X.COM Meadow",
  "CK42X.COM Beeswax",
  "CK42X.COM Flower Power",
  "CK42X.COM Hivemind",
  "CK42X.COM Busy Bee",
  "CK42X.COM Save the Bees"
};

void initAPPool() {
  for (int i = 0; i < AP_COUNT; i++) {
    for (int j = 0; j < 6; j++) apMACs[i][j] = random(256);
    apMACs[i][0] |= 0x02;
    apMACs[i][0] &= 0xFE;
    apSeqNums[i] = 0;
    strncpy(apSSIDs[i], ssidVariants[i], 32);
    apSSIDs[i][32] = '\0';
    apSSIDLens[i] = strlen(apSSIDs[i]);
  }
}

void sendBeacon(int apIndex, uint8_t channel) {
  uint8_t frame[128];
  memset(frame, 0, sizeof(frame));
  int pos = 0;

  // 802.11 Header
  frame[pos++] = 0x80; frame[pos++] = 0x00; // Beacon
  frame[pos++] = 0x00; frame[pos++] = 0x00; // Duration

  // Destination: broadcast
  memset(&frame[pos], 0xFF, 6); pos += 6;

  // Source MAC ,persistent per fake AP
  memcpy(&frame[pos], apMACs[apIndex], 6); pos += 6;

  // BSSID ,same as source
  memcpy(&frame[pos], apMACs[apIndex], 6); pos += 6;

  // Sequence number ,increment like a real AP
  apSeqNums[apIndex] += 16; // Seq numbers increment by 1 in the upper 12 bits
  frame[pos++] = apSeqNums[apIndex] & 0xFF;
  frame[pos++] = (apSeqNums[apIndex] >> 8) & 0xFF;

  // Timestamp
  uint64_t timestamp = (uint64_t)esp_timer_get_time();
  memcpy(&frame[pos], &timestamp, 8); pos += 8;

  // Beacon interval (100 TU)
  frame[pos++] = 0x64;
  frame[pos++] = 0x00;

  // Capability: ESS
  frame[pos++] = 0x01;
  frame[pos++] = 0x04;

  // SSID tag
  frame[pos++] = 0x00;
  frame[pos++] = apSSIDLens[apIndex];
  memcpy(&frame[pos], apSSIDs[apIndex], apSSIDLens[apIndex]); pos += apSSIDLens[apIndex];

  // Supported rates
  frame[pos++] = 0x01; frame[pos++] = 0x08;
  frame[pos++] = 0x82; frame[pos++] = 0x84;
  frame[pos++] = 0x8b; frame[pos++] = 0x96;
  frame[pos++] = 0x0c; frame[pos++] = 0x18;
  frame[pos++] = 0x30; frame[pos++] = 0x48;

  // DS Parameter (channel)
  frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = channel;

  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_80211_tx(WIFI_IF_AP, frame, pos, false);
}

void drawDisplay() {
  u8g2.clearBuffer();

  u8g2.setFont(u8g2_font_helvB14_tr);
  u8g2.drawStr(12, 16, "CK42X.COM");

  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(0, 30, "--- BEACON SPAM ---");

  char buf[32];
  snprintf(buf, sizeof(buf), "Beacons: %lu", (unsigned long)beaconsSent);
  u8g2.drawStr(0, 44, buf);

  snprintf(buf, sizeof(buf), "Ch: 1, 6, 11");
  u8g2.setFont(u8g2_font_5x8_tr);
  u8g2.drawStr(0, 54, buf);

  u8g2.drawStr(0, 64, "L=Exit");
  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

} // namespace

void ck42xSpamSetup() {
  randomSeed((uint32_t)esp_random());

  initWiFi(WIFI_MODE_AP);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  channelIndex = 0;
  batchesSinceSwitch = 0;
  beaconsSent = 0;
  lastBatch = 0;
  needsRedraw = true;

  initAPPool();
  drawDisplay();
}

void ck42xSpamLoop() {
  unsigned long now = millis();

  if (now - lastBatch >= 50) {
    lastBatch = now;

    uint8_t ch = channels[channelIndex];
    // Cycle through all 30 fake APs, sending one beacon each
    for (int i = 0; i < AP_COUNT; i++) {
      sendBeacon(i, ch);
      beaconsSent++;
      delayMicroseconds(100);
    }

    if (++batchesSinceSwitch >= 4) {
      batchesSinceSwitch = 0;
      channelIndex = (channelIndex + 1) % 3;
    }

    needsRedraw = true;
  }

  if (needsRedraw) {
    needsRedraw = false;
    drawDisplay();
  }
}
