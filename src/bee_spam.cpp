/*
    hackbox
    hackbox custom firmware

    Bee Emoji BLE Spam - floods nearby devices with bee-themed
    BLE device names using bee emojis and honeycomb text
*/

#include "../include/bee_spam.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include <Arduino.h>
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

static bool isAdvertising = false;
static uint32_t spamCount = 0;
static unsigned long lastDraw = 0;
static bool needsRedraw = true;

static esp_ble_adv_params_t adv_params = {
    .adv_int_min = 0x20,
    .adv_int_max = 0x40,
    .adv_type = ADV_TYPE_IND,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY
};

// Bee-themed device names with emojis
const char* beeNames[] = {
    "\xF0\x9F\x90\x9D hackbox",                    // bee hackbox
    "\xF0\x9F\x90\x9D\xF0\x9F\x90\x9D\xF0\x9F\x90\x9D", // bee bee bee
    "\xF0\x9F\x8D\xAF Honey Trap",                 // honey pot Honey Trap
    "\xF0\x9F\x90\x9D BUZZ BUZZ",                  // bee BUZZ BUZZ
    "\xF0\x9F\x90\x9D Queen Bee",                  // bee Queen Bee
    "\xF0\x9F\x8D\xAF\xF0\x9F\x90\x9D HoneyBee",  // honey bee HoneyBee
    "\xF0\x9F\x90\x9D The Hive",                   // bee The Hive
    "\xF0\x9F\x90\x9D Bee Signal",                 // bee Bee Signal
    "\xF0\x9F\x90\x9D Save the Bees",              // bee Save the Bees
    "\xF0\x9F\x90\x9D\xF0\x9F\x92\x9B BeeMyVal",  // bee yellow heart
    "\xF0\x9F\x90\x9D Pollinator",                 // bee Pollinator
    "\xF0\x9F\x8C\xBB\xF0\x9F\x90\x9D Sunflower", // sunflower bee
    "\xF0\x9F\x90\x9D Hivemind",                   // bee Hivemind
    "\xF0\x9F\x90\x9D Drone #42",                  // bee Drone
    "\xF0\x9F\x90\x9D Worker Bee",                 // bee Worker
    "\xF0\x9F\x8D\xAF Sweet as Honey",             // honey
    "\xF0\x9F\x90\x9D\xE2\x9A\xA1 ZapBee",        // bee zap
    "\xF0\x9F\x90\x9D Bee Careful",                // bee Bee Careful
    "\xF0\x9F\x90\x9D Bee Happy",                  // bee Bee Happy
    "\xF0\x9F\x90\x9D Bee Yourself",               // bee Bee Yourself
    "\xF0\x9F\x90\x9D\xF0\x9F\x94\xA5 Fire Bee",  // bee fire
    "\xF0\x9F\x90\x9D Bee-ware!",                  // bee Bee-ware
    "\xF0\x9F\x90\x9D Bee Gone",                   // bee Bee Gone
    "\xF0\x9F\x90\x9D Let It Bee",                 // bee Let It Bee
    "\xF0\x9F\xA7\x8B\xF0\x9F\x90\x9D Bee Tea",   // boba bee
    "\xF0\x9F\x90\x9D CK42X.COM",                  // bee CK42X
    "\xF0\x9F\x90\x9D\xF0\x9F\x90\x9D Swarm",     // bee bee Swarm
    "\xF0\x9F\x90\x9D Royal Jelly",                // bee Royal Jelly
    "\xF0\x9F\x90\x9D Nectar Net",                 // bee Nectar
    "\xF0\x9F\x90\x9D\xF0\x9F\x91\x91 King Bee"   // bee crown
};
const int BEE_NAME_COUNT = 30;

void advertise(const char* name) {
    if (isAdvertising) {
        esp_ble_gap_stop_advertising();
        delay(5);
        isAdvertising = false;
    }

    // Random MAC
    esp_bd_addr_t addr;
    for (int i = 0; i < 6; i++) addr[i] = random(256);
    addr[0] = (addr[0] & 0x3F) | 0xC0; // Random static address
    esp_ble_gap_set_rand_addr(addr);
    delay(5);

    // Build advertisement packet
    uint8_t nameLen = strlen(name);
    // Hard cap: 3 (flags) + 2 (name AD header) + nameLen must fit in pkt[31].
    // Leave headroom for the optional HID UUID (4) and TX Power (3) AD records.
    if (nameLen > 19) nameLen = 19;
    uint8_t pkt[31];
    uint8_t p = 0;

    // Flags
    pkt[p++] = 2;
    pkt[p++] = 0x01;
    pkt[p++] = 0x06;

    // Complete Local Name
    pkt[p++] = nameLen + 1;
    pkt[p++] = 0x09;
    memcpy(&pkt[p], name, nameLen);
    p += nameLen;

    // Service UUID (HID - makes it show up on more devices)
    if (p + 4 <= 31) {
        pkt[p++] = 3;
        pkt[p++] = 0x02;
        pkt[p++] = 0x12;
        pkt[p++] = 0x18;
    }

    // TX Power
    if (p + 3 <= 31) {
        pkt[p++] = 2;
        pkt[p++] = 0x0A;
        pkt[p++] = 0x00;
    }

    esp_ble_gap_config_adv_data_raw(pkt, p);
    delay(5);
    esp_ble_gap_start_advertising(&adv_params);
    isAdvertising = true;
}

void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "BEE SPAM");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawHLine(0, 12, 128);

    char buf[32];
    snprintf(buf, sizeof(buf), "Sent: %lu", (unsigned long)spamCount);
    u8g2.drawStr(0, 24, buf);

    // Show last few names being spammed
    int showStart = (spamCount > 3) ? (spamCount % BEE_NAME_COUNT) : 0;
    for (int i = 0; i < 3; i++) {
        int idx = (showStart + i) % BEE_NAME_COUNT;
        // Can't render emoji on OLED, show ASCII portion
        const char* name = beeNames[idx];
        // Skip leading UTF-8 emoji bytes to find ASCII text
        int offset = 0;
        while (name[offset] && (uint8_t)name[offset] >= 0x80) offset++;
        while (name[offset] == ' ') offset++;
        char display[22];
        snprintf(display, sizeof(display), "> %.20s", &name[offset]);
        u8g2.drawStr(0, 34 + (i * 9), display);
    }

    u8g2.drawStr(0, 62, "L=Back");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

}

void beeSpamSetup() {
    randomSeed((uint32_t)esp_random());
    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    initBLE();
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
    esp_ble_gap_register_callback([](esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param){});

    isAdvertising = false;
    spamCount = 0;
    needsRedraw = true;
    lastDraw = 0;

    drawScreen();
}

void beeSpamLoop() {
    unsigned long now = millis();
    static unsigned long lastSpam = 0;

    // Spam a bee name every 50ms — gives BLE stack time to process
    if (now - lastSpam >= 50) {
        lastSpam = now;
        int idx = spamCount % BEE_NAME_COUNT;
        advertise(beeNames[idx]);
        spamCount++;
    }

    if (now - lastDraw >= 500) {
        lastDraw = now;
        drawScreen();
    }
}
