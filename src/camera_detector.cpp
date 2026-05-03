/*
    hackbox
    hackbox custom firmware

    Camera Detector

    Passive WiFi camera fingerprinting using OUI/MA-M/MA-S prefixes,
    camera-name SSID/probe heuristics, and station traffic behavior.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#include "../include/camera_detector.h"
#include "../include/about.h"
#include "../include/display_mirror.h"
#include "../include/neopixel.h"
#include "../include/pindefs.h"
#include "../include/radio_manager.h"
#include "../include/setting.h"
#include "esp_wifi.h"
#include <algorithm>
#include <ctype.h>
#include <string.h>
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

enum CameraMode : uint8_t {
    MODE_SCAN = 0,
    MODE_DETAIL,
    MODE_LOCK
};

enum EvidenceBits : uint8_t {
    EVIDENCE_PREFIX  = 1 << 0,
    EVIDENCE_NAME    = 1 << 1,
    EVIDENCE_TRAFFIC = 1 << 2,
    EVIDENCE_SETUP   = 1 << 3
};

struct VendorPrefix {
    uint64_t prefix;
    uint8_t bits;
    const char *brand;
    uint8_t score;
};

struct KeywordRule {
    const char *needle;
    const char *brand;
    uint8_t score;
};

struct CameraDevice {
    uint8_t mac[6];
    const char *brand;
    uint8_t prefixScore;
    uint8_t keywordScore;
    uint8_t flowScore;
    uint8_t confidence;
    uint8_t evidence;
    int8_t rssi;
    uint8_t channel;
    bool hasSsid;
    char ssid[17];
    bool seenAsAp;
    bool seenAsStation;
    uint16_t mgmtFrames;
    uint16_t dataFrames;
    uint16_t uplinkFrames;
    uint16_t downlinkFrames;
    uint32_t dataBytes;
    uint16_t maxFrameLen;
    unsigned long firstSeen;
    unsigned long lastSeen;
};

// Prefixes were seeded from the IEEE public MA-L/MA-M/MA-S registries on
// 2026-04-24. High scores are camera-specific vendors; lower scores are
// useful broad vendors that need traffic/name evidence to rank as cameras.
const VendorPrefix CAMERA_PREFIXES[] = {
    { 0x00B463ULL, 24, "Ring", 72 },
    { 0x187F88ULL, 24, "Ring", 72 },
    { 0x242BD6ULL, 24, "Ring", 72 },
    { 0x343EA4ULL, 24, "Ring", 72 },
    { 0x50E467ULL, 24, "Ring", 72 },
    { 0x54E019ULL, 24, "Ring", 72 },
    { 0x5C475EULL, 24, "Ring", 72 },
    { 0x649A63ULL, 24, "Ring", 72 },
    { 0x90486CULL, 24, "Ring", 72 },
    { 0x9873C4ULL, 24, "Ring", 72 },
    { 0x9C7613ULL, 24, "Ring", 72 },
    { 0xAC9FC3ULL, 24, "Ring", 72 },
    { 0xC4DBADULL, 24, "Ring", 72 },
    { 0xCC3BFBULL, 24, "Ring", 72 },
    { 0x3CA070ULL, 24, "Blink", 72 },
    { 0x70AD43ULL, 24, "Blink", 72 },
    { 0x741348ULL, 24, "Blink", 72 },
    { 0x74AB93ULL, 24, "Blink", 72 },
    { 0xF074C1ULL, 24, "Blink", 72 },
    { 0x18B430ULL, 24, "Nest", 72 },
    { 0x641666ULL, 24, "Nest", 72 },
    { 0x486264ULL, 24, "Arlo", 72 },
    { 0xA41162ULL, 24, "Arlo", 72 },
    { 0xFC9C98ULL, 24, "Arlo", 72 },
    { 0x2CAA8EULL, 24, "Wyze", 72 },
    { 0x7C78B2ULL, 24, "Wyze", 72 },
    { 0x80482CULL, 24, "Wyze", 72 },
    { 0xD03F27ULL, 24, "Wyze", 72 },
    { 0xF0C88BULL, 24, "Wyze", 72 },
    { 0xA4DA222ULL, 28, "Wyze", 72 },
    { 0xEC71DBULL, 24, "Reolink", 72 },
    { 0x00408CULL, 24, "Axis", 72 },
    { 0xACCC8EULL, 24, "Axis", 72 },
    { 0xB8A44FULL, 24, "Axis", 72 },
    { 0xE82725ULL, 24, "Axis", 72 },
    { 0x00651EULL, 24, "Amcrest", 72 },
    { 0x9C8ECDULL, 24, "Amcrest", 72 },
    { 0xA06032ULL, 24, "Amcrest", 72 },
    { 0x3446632ULL, 28, "Amcrest", 72 },
    { 0x00BC99ULL, 24, "Hikvision", 72 },
    { 0x040312ULL, 24, "Hikvision", 72 },
    { 0x04EECDULL, 24, "Hikvision", 72 },
    { 0x083BC1ULL, 24, "Hikvision", 72 },
    { 0x085411ULL, 24, "Hikvision", 72 },
    { 0x08A189ULL, 24, "Hikvision", 72 },
    { 0x08CC81ULL, 24, "Hikvision", 72 },
    { 0x0C75D2ULL, 24, "Hikvision", 72 },
    { 0x1012FBULL, 24, "Hikvision", 72 },
    { 0x1868CBULL, 24, "Hikvision", 72 },
    { 0x188025ULL, 24, "Hikvision", 72 },
    { 0x240F9BULL, 24, "Hikvision", 72 },
    { 0x2428FDULL, 24, "Hikvision", 72 },
    { 0x2432AEULL, 24, "Hikvision", 72 },
    { 0x244845ULL, 24, "Hikvision", 72 },
    { 0x2857BEULL, 24, "Hikvision", 72 },
    { 0x2CA59CULL, 24, "Hikvision", 72 },
    { 0x340962ULL, 24, "Hikvision", 72 },
    { 0x3C1BF8ULL, 24, "Hikvision", 72 },
    { 0x40ACBFULL, 24, "Hikvision", 72 },
    { 0x4419B6ULL, 24, "Hikvision", 72 },
    { 0x4447CCULL, 24, "Hikvision", 72 },
    { 0x44A642ULL, 24, "Hikvision", 72 },
    { 0x48785BULL, 24, "Hikvision", 72 },
    { 0x4C1F86ULL, 24, "Hikvision", 72 },
    { 0x4C62DFULL, 24, "Hikvision", 72 },
    { 0x4CBD8FULL, 24, "Hikvision", 72 },
    { 0x4CF5DCULL, 24, "Hikvision", 72 },
    { 0x50E538ULL, 24, "Hikvision", 72 },
    { 0x548C81ULL, 24, "Hikvision", 72 },
    { 0x54C415ULL, 24, "Hikvision", 72 },
    { 0x5803FBULL, 24, "Hikvision", 72 },
    { 0x5850EDULL, 24, "Hikvision", 72 },
    { 0x5C345BULL, 24, "Hikvision", 72 },
    { 0x64DB8BULL, 24, "Hikvision", 72 },
    { 0x686DBCULL, 24, "Hikvision", 72 },
    { 0x743FC2ULL, 24, "Hikvision", 72 },
    { 0x80489FULL, 24, "Hikvision", 72 },
    { 0x807C62ULL, 24, "Hikvision", 72 },
    { 0x80BEAFULL, 24, "Hikvision", 72 },
    { 0x80F5AEULL, 24, "Hikvision", 72 },
    { 0x849459ULL, 24, "Hikvision", 72 },
    { 0x849A40ULL, 24, "Hikvision", 72 },
    { 0x88DE39ULL, 24, "Hikvision", 72 },
    { 0x8C22D2ULL, 24, "Hikvision", 72 },
    { 0x8CE748ULL, 24, "Hikvision", 72 },
    { 0x94E1ACULL, 24, "Hikvision", 72 },
    { 0x988B0AULL, 24, "Hikvision", 72 },
    { 0x989DE5ULL, 24, "Hikvision", 72 },
    { 0x98DF82ULL, 24, "Hikvision", 72 },
    { 0x98F112ULL, 24, "Hikvision", 72 },
    { 0xA0FF0CULL, 24, "Hikvision", 72 },
    { 0xA41437ULL, 24, "Hikvision", 72 },
    { 0xA42902ULL, 24, "Hikvision", 72 },
    { 0xA44BD9ULL, 24, "Hikvision", 72 },
    { 0xA4A459ULL, 24, "Hikvision", 72 },
    { 0xA4D5C2ULL, 24, "Hikvision", 72 },
    { 0xACB92FULL, 24, "Hikvision", 72 },
    { 0xACCB51ULL, 24, "Hikvision", 72 },
    { 0xB4A382ULL, 24, "Hikvision", 72 },
    { 0xBC5E33ULL, 24, "Hikvision", 72 },
    { 0xBC9B5EULL, 24, "Hikvision", 72 },
    { 0xBCAD28ULL, 24, "Hikvision", 72 },
    { 0xBCBAC2ULL, 24, "Hikvision", 72 },
    { 0xC0517EULL, 24, "Hikvision", 72 },
    { 0xC056E3ULL, 24, "Hikvision", 72 },
    { 0xC06DEDULL, 24, "Hikvision", 72 },
    { 0xC42F90ULL, 24, "Hikvision", 72 },
    { 0xC8A702ULL, 24, "Hikvision", 72 },
    { 0xCC13F3ULL, 24, "Hikvision", 72 },
    { 0xD4E853ULL, 24, "Hikvision", 72 },
    { 0xDC07F8ULL, 24, "Hikvision", 72 },
    { 0xDCD26AULL, 24, "Hikvision", 72 },
    { 0xE0BAADULL, 24, "Hikvision", 72 },
    { 0xE0CA3CULL, 24, "Hikvision", 72 },
    { 0xE0DF13ULL, 24, "Hikvision", 72 },
    { 0xE4D58BULL, 24, "Hikvision", 72 },
    { 0xE8A0EDULL, 24, "Hikvision", 72 },
    { 0xECA971ULL, 24, "Hikvision", 72 },
    { 0xECC89CULL, 24, "Hikvision", 72 },
    { 0xF84DFCULL, 24, "Hikvision", 72 },
    { 0xFC9FFDULL, 24, "Hikvision", 72 },
    { 0x08EDEDULL, 24, "Dahua", 72 },
    { 0x14A78BULL, 24, "Dahua", 72 },
    { 0x24526AULL, 24, "Dahua", 72 },
    { 0x30DDAAULL, 24, "Dahua", 72 },
    { 0x38AF29ULL, 24, "Dahua", 72 },
    { 0x3CE36BULL, 24, "Dahua", 72 },
    { 0x3CEF8CULL, 24, "Dahua", 72 },
    { 0x407AA4ULL, 24, "Dahua", 72 },
    { 0x4C11BFULL, 24, "Dahua", 72 },
    { 0x4C99E8ULL, 24, "Dahua", 72 },
    { 0x5CF51AULL, 24, "Dahua", 72 },
    { 0x64FD29ULL, 24, "Dahua", 72 },
    { 0x6C1C71ULL, 24, "Dahua", 72 },
    { 0x74C929ULL, 24, "Dahua", 72 },
    { 0x8CE9B4ULL, 24, "Dahua", 72 },
    { 0x9002A9ULL, 24, "Dahua", 72 },
    { 0x98F9CCULL, 24, "Dahua", 72 },
    { 0x9C1463ULL, 24, "Dahua", 72 },
    { 0xA0BD1DULL, 24, "Dahua", 72 },
    { 0xA8CA87ULL, 24, "Dahua", 72 },
    { 0xB44C3BULL, 24, "Dahua", 72 },
    { 0xBC325FULL, 24, "Dahua", 72 },
    { 0xC0395AULL, 24, "Dahua", 72 },
    { 0xC4AAC4ULL, 24, "Dahua", 72 },
    { 0xD4430EULL, 24, "Dahua", 72 },
    { 0xE02EFEULL, 24, "Dahua", 72 },
    { 0xE0508BULL, 24, "Dahua", 72 },
    { 0xE4246CULL, 24, "Dahua", 72 },
    { 0xF4B1C2ULL, 24, "Dahua", 72 },
    { 0xF8CE07ULL, 24, "Dahua", 72 },
    { 0xFC5F49ULL, 24, "Dahua", 72 },
    { 0xFCB69DULL, 24, "Dahua", 72 },
    { 0x0CA64CULL, 24, "EZVIZ", 72 },
    { 0x20BBBCULL, 24, "EZVIZ", 72 },
    { 0x34C6DDULL, 24, "EZVIZ", 72 },
    { 0x54D60DULL, 24, "EZVIZ", 72 },
    { 0x588FCFULL, 24, "EZVIZ", 72 },
    { 0x64244DULL, 24, "EZVIZ", 72 },
    { 0x64F2FBULL, 24, "EZVIZ", 72 },
    { 0x78A6A0ULL, 24, "EZVIZ", 72 },
    { 0x78C1AEULL, 24, "EZVIZ", 72 },
    { 0x94EC13ULL, 24, "EZVIZ", 72 },
    { 0xAC1C26ULL, 24, "EZVIZ", 72 },
    { 0xEC97E0ULL, 24, "EZVIZ", 72 },
    { 0xF47018ULL, 24, "EZVIZ", 72 },
    { 0xFC2422ULL, 24, "EZVIZ", 72 },
    { 0x48EA63ULL, 24, "Uniview", 72 },
    { 0x6CF17EULL, 24, "Uniview", 72 },
    { 0x88263FULL, 24, "Uniview", 72 },
    { 0xC47905ULL, 24, "Uniview", 72 },
    { 0x0002D1ULL, 24, "Vivotek", 72 },
    { 0x001F54ULL, 24, "Lorex", 72 },
    { 0x000131ULL, 24, "Bosch", 72 },
    { 0x000463ULL, 24, "Bosch", 72 },
    { 0x50FACB9ULL, 28, "Bosch", 72 },
    { 0x0013E2ULL, 24, "GeoVision", 72 },
    { 0x0003C5ULL, 24, "Mobotix", 72 },
    { 0x045C06ULL, 24, "Zmodo", 72 },
    { 0xF85128ULL, 24, "SimpliSafe", 72 },
    { 0xBC51FEULL, 24, "Swann", 72 },
    { 0x701AD5ULL, 24, "Avigilon", 62 },
    { 0x44B423ULL, 24, "Hanwha", 62 },
    { 0x8C1D55ULL, 24, "Hanwha", 62 },
    { 0xE43022ULL, 24, "Hanwha", 62 },
    { 0x5870C6ULL, 24, "YI", 62 },
    { 0x70B3D5C4BULL, 36, "Eufy", 60 },
    { 0x00156DULL, 24, "Ubiquiti", 34 },
    { 0x002722ULL, 24, "Ubiquiti", 34 },
    { 0x0418D6ULL, 24, "Ubiquiti", 34 },
    { 0x0CEA14ULL, 24, "Ubiquiti", 34 },
    { 0x18E829ULL, 24, "Ubiquiti", 34 },
    { 0x1C0B8BULL, 24, "Ubiquiti", 34 },
    { 0x1C6A1BULL, 24, "Ubiquiti", 34 },
    { 0x245A4CULL, 24, "Ubiquiti", 34 },
    { 0x24A43CULL, 24, "Ubiquiti", 34 },
    { 0x28704EULL, 24, "Ubiquiti", 34 },
    { 0x44D9E7ULL, 24, "Ubiquiti", 34 },
    { 0x58D61FULL, 24, "Ubiquiti", 34 },
    { 0x602232ULL, 24, "Ubiquiti", 34 },
    { 0x687251ULL, 24, "Ubiquiti", 34 },
    { 0x68D79AULL, 24, "Ubiquiti", 34 },
    { 0x6C63F8ULL, 24, "Ubiquiti", 34 },
    { 0x70A741ULL, 24, "Ubiquiti", 34 },
    { 0x7483C2ULL, 24, "Ubiquiti", 34 },
    { 0x74ACB9ULL, 24, "Ubiquiti", 34 },
    { 0x74F92CULL, 24, "Ubiquiti", 34 },
    { 0x74FA29ULL, 24, "Ubiquiti", 34 },
    { 0x784558ULL, 24, "Ubiquiti", 34 },
    { 0x788A20ULL, 24, "Ubiquiti", 34 },
    { 0x802AA8ULL, 24, "Ubiquiti", 34 },
    { 0x847848ULL, 24, "Ubiquiti", 34 },
    { 0x8C3066ULL, 24, "Ubiquiti", 34 },
    { 0x8CEDE1ULL, 24, "Ubiquiti", 34 },
    { 0x9041B2ULL, 24, "Ubiquiti", 34 },
    { 0x942A6FULL, 24, "Ubiquiti", 34 },
    { 0x9C05D6ULL, 24, "Ubiquiti", 34 },
    { 0xA4F8FFULL, 24, "Ubiquiti", 34 },
    { 0xA89C6CULL, 24, "Ubiquiti", 34 },
    { 0xAC8BA9ULL, 24, "Ubiquiti", 34 },
    { 0xB4FBE4ULL, 24, "Ubiquiti", 34 },
    { 0xCC35D9ULL, 24, "Ubiquiti", 34 },
    { 0xD021F9ULL, 24, "Ubiquiti", 34 },
    { 0xD489C1ULL, 24, "Ubiquiti", 34 },
    { 0xD8B370ULL, 24, "Ubiquiti", 34 },
    { 0xDC9FDBULL, 24, "Ubiquiti", 34 },
    { 0xE063DAULL, 24, "Ubiquiti", 34 },
    { 0xE43883ULL, 24, "Ubiquiti", 34 },
    { 0xF09FC2ULL, 24, "Ubiquiti", 34 },
    { 0xF492BFULL, 24, "Ubiquiti", 34 },
    { 0xF4E2C6ULL, 24, "Ubiquiti", 34 },
    { 0xFCECDAULL, 24, "Ubiquiti", 34 },
};

const KeywordRule CAMERA_KEYWORDS[] = {
    { "ringcam", "Ring", 64 },
    { "ring-", "Ring", 58 },
    { "ring_", "Ring", 58 },
    { "ring", "Ring", 54 },
    { "blink", "Blink", 60 },
    { "sync module", "Blink", 58 },
    { "nest", "Nest", 58 },
    { "dropcam", "Nest", 62 },
    { "arlo", "Arlo", 58 },
    { "wyzecam", "Wyze", 64 },
    { "wyze", "Wyze", 60 },
    { "reolink", "Reolink", 62 },
    { "eufy", "Eufy", 60 },
    { "anker", "Eufy", 44 },
    { "hikvision", "Hikvision", 62 },
    { "hikwifi", "Hikvision", 58 },
    { "ezviz", "EZVIZ", 62 },
    { "dahua", "Dahua", 62 },
    { "imou", "Dahua", 58 },
    { "axis", "Axis", 58 },
    { "amcrest", "Amcrest", 62 },
    { "lorex", "Lorex", 58 },
    { "uniview", "Uniview", 58 },
    { "vivotek", "Vivotek", 58 },
    { "foscam", "Foscam", 58 },
    { "zmodo", "Zmodo", 58 },
    { "swann", "Swann", 58 },
    { "simplisafe", "SimpliSafe", 58 },
    { "tapo", "TP-Link", 56 },
    { "kasa", "TP-Link", 52 },
    { "unifi", "Ubiquiti", 54 },
    { "ubnt", "Ubiquiti", 46 },
    { "uvc", "Ubiquiti", 46 },
    { "protect", "Ubiquiti", 44 },
    { "xiaoyi", "YI", 58 },
    { "yi home", "YI", 58 },
    { "yicam", "YI", 54 },
    { "onvif", "ONVIF", 52 },
    { "ipcam", "IPCam", 48 },
    { "ipc-", "IPCam", 46 },
    { "ip camera", "IPCam", 48 },
    { "webcam", "Camera", 44 },
    { "camera", "Camera", 42 },
    { "cam-", "Camera", 40 },
    { "cam_", "Camera", 40 },
    { "nvr", "NVR", 36 },
    { "dvr", "DVR", 36 },
};

const int MAX_DEVICES = 64;
const uint8_t DISPLAY_THRESHOLD = 45;
const unsigned long CHANNEL_HOP_INTERVAL = 350;
const unsigned long DRAW_INTERVAL = 180;
const unsigned long STALE_STRONG_MS = 300000;
const unsigned long STALE_WEAK_MS = 45000;
const unsigned long ABSENT_TIMEOUT_MS = 12000;
const unsigned long SERIAL_INTERVAL = 250;
const unsigned long SCAN_STATS_INTERVAL = 1000;
const unsigned long SCAN_SERIAL_INTERVAL = 2000;

std::vector<CameraDevice> devices;
CameraMode mode = MODE_SCAN;
int selectedIndex = 0;
int scrollOffset = 0;
uint8_t currentChannel = 1;
unsigned long lastHop = 0;
unsigned long lastDraw = 0;
unsigned long lastPrune = 0;
unsigned long lastButtonMs = 0;
volatile bool needsRedraw = true;

volatile unsigned long scanFramesSeen = 0;
volatile unsigned long scanMgmtFrames = 0;
volatile unsigned long scanDataFrames = 0;
volatile unsigned long scanTrackedFrames = 0;
unsigned long scanStartedAt = 0;
unsigned long lastStatsAt = 0;
unsigned long lastScanFrames = 0;
unsigned long lastTrackedFrames = 0;
unsigned long scanFramesPerSecond = 0;
unsigned long trackedFramesPerSecond = 0;
unsigned long lastScanSerialAt = 0;

uint8_t targetMac[6] = {0};
const char *targetBrand = "Camera";
char targetSsid[17] = {0};
bool targetHasSsid = false;
uint8_t targetChannel = 1;
volatile int8_t targetRssi = -127;
volatile uint8_t targetConfidence = 0;
volatile unsigned long targetLastSeen = 0;
volatile unsigned long targetSamples = 0;
bool serialOutput = false;
unsigned long lastSerialAt = 0;

bool upPrev = false;
bool downPrev = false;
bool rightPrev = false;
bool centerPrev = false;

uint64_t macToU48(const uint8_t *mac) {
    return ((uint64_t)mac[0] << 40) |
           ((uint64_t)mac[1] << 32) |
           ((uint64_t)mac[2] << 24) |
           ((uint64_t)mac[3] << 16) |
           ((uint64_t)mac[4] << 8) |
           (uint64_t)mac[5];
}

bool isUsableUnicast(const uint8_t *mac) {
    if (mac[0] & 0x01) return false;
    return mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5];
}

void macToStr(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void shortMac(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02X%02X%02X", mac[3], mac[4], mac[5]);
}

void formatCount(unsigned long value, char *buf, size_t len) {
    if (value >= 1000000UL) {
        snprintf(buf, len, "%luM", value / 1000000UL);
    } else if (value >= 10000UL) {
        snprintf(buf, len, "%luk", value / 1000UL);
    } else {
        snprintf(buf, len, "%lu", value);
    }
}

void resetScanStats(unsigned long now) {
    scanFramesSeen = 0;
    scanMgmtFrames = 0;
    scanDataFrames = 0;
    scanTrackedFrames = 0;
    scanStartedAt = now;
    lastStatsAt = now;
    lastScanFrames = 0;
    lastTrackedFrames = 0;
    scanFramesPerSecond = 0;
    trackedFramesPerSecond = 0;
    lastScanSerialAt = now;
}

int asciiLower(int c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

bool isAsciiAlnum(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

bool containsIgnoreCase(const char *haystack, const char *needle) {
    if (!haystack || !needle || !needle[0]) return false;
    size_t nLen = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        size_t j = 0;
        while (j < nLen && haystack[i + j] &&
               asciiLower(haystack[i + j]) == asciiLower(needle[j])) {
            j++;
        }
        if (j == nLen) return true;
    }
    return false;
}

bool keywordMatches(const char *text, const char *needle) {
    if (!text || !needle || !needle[0]) return false;
    size_t nLen = strlen(needle);
    bool boundarySensitive = nLen <= 4;
    for (size_t i = 0; text[i]; i++) {
        size_t j = 0;
        while (j < nLen && text[i + j] &&
               asciiLower(text[i + j]) == asciiLower(needle[j])) {
            j++;
        }
        if (j != nLen) continue;
        if (!boundarySensitive) return true;

        char before = (i == 0) ? '\0' : text[i - 1];
        char after = text[i + nLen];
        if (!isAsciiAlnum(before) && !isAsciiAlnum(after)) {
            return true;
        }
    }
    return false;
}

const VendorPrefix *matchVendorPrefix(const uint8_t *mac) {
    if (mac[0] & 0x02) return nullptr;

    uint64_t mac48 = macToU48(mac);
    const VendorPrefix *best = nullptr;
    for (const auto &p : CAMERA_PREFIXES) {
        uint64_t candidate = mac48 >> (48 - p.bits);
        if (candidate == p.prefix && (!best || p.score > best->score || p.bits > best->bits)) {
            best = &p;
        }
    }
    return best;
}

const KeywordRule *matchKeyword(const char *text) {
    if (!text || !text[0]) return nullptr;

    const KeywordRule *best = nullptr;
    for (const auto &rule : CAMERA_KEYWORDS) {
        if (keywordMatches(text, rule.needle) &&
            (!best || rule.score > best->score)) {
            best = &rule;
        }
    }
    return best;
}

uint8_t computeConfidence(const CameraDevice &d) {
    uint16_t score = max(max(d.prefixScore, d.keywordScore), d.flowScore);

    if (d.dataFrames >= 8) score += 8;
    if (d.dataFrames >= 30) score += 8;
    if (d.uplinkFrames >= 8) score += 6;
    if (d.flowScore > 0 && d.downlinkFrames >= 8) score += 4;

    if (d.dataFrames > 0) {
        uint16_t avgLen = d.dataBytes / d.dataFrames;
        if (avgLen >= 256) score += 8;
        if (avgLen >= 700) score += 6;
    }

    if (d.dataFrames > (uint16_t)(d.mgmtFrames * 2 + 4)) score += 5;
    if (d.seenAsStation) score += 6;
    if (d.seenAsAp && d.keywordScore >= 40) score += 8;
    if (d.flowScore > 0 && d.maxFrameLen >= 1000) score += 5;
    if (d.rssi > -67) score += 4;
    if (d.rssi > -55) score += 3;

    if (score > 99) score = 99;
    return (uint8_t)score;
}

uint8_t genericFlowScore(bool isData, uint16_t frameLen, int8_t rssi) {
    if (!isData) return 0;
    if (frameLen >= 1100 && rssi >= -82) return 32;
    if (frameLen >= 700 && rssi >= -82) return 24;
    if (frameLen >= 450 && rssi >= -67) return 18;
    return 0;
}

int findDevice(const uint8_t *mac) {
    for (size_t i = 0; i < devices.size(); i++) {
        if (memcmp(devices[i].mac, mac, 6) == 0) return (int)i;
    }
    return -1;
}

int findReplacementIndex(uint8_t incomingPotential) {
    int idx = -1;
    uint8_t weakest = 255;
    unsigned long oldest = ULONG_MAX;
    for (size_t i = 0; i < devices.size(); i++) {
        uint8_t conf = devices[i].confidence;
        if (conf < weakest || (conf == weakest && devices[i].lastSeen < oldest)) {
            weakest = conf;
            oldest = devices[i].lastSeen;
            idx = (int)i;
        }
    }
    if (idx >= 0 && incomingPotential > weakest) return idx;
    return -1;
}

void storeSsid(CameraDevice &d, const char *ssid, const KeywordRule *keyword) {
    if (!ssid || !ssid[0]) return;
    if (!d.hasSsid || (keyword && keyword->score >= d.keywordScore)) {
        strncpy(d.ssid, ssid, sizeof(d.ssid) - 1);
        d.ssid[sizeof(d.ssid) - 1] = '\0';
        d.hasSsid = true;
    }
}

void updateDevice(const uint8_t *mac, int8_t rssi, uint8_t channel,
                  bool isMgmt, bool isData, bool uplink, bool downlink,
                  bool seenAsAp, const char *ssid, uint16_t frameLen) {
    if (!isUsableUnicast(mac)) return;

    if (mode == MODE_LOCK && memcmp(mac, targetMac, 6) != 0) {
        return;
    }

    const VendorPrefix *vendor = matchVendorPrefix(mac);
    const KeywordRule *keyword = matchKeyword(ssid);
    uint8_t flowPotential = genericFlowScore(isData, frameLen, rssi);
    uint8_t potential = 0;
    if (vendor) potential = max(potential, vendor->score);
    if (keyword) potential = max(potential, keyword->score);
    if (!vendor && !keyword) potential = max(potential, flowPotential);
    if (isData && frameLen >= 450 && potential > 0) potential += 8;

    int idx = findDevice(mac);
    if (idx < 0) {
        bool genericFlowCandidate = (!vendor && !keyword && flowPotential >= 18);
        if (potential < 30 && !genericFlowCandidate && mode != MODE_LOCK) return;

        CameraDevice fresh = {};
        memcpy(fresh.mac, mac, 6);
        fresh.brand = vendor ? vendor->brand : (keyword ? keyword->brand : (flowPotential ? "IPCam?" : "Camera"));
        fresh.prefixScore = vendor ? vendor->score : 0;
        fresh.keywordScore = keyword ? keyword->score : 0;
        fresh.flowScore = flowPotential;
        fresh.rssi = rssi;
        fresh.channel = channel;
        fresh.firstSeen = millis();
        fresh.lastSeen = fresh.firstSeen;
        fresh.confidence = computeConfidence(fresh);
        storeSsid(fresh, ssid, keyword);

        if (devices.size() < (size_t)MAX_DEVICES) {
            devices.push_back(fresh);
            idx = (int)devices.size() - 1;
        } else {
            int replaceIdx = findReplacementIndex(potential);
            if (replaceIdx < 0) return;
            devices[replaceIdx] = fresh;
            idx = replaceIdx;
        }
    }

    CameraDevice &d = devices[idx];
    d.rssi = rssi;
    d.channel = channel;
    d.lastSeen = millis();
    if (vendor && vendor->score >= d.prefixScore) {
        d.prefixScore = vendor->score;
        if (vendor->score >= d.keywordScore) d.brand = vendor->brand;
        d.evidence |= EVIDENCE_PREFIX;
    }
    if (keyword && keyword->score >= d.keywordScore) {
        d.keywordScore = keyword->score;
        if (keyword->score >= d.prefixScore || strcmp(d.brand, "Camera") == 0) {
            d.brand = keyword->brand;
        }
        d.evidence |= EVIDENCE_NAME;
    }
    storeSsid(d, ssid, keyword);

    if (isMgmt) {
        if (d.mgmtFrames < 65535) d.mgmtFrames++;
    }
    if (isData) {
        if (d.dataFrames < 65535) d.dataFrames++;
        d.dataBytes += frameLen;
        if (frameLen > d.maxFrameLen) d.maxFrameLen = frameLen;
        if (uplink && d.uplinkFrames < 65535) d.uplinkFrames++;
        if (downlink && d.downlinkFrames < 65535) d.downlinkFrames++;
        if (!vendor && !keyword && flowPotential > d.flowScore) d.flowScore = flowPotential;
        if (!vendor && !keyword && d.dataFrames >= 8 && d.maxFrameLen >= 700) {
            if (d.flowScore < 30) d.flowScore = 30;
            if (strcmp(d.brand, "Camera") == 0) d.brand = "IPCam?";
        }
        if (!vendor && !keyword && d.dataFrames >= 16 &&
            (d.uplinkFrames >= 12 || d.downlinkFrames >= 12)) {
            if (d.flowScore < 36) d.flowScore = 36;
            d.brand = "IPCam?";
        }
        if (d.dataFrames >= 8) d.evidence |= EVIDENCE_TRAFFIC;
    }
    if (seenAsAp) {
        d.seenAsAp = true;
        if (d.keywordScore >= 40) d.evidence |= EVIDENCE_SETUP;
    }
    if (isData && !seenAsAp) {
        d.seenAsStation = true;
    }

    d.confidence = computeConfidence(d);
    scanTrackedFrames++;

    if (mode == MODE_LOCK && memcmp(mac, targetMac, 6) == 0) {
        targetRssi = d.rssi;
        targetConfidence = d.confidence;
        targetLastSeen = d.lastSeen;
        targetSamples++;
    }

    needsRedraw = true;
}

bool extractSsid(const uint8_t *frame, uint16_t len, uint8_t subtype,
                 char *out, size_t outSize) {
    if (!out || outSize == 0) return false;
    out[0] = '\0';
    if (len < 26) return false;

    int offset = 24;
    if (subtype == 8 || subtype == 5) {
        if (len < 38) return false;
        offset += 12;
    } else if (subtype == 0) {
        if (len < 30) return false;
        offset += 4;
    } else if (subtype == 2) {
        if (len < 36) return false;
        offset += 10;
    } else if (subtype != 4) {
        return false;
    }

    while (offset + 2 <= (int)len) {
        uint8_t tag = frame[offset];
        uint8_t tagLen = frame[offset + 1];
        if (offset + 2 + tagLen > (int)len) break;

        if (tag == 0) {
            if (tagLen == 0) return false;
            size_t copyLen = min((size_t)tagLen, outSize - 1);
            for (size_t i = 0; i < copyLen; i++) {
                uint8_t c = frame[offset + 2 + i];
                out[i] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            out[copyLen] = '\0';
            return out[0] != '\0';
        }

        offset += 2 + tagLen;
    }
    return false;
}

void cameraSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)type;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len > 4) len -= 4;
    if (len < 16) return;
    scanFramesSeen++;

    uint16_t fc = frame[0] | ((uint16_t)frame[1] << 8);
    uint8_t ftype = (frame[0] >> 2) & 0x03;
    uint8_t subtype = (frame[0] >> 4) & 0x0F;
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t channel = pkt->rx_ctrl.channel ? pkt->rx_ctrl.channel : currentChannel;

    if (ftype == 0) {
        scanMgmtFrames++;
        if (len < 24) return;
        const uint8_t *source = &frame[10];
        bool beaconLike = (subtype == 8 || subtype == 5);
        bool stationMgmt = (subtype == 4 || subtype == 0 || subtype == 2);
        if (!beaconLike && !stationMgmt) return;

        char ssid[33] = {0};
        extractSsid(frame, len, subtype, ssid, sizeof(ssid));
        updateDevice(source, rssi, channel, true, false, false, false,
                     beaconLike, ssid, len);
        return;
    }

    if (ftype != 2 || len < 24) return;
    scanDataFrames++;

    bool toDs = (fc & 0x0100) != 0;
    bool fromDs = (fc & 0x0200) != 0;
    const uint8_t *station = nullptr;
    bool uplink = false;
    bool downlink = false;

    if (toDs && !fromDs) {
        station = &frame[10];
        uplink = true;
    } else if (!toDs && fromDs) {
        station = &frame[4];
        downlink = true;
    } else if (!toDs && !fromDs) {
        station = &frame[10];
        uplink = true;
    } else if (toDs && fromDs && len >= 30) {
        station = &frame[24];
        uplink = true;
    }

    if (!station) return;
    updateDevice(station, rssi, channel, false, true, uplink, downlink,
                 false, nullptr, len);
}

bool buttonEdge(uint8_t pin, bool &prev, unsigned long now) {
    bool pressed = digitalRead(pin) == LOW;
    bool edge = pressed && !prev && (now - lastButtonMs > 150);
    prev = pressed;
    if (edge) lastButtonMs = now;
    return edge;
}

void sortDevices() {
    std::sort(devices.begin(), devices.end(), [](const CameraDevice &a, const CameraDevice &b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        if (a.rssi != b.rssi) return a.rssi > b.rssi;
        return a.lastSeen > b.lastSeen;
    });
}

int displayableCount() {
    int count = 0;
    for (const auto &d : devices) {
        if (d.confidence >= DISPLAY_THRESHOLD) count++;
    }
    return count;
}

CameraDevice *displayDeviceAt(int visibleIndex) {
    int seen = 0;
    for (auto &d : devices) {
        if (d.confidence < DISPLAY_THRESHOLD) continue;
        if (seen == visibleIndex) return &d;
        seen++;
    }
    return nullptr;
}

CameraDevice *bestDevice() {
    if (devices.empty()) return nullptr;
    return &devices[0];
}

void updateScanStats(unsigned long now) {
    if (lastStatsAt == 0) {
        lastStatsAt = now;
        return;
    }

    unsigned long elapsed = now - lastStatsAt;
    if (elapsed < SCAN_STATS_INTERVAL) return;

    unsigned long currentFrames = scanFramesSeen;
    unsigned long currentTracked = scanTrackedFrames;
    scanFramesPerSecond = ((currentFrames - lastScanFrames) * 1000UL) / elapsed;
    trackedFramesPerSecond = ((currentTracked - lastTrackedFrames) * 1000UL) / elapsed;
    lastScanFrames = currentFrames;
    lastTrackedFrames = currentTracked;
    lastStatsAt = now;
    needsRedraw = true;
}

void pruneStale(unsigned long now) {
    devices.erase(std::remove_if(devices.begin(), devices.end(), [now](const CameraDevice &d) {
        unsigned long age = now - d.lastSeen;
        if (d.confidence >= DISPLAY_THRESHOLD) return age > STALE_STRONG_MS;
        return age > STALE_WEAK_MS;
    }), devices.end());
}

const char *signalZone(int8_t rssi) {
    if (rssi >= -55) return "HOT";
    if (rssi >= -67) return "NEAR";
    if (rssi >= -78) return "MID";
    return "FAR";
}

void evidenceString(const CameraDevice &d, char *buf, size_t len) {
    buf[0] = '\0';
    if (d.evidence & EVIDENCE_PREFIX) strncat(buf, "OUI", len - strlen(buf) - 1);
    if (d.evidence & EVIDENCE_NAME) {
        if (buf[0]) strncat(buf, "+", len - strlen(buf) - 1);
        strncat(buf, "NAME", len - strlen(buf) - 1);
    }
    if (d.evidence & EVIDENCE_TRAFFIC) {
        if (buf[0]) strncat(buf, "+", len - strlen(buf) - 1);
        strncat(buf, "FLOW", len - strlen(buf) - 1);
    }
    if (d.evidence & EVIDENCE_SETUP) {
        if (buf[0]) strncat(buf, "+", len - strlen(buf) - 1);
        strncat(buf, "AP", len - strlen(buf) - 1);
    }
    if (!buf[0]) strncpy(buf, "HEUR", len - 1);
    buf[len - 1] = '\0';
}

void printScanSummary(unsigned long now) {
    if (now - lastScanSerialAt < SCAN_SERIAL_INTERVAL) return;
    lastScanSerialAt = now;

    CameraDevice *best = bestDevice();
    char id[17] = "---";
    char evidence[24] = "---";
    const char *brand = "none";
    uint8_t confidence = 0;
    int rssi = -127;
    unsigned long age = 0;

    if (best) {
        brand = best->brand;
        confidence = best->confidence;
        rssi = best->rssi;
        age = (now - best->lastSeen) / 1000UL;
        if (best->hasSsid && !privacyModeEnabled) {
            strncpy(id, best->ssid, sizeof(id) - 1);
            id[sizeof(id) - 1] = '\0';
        } else if (privacyModeEnabled) {
            strncpy(id, "masked", sizeof(id) - 1);
            id[sizeof(id) - 1] = '\0';
        } else {
            shortMac(best->mac, id, sizeof(id));
        }
        evidenceString(*best, evidence, sizeof(evidence));
    }

    Serial.printf("# scan t=%lus ch=%u rx=%lu rate=%lu/s mgmt=%lu data=%lu tracked=%lu rate=%lu/s shown=%d raw=%d best=%s conf=%u rssi=%d id=%s ev=%s age=%lus\n",
                  (now - scanStartedAt) / 1000UL,
                  (unsigned int)currentChannel,
                  (unsigned long)scanFramesSeen,
                  (unsigned long)scanFramesPerSecond,
                  (unsigned long)scanMgmtFrames,
                  (unsigned long)scanDataFrames,
                  (unsigned long)scanTrackedFrames,
                  (unsigned long)trackedFramesPerSecond,
                  displayableCount(),
                  (int)devices.size(),
                  brand,
                  (unsigned int)confidence,
                  rssi,
                  id,
                  evidence,
                  age);
}

void drawConfidenceBar(uint8_t confidence, int y) {
    u8g2.drawFrame(0, y, 128, 6);
    int width = (confidence * 126) / 100;
    if (width > 0) u8g2.drawBox(1, y + 1, width, 4);
}

void drawSignalBars(int8_t rssi, int x, int y) {
    int clamped = constrain((int)rssi, -95, -40);
    int level = map(clamped, -95, -40, 0, 5);
    for (int i = 0; i < 5; i++) {
        int h = 3 + i * 2;
        int bx = x + i * 5;
        int by = y - h;
        if (i < level) u8g2.drawBox(bx, by, 4, h);
        else u8g2.drawFrame(bx, by, 4, h);
    }
}

void drawScan() {
    sortDevices();
    int count = displayableCount();
    int rawCount = (int)devices.size();
    if (selectedIndex >= count) selectedIndex = max(0, count - 1);
    if (scrollOffset > selectedIndex) scrollOffset = selectedIndex;
    if (selectedIndex >= scrollOffset + 5) scrollOffset = selectedIndex - 4;
    if (scrollOffset < 0) scrollOffset = 0;

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char header[32];
    snprintf(header, sizeof(header), "Cam c%02u %d/%d RX%lu/s",
             (unsigned int)currentChannel, count, rawCount,
             (unsigned long)scanFramesPerSecond);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    if (count == 0) {
        char rx[8], mgmt[8], data[8], tracked[8];
        formatCount(scanFramesSeen, rx, sizeof(rx));
        formatCount(scanMgmtFrames, mgmt, sizeof(mgmt));
        formatCount(scanDataFrames, data, sizeof(data));
        formatCount(scanTrackedFrames, tracked, sizeof(tracked));

        char line[32];
        snprintf(line, sizeof(line), "RX %-6s %3lu/s hop%lums",
                 rx, scanFramesPerSecond, CHANNEL_HOP_INTERVAL);
        u8g2.drawStr(0, 19, line);

        snprintf(line, sizeof(line), "MG %-6s DATA %-6s", mgmt, data);
        u8g2.drawStr(0, 28, line);

        snprintf(line, sizeof(line), "Tracked %-6s %3lu/s", tracked, trackedFramesPerSecond);
        u8g2.drawStr(0, 37, line);

        CameraDevice *best = bestDevice();
        if (best) {
            snprintf(line, sizeof(line), "Best %.8s %u%% %ddBm",
                     best->brand, (unsigned int)best->confidence, (int)best->rssi);
            u8g2.drawStr(0, 46, line);

            char ev[24];
            evidenceString(*best, ev, sizeof(ev));
            snprintf(line, sizeof(line), "Ev %.18s age%lus",
                     ev, (unsigned long)((millis() - best->lastSeen) / 1000UL));
            u8g2.drawStr(0, 55, line);
        } else {
            u8g2.drawStr(0, 46, "Best -- listening");
            u8g2.drawStr(0, 55, "OUI+SSID+FLOW active");
        }
        u8g2.drawStr(0, 64, "C=Clear L=Exit");
    } else {
        for (int row = 0; row < 5; row++) {
            int visibleIdx = scrollOffset + row;
            CameraDevice *d = displayDeviceAt(visibleIdx);
            if (!d) break;

            int top = 12 + row * 9;
            int textY = top + 7;
            if (visibleIdx == selectedIndex) {
                u8g2.drawBox(0, top, 128, 9);
                u8g2.setDrawColor(0);
            }

            char id[12];
            if (d->hasSsid && !privacyModeEnabled) {
                strncpy(id, d->ssid, sizeof(id) - 1);
                id[sizeof(id) - 1] = '\0';
            } else if (privacyModeEnabled) {
                strncpy(id, "XX:XX:XX", sizeof(id) - 1);
                id[sizeof(id) - 1] = '\0';
            } else {
                shortMac(d->mac, id, sizeof(id));
            }

            char line[32];
            snprintf(line, sizeof(line), "%-6.6s %2u%% %4d c%02u %-5.5s",
                     d->brand, (unsigned int)d->confidence, (int)d->rssi,
                     (unsigned int)d->channel, id);
            u8g2.drawStr(0, textY, line);

            if (visibleIdx == selectedIndex) {
                u8g2.setDrawColor(1);
            }
        }
        u8g2.drawStr(0, 62, "R=Detail C=Clear L=Exit");
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawDetail(const CameraDevice &d) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char line[36];
    snprintf(line, sizeof(line), "%-10.10s %u%% ch%u",
             d.brand, (unsigned int)d.confidence, (unsigned int)d.channel);
    u8g2.drawStr(0, 8, line);
    u8g2.drawHLine(0, 10, 128);

    char mac[18];
    if (privacyModeEnabled) strncpy(mac, "XX:XX:XX:XX:XX:XX", sizeof(mac));
    else macToStr(d.mac, mac, sizeof(mac));
    snprintf(line, sizeof(line), "MAC %s", mac);
    u8g2.drawStr(0, 19, line);

    char ssid[17] = "---";
    if (d.hasSsid) {
        if (privacyModeEnabled) maskName(d.ssid, ssid, sizeof(ssid) - 1);
        else strncpy(ssid, d.ssid, sizeof(ssid) - 1);
        ssid[sizeof(ssid) - 1] = '\0';
    }
    snprintf(line, sizeof(line), "SSID %.16s", ssid);
    u8g2.drawStr(0, 28, line);

    snprintf(line, sizeof(line), "RSSI %d %s age %lus",
             (int)d.rssi, signalZone(d.rssi),
             (unsigned long)((millis() - d.lastSeen) / 1000));
    u8g2.drawStr(0, 37, line);

    snprintf(line, sizeof(line), "D%u U%u M%u max%u",
             (unsigned int)d.dataFrames,
             (unsigned int)d.uplinkFrames,
             (unsigned int)d.mgmtFrames,
             (unsigned int)d.maxFrameLen);
    u8g2.drawStr(0, 46, line);

    char ev[24];
    evidenceString(d, ev, sizeof(ev));
    snprintf(line, sizeof(line), "Why %.22s", ev);
    u8g2.drawStr(0, 55, line);
    u8g2.drawStr(0, 64, "R=Lock C=List");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawLock() {
    bool live = targetLastSeen != 0 && (millis() - targetLastSeen <= ABSENT_TIMEOUT_MS);
    int8_t rssi = live ? targetRssi : -127;
    uint8_t conf = targetConfidence;

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char header[32];
    if (targetHasSsid && !privacyModeEnabled) {
        snprintf(header, sizeof(header), "LOCK %.16s", targetSsid);
    } else {
        snprintf(header, sizeof(header), "LOCK %.12s", targetBrand);
    }
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    u8g2.setFont(u8g2_font_helvB18_tr);
    char big[8];
    if (live) snprintf(big, sizeof(big), "%d", (int)rssi);
    else strncpy(big, "---", sizeof(big));
    int w = u8g2.getUTF8Width(big);
    u8g2.setCursor((128 - w) / 2, 32);
    u8g2.print(big);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(54, 42, "dBm");
    drawConfidenceBar(conf, 46);
    drawSignalBars(live ? rssi : -95, 99, 62);

    char footer[32];
    snprintf(footer, sizeof(footer), "%-4s %u%% n%lu ch%u %s",
             live ? signalZone(rssi) : "LOST",
             (unsigned int)conf,
             (unsigned long)targetSamples,
             (unsigned int)targetChannel,
             serialOutput ? "csv" : "");
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void enterScanMode(bool clearList) {
    mode = MODE_SCAN;
    if (clearList) {
        devices.clear();
        selectedIndex = 0;
        scrollOffset = 0;
    }
    currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
    if (clearList) resetScanStats(lastHop);
    serialOutput = false;
    neoSetStatus(NEO_RECON);
    needsRedraw = true;
}

void enterLockMode(const CameraDevice &d) {
    memcpy(targetMac, d.mac, 6);
    targetBrand = d.brand;
    targetHasSsid = d.hasSsid;
    if (d.hasSsid) {
        strncpy(targetSsid, d.ssid, sizeof(targetSsid) - 1);
        targetSsid[sizeof(targetSsid) - 1] = '\0';
    } else {
        targetSsid[0] = '\0';
    }
    targetChannel = (d.channel >= 1 && d.channel <= 13) ? d.channel : currentChannel;
    targetRssi = d.rssi;
    targetConfidence = d.confidence;
    targetLastSeen = d.lastSeen;
    targetSamples = 0;
    serialOutput = false;

    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    mode = MODE_LOCK;
    neoSetStatus(NEO_CAPTURE);
    needsRedraw = true;

    char mac[18];
    macToStr(targetMac, mac, sizeof(mac));
    Serial.println();
    Serial.printf("# hackbox Camera Detector lock,%s,%s,ch%u\n",
                  targetBrand, mac, (unsigned int)targetChannel);
    Serial.println("# timestamp_ms,brand,mac,rssi_dbm,confidence,channel,samples");
}

} // namespace

bool cameraDetectorClassifyPromiscPacket(void *buf,
                                         wifi_promiscuous_pkt_type_t type,
                                         CameraFrameMatch *out) {
    (void)type;
    if (!buf || !out) return false;
    memset(out, 0, sizeof(CameraFrameMatch));

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len > 4) len -= 4;
    if (len < 16) return false;

    uint16_t fc = frame[0] | ((uint16_t)frame[1] << 8);
    uint8_t ftype = (frame[0] >> 2) & 0x03;
    uint8_t subtype = (frame[0] >> 4) & 0x0F;
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t channel = pkt->rx_ctrl.channel ? pkt->rx_ctrl.channel : 1;

    const uint8_t *candidate = nullptr;
    bool isMgmt = false;
    bool isData = false;
    bool seenAsAp = false;
    bool seenAsStation = false;
    bool uplink = false;
    bool downlink = false;
    char ssid[33] = {0};

    if (ftype == 0) {
        if (len < 24) return false;
        bool beaconLike = (subtype == 8 || subtype == 5);
        bool stationMgmt = (subtype == 4 || subtype == 0 || subtype == 2);
        if (!beaconLike && !stationMgmt) return false;
        candidate = &frame[10];
        isMgmt = true;
        seenAsAp = beaconLike;
        seenAsStation = stationMgmt;
        extractSsid(frame, len, subtype, ssid, sizeof(ssid));
    } else if (ftype == 2) {
        if (len < 24) return false;
        bool toDs = (fc & 0x0100) != 0;
        bool fromDs = (fc & 0x0200) != 0;
        if (toDs && !fromDs) {
            candidate = &frame[10];
            uplink = true;
        } else if (!toDs && fromDs) {
            candidate = &frame[4];
            downlink = true;
        } else if (!toDs && !fromDs) {
            candidate = &frame[10];
            uplink = true;
        } else if (toDs && fromDs && len >= 30) {
            candidate = &frame[24];
            uplink = true;
        }
        isData = true;
        seenAsStation = true;
    } else {
        return false;
    }

    if (!candidate || !isUsableUnicast(candidate)) return false;

    const VendorPrefix *vendor = matchVendorPrefix(candidate);
    const KeywordRule *keyword = matchKeyword(ssid);
    uint8_t flowPotential = genericFlowScore(isData, len, rssi);
    uint8_t potential = 0;
    if (vendor) potential = max(potential, vendor->score);
    if (keyword) potential = max(potential, keyword->score);
    if (!vendor && !keyword) potential = max(potential, flowPotential);
    if (isData && len >= 450 && potential > 0) potential += 8;
    if (potential < 30) return false;
    if (potential > 99) potential = 99;

    memcpy(out->mac, candidate, 6);
    out->brand = vendor ? vendor->brand : (keyword ? keyword->brand : (flowPotential ? "IPCam?" : "Camera"));
    out->baseScore = potential;
    out->rssi = rssi;
    out->channel = channel;
    out->isMgmt = isMgmt;
    out->isData = isData;
    out->seenAsAp = seenAsAp;
    out->seenAsStation = seenAsStation;
    out->uplink = uplink;
    out->downlink = downlink;
    out->frameLen = len;
    if (vendor) out->evidence |= CAMERA_FRAME_PREFIX;
    if (keyword) out->evidence |= CAMERA_FRAME_NAME;
    if (isData && (vendor || keyword || flowPotential)) out->evidence |= CAMERA_FRAME_TRAFFIC;
    if (keyword && keyword->score < 50) out->evidence |= CAMERA_FRAME_SETUP;
    if (ssid[0]) {
        strncpy(out->ssid, ssid, sizeof(out->ssid) - 1);
        out->ssid[sizeof(out->ssid) - 1] = '\0';
    }

    return true;
}

void cameraDetectorSetup() {
    devices.clear();
    devices.reserve(MAX_DEVICES);
    mode = MODE_SCAN;
    selectedIndex = 0;
    scrollOffset = 0;
    currentChannel = 1;
    lastHop = millis();
    lastDraw = 0;
    lastPrune = 0;
    lastButtonMs = 0;
    needsRedraw = true;
    resetScanStats(lastHop);
    targetLastSeen = 0;
    targetSamples = 0;
    serialOutput = false;
    upPrev = downPrev = rightPrev = centerPrev = false;

    u8g2.begin();
    u8g2.setFont(u8g2_font_5x8_tr);

    initWiFi(WIFI_MODE_AP);
    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(cameraSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);

    Serial.println();
    Serial.printf("# hackbox Camera Detector %s\n", HACKBOX_VERSION);
    Serial.println("# Passive: OUI/MA-M/MA-S + SSID/probe keywords + traffic flow scoring");
    Serial.println("# LOCK CSV: timestamp_ms,brand,mac,rssi_dbm,confidence,channel,samples");

    neoSetStatus(NEO_RECON);
    drawScan();
}

void cameraDetectorLoop() {
    unsigned long now = millis();

    bool upEdge = buttonEdge(BUTTON_PIN_UP, upPrev, now);
    bool downEdge = buttonEdge(BUTTON_PIN_DOWN, downPrev, now);
    bool rightEdge = buttonEdge(BUTTON_PIN_RIGHT, rightPrev, now);
    bool centerEdge = buttonEdge(BUTTON_PIN_CENTER, centerPrev, now);

    if (mode == MODE_SCAN) {
        updateScanStats(now);

        if (now - lastHop >= CHANNEL_HOP_INTERVAL) {
            currentChannel++;
            if (currentChannel > 13) currentChannel = 1;
            esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            lastHop = now;
            needsRedraw = true;
        }

        int count = displayableCount();
        if (upEdge && selectedIndex > 0) {
            selectedIndex--;
            needsRedraw = true;
        }
        if (downEdge && selectedIndex + 1 < count) {
            selectedIndex++;
            needsRedraw = true;
        }
        if (rightEdge && count > 0) {
            mode = MODE_DETAIL;
            needsRedraw = true;
        }
        if (centerEdge) {
            enterScanMode(true);
        }

        if (now - lastPrune >= 5000) {
            pruneStale(now);
            lastPrune = now;
            needsRedraw = true;
        }

        sortDevices();
        uint8_t topConfidence = devices.empty() ? 0 : devices[0].confidence;
        if (topConfidence >= 85) neoSetStatus(NEO_ALERT);
        else if (displayableCount() > 0) neoSetStatus(NEO_CAPTURE);
        else neoSetStatus(NEO_RECON);

        printScanSummary(now);

        if (needsRedraw && now - lastDraw >= DRAW_INTERVAL) {
            needsRedraw = false;
            lastDraw = now;
            drawScan();
        }
        return;
    }

    if (mode == MODE_DETAIL) {
        int count = displayableCount();
        if (count == 0) {
            enterScanMode(false);
            return;
        }
        if (selectedIndex >= count) selectedIndex = count - 1;
        CameraDevice *d = displayDeviceAt(selectedIndex);
        if (!d) {
            enterScanMode(false);
            return;
        }
        if (upEdge && selectedIndex > 0) {
            selectedIndex--;
            needsRedraw = true;
        }
        if (downEdge && selectedIndex + 1 < count) {
            selectedIndex++;
            needsRedraw = true;
        }
        if (centerEdge) {
            mode = MODE_SCAN;
            needsRedraw = true;
        }
        if (rightEdge) {
            enterLockMode(*d);
            return;
        }
        if (needsRedraw && now - lastDraw >= DRAW_INTERVAL) {
            needsRedraw = false;
            lastDraw = now;
            d = displayDeviceAt(selectedIndex);
            if (d) drawDetail(*d);
        }
        return;
    }

    if (mode == MODE_LOCK) {
        if (centerEdge) {
            enterScanMode(false);
            return;
        }
        if (rightEdge) {
            serialOutput = !serialOutput;
            needsRedraw = true;
        }

        if (serialOutput && targetLastSeen != 0 &&
            now - lastSerialAt >= SERIAL_INTERVAL) {
            char mac[18];
            macToStr(targetMac, mac, sizeof(mac));
            Serial.printf("%lu,%s,%s,%d,%u,%u,%lu\n",
                          (unsigned long)targetLastSeen,
                          targetBrand,
                          mac,
                          (int)targetRssi,
                          (unsigned int)targetConfidence,
                          (unsigned int)targetChannel,
                          (unsigned long)targetSamples);
            lastSerialAt = now;
        }

        if (targetLastSeen != 0 && now - targetLastSeen > ABSENT_TIMEOUT_MS) {
            neoSetStatus(NEO_RECON);
        } else if (targetConfidence >= 85) {
            neoSetStatus(NEO_ALERT);
        } else {
            neoSetStatus(NEO_CAPTURE);
        }

        if (needsRedraw && now - lastDraw >= DRAW_INTERVAL) {
            needsRedraw = false;
            lastDraw = now;
            drawLock();
        } else if (now - lastDraw >= 1000) {
            lastDraw = now;
            drawLock();
        }
    }
}

void cameraDetectorCleanup() {
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    devices.clear();
    serialOutput = false;
    targetLastSeen = 0;
}
