/*
    hackbox Tracker Sweep

    Single-screen, one-button answer to the question "am I being
    followed?" Runs a continuous BLE scan, classifies every
    advertisement against a table of known tracker signatures
    (AirTag, SmartTag, Tile, Flipper Zero, Ray-Ban Meta, Axon bodycam,
    Flock Safety BLE), deduplicates by MAC, and shows a weighted
    threat score at the top of the screen with per-category counts
    below.

    Detection predicates are inlined rather than shared with the
    existing standalone detectors, deliberately. The per-device apps
    each own their own state, rescan cadence, and Locate mode. This
    sweep cares about "did we see anything at all in the last N
    seconds" and nothing else. Each predicate here is a direct port
    of the match condition from its corresponding detector file, so
    a fix there should be mirrored here when it matters.

    Deliberate scope for v1:
    - BLE only. Flock's WiFi side is not covered by this sweep; use
      the standalone Flock Detector for full-coverage Flock hunting.
    - No Locate mode, no CSV export, no persistence. This is a live
      situational-awareness view, not a forensics tool.
    - Max 64 unique devices tracked per session.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#include "../include/tracking_sweep.h"
#include "../include/radio_manager.h"
#include "../include/display_mirror.h"
#include <Adafruit_NeoPixel.h>
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;

// ============================================================
// Tracker categories and weights
// ============================================================

enum TrackerCategory : uint8_t {
    TRK_AIRTAG = 0,
    TRK_SMARTTAG,
    TRK_TILE,
    TRK_FLIPPER,
    TRK_RAYBAN,
    TRK_AXON,
    TRK_FLOCK,
    TRK_SKIMMER,      // HC-series BT card skimmers
    TRK_HACKBOX,      // other hackbox devices broadcasting
    TRK_MESHTASTIC,   // v1.3: Meshtastic mesh nodes
    TRK_MESHCORE,     // v1.3: MeshCore mesh nodes
    TRK_COUNT,
    TRK_NONE = 0xFF
};

// Per-device weights that feed the threat score. Values were picked
// on the rough principle "how alarmed should the user be about one
// of these being in range" -- a Flock BLE transponder implies fixed
// surveillance infrastructure nearby so it weighs the most, an Axon
// bodycam implies an officer is physically present and recording,
// AirTag / SmartTag are the classic stalker-tool trackers, Tile is
// the same story on a smaller network, Ray-Ban Meta is a person with
// glasses that can record audio and video, and Flipper Zero is the
// weakest signal because it is just somebody with a gadget nearby.
//
// Total threat score is clamped at 99 so the display stays two-digit
// and the user reads "max" rather than a random large number.
// Persistent devices (seen 5+ min) get 3x weight multiplier.
static const uint8_t CATEGORY_WEIGHT[TRK_COUNT] = {
    15,  // TRK_AIRTAG
    15,  // TRK_SMARTTAG
    10,  // TRK_TILE
    5,   // TRK_FLIPPER
    8,   // TRK_RAYBAN
    25,  // TRK_AXON
    30,  // TRK_FLOCK
    20,  // TRK_SKIMMER
    2,   // TRK_HACKBOX
    3,   // TRK_MESHTASTIC -- mesh node, low threat alone
    3    // TRK_MESHCORE   -- mesh node, low threat alone
};

// Display label shown on the dashboard. Kept short because the left
// column of the dashboard grid is ~60 px wide (5 px font).
static const char *CATEGORY_NAME[TRK_COUNT] = {
    "AirTag",
    "SmarTag",
    "Tile",
    "Flipper",
    "Rayban",
    "Axon",
    "Flock",
    "Skim",
    "Bee",
    "Mesh",
    "MCore"
};

// Serial-safe lowercase label emitted by emitHitLine() and listed in
// the session banner. The AIO web page matches on these exact
// strings. Keep in sync with the `# categories:` line in the banner
// and with the matching parser in ck42x/src/app/hackbox/aio/page.tsx.
static const char *CATEGORY_WIRE[TRK_COUNT] = {
    "airtag",
    "smarttag",
    "tile",
    "flipper",
    "rayban",
    "axon",
    "flock",
    "skimmer",
    "hackbox",
    "meshtastic",
    "meshcore"
};

// ============================================================
// Flock signature tables (ported verbatim from flock_detector.cpp
// lines 52-78). BLE-relevant columns only. When the standalone
// detector grows new entries, mirror them here.
// ============================================================

static const char *FLOCK_MAC_PREFIXES[] = {
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84",
    "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
    "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea"
};
static const int FLOCK_MAC_PREFIX_COUNT =
    sizeof(FLOCK_MAC_PREFIXES) / sizeof(FLOCK_MAC_PREFIXES[0]);

static const char *FLOCK_NAME_PATTERNS[] = {
    "FS Ext Battery",
    "Penguin",
    "Pigvision"
};
static const int FLOCK_NAME_PATTERN_COUNT =
    sizeof(FLOCK_NAME_PATTERNS) / sizeof(FLOCK_NAME_PATTERNS[0]);

// Flipper Zero OUIs (flipperzero_detector.cpp lines 127-133).
static const char *FLIPPER_MAC_PREFIXES[] = {
    "80:e1:26", "80:e1:27", "0c:fa:22"
};
static const int FLIPPER_MAC_PREFIX_COUNT =
    sizeof(FLIPPER_MAC_PREFIXES) / sizeof(FLIPPER_MAC_PREFIXES[0]);

// Axon bodycam OUI (axon_detector.cpp lines 88-90).
static const char *AXON_MAC_PREFIX = "00:25:df";

// ============================================================
// State
// ============================================================

struct TrackerHit {
    uint8_t  mac[6];
    uint8_t  category;     // TrackerCategory value
    int8_t   rssi;
    unsigned long firstSeen;
    unsigned long lastSeen;
    bool     persistent;   // seen for 5+ minutes = "following you"
};

static const int MAX_HITS = 64;

// All mutable state for the sweep app lives inside this one struct,
// and the struct itself is heap-allocated in trackingSweepSetup and
// freed in trackingSweepCleanup. The only BSS footprint this file
// costs is the single `state` pointer below. The firmware as a whole
// is right at the ESP32's DRAM limit under the full build, so any
// new app that wants ~800 bytes of working memory has to keep it out
// of .bss / .data and put it on the heap on demand.
// Two on-screen views. Dashboard is the default -- threat score +
// category counts. List is the drill-down reached by RIGHT -- one
// row per unique hit with MAC / RSSI / age / category, scrollable.
enum SweepView : uint8_t {
    VIEW_DASHBOARD = 0,
    VIEW_LIST
};

struct TrackerSweepState {
    TrackerHit hits[MAX_HITS];
    int hitCount;
    int categoryCounts[TRK_COUNT];
    int threatScore;

    bool isScanning;
    unsigned long scanStartedAt;
    unsigned long lastRedraw;
    bool needsRedraw;

    // Blink the threat banner when score >= 50. Cosmetic only.
    bool scoreBlinkOn;
    unsigned long lastBlinkToggle;

    int persistentCount;           // devices seen 5+ minutes
    unsigned long lastAgeCheck;     // when we last ran the aging pass

    // Button debounce inside the loop. RIGHT and CENTER are edge-
    // triggered via the *Prev flags so holding the button does not
    // spam view-toggles or scan-resets. UP and DOWN stay purely
    // time-based so scrolling the drill-down list auto-repeats when
    // held, matching desktop UI convention.
    bool rightPrev;
    bool centerPrev;
    unsigned long lastUp;
    unsigned long lastDown;

    // Drill-down view state.
    uint8_t currentView;   // SweepView
    int listSelected;      // selected index in the drill-down list
    int listScroll;        // top-of-visible index in the drill-down list
};

static TrackerSweepState *state = nullptr;
static bool bleInitialized = false;

static const unsigned long SCAN_WINDOW_SEC = 8;       // each start_scanning call
static const unsigned long REDRAW_INTERVAL_MS = 300;
static const unsigned long BLINK_INTERVAL_MS = 500;
static const unsigned long STALE_TIMEOUT_MS = 60000;   // drop devices not seen in 60s
static const unsigned long PERSISTENT_MS = 300000;     // 5 min = "following you"
static const unsigned long AGE_CHECK_MS = 5000;        // run aging every 5s

// const so the struct itself lives in .rodata (flash) instead of .data
// (DRAM). The ESP-IDF API wants a non-const pointer on the call side,
// which we bridge with a cast at the single call site in setup().
// Tighter scan: interval 0x80 (80ms), window 0x70 (70ms) = 87.5% duty
// vs old 0x100/0xA0 = 62.5%. More aggressive catch rate for trackers
// that advertise infrequently.
static const esp_ble_scan_params_t sweep_scan_params = {
    .scan_type          = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval      = 0x80,
    .scan_window        = 0x70,
    .scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE
};

// ============================================================
// Helpers
// ============================================================

static void bdaToStr(const uint8_t *bda, char *out) {
    // Lowercase hex to match the prefix tables from flock/flipper/axon.
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             bda[0], bda[1], bda[2], bda[3], bda[4], bda[5]);
}

static bool macPrefixMatch(const char *macStr, const char *const *table, int count) {
    for (int i = 0; i < count; i++) {
        if (strncasecmp(macStr, table[i], 8) == 0) return true;
    }
    return false;
}

// ============================================================
// Per-category predicates
//
// Each function takes the full scan_result and returns true if the
// advertisement matches that category. Conditions were ported from
// their standalone detectors -- see top-of-file comment for policy.
// ============================================================

static bool isAirtagAdv(esp_ble_gap_cb_param_t *p) {
    // Fixed: only match Apple Find My (Continuity type 0x12), not all
    // Apple Continuity ads. The old check matched 0x1E FF 4C 00 which
    // fires on every AirPod, Apple Watch, and iPhone in range.
    // Find My ads carry: FF 4C 00 12 19 (mfg data, Apple CID, type
    // 0x12 = Find My, length 0x19). We walk the AD structures properly
    // to avoid false positives from random byte sequences.
    uint8_t *adv = p->scan_rst.ble_adv;
    int len = p->scan_rst.adv_data_len;
    int i = 0;
    while (i < len) {
        uint8_t field_len = adv[i];
        if (field_len == 0 || i + field_len >= len) break;
        uint8_t field_type = adv[i + 1];
        // Manufacturer Specific Data
        if (field_type == 0xFF && field_len >= 5) {
            uint8_t lo = adv[i + 2];
            uint8_t hi = adv[i + 3];
            // Apple company ID: 0x004C (little-endian: 4C 00)
            if (lo == 0x4C && hi == 0x00) {
                uint8_t subtype = adv[i + 4];
                // 0x12 = Find My network (AirTag, Find My accessories)
                if (subtype == 0x12) return true;
            }
        }
        i += field_len + 1;
    }
    return false;
}

// Walk the 16-bit service UUID fields (complete + partial lists) in
// an advertisement looking for a given 16-bit value. Used by
// SmartTag, Tile, and Ray-Ban predicates. UUIDs in BLE adv payloads
// are little-endian byte pairs.
static bool hasService16(esp_ble_gap_cb_param_t *p, uint16_t uuid) {
    uint8_t *adv = p->scan_rst.ble_adv;
    int len = p->scan_rst.adv_data_len;
    int i = 0;
    while (i < len) {
        uint8_t field_len = adv[i];
        if (field_len == 0 || i + field_len >= len) break;
        uint8_t field_type = adv[i + 1];
        if (field_type == ESP_BLE_AD_TYPE_16SRV_CMPL ||
            field_type == ESP_BLE_AD_TYPE_16SRV_PART) {
            int n = (field_len - 1) / 2;
            for (int k = 0; k < n; k++) {
                uint8_t lo = adv[i + 2 + k * 2];
                uint8_t hi = adv[i + 2 + k * 2 + 1];
                uint16_t u = (uint16_t)lo | ((uint16_t)hi << 8);
                if (u == uuid) return true;
            }
        }
        i += field_len + 1;
    }
    return false;
}

// Walk the 128-bit service UUID fields (complete + partial lists)
// in an advertisement looking for a byte-exact 16-byte pattern.
// Used by the hackbox detector, whose service UUID is a 128-bit
// value that encodes an ASCII signature. Target buffer is compared
// directly against the raw bytes in the ad, which is what
// hackbox_detector.cpp does, so we do not have to worry about
// big/little-endian UUID conversion.
static bool hasService128(esp_ble_gap_cb_param_t *p, const uint8_t target[16]) {
    uint8_t *adv = p->scan_rst.ble_adv;
    int len = p->scan_rst.adv_data_len;
    int i = 0;
    while (i < len) {
        uint8_t field_len = adv[i];
        if (field_len == 0 || i + field_len >= len) break;
        uint8_t field_type = adv[i + 1];
        if (field_type == ESP_BLE_AD_TYPE_128SRV_CMPL ||
            field_type == ESP_BLE_AD_TYPE_128SRV_PART) {
            int uuid_data_len = field_len - 1;
            for (int k = 0; k + 16 <= uuid_data_len; k += 16) {
                if (memcmp(&adv[i + 2 + k], target, 16) == 0) {
                    return true;
                }
            }
        }
        i += field_len + 1;
    }
    return false;
}

// Pull the advertised name (complete or short) into `out`, returning
// true if a non-empty name was found. `out` must be at least 33
// bytes to hold the max 32-char name plus a null terminator. Used
// by the skimmer predicate and the existing Flock name-pattern
// fallback -- factored out here so both paths share the same
// lookup, even though the Flock path still inlines it for now.
static bool getAdvName(esp_ble_gap_cb_param_t *p, char *out, int outSize) {
    if (!out || outSize < 1) return false;
    uint8_t name_len = 0;
    uint8_t *name = esp_ble_resolve_adv_data(p->scan_rst.ble_adv,
                                             ESP_BLE_AD_TYPE_NAME_CMPL,
                                             &name_len);
    if (!name || name_len == 0) {
        name_len = 0;
        name = esp_ble_resolve_adv_data(p->scan_rst.ble_adv,
                                        ESP_BLE_AD_TYPE_NAME_SHORT,
                                        &name_len);
    }
    if (!name || name_len == 0) {
        out[0] = '\0';
        return false;
    }
    int n = (name_len < outSize - 1) ? name_len : outSize - 1;
    memcpy(out, name, n);
    out[n] = '\0';
    return true;
}

// hackbox service UUID: the 16 raw bytes hackbox_detector.cpp
// matches on, spelling "hackbox-service!" in reverse ASCII. Any
// hackbox device advertising its presence will carry this UUID in
// its 128-bit service UUID list.
static const uint8_t HACKBOX_SERVICE_UUID[16] = {
    0x21, 0x65, 0x63, 0x69,
    0x76, 0x72, 0x65, 0x73,
    0x2d, 0x78, 0x6f, 0x62,
    0x6b, 0x63, 0x61, 0x68
};

// Meshtastic 128-bit service UUID (from meshtastic_detector.cpp:83-86)
static const uint8_t MESHTASTIC_SERVICE_UUID[16] = {
    0xFD, 0xEA, 0x73, 0xE2, 0xCA, 0x5D, 0xA8, 0x9F,
    0x1F, 0x46, 0xA8, 0x15, 0x18, 0xB2, 0xA1, 0x6B
};

// MeshCore 128-bit service UUID (from meshcore_detector.cpp:83-86)
static const uint8_t MESHCORE_SERVICE_UUID[16] = {
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
    0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E
};

static bool isMeshtasticAdv(esp_ble_gap_cb_param_t *p) {
    return hasService128(p, MESHTASTIC_SERVICE_UUID);
}

static bool isMeshCoreAdv(esp_ble_gap_cb_param_t *p) {
    return hasService128(p, MESHCORE_SERVICE_UUID);
}

static bool isSmarttagAdv(esp_ble_gap_cb_param_t *p) {
    // smarttag_detector.cpp:86-112 -- service UUID 0xFD5A.
    return hasService16(p, 0xFD5A);
}

static bool isTileAdv(esp_ble_gap_cb_param_t *p) {
    // tile_detector.cpp:84-110 -- Tile publishes on 0xFEED or 0xFEEC.
    return hasService16(p, 0xFEED) || hasService16(p, 0xFEEC);
}

static bool isRaybanAdv(esp_ble_gap_cb_param_t *p) {
    // rayban_detector.cpp:86-112 -- service UUID 0xFD5F.
    return hasService16(p, 0xFD5F);
}

static bool isFlipperAdv(esp_ble_gap_cb_param_t *p, const char *macStr) {
    // flipperzero_detector.cpp:127-133 -- OUI-based match.
    return macPrefixMatch(macStr, FLIPPER_MAC_PREFIXES, FLIPPER_MAC_PREFIX_COUNT);
}

static bool isAxonAdv(esp_ble_gap_cb_param_t *p, const char *macStr) {
    // axon_detector.cpp:88-90 -- single OUI 00:25:df.
    return strncasecmp(macStr, AXON_MAC_PREFIX, 8) == 0;
}

static bool isSkimmerAdv(esp_ble_gap_cb_param_t *p) {
    // cardskimmer_detector.cpp:89-96 -- exact advertised name match
    // against the three HC-series Bluetooth modules found in cheap
    // commodity card skimmers.
    char name[33];
    if (!getAdvName(p, name, sizeof(name))) return false;
    return strcmp(name, "HC-03") == 0 ||
           strcmp(name, "HC-05") == 0 ||
           strcmp(name, "HC-06") == 0;
}

static bool isHackboxAdv(esp_ble_gap_cb_param_t *p) {
    // hackbox_detector.cpp:106-144 -- 128-bit service UUID match
    // against the "hackbox-service!" signature. This is what
    // another hackbox broadcasts when hackbox Advertiser is
    // running on it, so the sweep view can reveal whether there
    // is another unit in range.
    return hasService128(p, HACKBOX_SERVICE_UUID);
}

static bool isFlockAdv(esp_ble_gap_cb_param_t *p, const char *macStr) {
    // flock_detector.cpp BLE path: MAC prefix OR advertised-name pattern.
    if (macPrefixMatch(macStr, FLOCK_MAC_PREFIXES, FLOCK_MAC_PREFIX_COUNT)) {
        return true;
    }
    // Check advertised name against the Flock name patterns.
    uint8_t name_len = 0;
    uint8_t *name = esp_ble_resolve_adv_data(p->scan_rst.ble_adv,
                                             ESP_BLE_AD_TYPE_NAME_CMPL,
                                             &name_len);
    if (!name || name_len == 0) {
        name = esp_ble_resolve_adv_data(p->scan_rst.ble_adv,
                                        ESP_BLE_AD_TYPE_NAME_SHORT,
                                        &name_len);
    }
    if (name && name_len > 0 && name_len < 32) {
        char buf[33];
        memcpy(buf, name, name_len);
        buf[name_len] = '\0';
        for (int i = 0; i < FLOCK_NAME_PATTERN_COUNT; i++) {
            if (strcasestr(buf, FLOCK_NAME_PATTERNS[i])) return true;
        }
    }
    return false;
}

// Classification order matters only for dedupe: each MAC is stored
// once, under whichever category claimed it first. AirTag is checked
// first because it's the most common tracker and the match is the
// cheapest (raw byte scan, no UUID decode).
static TrackerCategory classify(esp_ble_gap_cb_param_t *p, const char *macStr) {
    if (isAirtagAdv(p))          return TRK_AIRTAG;
    if (isSmarttagAdv(p))        return TRK_SMARTTAG;
    if (isTileAdv(p))            return TRK_TILE;
    if (isRaybanAdv(p))          return TRK_RAYBAN;
    if (isAxonAdv(p, macStr))    return TRK_AXON;
    if (isFlipperAdv(p, macStr)) return TRK_FLIPPER;
    if (isFlockAdv(p, macStr))   return TRK_FLOCK;
    // hackbox UUID check is more specific than the name-based
    // skimmer check and effectively free (128-bit UUID walk), so it
    // goes first. Skimmer check last because it resolves the adv
    // name twice in the same scan callback if Flock already got
    // there via the name fallback; cheap but worth avoiding when
    // faster matches exist.
    if (isMeshtasticAdv(p))      return TRK_MESHTASTIC;
    if (isMeshCoreAdv(p))        return TRK_MESHCORE;
    if (isHackboxAdv(p))         return TRK_HACKBOX;
    if (isSkimmerAdv(p))         return TRK_SKIMMER;
    return TRK_NONE;
}

// ============================================================
// Hit storage + threat score
// ============================================================

static int findHitByMac(const uint8_t *bda) {
    if (!state) return -1;
    for (int i = 0; i < state->hitCount; i++) {
        if (memcmp(state->hits[i].mac, bda, 6) == 0) return i;
    }
    return -1;
}

static void recomputeThreat() {
    if (!state) return;
    // Recount everything from the hit array (needed after aging removes entries)
    memset(state->categoryCounts, 0, sizeof(state->categoryCounts));
    state->persistentCount = 0;
    for (int i = 0; i < state->hitCount; i++) {
        uint8_t cat = state->hits[i].category;
        if (cat < TRK_COUNT) state->categoryCounts[cat]++;
        if (state->hits[i].persistent) state->persistentCount++;
    }
    int t = 0;
    for (int i = 0; i < state->hitCount; i++) {
        uint8_t cat = state->hits[i].category;
        if (cat < TRK_COUNT) {
            // Persistent devices (following you 5+ min) get 3x weight
            int w = CATEGORY_WEIGHT[cat];
            if (state->hits[i].persistent) w *= 3;
            t += w;
        }
    }
    if (t > 99) t = 99;
    state->threatScore = t;
}

// Remove devices not seen in STALE_TIMEOUT_MS, compact the array.
static void ageOutStaleHits() {
    if (!state) return;
    unsigned long now = millis();
    int dst = 0;
    for (int src = 0; src < state->hitCount; src++) {
        if ((now - state->hits[src].lastSeen) < STALE_TIMEOUT_MS) {
            if (dst != src) state->hits[dst] = state->hits[src];
            dst++;
        }
    }
    if (dst < state->hitCount) {
        state->hitCount = dst;
        recomputeThreat();
        state->needsRedraw = true;
    }
}

// Check all hits for persistent status (seen for 5+ minutes).
static void checkPersistent() {
    if (!state) return;
    unsigned long now = millis();
    bool changed = false;
    for (int i = 0; i < state->hitCount; i++) {
        if (!state->hits[i].persistent &&
            (now - state->hits[i].firstSeen) >= PERSISTENT_MS) {
            state->hits[i].persistent = true;
            changed = true;
        }
    }
    if (changed) {
        recomputeThreat();
        state->needsRedraw = true;
    }
}

// Emit one sweep row on the serial console for the ck42x AIO web
// interface to parse. Format:
//   TRK,<category>,<mac>,<rssi_dbm>,<age_ms_when_seen>
// Called once per *new unique* hit. Updates to an already-known MAC
// do not re-emit, to keep the stream from flooding the serial link
// on continuous scans.
static void emitHitLine(const TrackerHit &h) {
    if (h.category >= TRK_COUNT) return;
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4], h.mac[5]);
    unsigned long age = (h.lastSeen >= state->scanStartedAt)
        ? (h.lastSeen - state->scanStartedAt)
        : 0;
    Serial.printf("TRK,%s,%s,%d,%lu\n",
                  CATEGORY_WIRE[h.category], macStr, (int)h.rssi, age);
}

static void addOrUpdateHit(esp_ble_gap_cb_param_t *p, TrackerCategory cat) {
    if (!state) return;
    uint8_t *bda = p->scan_rst.bda;
    int existing = findHitByMac(bda);
    if (existing >= 0) {
        state->hits[existing].rssi = p->scan_rst.rssi;
        state->hits[existing].lastSeen = millis();
        return;
    }
    if (state->hitCount >= MAX_HITS) return;
    unsigned long now = millis();
    TrackerHit &h = state->hits[state->hitCount];
    memcpy(h.mac, bda, 6);
    h.category = (uint8_t)cat;
    h.rssi = p->scan_rst.rssi;
    h.firstSeen = now;
    h.lastSeen = now;
    h.persistent = false;
    state->hitCount++;
    if (cat < TRK_COUNT) state->categoryCounts[cat]++;
    recomputeThreat();
    emitHitLine(h);
    state->needsRedraw = true;

    // NeoPixel flash: red for high-threat, yellow for low-threat
    uint8_t w = (cat < TRK_COUNT) ? CATEGORY_WEIGHT[cat] : 5;
    if (w >= 15) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    } else {
        pixels.setPixelColor(0, pixels.Color(255, 140, 0));
    }
    pixels.show();
}

// ============================================================
// GAP callback
// ============================================================

static void gapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    if (!state) return;
    switch (event) {
        case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
            if (param->scan_param_cmpl.status == ESP_BT_STATUS_SUCCESS) {
                state->isScanning = true;
                esp_ble_gap_start_scanning(SCAN_WINDOW_SEC);
                state->scanStartedAt = millis();
            }
            break;
        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
            if (param->scan_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                state->isScanning = false;
            }
            break;
        case ESP_GAP_BLE_SCAN_RESULT_EVT: {
            if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
                char macStr[18];
                bdaToStr(param->scan_rst.bda, macStr);
                TrackerCategory cat = classify(param, macStr);
                if (cat != TRK_NONE) {
                    addOrUpdateHit(param, cat);
                }
            } else if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
                // End of a scan window. Restart immediately so the
                // sweep runs continuously until the user leaves.
                state->isScanning = true;
                esp_ble_gap_start_scanning(SCAN_WINDOW_SEC);
                state->scanStartedAt = millis();
            }
            break;
        }
        case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
            state->isScanning = false;
            break;
        default:
            break;
    }
}

bool trackerSweepClassifyAdv(esp_ble_gap_cb_param_t *param,
                             TrackerAdvMatch *out) {
    if (!param || !out) return false;
    if (param->scan_rst.search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) return false;

    char macStr[18];
    bdaToStr(param->scan_rst.bda, macStr);
    TrackerCategory cat = classify(param, macStr);
    if (cat == TRK_NONE || cat >= TRK_COUNT) return false;

    out->category = (uint8_t)cat;
    out->label = CATEGORY_NAME[cat];
    out->wire = CATEGORY_WIRE[cat];
    out->weight = CATEGORY_WEIGHT[cat];
    return true;
}

// ============================================================
// Drawing
// ============================================================

static void drawDashboard() {
    if (!state) return;
    u8g2.clearBuffer();

    // Threat score banner. Big font so the number is readable at
    // arm's length. At score >= 50 the banner inverts every half
    // second so the user can tell "this is bad" without reading.
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "TRACKER SWEEP");

    char scoreStr[16];
    snprintf(scoreStr, sizeof(scoreStr), "T:%d", state->threatScore);
    int scoreX = 128 - u8g2.getStrWidth(scoreStr);
    if (state->threatScore >= 50 && !state->scoreBlinkOn) {
        // Inverted: draw a filled box behind, text in clear.
        int w = u8g2.getStrWidth(scoreStr) + 2;
        u8g2.drawBox(scoreX - 1, 1, w, 10);
        u8g2.setDrawColor(0);
        u8g2.drawStr(scoreX, 10, scoreStr);
        u8g2.setDrawColor(1);
    } else {
        u8g2.drawStr(scoreX, 10, scoreStr);
    }
    u8g2.drawHLine(0, 12, 128);

    // Category counts in two columns with 7px row height to fit 11
    // categories. Left col: personal trackers. Right col: infra + mesh.
    u8g2.setFont(u8g2_font_5x8_tr);

    struct Row { int cat; int x; int y; };
    Row rows[] = {
        { TRK_AIRTAG,      0, 20 },
        { TRK_SMARTTAG,    0, 27 },
        { TRK_TILE,        0, 34 },
        { TRK_FLIPPER,     0, 41 },
        { TRK_SKIMMER,     0, 48 },
        { TRK_RAYBAN,     66, 20 },
        { TRK_AXON,       66, 27 },
        { TRK_FLOCK,      66, 34 },
        { TRK_MESHTASTIC, 66, 41 },
        { TRK_MESHCORE,   66, 48 }
    };

    char line[20];
    for (unsigned int i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        snprintf(line, sizeof(line), "%s:%d",
                 CATEGORY_NAME[rows[i].cat],
                 state->categoryCounts[rows[i].cat]);
        u8g2.drawStr(rows[i].x, rows[i].y, line);
    }

    // Bottom status: unique count, persistent count (! = following you), elapsed
    char total[28];
    unsigned long elapsed = (millis() - state->scanStartedAt) / 1000;
    if (state->persistentCount > 0) {
        snprintf(total, sizeof(total), "U:%d !%d %lus",
                 state->hitCount, state->persistentCount, elapsed);
    } else {
        snprintf(total, sizeof(total), "U:%d %lus", state->hitCount, elapsed);
    }
    u8g2.drawStr(0, 55, total);

    u8g2.drawStr(0, 62, "C=Reset R=List L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// Short category label for the drill-down list. Three chars keeps
// rows narrow enough that the MAC still fits on a 128 px wide line
// using the 5x8 font (~25 chars total per line).
static const char *CATEGORY_SHORT[TRK_COUNT] = {
    "AIR",  // AirTag
    "SMT",  // SmartTag
    "TIL",  // Tile
    "FLP",  // Flipper
    "RAY",  // Ray-Ban
    "AXN",  // Axon
    "FLK",  // Flock
    "SKM",  // Skimmer
    "BEE",  // hackbox
    "MSH",  // Meshtastic
    "MCR"   // MeshCore
};

static void drawListView() {
    if (!state) return;
    u8g2.clearBuffer();

    // Header row: title on the left, total count on the right so the
    // user always knows how big the list is even when scrolled deep.
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "HITS");
    char countStr[16];
    snprintf(countStr, sizeof(countStr), "%d/%d",
             state->hitCount, MAX_HITS);
    int countX = 128 - u8g2.getStrWidth(countStr);
    u8g2.drawStr(countX, 10, countStr);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (state->hitCount == 0) {
        u8g2.drawStr(0, 28, "No trackers seen yet.");
        u8g2.drawStr(0, 38, "Scan is live.");
        u8g2.drawStr(0, 62, "R=Back L=Exit");
        u8g2.sendBuffer();
        displayMirrorSend(u8g2);
        return;
    }

    // Five visible rows at y=22, 30, 38, 46, 54. Each row is:
    //   "> CAT aabbccddeeff -42 9s"
    //       3   12           4  4   = 23 chars, fits in 128 px.
    const int ROWS_VISIBLE = 5;
    int start = state->listScroll;
    if (start < 0) start = 0;
    if (start > state->hitCount - 1) start = state->hitCount - 1;

    for (int r = 0; r < ROWS_VISIBLE; r++) {
        int idx = start + r;
        if (idx >= state->hitCount) break;
        const TrackerHit &h = state->hits[idx];

        const char *catLabel = (h.category < TRK_COUNT)
            ? CATEGORY_SHORT[h.category] : "???";

        // Seconds since last seen, clamped to 99s display.
        unsigned long ageS = (millis() - h.lastSeen) / 1000;
        if (ageS > 99) ageS = 99;

        // '!' prefix for persistent (following you) devices
        char line[28];
        snprintf(line, sizeof(line), "%c%s%c%02x%02x%02x%02x%02x%02x %d %lus",
                 (idx == state->listSelected) ? '>' : ' ',
                 catLabel,
                 h.persistent ? '!' : ' ',
                 h.mac[0], h.mac[1], h.mac[2],
                 h.mac[3], h.mac[4], h.mac[5],
                 (int)h.rssi, ageS);
        u8g2.drawStr(0, 22 + (r * 8), line);
    }

    // Scroll indicator on the right edge: a filled rectangle whose
    // vertical position reflects the scroll offset as a fraction of
    // total hits. Only drawn when the list actually needs scrolling.
    if (state->hitCount > ROWS_VISIBLE) {
        int barX = 125;
        int barY = 14;
        int barH = 48;
        u8g2.drawFrame(barX, barY, 3, barH);
        int thumbH = (barH * ROWS_VISIBLE) / state->hitCount;
        if (thumbH < 3) thumbH = 3;
        int maxTravel = barH - thumbH;
        int maxStart = state->hitCount - ROWS_VISIBLE;
        int thumbY = barY + (maxStart > 0
            ? (state->listScroll * maxTravel) / maxStart
            : 0);
        u8g2.drawBox(barX, thumbY, 3, thumbH);
    }

    u8g2.drawStr(0, 62, "U/D=Scroll R=Back L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void drawSweep() {
    if (!state) return;
    if (state->currentView == VIEW_LIST) {
        drawListView();
    } else {
        drawDashboard();
    }
}

// ============================================================
// Public entry points
// ============================================================

void trackingSweepSetup() {
    // Allocate the full state block on the heap. Freed in
    // trackingSweepCleanup(). If malloc fails we bail to a degraded
    // state that still paints the UI but never records hits --
    // better than crashing.
    if (!state) {
        state = (TrackerSweepState *)calloc(1, sizeof(TrackerSweepState));
    }
    if (state) {
        state->scoreBlinkOn = true;
        state->needsRedraw = true;
        state->scanStartedAt = millis();
    }

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    // Paint a stub frame immediately so the user sees the app start
    // before BLE init completes.
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "TRACKER SWEEP");
    u8g2.drawHLine(0, 12, 128);
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 30, state ? "Starting BLE scan..."
                               : "ERR: out of memory");
    u8g2.drawStr(0, 62, "L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);

    initBLE();
    esp_ble_gap_register_callback(gapCallback);
    // sweep_scan_params is const so it can live in .rodata; the
    // ESP-IDF API wants a non-const pointer but does not modify it.
    esp_ble_gap_set_scan_params((esp_ble_scan_params_t *)&sweep_scan_params);
    bleInitialized = true;

    // Session banner for the ck42x AIO web interface. A connected
    // Web Serial client scans for this header string to auto-switch
    // into the Tracker Sweep parser mode. Keep the version number
    // stable unless the wire format below actually changes.
    Serial.println();
    Serial.println("# hackbox tracker sweep v1");
    Serial.println("# format: TRK,category,mac,rssi_dbm,age_ms");
    Serial.println("# categories: airtag smarttag tile flipper rayban axon flock skimmer hackbox meshtastic meshcore");
}

void trackingSweepLoop() {
    if (!bleInitialized || !state) return;

    unsigned long now = millis();
    const unsigned long DEBOUNCE_MS = 150;

    bool centerDown = digitalRead(BUTTON_PIN_CENTER) == LOW;
    bool rightDown  = digitalRead(BUTTON_PIN_RIGHT)  == LOW;
    bool upDown     = digitalRead(BUTTON_PIN_UP)     == LOW;
    bool downDown   = digitalRead(BUTTON_PIN_DOWN)   == LOW;

    // Edge detection for RIGHT (view toggle) and CENTER (reset).
    // Both are tracked unconditionally regardless of current view so
    // the prev flags never fall out of sync with the physical button
    // state -- otherwise a press held across a view switch could
    // produce a stale edge when the user comes back.
    bool rightEdge  = rightDown  && !state->rightPrev;
    bool centerEdge = centerDown && !state->centerPrev;
    state->rightPrev  = rightDown;
    state->centerPrev = centerDown;

    // RIGHT: toggle between dashboard and drill-down list view.
    // LEFT stays reserved for the framework app-exit.
    if (rightEdge) {
        state->currentView = (state->currentView == VIEW_DASHBOARD)
            ? VIEW_LIST : VIEW_DASHBOARD;
        if (state->currentView == VIEW_LIST) {
            state->listSelected = 0;
            state->listScroll = 0;
        }
        state->needsRedraw = true;
    }

    if (state->currentView == VIEW_DASHBOARD) {
        // CENTER: reset the sweep and restart the elapsed timer.
        if (centerEdge) {
            state->hitCount = 0;
            memset(state->categoryCounts, 0, sizeof(state->categoryCounts));
            state->threatScore = 0;
            state->scanStartedAt = now;
            // Re-emit the session banner so any connected web client
            // treats this as a fresh sweep session rather than
            // appending to the previous hit list.
            Serial.println();
            Serial.println("# hackbox tracker sweep v1");
            Serial.println("# format: TRK,category,mac,rssi_dbm,age_ms");
            Serial.println("# RESCAN");
            state->needsRedraw = true;
        }
    } else {
        // VIEW_LIST: UP/DOWN scrolls the selection. Scroll offset
        // tracks the selection with a 5-row visible window.
        const int ROWS_VISIBLE = 5;
        if (upDown && (now - state->lastUp) > DEBOUNCE_MS) {
            state->lastUp = now;
            if (state->listSelected > 0) {
                state->listSelected--;
                if (state->listSelected < state->listScroll) {
                    state->listScroll = state->listSelected;
                }
                state->needsRedraw = true;
            }
        }
        if (downDown && (now - state->lastDown) > DEBOUNCE_MS) {
            state->lastDown = now;
            if (state->listSelected < state->hitCount - 1) {
                state->listSelected++;
                if (state->listSelected >= state->listScroll + ROWS_VISIBLE) {
                    state->listScroll = state->listSelected - (ROWS_VISIBLE - 1);
                }
                state->needsRedraw = true;
            }
        }
    }
    // LEFT is owned by the framework (app-exit). Don't read it.

    // Periodic aging: drop stale devices, check for persistent trackers
    if ((now - state->lastAgeCheck) > AGE_CHECK_MS) {
        state->lastAgeCheck = now;
        ageOutStaleHits();
        checkPersistent();
        // Fade NeoPixel back to off between new detections
        pixels.setPixelColor(0, 0);
        pixels.show();
    }

    // Blink the score banner if threat is high. Only drives redraw
    // in dashboard view; the list view does not depend on the blink
    // state so we skip the wakeup there.
    if (state->currentView == VIEW_DASHBOARD &&
        state->threatScore >= 50 &&
        (now - state->lastBlinkToggle) > BLINK_INTERVAL_MS) {
        state->lastBlinkToggle = now;
        state->scoreBlinkOn = !state->scoreBlinkOn;
        state->needsRedraw = true;
    }

    // Redraw on a timer so the "scanning Ns" counter on the dashboard
    // and the age field in the list both tick forward even when no
    // new hits are coming in.
    if (state->needsRedraw || (now - state->lastRedraw) > REDRAW_INTERVAL_MS) {
        drawSweep();
        state->lastRedraw = now;
        state->needsRedraw = false;
    }
}

void trackingSweepCleanup() {
    // Shared BLE teardown -- same helper the per-device detectors
    // use in their cleanup functions. Releases the controller and
    // bluedroid stack so the next app gets a clean slate.
    if (bleInitialized) {
        esp_ble_gap_stop_scanning();
        cleanupBLE();
        bleInitialized = false;
    }
    if (state) {
        free(state);
        state = nullptr;
    }
}
