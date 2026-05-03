/*
    hackbox AIO Find Mode

    Passive combo locator for the common "what is near me and where is it"
    workflow. It time-slices WiFi promiscuous camera fingerprinting with BLE
    tracker/security signatures, then lets the user lock onto the strongest
    target with live RSSI and serial CSV.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#include "../include/aio_find_mode.h"
#include "../include/about.h"
#include "../include/camera_detector.h"
#include "../include/display_mirror.h"
#include "../include/neopixel.h"
#include "../include/radio_manager.h"
#include "../include/session_log.h"
#include "../include/setting.h"
#include "../include/tracking_sweep.h"
#include "esp_wifi.h"
#include "esp_gap_ble_api.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include <Adafruit_NeoPixel.h>
#include <Arduino.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;

namespace {

enum AioPhase : uint8_t {
    AIO_PHASE_WIFI = 0,
    AIO_PHASE_BLE
};

enum AioView : uint8_t {
    AIO_VIEW_DASH = 0,
    AIO_VIEW_LIST,
    AIO_VIEW_LOCATE
};

enum AioKind : uint8_t {
    AIO_KIND_CAMERA = 0,
    AIO_KIND_TRACKER,
    AIO_KIND_SECURITY,
    AIO_KIND_MESH,
    AIO_KIND_DEVICE
};

struct AioHit {
    uint8_t mac[6];
    uint8_t kind;
    uint8_t confidence;
    uint8_t weight;
    uint8_t evidence;
    int8_t rssi;
    int8_t bestRssi;
    uint8_t channel;
    uint16_t samples;
    uint16_t dataFrames;
    unsigned long firstSeen;
    unsigned long lastSeen;
    unsigned long lastSerial;
    bool persistent;
    bool loggedStrong;
    char label[14];
    char wire[14];
    char name[17];
};

struct AioFindState {
    AioHit hits[56];
    int hitCount;
    int selectedIndex;
    int scrollOffset;
    int lockedIndex;
    uint8_t view;
    uint8_t phase;
    uint8_t currentChannel;
    bool wifiActive;
    bool bleActive;
    bool bleScanning;
    bool rightPrev;
    bool centerPrev;
    bool csvEnabled;
    bool needsRedraw;
    bool logPending;
    char logCategory[16];
    char logDetail[32];
    unsigned long phaseStarted;
    unsigned long scanStarted;
    unsigned long lastHop;
    unsigned long lastDraw;
    unsigned long lastPrune;
    unsigned long lastCsv;
    unsigned long lastNeo;
    unsigned long lastUp;
    unsigned long lastDown;
    uint32_t wifiFrames;
    uint32_t wifiMatches;
    uint32_t bleFrames;
    uint32_t bleMatches;
};

static AioFindState *state = nullptr;

static const unsigned long WIFI_PHASE_MS = 9000;
static const unsigned long BLE_PHASE_MS = 7000;
static const unsigned long CHANNEL_HOP_MS = 320;
static const unsigned long DRAW_MS = 250;
static const unsigned long PRUNE_MS = 5000;
static const unsigned long STALE_MS = 120000;
static const unsigned long PERSISTENT_MS = 300000;
static const unsigned long SERIAL_SCAN_MS = 1500;
static const unsigned long CSV_MS = 500;
static const unsigned long BUTTON_REPEAT_MS = 180;
static const uint32_t BLE_SCAN_WINDOW_SEC = 5;

static const esp_ble_scan_params_t AIO_SCAN_PARAMS = {
    .scan_type          = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval      = 0x80,
    .scan_window        = 0x70,
    .scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE
};

static void aioWifiSniffer(void *buf, wifi_promiscuous_pkt_type_t type);
static void aioGapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

static void copyText(char *dst, size_t len, const char *src) {
    if (!dst || len == 0) return;
    if (!src) src = "";
    strncpy(dst, src, len - 1);
    dst[len - 1] = '\0';
}

static const char *phaseName() {
    if (!state) return "?";
    return state->phase == AIO_PHASE_WIFI ? "wifi" : "ble";
}

static const char *phaseDisplay() {
    if (!state) return "?";
    return state->phase == AIO_PHASE_WIFI ? "WIFI" : "BLE";
}

static const char *kindShort(uint8_t kind) {
    switch (kind) {
        case AIO_KIND_CAMERA:   return "CAM";
        case AIO_KIND_TRACKER:  return "TRK";
        case AIO_KIND_SECURITY: return "SEC";
        case AIO_KIND_MESH:     return "MESH";
        default:                return "DEV";
    }
}

static void macToStr(const uint8_t *mac, char *out, bool lower) {
    if (lower) {
        snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

static void formatMac(const uint8_t *mac, char *out, size_t outLen, bool lower) {
    char raw[18];
    macToStr(mac, raw, lower);
    if (privacyModeEnabled) {
        maskMAC(raw, out);
    } else {
        copyText(out, outLen, raw);
    }
}

static void compactNumber(uint32_t value, char *out, size_t outLen) {
    if (value >= 1000000UL) {
        snprintf(out, outLen, "%luM", (unsigned long)(value / 1000000UL));
    } else if (value >= 1000UL) {
        snprintf(out, outLen, "%luk", (unsigned long)(value / 1000UL));
    } else {
        snprintf(out, outLen, "%lu", (unsigned long)value);
    }
}

static uint8_t proximityBonus(int8_t rssi) {
    if (rssi >= -45) return 18;
    if (rssi >= -55) return 14;
    if (rssi >= -65) return 10;
    if (rssi >= -75) return 6;
    if (rssi >= -85) return 3;
    return 0;
}

static uint8_t proximityWidth(int8_t rssi, uint8_t maxWidth) {
    int v = (int)rssi + 95;
    if (v < 0) v = 0;
    if (v > 60) v = 60;
    return (uint8_t)((v * maxWidth) / 60);
}

static uint8_t computeConfidence(uint8_t baseScore,
                                 int8_t rssi,
                                 uint16_t samples,
                                 uint8_t evidence,
                                 bool persistent) {
    uint16_t score = baseScore;
    if (samples >= 3) score += 4;
    if (samples >= 10) score += 5;
    if (evidence & CAMERA_FRAME_TRAFFIC) score += 5;
    if (evidence & CAMERA_FRAME_NAME) score += 4;
    if (persistent) score += 8;
    score += proximityBonus(rssi) / 2;
    if (score > 99) score = 99;
    return (uint8_t)score;
}

static int hitRank(const AioHit &h) {
    int rank = h.confidence + h.weight + proximityBonus(h.rssi);
    if (h.persistent) rank += 12;
    if (h.samples >= 8) rank += 5;
    return rank;
}

static int bestIndex() {
    if (!state || state->hitCount == 0) return -1;
    int best = -1;
    int bestRank = -1;
    for (int i = 0; i < state->hitCount; i++) {
        int rank = hitRank(state->hits[i]);
        if (rank > bestRank) {
            bestRank = rank;
            best = i;
        }
    }
    return best;
}

static int findHit(const uint8_t *mac, uint8_t kind) {
    if (!state) return -1;
    for (int i = 0; i < state->hitCount; i++) {
        if (state->hits[i].kind == kind &&
            memcmp(state->hits[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static int allocateSlot(uint8_t incomingKind, uint8_t incomingScore, uint8_t incomingWeight) {
    if (!state) return -1;
    const int maxHits = (int)(sizeof(state->hits) / sizeof(state->hits[0]));
    if (state->hitCount < maxHits) {
        return state->hitCount++;
    }

    unsigned long now = millis();
    int victim = -1;
    int victimRank = 9999;
    int incomingRank = incomingScore + incomingWeight;
    for (int i = 0; i < state->hitCount; i++) {
        if (i == state->lockedIndex) continue;
        if (now - state->hits[i].lastSeen > STALE_MS) return i;
        int rank = hitRank(state->hits[i]);
        if (rank < victimRank) {
            victimRank = rank;
            victim = i;
        }
    }

    if (victim >= 0 && incomingRank >= victimRank) {
        return victim;
    }
    (void)incomingKind;
    return -1;
}

static void queueLog(const char *category, const char *detail) {
    if (!state || state->logPending) return;
    copyText(state->logCategory, sizeof(state->logCategory), category);
    copyText(state->logDetail, sizeof(state->logDetail), detail);
    state->logPending = true;
}

static void flushLog() {
    if (!state || !state->logPending) return;
    sessionLogEvent(state->logCategory, state->logDetail);
    state->logPending = false;
}

static void emitHitLine(const AioHit &h, const char *eventName) {
    char mac[20];
    formatMac(h.mac, mac, sizeof(mac), true);
    Serial.printf("AIO,%s,%lu,%s,%s,%s,%s,%d,%u,%u,%u\n",
                  eventName,
                  (unsigned long)(millis() - state->scanStarted),
                  phaseName(),
                  kindShort(h.kind),
                  h.wire,
                  mac,
                  (int)h.rssi,
                  (unsigned int)h.confidence,
                  (unsigned int)h.channel,
                  (unsigned int)h.samples);
}

static uint8_t kindFromTracker(const char *wire) {
    if (!wire) return AIO_KIND_DEVICE;
    if (strcmp(wire, "airtag") == 0 ||
        strcmp(wire, "smarttag") == 0 ||
        strcmp(wire, "tile") == 0) {
        return AIO_KIND_TRACKER;
    }
    if (strcmp(wire, "axon") == 0 ||
        strcmp(wire, "flock") == 0 ||
        strcmp(wire, "skimmer") == 0 ||
        strcmp(wire, "rayban") == 0) {
        return AIO_KIND_SECURITY;
    }
    if (strcmp(wire, "meshtastic") == 0 ||
        strcmp(wire, "meshcore") == 0) {
        return AIO_KIND_MESH;
    }
    return AIO_KIND_DEVICE;
}

static uint8_t trackerBaseScore(const TrackerAdvMatch &match) {
    uint16_t score = 42 + (uint16_t)match.weight * 2;
    if (strcmp(match.wire, "airtag") == 0 ||
        strcmp(match.wire, "smarttag") == 0) {
        score += 6;
    }
    if (score > 92) score = 92;
    return (uint8_t)score;
}

static void updateHit(uint8_t kind,
                      const char *label,
                      const char *wire,
                      const uint8_t *mac,
                      int8_t rssi,
                      uint8_t channel,
                      uint8_t baseScore,
                      uint8_t weight,
                      uint8_t evidence,
                      const char *name,
                      bool dataFrame) {
    if (!state || !mac) return;

    int idx = findHit(mac, kind);
    bool fresh = idx < 0;
    if (fresh) {
        idx = allocateSlot(kind, baseScore, weight);
        if (idx < 0) return;
        memset(&state->hits[idx], 0, sizeof(AioHit));
        memcpy(state->hits[idx].mac, mac, 6);
        state->hits[idx].kind = kind;
        state->hits[idx].firstSeen = millis();
        state->hits[idx].bestRssi = rssi;
        state->hits[idx].lastSerial = 0;
        copyText(state->hits[idx].label, sizeof(state->hits[idx].label), label);
        copyText(state->hits[idx].wire, sizeof(state->hits[idx].wire), wire);
    }

    AioHit &h = state->hits[idx];
    unsigned long now = millis();
    if (h.samples < 65535) h.samples++;
    if (dataFrame && h.dataFrames < 65535) h.dataFrames++;
    if (fresh || rssi > h.bestRssi) h.bestRssi = rssi;
    h.rssi = rssi;
    h.channel = channel;
    h.weight = weight;
    h.evidence |= evidence;
    h.lastSeen = now;
    if (name && name[0]) copyText(h.name, sizeof(h.name), name);
    if ((now - h.firstSeen) >= PERSISTENT_MS) h.persistent = true;
    h.confidence = computeConfidence(baseScore, rssi, h.samples, h.evidence, h.persistent);

    if (kind == AIO_KIND_CAMERA) {
        state->wifiMatches++;
    } else {
        state->bleMatches++;
    }

    bool emittedSerial = false;
    if (fresh) {
        emitHitLine(h, "new");
        emittedSerial = true;
        char detail[32];
        snprintf(detail, sizeof(detail), "%s %s %ddBm",
                 kindShort(h.kind), h.label, (int)h.rssi);
        queueLog("aio_hit", detail);
    } else if (now - h.lastSerial >= SERIAL_SCAN_MS) {
        emitHitLine(h, "scan");
        emittedSerial = true;
    }
    if (emittedSerial) h.lastSerial = now;

    if (!h.loggedStrong && h.confidence >= 85) {
        h.loggedStrong = true;
        char detail[32];
        snprintf(detail, sizeof(detail), "%s %s conf%u",
                 kindShort(h.kind), h.label, (unsigned int)h.confidence);
        queueLog("aio_strong", detail);
    }

    state->needsRedraw = true;
}

static void updateCameraHit(const CameraFrameMatch &match) {
    uint8_t evidence = match.evidence;
    uint8_t weight = 18;
    updateHit(AIO_KIND_CAMERA,
              match.brand ? match.brand : "Camera",
              "camera",
              match.mac,
              match.rssi,
              match.channel,
              match.baseScore,
              weight,
              evidence,
              match.ssid,
              match.isData);
}

static void updateBleHit(esp_ble_gap_cb_param_t *param, const TrackerAdvMatch &match) {
    uint8_t kind = kindFromTracker(match.wire);
    updateHit(kind,
              match.label ? match.label : "BLE",
              match.wire ? match.wire : "ble",
              param->scan_rst.bda,
              param->scan_rst.rssi,
              0,
              trackerBaseScore(match),
              match.weight,
              0,
              nullptr,
              false);
}

static bool lockedValid() {
    return state && state->lockedIndex >= 0 && state->lockedIndex < state->hitCount;
}

static bool lockedIsCamera() {
    return lockedValid() && state->hits[state->lockedIndex].kind == AIO_KIND_CAMERA;
}

static void stopWifiPhase() {
    if (!state || !state->wifiActive) return;
    state->wifiActive = false;
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
}

static void stopBlePhase() {
    if (!state || !state->bleActive) return;
    state->bleActive = false;
    state->bleScanning = false;
    esp_ble_gap_stop_scanning();
    cleanupBLE();
}

static void setWifiChannel(uint8_t channel) {
    if (!state || !state->wifiActive) return;
    if (channel < 1 || channel > 13) channel = 1;
    if (state->currentChannel != channel) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        state->currentChannel = channel;
        state->needsRedraw = true;
    }
}

static void startWifiPhase() {
    if (!state) return;
    if (state->phase == AIO_PHASE_WIFI && state->wifiActive) return;
    stopBlePhase();

    state->phase = AIO_PHASE_WIFI;
    state->phaseStarted = millis();
    state->lastHop = state->phaseStarted;
    uint8_t startChannel = lockedIsCamera() ? state->hits[state->lockedIndex].channel : 1;
    if (startChannel < 1 || startChannel > 13) startChannel = 1;
    state->currentChannel = startChannel;

    if (!initWiFi(WIFI_MODE_AP)) {
        state->needsRedraw = true;
        return;
    }

    state->wifiActive = true;
    esp_wifi_set_promiscuous_rx_cb(aioWifiSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(state->currentChannel, WIFI_SECOND_CHAN_NONE);
    state->needsRedraw = true;
}

static void startBlePhase() {
    if (!state) return;
    if (state->phase == AIO_PHASE_BLE && state->bleActive) return;
    stopWifiPhase();

    state->phase = AIO_PHASE_BLE;
    state->phaseStarted = millis();
    state->bleScanning = false;
    if (!initBLE()) {
        state->needsRedraw = true;
        return;
    }

    state->bleActive = true;
    esp_ble_gap_register_callback(aioGapCallback);
    esp_ble_gap_set_scan_params((esp_ble_scan_params_t *)&AIO_SCAN_PARAMS);
    state->needsRedraw = true;
}

static void updatePhase(unsigned long now) {
    if (!state) return;

    if (state->view == AIO_VIEW_LOCATE && lockedValid()) {
        if (lockedIsCamera()) {
            if (state->phase != AIO_PHASE_WIFI || !state->wifiActive) {
                startWifiPhase();
            }
            uint8_t channel = state->hits[state->lockedIndex].channel;
            setWifiChannel(channel);
        } else if (state->phase != AIO_PHASE_BLE || !state->bleActive) {
            startBlePhase();
        }
        return;
    }

    if (state->phase == AIO_PHASE_WIFI) {
        if (state->wifiActive && now - state->lastHop >= CHANNEL_HOP_MS) {
            uint8_t next = state->currentChannel + 1;
            if (next > 13) next = 1;
            setWifiChannel(next);
            state->lastHop = now;
        }
        if (now - state->phaseStarted >= WIFI_PHASE_MS) {
            startBlePhase();
        }
    } else {
        if (now - state->phaseStarted >= BLE_PHASE_MS) {
            startWifiPhase();
        }
    }
}

static void aioWifiSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!state || !state->wifiActive || state->phase != AIO_PHASE_WIFI) return;
    state->wifiFrames++;

    CameraFrameMatch match;
    if (!cameraDetectorClassifyPromiscPacket(buf, type, &match)) return;

    if (state->view == AIO_VIEW_LOCATE && lockedIsCamera()) {
        AioHit &locked = state->hits[state->lockedIndex];
        if (memcmp(locked.mac, match.mac, 6) != 0) return;
    }

    updateCameraHit(match);
}

static void aioGapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    if (!state || !state->bleActive || state->phase != AIO_PHASE_BLE) return;

    switch (event) {
        case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
            if (param->scan_param_cmpl.status == ESP_BT_STATUS_SUCCESS) {
                state->bleScanning = true;
                esp_ble_gap_start_scanning(BLE_SCAN_WINDOW_SEC);
            }
            break;
        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
            state->bleScanning =
                param->scan_start_cmpl.status == ESP_BT_STATUS_SUCCESS;
            break;
        case ESP_GAP_BLE_SCAN_RESULT_EVT:
            if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
                state->bleFrames++;
                TrackerAdvMatch match;
                if (trackerSweepClassifyAdv(param, &match)) {
                    updateBleHit(param, match);
                }
            } else if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
                if (state->bleActive && state->phase == AIO_PHASE_BLE) {
                    state->bleScanning = true;
                    esp_ble_gap_start_scanning(BLE_SCAN_WINDOW_SEC);
                }
            }
            break;
        case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
            state->bleScanning = false;
            break;
        default:
            break;
    }
}

static void clampSelection() {
    if (!state) return;
    if (state->hitCount <= 0) {
        state->selectedIndex = 0;
        state->scrollOffset = 0;
        return;
    }
    if (state->selectedIndex < 0) state->selectedIndex = 0;
    if (state->selectedIndex >= state->hitCount) state->selectedIndex = state->hitCount - 1;
    if (state->scrollOffset > state->selectedIndex) state->scrollOffset = state->selectedIndex;
    if (state->selectedIndex >= state->scrollOffset + 5) {
        state->scrollOffset = state->selectedIndex - 4;
    }
    if (state->scrollOffset < 0) state->scrollOffset = 0;
}

static bool buttonEdge(uint8_t pin, bool &prev) {
    bool down = digitalRead(pin) == LOW;
    bool edge = down && !prev;
    prev = down;
    return edge;
}

static bool buttonRepeat(uint8_t pin, unsigned long &last, unsigned long now) {
    if (digitalRead(pin) != LOW) return false;
    if (now - last < BUTTON_REPEAT_MS) return false;
    last = now;
    return true;
}

static void enterLocate(int idx) {
    if (!state || idx < 0 || idx >= state->hitCount) return;
    state->lockedIndex = idx;
    state->selectedIndex = idx;
    state->view = AIO_VIEW_LOCATE;
    state->csvEnabled = false;
    state->lastCsv = 0;
    state->needsRedraw = true;

    AioHit &h = state->hits[idx];
    emitHitLine(h, "lock");
    char detail[32];
    snprintf(detail, sizeof(detail), "%s %s %ddBm",
             kindShort(h.kind), h.label, (int)h.rssi);
    queueLog("aio_lock", detail);

    if (h.kind == AIO_KIND_CAMERA) {
        startWifiPhase();
        setWifiChannel(h.channel);
    } else {
        startBlePhase();
    }
}

static void handleButtons(unsigned long now) {
    if (!state) return;

    bool rightEdge = buttonEdge(BUTTON_PIN_RIGHT, state->rightPrev);
    bool centerEdge = buttonEdge(BUTTON_PIN_CENTER, state->centerPrev);
    bool up = buttonRepeat(BUTTON_PIN_UP, state->lastUp, now);
    bool down = buttonRepeat(BUTTON_PIN_DOWN, state->lastDown, now);

    if (centerEdge) {
        if (state->view == AIO_VIEW_LOCATE) {
            state->view = AIO_VIEW_LIST;
            state->lockedIndex = -1;
            state->csvEnabled = false;
        } else {
            state->view = (state->view == AIO_VIEW_DASH) ? AIO_VIEW_LIST : AIO_VIEW_DASH;
        }
        state->needsRedraw = true;
    }

    if (rightEdge) {
        if (state->view == AIO_VIEW_LOCATE && lockedValid()) {
            state->csvEnabled = !state->csvEnabled;
            Serial.printf("# AIO lock CSV %s\n", state->csvEnabled ? "on" : "off");
            Serial.println("# format: AIO,event,ms,phase,kind,label,mac,rssi_dbm,confidence,channel,samples");
        } else if (state->hitCount > 0) {
            int idx = (state->view == AIO_VIEW_DASH) ? bestIndex() : state->selectedIndex;
            enterLocate(idx);
        }
        state->needsRedraw = true;
    }

    if (up && state->hitCount > 0 && state->view != AIO_VIEW_DASH) {
        state->selectedIndex--;
        if (state->selectedIndex < 0) state->selectedIndex = state->hitCount - 1;
        clampSelection();
        if (state->view == AIO_VIEW_LOCATE) enterLocate(state->selectedIndex);
        state->needsRedraw = true;
    }

    if (down && state->hitCount > 0 && state->view != AIO_VIEW_DASH) {
        state->selectedIndex++;
        if (state->selectedIndex >= state->hitCount) state->selectedIndex = 0;
        clampSelection();
        if (state->view == AIO_VIEW_LOCATE) enterLocate(state->selectedIndex);
        state->needsRedraw = true;
    }
}

static void pruneHits(unsigned long now) {
    if (!state || now - state->lastPrune < PRUNE_MS) return;
    state->lastPrune = now;
    int dst = 0;
    int oldLocked = state->lockedIndex;
    int newLocked = -1;
    bool changed = false;

    for (int src = 0; src < state->hitCount; src++) {
        bool keep = (src == oldLocked) || ((now - state->hits[src].lastSeen) < STALE_MS);
        if (!keep) {
            changed = true;
            continue;
        }
        if (dst != src) {
            state->hits[dst] = state->hits[src];
            changed = true;
        }
        if (src == oldLocked) newLocked = dst;
        dst++;
    }

    if (changed) {
        state->hitCount = dst;
        state->lockedIndex = newLocked;
        clampSelection();
        state->needsRedraw = true;
    }
}

static void emitLockCsv(unsigned long now) {
    if (!state || !state->csvEnabled || !lockedValid()) return;
    if (now - state->lastCsv < CSV_MS) return;
    emitHitLine(state->hits[state->lockedIndex], "csv");
    state->lastCsv = now;
}

static void updateNeo(unsigned long now) {
    if (!state || now - state->lastNeo < 250) return;
    state->lastNeo = now;

    int idx = lockedValid() ? state->lockedIndex : bestIndex();
    if (idx < 0) {
        neoSetStatus(NEO_RECON);
        return;
    }

    AioHit &h = state->hits[idx];
    if (now - h.lastSeen > 4000) {
        pixels.setPixelColor(0, pixels.Color(0, 0, 40));
    } else if (h.rssi >= -50) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    } else if (h.rssi >= -62) {
        pixels.setPixelColor(0, pixels.Color(255, 120, 0));
    } else if (h.rssi >= -75) {
        pixels.setPixelColor(0, pixels.Color(160, 160, 0));
    } else {
        pixels.setPixelColor(0, pixels.Color(0, 0, 120));
    }
    pixels.show();
}

static void drawClipped(int x, int y, const char *text, int maxWidth) {
    char buf[24];
    copyText(buf, sizeof(buf), text);
    int len = strlen(buf);
    while (len > 0 && u8g2.getStrWidth(buf) > maxWidth) {
        buf[--len] = '\0';
    }
    u8g2.drawStr(x, y, buf);
}

static void drawBar(int x, int y, int w, int h, int8_t rssi) {
    u8g2.drawFrame(x, y, w, h);
    uint8_t fill = proximityWidth(rssi, w - 2);
    if (fill > 0) u8g2.drawBox(x + 1, y + 1, fill, h - 2);
}

static void drawDashboard() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "AIO FIND");
    char phase[16];
    if (state->phase == AIO_PHASE_WIFI) {
        snprintf(phase, sizeof(phase), "W ch%u", (unsigned int)state->currentChannel);
    } else {
        snprintf(phase, sizeof(phase), "BLE");
    }
    u8g2.drawStr(128 - u8g2.getStrWidth(phase), 10, phase);
    u8g2.drawHLine(0, 12, 128);

    int cam = 0, trk = 0, sec = 0, mesh = 0;
    for (int i = 0; i < state->hitCount; i++) {
        switch (state->hits[i].kind) {
            case AIO_KIND_CAMERA: cam++; break;
            case AIO_KIND_TRACKER: trk++; break;
            case AIO_KIND_SECURITY: sec++; break;
            default: mesh++; break;
        }
    }

    u8g2.setFont(u8g2_font_5x8_tr);
    char line[32];
    snprintf(line, sizeof(line), "CAM %d  TRK %d  SEC %d  OTH %d", cam, trk, sec, mesh);
    u8g2.drawStr(0, 22, line);

    int idx = bestIndex();
    if (idx >= 0) {
        AioHit &h = state->hits[idx];
        snprintf(line, sizeof(line), "%s %s conf%u",
                 kindShort(h.kind), h.label, (unsigned int)h.confidence);
        drawClipped(0, 32, line, 128);
        snprintf(line, sizeof(line), "%ddBm ch%u age%lus s%u",
                 (int)h.rssi,
                 (unsigned int)h.channel,
                 (unsigned long)((millis() - h.lastSeen) / 1000),
                 (unsigned int)h.samples);
        u8g2.drawStr(0, 42, line);
        drawBar(0, 46, 128, 8, h.rssi);
    } else {
        char w[10], b[10];
        compactNumber(state->wifiFrames, w, sizeof(w));
        compactNumber(state->bleFrames, b, sizeof(b));
        u8g2.drawStr(0, 34, "Passive scan running");
        snprintf(line, sizeof(line), "WiFi %s  BLE %s", w, b);
        u8g2.drawStr(0, 44, line);
        u8g2.drawStr(0, 54, "camera + tracker sweep");
    }

    u8g2.drawStr(0, 64, "C=list R=loc L=exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void drawList() {
    clampSelection();
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "AIO HITS");
    u8g2.drawStr(128 - u8g2.getStrWidth(phaseDisplay()), 10, phaseDisplay());
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);
    if (state->hitCount == 0) {
        u8g2.drawStr(0, 32, "No hits yet");
        u8g2.drawStr(0, 44, "Scanning both radios");
    } else {
        for (int row = 0; row < 5; row++) {
            int idx = state->scrollOffset + row;
            if (idx >= state->hitCount) break;
            AioHit &h = state->hits[idx];
            char line[32];
            snprintf(line, sizeof(line), "%c%s %-7.7s %4d %2u",
                     idx == state->selectedIndex ? '>' : ' ',
                     kindShort(h.kind),
                     h.label,
                     (int)h.rssi,
                     (unsigned int)h.confidence);
            u8g2.drawStr(0, 22 + row * 8, line);
        }
    }

    u8g2.drawStr(0, 64, "U/D sel R=loc C=dash");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void drawLocate() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    if (!lockedValid()) {
        u8g2.drawStr(0, 10, "AIO LOCATE");
        u8g2.drawHLine(0, 12, 128);
        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 34, "No target");
        u8g2.drawStr(0, 64, "C=back L=exit");
        u8g2.sendBuffer();
        displayMirrorSend(u8g2);
        return;
    }

    AioHit &h = state->hits[state->lockedIndex];
    char line[32];
    snprintf(line, sizeof(line), "LOC %s %.8s", kindShort(h.kind), h.label);
    drawClipped(0, 10, line, 106);
    snprintf(line, sizeof(line), "%s", state->csvEnabled ? "CSV" : "");
    u8g2.drawStr(128 - u8g2.getStrWidth(line), 10, line);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_6x10_tr);
    snprintf(line, sizeof(line), "%d dBm", (int)h.rssi);
    u8g2.drawStr(0, 26, line);
    snprintf(line, sizeof(line), "best %d", (int)h.bestRssi);
    u8g2.drawStr(128 - u8g2.getStrWidth(line), 26, line);
    drawBar(0, 30, 128, 10, h.rssi);

    u8g2.setFont(u8g2_font_5x8_tr);
    char mac[20];
    formatMac(h.mac, mac, sizeof(mac), false);
    snprintf(line, sizeof(line), "MAC %s", mac);
    u8g2.drawStr(0, 48, line);
    snprintf(line, sizeof(line), "conf %u ch%u s%u age%lus",
             (unsigned int)h.confidence,
             (unsigned int)h.channel,
             (unsigned int)h.samples,
             (unsigned long)((millis() - h.lastSeen) / 1000));
    u8g2.drawStr(0, 56, line);
    u8g2.drawStr(0, 64, "C=back R=csv U/D=next");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void drawCurrent() {
    if (!state) return;
    if (state->view == AIO_VIEW_LIST) {
        drawList();
    } else if (state->view == AIO_VIEW_LOCATE) {
        drawLocate();
    } else {
        drawDashboard();
    }
    state->lastDraw = millis();
    state->needsRedraw = false;
}

} // namespace

void aioFindModeSetup() {
    if (!state) {
        state = (AioFindState *)calloc(1, sizeof(AioFindState));
    }

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    if (state) {
        state->lockedIndex = -1;
        state->view = AIO_VIEW_DASH;
        state->phase = AIO_PHASE_WIFI;
        state->currentChannel = 1;
        state->scanStarted = millis();
        state->phaseStarted = state->scanStarted;
        state->needsRedraw = true;
    }

    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "AIO FIND");
    u8g2.drawHLine(0, 12, 128);
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 30, state ? "Starting passive scan..." : "ERR: out of memory");
    u8g2.drawStr(0, 64, "L=exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);

    Serial.println();
    Serial.printf("# hackbox AIO Find Mode %s\n", HACKBOX_VERSION);
    Serial.println("# passive WiFi camera + BLE tracker/security locator");
    Serial.println("# format: AIO,event,ms,phase,kind,label,mac,rssi_dbm,confidence,channel,samples");
    Serial.println("# events: new scan lock csv");

    neoSetStatus(NEO_RECON);
    if (state) startWifiPhase();
}

void aioFindModeLoop() {
    if (!state) return;

    unsigned long now = millis();
    handleButtons(now);
    pruneHits(now);
    updatePhase(now);
    emitLockCsv(now);
    updateNeo(now);
    flushLog();

    if (state->needsRedraw || now - state->lastDraw >= DRAW_MS) {
        drawCurrent();
    }
}

void aioFindModeCleanup() {
    if (!state) return;
    stopWifiPhase();
    stopBlePhase();
    neoSetStatus(NEO_IDLE);
    free(state);
    state = nullptr;
}
