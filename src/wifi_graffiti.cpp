/*
    hackbox
    hackbox custom firmware

    WiFi Graffiti
    Broadcast custom messages as WiFi SSIDs visible to everyone scanning nearby.
    Modes: Plain, L33T, =[ Border ]=, Flip (upside-down UTF-8), Marquee (scrolling)
*/

#include "../include/wifi_graffiti.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/level_system.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <DNSServer.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);

namespace {

// ===== States & Modes =====
enum GraffitiState { GRAF_INPUT, GRAF_BROADCASTING };
enum GraffitiMode  { MODE_PLAIN = 0, MODE_L33T, MODE_BORDER, MODE_FLIP, MODE_MARQUEE };

GraffitiState currentState = GRAF_INPUT;
GraffitiMode  currentMode  = MODE_PLAIN;
bool needsRedraw = true;

// ===== Message storage =====
const int MAX_SSIDS = 6;
const int SSID_MAX_LEN = 32;
char ssidLines[MAX_SSIDS][SSID_MAX_LEN + 1];
int ssidCount = 0;
char rawMessage[240];      // original input

// ===== Beacon transmission =====
uint32_t beaconsSent = 0;
unsigned long lastBeaconBatch = 0;
const unsigned long BEACON_INTERVAL = 80;
const uint8_t channels[] = {1, 6, 11};
uint8_t channelIndex = 0;

// Marquee state
int marqueeOffset = 0;
char marqueeBuf[42]; // padded message for scrolling window

// ===== Web server (heap-allocated) =====
WebServer *grafServer = nullptr;
DNSServer *grafDNS = nullptr;
esp_netif_t *graf_ap_netif = NULL;

// ===== Beacon frame builder =====
void sendGraffitiBeacon(const char *ssid, uint8_t ssidLen, uint8_t channel) {
    if (ssidLen > 32) ssidLen = 32;
    uint8_t frame[128];
    memset(frame, 0, sizeof(frame));
    int p = 0;

    frame[p++] = 0x80; frame[p++] = 0x00;
    frame[p++] = 0x00; frame[p++] = 0x00;
    memset(&frame[p], 0xFF, 6); p += 6;

    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = random(256);
    mac[0] |= 0x02; mac[0] &= 0xFE;
    memcpy(&frame[p], mac, 6); p += 6;
    memcpy(&frame[p], mac, 6); p += 6;

    uint16_t seq = random(4096) << 4;
    frame[p++] = seq & 0xFF;
    frame[p++] = (seq >> 8) & 0xFF;

    uint64_t ts = (uint64_t)esp_timer_get_time();
    memcpy(&frame[p], &ts, 8); p += 8;
    frame[p++] = 0x64; frame[p++] = 0x00;
    frame[p++] = 0x01; frame[p++] = 0x04;

    frame[p++] = 0x00;
    frame[p++] = ssidLen;
    memcpy(&frame[p], ssid, ssidLen); p += ssidLen;

    frame[p++] = 0x01; frame[p++] = 0x08;
    frame[p++] = 0x82; frame[p++] = 0x84;
    frame[p++] = 0x8b; frame[p++] = 0x96;
    frame[p++] = 0x0c; frame[p++] = 0x18;
    frame[p++] = 0x30; frame[p++] = 0x48;

    frame[p++] = 0x03; frame[p++] = 0x01; frame[p++] = channel;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, p, false);
}

// ================================================================
// MODE TRANSFORMS
// ================================================================

// --- L33T ---
void applyL33t(char *dst, const char *src, size_t dstLen) {
    size_t i = 0;
    for (; src[i] && i < dstLen - 1; i++) {
        char c = src[i];
        switch (c) {
            case 'a': case 'A': dst[i] = '4'; break;
            case 'e': case 'E': dst[i] = '3'; break;
            case 'i': case 'I': dst[i] = '1'; break;
            case 'o': case 'O': dst[i] = '0'; break;
            case 's': case 'S': dst[i] = '5'; break;
            case 't': case 'T': dst[i] = '7'; break;
            case 'l': case 'L': dst[i] = '1'; break;
            case 'b': case 'B': dst[i] = '8'; break;
            case 'g': case 'G': dst[i] = '6'; break;
            default: dst[i] = c; break;
        }
    }
    dst[i] = '\0';
}

// --- FLIP (upside-down UTF-8) ---
// Returns a pointer to the UTF-8 flip of an ASCII char.
// Result is valid until the next call with a non-mapped character.
const char* getFlipChar(char c) {
    switch (c) {
        case 'a': case 'A': return "\xc9\x90";
        case 'b': case 'B': return "q";
        case 'c': case 'C': return "\xc9\x94";
        case 'd': case 'D': return "p";
        case 'e': case 'E': return "\xc7\x9d";
        case 'f': case 'F': return "\xc9\x9f";
        case 'g': case 'G': return "\xc6\x83";
        case 'h': case 'H': return "\xc9\xa5";
        case 'i': case 'I': return "\xc4\xb1";
        case 'j': case 'J': return "\xc9\xbe";
        case 'k': case 'K': return "\xca\x9e";
        case 'l': case 'L': return "l";
        case 'm': case 'M': return "\xc9\xaf";
        case 'n': case 'N': return "u";
        case 'o': case 'O': return "o";
        case 'p': case 'P': return "d";
        case 'q': case 'Q': return "b";
        case 'r': case 'R': return "\xc9\xb9";
        case 's': case 'S': return "s";
        case 't': case 'T': return "\xca\x87";
        case 'u': case 'U': return "n";
        case 'v': case 'V': return "\xca\x8c";
        case 'w': case 'W': return "\xca\x8d";
        case 'x': case 'X': return "x";
        case 'y': case 'Y': return "\xca\x8e";
        case 'z': case 'Z': return "z";
        case '!': return "\xc2\xa1";
        case '?': return "\xc2\xbf";
        case '.': return "\xcb\x99";
        case ',': return "'";
        case '\'': return ",";
        case '(': return ")";
        case ')': return "(";
        case '[': return "]";
        case ']': return "[";
        case '<': return ">";
        case '>': return "<";
        case '6': return "9";
        case '9': return "6";
        default: return nullptr;
    }
}

// Build flipped (reversed + substituted) UTF-8 string.
// Returns byte length written (excluding NUL).
int applyFlip(char *dst, const char *src, size_t dstLen) {
    int srcLen = strlen(src);
    int pos = 0;

    // Walk source in reverse
    for (int i = srcLen - 1; i >= 0 && pos < (int)dstLen - 3; i--) {
        const char *flip = getFlipChar(src[i]);
        if (flip) {
            int flen = strlen(flip);
            if (pos + flen >= (int)dstLen - 1) break;
            memcpy(&dst[pos], flip, flen);
            pos += flen;
        } else {
            dst[pos++] = src[i];
        }
    }
    dst[pos] = '\0';
    return pos;
}

// ================================================================
// MESSAGE SPLITTING
// ================================================================

// Standard ASCII split by character count
void splitPlain(const char *msg) {
    ssidCount = 0;
    int msgLen = strlen(msg);
    if (msgLen == 0) return;

    if (msgLen <= SSID_MAX_LEN) {
        strncpy(ssidLines[0], msg, SSID_MAX_LEN);
        ssidLines[0][SSID_MAX_LEN] = '\0';
        ssidCount = 1;
        return;
    }

    const int PREFIX_LEN = 3;
    const int CHARS_PER_LINE = SSID_MAX_LEN - PREFIX_LEN;
    int offset = 0, lineNum = 1;

    while (offset < msgLen && ssidCount < MAX_SSIDS) {
        int remaining = msgLen - offset;
        int chunkLen = remaining > CHARS_PER_LINE ? CHARS_PER_LINE : remaining;
        snprintf(ssidLines[ssidCount], SSID_MAX_LEN + 1, "%d: %.*s",
                 lineNum, chunkLen, &msg[offset]);
        offset += chunkLen;
        lineNum++;
        ssidCount++;
    }
}

// Byte-aware split for UTF-8 content (flip mode)
void splitBytes(const char *msg, int msgBytes) {
    ssidCount = 0;
    if (msgBytes == 0) return;

    if (msgBytes <= SSID_MAX_LEN) {
        memcpy(ssidLines[0], msg, msgBytes);
        ssidLines[0][msgBytes] = '\0';
        ssidCount = 1;
        return;
    }

    const int PREFIX_LEN = 3;
    const int BYTES_PER_LINE = SSID_MAX_LEN - PREFIX_LEN;
    int offset = 0, lineNum = 1;

    while (offset < msgBytes && ssidCount < MAX_SSIDS) {
        int remaining = msgBytes - offset;
        int chunkBytes = remaining > BYTES_PER_LINE ? BYTES_PER_LINE : remaining;

        // Don't split in the middle of a UTF-8 sequence
        while (chunkBytes > 0 && (msg[offset + chunkBytes] & 0xC0) == 0x80) {
            chunkBytes--;
        }
        if (chunkBytes == 0) break;

        int written = snprintf(ssidLines[ssidCount], SSID_MAX_LEN + 1,
                               "%d: ", lineNum);
        memcpy(&ssidLines[ssidCount][written], &msg[offset], chunkBytes);
        ssidLines[ssidCount][written + chunkBytes] = '\0';

        offset += chunkBytes;
        lineNum++;
        ssidCount++;
    }
}

// Border mode: split first, then wrap each line
void splitBorder(const char *msg) {
    ssidCount = 0;
    int msgLen = strlen(msg);
    if (msgLen == 0) return;

    // Single SSID with border: =[ msg ]= (6 chars overhead)
    if (msgLen <= SSID_MAX_LEN - 6) {
        snprintf(ssidLines[0], SSID_MAX_LEN + 1, "=[ %s ]=", msg);
        ssidCount = 1;
        return;
    }

    // Multi-line with borders
    // First: =[ ...   Last: ... ]=   Middle: | ... |
    // Overhead: first/last 3 chars, middle 4 chars
    const int FIRST_USABLE = SSID_MAX_LEN - 3;  // "=[ " prefix
    const int LAST_USABLE  = SSID_MAX_LEN - 3;  // " ]=" suffix
    const int MID_USABLE   = SSID_MAX_LEN - 4;  // "| " prefix + " |" suffix

    int offset = 0;

    // First line
    if (ssidCount < MAX_SSIDS) {
        int chunk = (msgLen - offset) > FIRST_USABLE ? FIRST_USABLE : (msgLen - offset);
        snprintf(ssidLines[ssidCount], SSID_MAX_LEN + 1, "=[ %.*s", chunk, &msg[offset]);
        offset += chunk;
        ssidCount++;
    }

    // Middle lines
    while (offset < msgLen && ssidCount < MAX_SSIDS - 1) {
        int remaining = msgLen - offset;
        if (remaining <= LAST_USABLE) break; // save for last line
        int chunk = remaining > MID_USABLE ? MID_USABLE : remaining;
        snprintf(ssidLines[ssidCount], SSID_MAX_LEN + 1, "| %.*s |", chunk, &msg[offset]);
        offset += chunk;
        ssidCount++;
    }

    // Last line
    if (offset < msgLen && ssidCount < MAX_SSIDS) {
        int remaining = msgLen - offset;
        int chunk = remaining > LAST_USABLE ? LAST_USABLE : remaining;
        snprintf(ssidLines[ssidCount], SSID_MAX_LEN + 1, "%.*s ]=", chunk, &msg[offset]);
        ssidCount++;
    }
}

// Apply mode and split message into SSIDs
void processMessage(const char *msg) {
    switch (currentMode) {
        case MODE_PLAIN:
            splitPlain(msg);
            break;

        case MODE_L33T: {
            char *buf = (char *)malloc(480);
            if (buf) {
                applyL33t(buf, msg, 480);
                splitPlain(buf);
                free(buf);
            }
            break;
        }

        case MODE_BORDER:
            splitBorder(msg);
            break;

        case MODE_FLIP: {
            char *buf = (char *)malloc(480);
            if (buf) {
                int flipBytes = applyFlip(buf, msg, 480);
                splitBytes(buf, flipBytes);
                free(buf);
            }
            break;
        }

        case MODE_MARQUEE:
            // Marquee doesn't pre-split. Build a padded buffer for scrolling.
            // Format: "   <message>   " with 3-space padding on each side
            memset(marqueeBuf, ' ', sizeof(marqueeBuf));
            {
                int mlen = strlen(msg);
                if (mlen > 32) mlen = 32;
                int padded = mlen + 6; // 3 spaces each side
                if (padded > (int)sizeof(marqueeBuf) - 1) padded = sizeof(marqueeBuf) - 1;
                memset(marqueeBuf, ' ', 3);
                memcpy(&marqueeBuf[3], msg, mlen);
                memset(&marqueeBuf[3 + mlen], ' ', 3);
                marqueeBuf[3 + mlen + 3] = '\0';
            }
            marqueeOffset = 0;
            ssidCount = 1; // always 1 SSID for marquee
            ssidLines[0][0] = '\0'; // will be built each beacon cycle
            break;
    }
}

const char* modeName() {
    switch (currentMode) {
        case MODE_PLAIN:   return "Plain";
        case MODE_L33T:    return "L33T";
        case MODE_BORDER:  return "Border";
        case MODE_FLIP:    return "Flip";
        case MODE_MARQUEE: return "Marquee";
    }
    return "?";
}

// ================================================================
// HTML
// ================================================================

const char* inputHTML = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // graffiti</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#0a0a0a;border:1px solid #0d2e0d;max-width:420px;width:100%;margin:16px;padding:24px;text-align:center}
h1{font-size:18px;letter-spacing:2px;margin-bottom:4px}
.sub{color:#008f11;font-size:11px;margin-bottom:20px}
textarea{width:100%;height:70px;background:#050505;color:#00ff41;border:1px solid #0d2e0d;font-family:inherit;font-size:14px;padding:8px;resize:vertical;margin-bottom:4px}
textarea:focus{outline:none;border-color:#00ff41}
.count{color:#008f11;font-size:11px;margin-bottom:12px;text-align:right}
.modes{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;justify-content:center}
.modes label{background:#0a0a0a;border:1px solid #0d2e0d;padding:6px 10px;font-size:11px;cursor:pointer;white-space:nowrap}
.modes input{display:none}
.modes input:checked+span{color:#050505;background:#00ff41;margin:-6px -10px;padding:6px 10px;display:inline-block}
.info{color:#0d2e0d;font-size:10px;margin-bottom:14px;text-align:left;line-height:1.5}
button{padding:14px 32px;background:#00ff41;color:#050505;font-family:inherit;font-size:14px;font-weight:bold;border:none;letter-spacing:1px;text-transform:uppercase;cursor:pointer;width:100%}
button:hover{background:#00cc33}
</style>
</head>
<body>
<div class="card">
<h1>hackbox</h1>
<div class="sub">wifi graffiti</div>
<form method="POST" action="/spray">
<textarea name="msg" id="msg" maxlength="232" placeholder="Type your message..."></textarea>
<div class="count"><span id="cc">0</span>/232 chars</div>
<div class="modes">
<label><input type="radio" name="mode" value="0" checked><span>Plain</span></label>
<label><input type="radio" name="mode" value="1"><span>L33T</span></label>
<label><input type="radio" name="mode" value="2"><span>=[ Border ]=</span></label>
<label><input type="radio" name="mode" value="3"><span>Flip</span></label>
<label><input type="radio" name="mode" value="4"><span>Marquee</span></label>
</div>
<div class="info">Plain: broadcast as-is. L33T: h4ck3r 5p34k. Border: decorative frame.<br>Flip: upside-down text. Marquee: scrolling animation.</div>
<button type="submit">SPRAY IT</button>
</form>
</div>
<script>
var t=document.getElementById('msg'),cc=document.getElementById('cc');
t.addEventListener('input',function(){cc.textContent=t.value.length});
</script>
</body>
</html>
)rawhtml";

const char* sprayedHTML_pre = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // graffiti</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#0a0a0a;border:1px solid #0d2e0d;max-width:420px;width:100%;margin:16px;padding:24px;text-align:center}
h1{font-size:18px;letter-spacing:2px;margin-bottom:4px}
.sub{color:#008f11;font-size:11px;margin-bottom:20px}
.msg{background:#050505;border:1px solid #0d2e0d;padding:12px;text-align:left;font-size:13px;margin-bottom:12px;word-break:break-all}
.stats{color:#008f11;font-size:12px;margin-bottom:14px;text-align:left;line-height:2}
a{display:block;padding:12px 24px;background:#00ff41;color:#050505;font-family:inherit;font-size:13px;font-weight:bold;text-decoration:none;letter-spacing:1px;text-transform:uppercase;text-align:center}
a:hover{background:#00cc33}
</style>
</head>
<body>
<div class="card">
<h1>hackbox</h1>
<div class="sub">spraying...</div>
<div class="msg">)rawhtml";

void handleInputPage() {
    if (currentState == GRAF_BROADCASTING) {
        String html = sprayedHTML_pre;
        html += rawMessage;
        html += "</div><div class=\"stats\">Mode: ";
        html += modeName();
        html += "<br>SSIDs: ";
        html += String(ssidCount);
        html += "<br>Beacons: ";
        html += String(beaconsSent);
        html += "</div><a href=\"/new\">NEW MESSAGE</a></div></body></html>";
        grafServer->send(200, "text/html", html);
    } else {
        grafServer->send(200, "text/html", inputHTML);
    }
}

void handleSpray() {
    if (grafServer->hasArg("msg")) {
        String msg = grafServer->arg("msg");
        msg.trim();
        if (msg.length() > 0 && msg.length() <= 232) {
            strncpy(rawMessage, msg.c_str(), sizeof(rawMessage) - 1);
            rawMessage[sizeof(rawMessage) - 1] = '\0';

            // Read mode
            currentMode = MODE_PLAIN;
            if (grafServer->hasArg("mode")) {
                int m = grafServer->arg("mode").toInt();
                if (m >= 0 && m <= 4) currentMode = (GraffitiMode)m;
            }

            processMessage(rawMessage);
            beaconsSent = 0;
            channelIndex = 0;
            currentState = GRAF_BROADCASTING;
            addXP(5);
            needsRedraw = true;
        }
    }
    grafServer->sendHeader("Location", "/");
    grafServer->send(302, "text/plain", "");
}

void handleNewMessage() {
    currentState = GRAF_INPUT;
    ssidCount = 0;
    beaconsSent = 0;
    memset(rawMessage, 0, sizeof(rawMessage));
    needsRedraw = true;
    grafServer->sendHeader("Location", "/");
    grafServer->send(302, "text/plain", "");
}

// ===== OLED =====
void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    switch (currentState) {
        case GRAF_INPUT: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "WiFi Graffiti");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);
            u8g2.drawStr(0, 24, "Connect to WiFi:");
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 38, "hackbox");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawStr(0, 50, "Open browser or wait");
            u8g2.drawStr(0, 60, "for captive portal");
            break;
        }
        case GRAF_BROADCASTING: {
            u8g2.setFont(u8g2_font_6x10_tr);
            u8g2.drawStr(0, 10, "SPRAYING");
            u8g2.setFont(u8g2_font_5x8_tr);
            u8g2.drawHLine(0, 12, 128);

            char preview[26];
            int rawLen = strlen(rawMessage);
            if (rawLen <= 25) {
                strncpy(preview, rawMessage, 25);
                preview[rawLen] = '\0';
            } else {
                strncpy(preview, rawMessage, 22);
                preview[22] = '.'; preview[23] = '.'; preview[24] = '.'; preview[25] = '\0';
            }
            u8g2.drawStr(0, 24, preview);

            char buf[32];
            snprintf(buf, sizeof(buf), "Mode: %s", modeName());
            u8g2.drawStr(0, 36, buf);

            snprintf(buf, sizeof(buf), "SSIDs:%d Beacons:%lu",
                     ssidCount, (unsigned long)beaconsSent);
            u8g2.drawStr(0, 48, buf);

            u8g2.drawStr(0, 62, "L=Stop  Phone=New msg");
            break;
        }
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // anonymous namespace

// ===== Public API =====

void wifiGraffitiSetup() {
    currentState = GRAF_INPUT;
    currentMode = MODE_PLAIN;
    needsRedraw = true;
    ssidCount = 0;
    beaconsSent = 0;
    channelIndex = 0;
    marqueeOffset = 0;
    memset(rawMessage, 0, sizeof(rawMessage));
    graf_ap_netif = NULL;

    randomSeed((uint32_t)esp_random());

    cleanupWiFi();
    delay(50);

    esp_netif_init();
    esp_event_loop_create_default();

    graf_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t ap_config = {};
    strlcpy((char*)ap_config.ap.ssid, "hackbox", sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen((char*)ap_config.ap.ssid);
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    ap_config.ap.beacon_interval = 100;

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);

    if (grafServer) { delete grafServer; grafServer = nullptr; }
    if (grafDNS) { delete grafDNS; grafDNS = nullptr; }
    grafServer = new WebServer(80);
    grafDNS = new DNSServer();

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(graf_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        grafDNS->start(53, "*", apIP);
    }

    grafServer->on("/", handleInputPage);
    grafServer->on("/spray", HTTP_POST, handleSpray);
    grafServer->on("/new", handleNewMessage);
    grafServer->on("/generate_204", handleInputPage);
    grafServer->on("/hotspot-detect.html", handleInputPage);
    grafServer->on("/connecttest.txt", handleInputPage);
    grafServer->on("/redirect", handleInputPage);
    grafServer->on("/canonical.html", handleInputPage);
    grafServer->on("/success.txt", handleInputPage);
    grafServer->onNotFound(handleInputPage);
    grafServer->begin();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScreen();
}

void wifiGraffitiLoop() {
    if (grafDNS) grafDNS->processNextRequest();
    if (grafServer) grafServer->handleClient();

    unsigned long now = millis();

    if (currentState == GRAF_BROADCASTING && ssidCount > 0) {
        if (now - lastBeaconBatch >= BEACON_INTERVAL) {
            lastBeaconBatch = now;
            uint8_t ch = channels[channelIndex];

            if (currentMode == MODE_MARQUEE) {
                // Build scrolling window from padded buffer
                int padLen = strlen(marqueeBuf);
                if (padLen > 0) {
                    char window[SSID_MAX_LEN + 1];
                    int winLen = 0;
                    for (int i = 0; i < SSID_MAX_LEN && (marqueeOffset + i) < padLen; i++) {
                        window[i] = marqueeBuf[(marqueeOffset + i) % padLen];
                        winLen++;
                    }
                    window[winLen] = '\0';

                    // Trim trailing spaces for cleaner display
                    while (winLen > 0 && window[winLen - 1] == ' ') {
                        window[--winLen] = '\0';
                    }
                    // Trim leading spaces too
                    char *start = window;
                    while (*start == ' ') { start++; winLen--; }

                    if (winLen > 0) {
                        sendGraffitiBeacon(start, winLen, ch);
                    }
                    marqueeOffset = (marqueeOffset + 1) % padLen;
                }
            } else {
                // Static modes: broadcast all SSIDs
                for (int i = 0; i < ssidCount; i++) {
                    sendGraffitiBeacon(ssidLines[i], strlen(ssidLines[i]), ch);
                    delayMicroseconds(200);
                }
            }

            channelIndex = (channelIndex + 1) % 3;
            beaconsSent++;
            if (beaconsSent % 50 == 0) needsRedraw = true;
        }
    }

    static bool leftPrev = false;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;
    if (leftNow && !leftPrev && currentState == GRAF_BROADCASTING) {
        currentState = GRAF_INPUT;
        ssidCount = 0;
        beaconsSent = 0;
        memset(rawMessage, 0, sizeof(rawMessage));
        needsRedraw = true;
        delay(200);
    }
    leftPrev = leftNow;

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupWifiGraffiti() {
    if (grafServer) { grafServer->stop(); delete grafServer; grafServer = nullptr; }
    if (grafDNS) { grafDNS->stop(); delete grafDNS; grafDNS = nullptr; }
    cleanupWiFi();
    graf_ap_netif = NULL;
}
