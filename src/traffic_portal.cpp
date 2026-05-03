/*
    hackbox Traffic Portal
    Sniffs WiFi packets for readable data (URLs, HTTP, DNS, cleartext)
    and serves a live web dashboard over a local AP.

    Connect to AP "Guest WiFi" (pass: hackbox1) -> open 192.168.4.1
*/

#include "../include/traffic_portal.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <DNSServer.h>
#include <string.h>
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ==================== Data Structures ====================

enum EntryType {
    TYPE_URL,
    TYPE_HTTP_HOST,
    TYPE_HTTP_REQ,
    TYPE_DNS_QUERY,
    TYPE_CLEARTEXT
};

struct TrafficEntry {
    unsigned long timestamp;
    EntryType type;
    char data[128];       // The extracted string
    char srcMAC[18];
    char dstMAC[18];
    int8_t rssi;
    uint8_t channel;
};

const int MAX_ENTRIES = 100;
TrafficEntry entries[MAX_ENTRIES];
int entryHead = 0;
int entryCount = 0;

volatile uint32_t totalPackets = 0;
volatile uint32_t readableFound = 0;

// Sniff state
uint8_t sniffChannel = 1;
bool autoHop = true;
unsigned long lastHop = 0;
unsigned long lastDraw = 0;
const unsigned long HOP_INTERVAL = 400;
const unsigned long DRAW_INTERVAL = 500;
bool needsRedraw = true;

// Web server (runs on AP)
WebServer trafficServer(80);
DNSServer trafficDNS;
esp_netif_t *tp_ap_netif = NULL;
bool portalRunning = false;

// ==================== Helpers ====================

void macToStr(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void addEntry(EntryType type, const char *data, const uint8_t *srcMAC,
              const uint8_t *dstMAC, int8_t rssi, uint8_t ch) {
    TrafficEntry &e = entries[entryHead];
    e.timestamp = millis();
    e.type = type;
    strncpy(e.data, data, sizeof(e.data) - 1);
    e.data[sizeof(e.data) - 1] = '\0';
    macToStr(srcMAC, e.srcMAC);
    macToStr(dstMAC, e.dstMAC);
    e.rssi = rssi;
    e.channel = ch;

    entryHead = (entryHead + 1) % MAX_ENTRIES;
    if (entryCount < MAX_ENTRIES) entryCount++;
    readableFound++;
}

const char* typeName(EntryType t) {
    switch (t) {
        case TYPE_URL:        return "URL";
        case TYPE_HTTP_HOST:  return "HTTP Host";
        case TYPE_HTTP_REQ:   return "HTTP Req";
        case TYPE_DNS_QUERY:  return "DNS Query";
        case TYPE_CLEARTEXT:  return "Cleartext";
        default:              return "Unknown";
    }
}

const char* typeClass(EntryType t) {
    switch (t) {
        case TYPE_URL:        return "url";
        case TYPE_HTTP_HOST:  return "host";
        case TYPE_HTTP_REQ:   return "req";
        case TYPE_DNS_QUERY:  return "dns";
        case TYPE_CLEARTEXT:  return "txt";
        default:              return "unk";
    }
}

// ==================== Packet Parsing ====================

// Check if a byte sequence looks like printable ASCII
bool isPrintableASCII(const uint8_t *data, int len) {
    int printable = 0;
    for (int i = 0; i < len; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) printable++;
    }
    return (printable > len * 0.75); // 75%+ printable
}

// Extract DNS query name from DNS payload
bool parseDNSQuery(const uint8_t *dns, int len, char *out, int outLen) {
    if (len < 12) return false;

    // Check: standard query (QR=0, Opcode=0)
    if ((dns[2] & 0x80) != 0) return false;

    uint16_t qdcount = (dns[4] << 8) | dns[5];
    if (qdcount < 1) return false;

    // Parse QNAME starting at offset 12
    int pos = 12;
    int outPos = 0;
    while (pos < len && dns[pos] != 0) {
        int labelLen = dns[pos];
        if (labelLen > 63 || pos + labelLen >= len) return false;
        pos++;
        for (int i = 0; i < labelLen && outPos < outLen - 2; i++) {
            out[outPos++] = dns[pos + i];
        }
        pos += labelLen;
        if (dns[pos] != 0) out[outPos++] = '.';
    }
    out[outPos] = '\0';
    return outPos > 3;
}

// Search for HTTP methods and extract request lines
bool extractHTTP(const uint8_t *payload, int len, char *out, int outLen, EntryType &type) {
    const char *methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "HTTP/"};
    const int methodCount = 6;

    for (int m = 0; m < methodCount; m++) {
        int mlen = strlen(methods[m]);
        for (int i = 0; i <= len - mlen; i++) {
            if (memcmp(&payload[i], methods[m], mlen) == 0) {
                // Found HTTP method, extract until CR/LF or max length
                type = TYPE_HTTP_REQ;
                int start = i;
                int end = i;
                while (end < len && end - start < outLen - 1 &&
                       payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }
                int copyLen = end - start;
                if (copyLen > outLen - 1) copyLen = outLen - 1;
                memcpy(out, &payload[start], copyLen);
                out[copyLen] = '\0';
                return true;
            }
        }
    }

    // Look for "Host: " header
    const char *hostStr = "Host: ";
    int hostLen = 6;
    for (int i = 0; i <= len - hostLen; i++) {
        if (memcmp(&payload[i], hostStr, hostLen) == 0) {
            type = TYPE_HTTP_HOST;
            int start = i + hostLen;
            int end = start;
            while (end < len && end - start < outLen - 1 &&
                   payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            int copyLen = end - start;
            if (copyLen > outLen - 1) copyLen = outLen - 1;
            memcpy(out, &payload[start], copyLen);
            out[copyLen] = '\0';
            return true;
        }
    }

    return false;
}

// Search for URL patterns in payload
bool extractURL(const uint8_t *payload, int len, char *out, int outLen) {
    const char *prefixes[] = {"http://", "https://", "www."};
    const int prefixLens[] = {7, 8, 4};
    const int prefixCount = 3;

    for (int p = 0; p < prefixCount; p++) {
        for (int i = 0; i <= len - prefixLens[p]; i++) {
            if (memcmp(&payload[i], prefixes[p], prefixLens[p]) == 0) {
                int start = i;
                int end = i;
                // URL ends at whitespace, quote, angle bracket, or non-printable
                while (end < len && end - start < outLen - 1 &&
                       payload[end] > 0x20 && payload[end] < 0x7F &&
                       payload[end] != '"' && payload[end] != '\'' &&
                       payload[end] != '>' && payload[end] != '<') {
                    end++;
                }
                int copyLen = end - start;
                if (copyLen > 10 && copyLen < outLen - 1) {
                    memcpy(out, &payload[start], copyLen);
                    out[copyLen] = '\0';
                    return true;
                }
            }
        }
    }
    return false;
}

// ==================== Promiscuous Callback ====================

void IRAM_ATTR trafficSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 28) return;
    totalPackets++;

    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t fsubtype = (fc0 >> 4) & 0x0F;

    // Management frames: extract SSIDs from beacons and probe requests
    if (ftype == 0) {
        const uint8_t *srcMAC = &frame[10];
        const uint8_t *dstMAC = &frame[4];

        if (fsubtype == 0x08 || fsubtype == 0x04 || fsubtype == 0x05) {
            // Beacon (0x08), Probe Request (0x04), Probe Response (0x05)
            int fixedParamsLen = (fsubtype == 0x04) ? 0 : 12; // beacons have 12 bytes fixed params
            int tagStart = 24 + fixedParamsLen;

            if (len > tagStart + 2) {
                uint8_t tagNum = frame[tagStart];
                uint8_t tagLen = frame[tagStart + 1];

                if (tagNum == 0 && tagLen > 0 && tagLen <= 32 && tagStart + 2 + tagLen <= len) {
                    char ssid[33];
                    memcpy(ssid, &frame[tagStart + 2], tagLen);
                    ssid[tagLen] = '\0';

                    if (fsubtype == 0x04) {
                        char entry[64];
                        snprintf(entry, sizeof(entry), "Probe: %s", ssid);
                        addEntry(TYPE_DNS_QUERY, entry, srcMAC, dstMAC,
                                 pkt->rx_ctrl.rssi, sniffChannel);
                    }
                    // Don't log beacons (too many), only probe requests
                }
            }
        }
        return;
    }

    // Only care about data frames for content extraction
    if (ftype != 2) return;

    const uint8_t *srcMAC = &frame[10];
    const uint8_t *dstMAC = &frame[4];

    // Data frame: skip 802.11 header (24 bytes) + possible QoS (2 bytes) + LLC/SNAP (8 bytes)
    int headerLen = 24;
    if (fsubtype & 0x08) headerLen += 2; // QoS

    if (len < headerLen + 8) return;

    const uint8_t *llc = &frame[headerLen];

    // Check for LLC/SNAP header
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
        uint16_t etherType = (llc[6] << 8) | llc[7];
        const uint8_t *ipPayload = &llc[8];
        int ipLen = len - headerLen - 8;

        if (etherType == 0x0800 && ipLen > 20) {
            // IPv4
            uint8_t ipHeaderLen = (ipPayload[0] & 0x0F) * 4;
            uint8_t protocol = ipPayload[9];

            if (ipLen < ipHeaderLen) return;

            const uint8_t *transportPayload = &ipPayload[ipHeaderLen];
            int transportLen = ipLen - ipHeaderLen;

            // UDP (DNS on port 53)
            if (protocol == 17 && transportLen > 8) {
                uint16_t dstPort = (transportPayload[2] << 8) | transportPayload[3];
                if (dstPort == 53) {
                    char dnsName[96];
                    if (parseDNSQuery(&transportPayload[8], transportLen - 8, dnsName, sizeof(dnsName))) {
                        addEntry(TYPE_DNS_QUERY, dnsName, srcMAC, dstMAC,
                                 pkt->rx_ctrl.rssi, sniffChannel);
                    }
                }
            }

            // TCP
            if (protocol == 6 && transportLen > 20) {
                uint8_t tcpHeaderLen = ((transportPayload[12] >> 4) & 0x0F) * 4;
                if (transportLen > tcpHeaderLen) {
                    const uint8_t *appData = &transportPayload[tcpHeaderLen];
                    int appLen = transportLen - tcpHeaderLen;

                    if (appLen > 4) {
                        char extracted[128];
                        EntryType etype;

                        // Try HTTP extraction
                        if (extractHTTP(appData, appLen, extracted, sizeof(extracted), etype)) {
                            addEntry(etype, extracted, srcMAC, dstMAC,
                                     pkt->rx_ctrl.rssi, sniffChannel);
                            return;
                        }

                        // Try URL extraction
                        if (extractURL(appData, appLen, extracted, sizeof(extracted))) {
                            addEntry(TYPE_URL, extracted, srcMAC, dstMAC,
                                     pkt->rx_ctrl.rssi, sniffChannel);
                            return;
                        }

                        // Look for cleartext strings (min 20 printable chars)
                        if (appLen >= 20 && isPrintableASCII(appData, appLen > 120 ? 120 : appLen)) {
                            int copyLen = appLen > 120 ? 120 : appLen;
                            char cleartext[128];
                            memcpy(cleartext, appData, copyLen);
                            cleartext[copyLen] = '\0';
                            addEntry(TYPE_CLEARTEXT, cleartext, srcMAC, dstMAC,
                                     pkt->rx_ctrl.rssi, sniffChannel);
                        }
                    }
                }
            }
        }
    }
}

// ==================== Web Portal ====================

// Dashboard HTML is identical to hackbox-ck42x repo version
const char* dashboardHTML = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // traffic monitor</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh;padding:12px}
.header{border-bottom:1px solid #00ff41;padding-bottom:12px;margin-bottom:16px}
.header h1{font-size:20px;letter-spacing:2px}
.header .sub{color:#008f11;font-size:12px;margin-top:4px}
.stats{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap}
.stat{background:#111;border:1px solid #1a3a1a;border-radius:4px;padding:8px 12px;font-size:12px}
.stat .val{font-size:18px;color:#00ff41;font-weight:bold}
.stat .lbl{color:#008f11;font-size:10px;text-transform:uppercase;letter-spacing:1px}
.filters{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap}
.filters button{background:#111;color:#00ff41;border:1px solid #1a3a1a;padding:4px 10px;font-family:inherit;font-size:11px;cursor:pointer;border-radius:2px}
.filters button.active{background:#00ff41;color:#0a0a0a}
.filters button:hover{border-color:#00ff41}
#log{max-height:70vh;overflow-y:auto;border:1px solid #1a3a1a;background:#050505}
.entry{padding:6px 10px;border-bottom:1px solid #0d1f0d;font-size:12px;line-height:1.4;display:flex;gap:8px;align-items:flex-start}
.entry:hover{background:#0d1f0d}
.ts{color:#444;min-width:55px;flex-shrink:0}
.tag{padding:1px 5px;border-radius:2px;font-size:10px;font-weight:bold;min-width:48px;text-align:center;flex-shrink:0}
.tag.dns{background:#1a1a00;color:#ffff00;border:1px solid #333300}
.tag.url{background:#001a1a;color:#00ffff;border:1px solid #003333}
.tag.req{background:#1a001a;color:#ff00ff;border:1px solid #330033}
.tag.host{background:#001a00;color:#00ff41;border:1px solid #003300}
.tag.txt{background:#1a0a00;color:#ff8800;border:1px solid #331a00}
.mac{color:#555;font-size:10px;flex-shrink:0;min-width:105px}
.data{word-break:break-all;color:#00ff41}
.empty{text-align:center;padding:40px;color:#333}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:#0a0a0a}
::-webkit-scrollbar-thumb{background:#1a3a1a;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#00ff41}
</style>
</head>
<body>
<div class="header">
<h1>&gt; hackbox // traffic_monitor</h1>
<div class="sub">real-time packet analysis // readable data extraction</div>
</div>
<div class="stats">
<div class="stat"><div class="val" id="total">0</div><div class="lbl">packets</div></div>
<div class="stat"><div class="val" id="found">0</div><div class="lbl">readable</div></div>
<div class="stat"><div class="val" id="ch">1</div><div class="lbl">channel</div></div>
</div>
<div class="filters">
<button class="active" onclick="setFilter('all',this)">All</button>
<button onclick="setFilter('dns',this)">DNS</button>
<button onclick="setFilter('url',this)">URL</button>
<button onclick="setFilter('req',this)">HTTP Req</button>
<button onclick="setFilter('host',this)">HTTP Host</button>
<button onclick="setFilter('txt',this)">Cleartext</button>
</div>
<div id="log"><div class="empty">Waiting for traffic...</div></div>
<script>
var filter='all';
var lastCount=0;
function setFilter(f,el){
  filter=f;
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.entry').forEach(e=>{
    e.style.display=(f==='all'||e.dataset.type===f)?'flex':'none';
  });
}
function poll(){
  fetch('/api/data?since='+lastCount).then(r=>r.json()).then(d=>{
    document.getElementById('total').textContent=d.total;
    document.getElementById('found').textContent=d.found;
    document.getElementById('ch').textContent=d.ch;
    if(d.entries&&d.entries.length>0){
      var log=document.getElementById('log');
      if(lastCount===0)log.innerHTML='';
      d.entries.forEach(e=>{
        var div=document.createElement('div');
        div.className='entry';
        div.dataset.type=e.cls;
        var show=(filter==='all'||filter===e.cls)?'flex':'none';
        div.style.display=show;
        var secs=Math.floor(e.ts/1000);
        var m=Math.floor(secs/60);
        var s=secs%60;
        div.innerHTML='<span class="ts">'+m+':'+String(s).padStart(2,'0')+'</span>'
          +'<span class="tag '+e.cls+'">'+e.type+'</span>'
          +'<span class="mac">'+e.src+'</span>'
          +'<span class="data">'+e.data.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</span>';
        log.insertBefore(div,log.firstChild);
      });
      lastCount=d.count;
    }
  }).catch(()=>{});
  setTimeout(poll,2000);
}
poll();
</script>
</body>
</html>
)rawhtml";

void handleDashboard() {
    trafficServer.send(200, "text/html", dashboardHTML);
}

void handleAPI() {
    uint32_t since = 0;
    if (trafficServer.hasArg("since")) {
        since = trafficServer.arg("since").toInt();
    }

    String json = "{\"total\":";
    json += String((uint32_t)totalPackets);
    json += ",\"found\":";
    json += String((uint32_t)readableFound);
    json += ",\"ch\":";
    json += String(sniffChannel);
    json += ",\"count\":";
    json += String(entryCount);
    json += ",\"entries\":[";

    // Send entries newer than 'since'
    int sent = 0;
    int maxSend = 50; // Max entries per poll
    for (int i = 0; i < entryCount && sent < maxSend; i++) {
        int idx;
        if (entryCount >= MAX_ENTRIES) {
            idx = (entryHead + i) % MAX_ENTRIES;
        } else {
            idx = i;
        }

        if ((int)i < (int)since) continue;

        const TrafficEntry &e = entries[idx];
        if (sent > 0) json += ",";
        json += "{\"ts\":";
        json += String(e.timestamp);
        json += ",\"type\":\"";
        json += typeName(e.type);
        json += "\",\"cls\":\"";
        json += typeClass(e.type);
        json += "\",\"src\":\"";
        json += e.srcMAC;
        json += "\",\"dst\":\"";
        json += e.dstMAC;
        json += "\",\"rssi\":";
        json += String(e.rssi);
        json += ",\"data\":\"";
        // Escape JSON special chars in data
        for (int c = 0; e.data[c] && c < 127; c++) {
            char ch = e.data[c];
            if (ch == '"') json += "\\\"";
            else if (ch == '\\') json += "\\\\";
            else if (ch == '\n') json += "\\n";
            else if (ch == '\r') json += "\\r";
            else if (ch == '\t') json += "\\t";
            else if (ch >= 0x20 && ch < 0x7F) json += ch;
            else json += '.';
        }
        json += "\"}";
        sent++;
    }

    json += "]}";
    trafficServer.send(200, "application/json", json);
}

// ==================== AP + Sniffer Coexistence ====================
// We run the AP for serving the web dashboard, and use a timer-based
// channel hop on the STA interface for sniffing. The AP stays on ch1.

void setupTrafficAP() {
    esp_netif_init();
    esp_event_loop_create_default();

    wifi_mode_t currentMode;
    if (esp_wifi_get_mode(&currentMode) == ESP_OK) {
        esp_wifi_stop();
        delay(50);
        esp_wifi_deinit();
        delay(50);
    }

    if (tp_ap_netif != NULL) {
        esp_netif_destroy(tp_ap_netif);
        tp_ap_netif = NULL;
    }

    tp_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_APSTA); // AP for web + STA for promiscuous sniff
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t ap_config = {};
    memset(&ap_config, 0, sizeof(wifi_config_t));
    strncpy((char*)ap_config.ap.ssid, "Guest WiFi", sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid[sizeof(ap_config.ap.ssid) - 1] = '\0';
    ap_config.ap.ssid_len = strlen((char*)ap_config.ap.ssid);
    strncpy((char*)ap_config.ap.password, "hackbox1", sizeof(ap_config.ap.password) - 1);
    ap_config.ap.password[sizeof(ap_config.ap.password) - 1] = '\0';
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.ssid_hidden = 0;
    ap_config.ap.max_connection = 4;
    ap_config.ap.beacon_interval = 100;

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);

    // Enable promiscuous on STA interface - capture data AND management frames
    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(trafficSniffer);
    esp_wifi_set_promiscuous(true);

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(tp_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        trafficDNS.start(53, "*", apIP);
    }

    trafficServer.on("/", handleDashboard);
    trafficServer.on("/api/data", handleAPI);
    trafficServer.on("/generate_204", handleDashboard);
    trafficServer.on("/hotspot-detect.html", handleDashboard);
    trafficServer.on("/connecttest.txt", handleDashboard);
    trafficServer.on("/redirect", handleDashboard);
    trafficServer.on("/canonical.html", handleDashboard);
    trafficServer.on("/success.txt", handleDashboard);
    trafficServer.onNotFound(handleDashboard);
    trafficServer.begin();
    portalRunning = true;
}

// ==================== Display ====================

void drawTrafficScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    u8g2.drawStr(0, 8, "hackbox // monitor");
    u8g2.drawHLine(0, 10, 128);

    char line[32];
    snprintf(line, sizeof(line), "Packets: %lu", (unsigned long)totalPackets);
    u8g2.drawStr(0, 20, line);

    snprintf(line, sizeof(line), "Readable: %lu", (unsigned long)readableFound);
    u8g2.drawStr(0, 30, line);

    snprintf(line, sizeof(line), "Ch: %d %s", sniffChannel, autoHop ? "(hop)" : "(lock)");
    u8g2.drawStr(0, 40, line);

    u8g2.drawStr(0, 50, "AP:Guest WiFi pw:hackbox1");

    u8g2.drawStr(0, 62, "U/D=Ch  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ==================== Public API ====================

void trafficPortalSetup() {
    memset(entries, 0, sizeof(entries));
    entryHead = 0;
    entryCount = 0;
    totalPackets = 0;
    readableFound = 0;
    sniffChannel = 1;
    autoHop = true;
    lastHop = 0;
    lastDraw = 0;
    needsRedraw = true;
    portalRunning = false;

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    setupTrafficAP();
    drawTrafficScreen();
}

void trafficPortalLoop() {
    unsigned long now = millis();

    // Service web clients
    if (portalRunning) {
        trafficDNS.processNextRequest();
        trafficServer.handleClient();
    }

    // Button handling
    static bool upPrev = false, downPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;

    if (upNow && !upPrev) {
        if (autoHop) { autoHop = false; }
        else {
            sniffChannel++;
            if (sniffChannel > 13) { sniffChannel = 1; autoHop = true; }
            esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
        }
        needsRedraw = true;
        delay(200);
    }
    if (downNow && !downPrev) {
        if (autoHop) { autoHop = false; }
        else {
            sniffChannel--;
            if (sniffChannel < 1) { sniffChannel = 13; autoHop = true; }
            esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
        }
        needsRedraw = true;
        delay(200);
    }
    upPrev = upNow;
    downPrev = downNow;

    // Channel hopping
    if (autoHop && now - lastHop >= HOP_INTERVAL) {
        lastHop = now;
        sniffChannel++;
        if (sniffChannel > 13) sniffChannel = 1;
        esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
    }

    // Display update
    if (now - lastDraw >= DRAW_INTERVAL) {
        lastDraw = now;
        needsRedraw = true;
    }
    if (needsRedraw) {
        needsRedraw = false;
        drawTrafficScreen();
    }
}

void cleanupTrafficPortal() {
    if (portalRunning) {
        trafficServer.stop();
        trafficDNS.stop();
        portalRunning = false;
    }
    esp_wifi_set_promiscuous(false);
    cleanupWiFi();
    tp_ap_netif = NULL;
}
