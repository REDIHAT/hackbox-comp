/*
    hackbox HiveMind
    NRF24 SIGINT Dashboard

    WiFi AP broadcasts "=^..^= HiveMind", serves phone dashboard at 192.168.4.1.
    Continuous 3x NRF24 spectrum sweep with live visualization on both the
    OLED and the phone web dashboard. WiFi AP stays up the entire time
    (independent hardware from NRF24). View-only -- no remote tool launching,
    because the launched tools fought with HiveMind over the OLED render loop
    and produced unrecoverable display glitches on any tool that drew to u8g2.
*/

#include "../include/hivemind.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <SPI.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern void cleanupRadio();

namespace {

// ===== NRF24 Direct Register Access =====

struct NRFRadio { uint8_t ce; uint8_t csn; };

const NRFRadio radios[3] = {
    {RADIO_CE_PIN_1, RADIO_CSN_PIN_1},
    {RADIO_CE_PIN_2, RADIO_CSN_PIN_2},
    {RADIO_CE_PIN_3, RADIO_CSN_PIN_3},
};

#define NRF_CONFIG    0x00
#define NRF_EN_AA     0x01
#define NRF_RF_CH     0x05
#define NRF_RF_SETUP  0x06
#define NRF_RPD       0x09
#define NUM_CHANNELS  126
#define SAMPLES_PER_SCAN 30

uint8_t* signalMap = nullptr;
uint8_t* displayMap = nullptr;
uint8_t* peakMap = nullptr;
uint32_t totalPackets = 0;
uint32_t scanCount = 0;
int hotChannel = -1;
int hotStrength = 0;
unsigned long scanRateMs = 0;

// ===== NRF24 Low-level =====

byte nrfRead(int r, byte reg) {
    digitalWrite(radios[r].csn, LOW);
    SPI.transfer(reg & 0x1F);
    byte val = SPI.transfer(0);
    digitalWrite(radios[r].csn, HIGH);
    return val;
}

void nrfWrite(int r, byte reg, byte val) {
    digitalWrite(radios[r].csn, LOW);
    SPI.transfer((reg & 0x1F) | 0x20);
    SPI.transfer(val);
    digitalWrite(radios[r].csn, HIGH);
}

void nrfPowerUp(int r) {
    nrfWrite(r, NRF_CONFIG, nrfRead(r, NRF_CONFIG) | 0x02);
    delayMicroseconds(130);
}

void nrfEnableRX(int r) {
    nrfWrite(r, NRF_CONFIG, nrfRead(r, NRF_CONFIG) | 0x01);
    digitalWrite(radios[r].ce, HIGH);
    delayMicroseconds(100);
}

void nrfDisable(int r) {
    digitalWrite(radios[r].ce, LOW);
}

void initNRFRadio(int r) {
    pinMode(radios[r].ce, OUTPUT);
    pinMode(radios[r].csn, OUTPUT);
    nrfDisable(r);
    nrfPowerUp(r);
    nrfWrite(r, NRF_EN_AA, 0x00);
    nrfWrite(r, NRF_RF_SETUP, 0x0F);
}

void initAllRadios() {
    cleanupRadio();
    SPI.begin(18, 19, 23, 17);
    delay(100);
    SPI.setDataMode(SPI_MODE0);
    SPI.setFrequency(16000000);
    SPI.setBitOrder(MSBFIRST);
    for (int r = 0; r < 3; r++) initNRFRadio(r);
}

// ===== Scanning =====

void scanAllChannels() {
    unsigned long start = millis();
    if (!signalMap) return;
    memset(signalMap, 0, NUM_CHANNELS);

    for (int ch = 0; ch < 42; ch++) {
        for (int r = 0; r < 3; r++) {
            int aCh = ch + (r * 42);
            if (aCh >= NUM_CHANNELS) break;
            nrfDisable(r);
            nrfWrite(r, NRF_RF_CH, aCh);
        }
        for (int s = 0; s < SAMPLES_PER_SCAN; s++) {
            for (int r = 0; r < 3; r++) {
                int aCh = ch + (r * 42);
                if (aCh >= NUM_CHANNELS) break;
                nrfEnableRX(r);
            }
            delayMicroseconds(100);
            for (int r = 0; r < 3; r++) {
                int aCh = ch + (r * 42);
                if (aCh >= NUM_CHANNELS) break;
                nrfDisable(r);
                if (nrfRead(r, NRF_RPD)) {
                    signalMap[aCh]++;
                    totalPackets++;
                }
            }
        }
    }

    hotChannel = -1;
    hotStrength = 0;
    for (int i = 0; i < NUM_CHANNELS; i++) {
        int raw = signalMap[i];
        int scaled = raw > 0 ? 15 + (raw * 85) / SAMPLES_PER_SCAN : 0;
        if (scaled > 100) scaled = 100;
        if (displayMap) {
            int prev = displayMap[i];
            displayMap[i] = (uint8_t)(scaled > prev ? scaled : (prev * 7 + scaled) / 8);
        }
        if (peakMap && scaled > peakMap[i]) peakMap[i] = (uint8_t)scaled;
        if (displayMap && displayMap[i] > hotStrength) {
            hotStrength = displayMap[i];
            hotChannel = i;
        }
    }
    scanCount++;
    scanRateMs = millis() - start;
}

// ===== WiFi AP + Web Server =====

WebServer* hmServer = nullptr;
esp_netif_t* hmNetif = NULL;

const char HM_HTML[] PROGMEM = R"rawhtml(<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>HiveMind</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace;padding:8px}
.h{text-align:center;padding:6px 0;border-bottom:1px solid #333;margin-bottom:8px}.h h1{font-size:13px;color:#f5a623;letter-spacing:2px}.h .a{font-size:10px;color:#666}
.s{display:flex;gap:6px;margin-bottom:8px}.s div{flex:1;background:#111;border:1px solid #222;border-radius:4px;padding:5px;text-align:center}.s .v{font-size:15px;color:#f5a623;font-weight:bold}.s .l{font-size:8px;color:#666;text-transform:uppercase}
.c{background:#111;border:1px solid #222;border-radius:4px;padding:6px;margin-bottom:6px}.c canvas{width:100%;height:140px;display:block}
.b{background:#111;border:1px solid #222;border-radius:4px;padding:6px;font-size:11px;margin-bottom:6px}.b b{color:#f5a623;font-size:14px}.b i{color:#888;font-style:normal}
.f{text-align:center;font-size:8px;color:#333;margin-top:6px}
</style></head><body>
<div class="h"><div class="a">=^..^= HiveMind</div><h1>NRF24 SIGINT</h1></div>
<div class="s"><div><div class="v" id="sc">0</div><div class="l">Scans</div></div><div><div class="v" id="hi">0</div><div class="l">Hits</div></div><div><div class="v" id="rt">-</div><div class="l">ms</div></div><div><div class="v" id="ac">0</div><div class="l">Active</div></div></div>
<div class="c"><canvas id="cv" height="140"></canvas></div>
<div class="b" id="hb">Scanning...</div>
<div class="f">3x NRF24 | 126ch | 2400-2525MHz | view-only</div>
<script>
var cv=document.getElementById('cv'),cx=cv.getContext('2d');
cv.width=cv.clientWidth;cv.height=140;

function dr(d){var w=cv.width,h=cv.height,n=d.s.length,b=w/n;cx.clearRect(0,0,w,h);
cx.strokeStyle='#1a1a1a';for(var y=0;y<h;y+=h/4){cx.beginPath();cx.moveTo(0,y);cx.lineTo(w,y);cx.stroke()}
cx.fillStyle='#333';cx.font='9px monospace';cx.fillText('2400',2,h-2);cx.fillText('2525',w-28,h-2);
for(var i=0;i<n;i++){var ph=(d.p[i]/100)*h;if(ph>0){cx.fillStyle='#1a1510';cx.fillRect(i*b,h-ph,b-1,ph)}}
for(var i=0;i<n;i++){var bh=(d.s[i]/100)*h;if(bh>0){var t=d.s[i]/100;cx.fillStyle='rgb('+~~(245*t)+','+~~(166*t)+','+~~(35*t)+')';cx.fillRect(i*b,h-bh,b-1,bh)}}}

async function po(){try{var r=await fetch('/api/s'),d=await r.json();dr(d);
document.getElementById('sc').textContent=d.n;document.getElementById('hi').textContent=d.t;
document.getElementById('rt').textContent=d.m;document.getElementById('ac').textContent=d.s.filter(function(v){return v>0}).length;
if(d.h>=0){document.getElementById('hb').innerHTML='Hot: Ch <b>'+d.h+'</b> <i>('+(2400+d.h)+'MHz '+d.v+'%)</i>'}
else{document.getElementById('hb').textContent='Scanning...'}
}catch(e){}setTimeout(po,500)}po();
</script></body></html>)rawhtml";

void handleRoot() {
    hmServer->send(200, "text/html", HM_HTML);
}

void handleScanAPI() {
    // Build the JSON response into a fixed stack buffer instead of an
    // Arduino String. The dashboard polls this endpoint ~5x/sec and the
    // previous String-based implementation performed hundreds of heap
    // allocations per second, fragmenting the heap under sustained use
    // and opening a race on displayMap/peakMap if cleanup freed them
    // between the null check and the subsequent array read.
    //
    // Snapshot the map pointers once and then work off the local copies so
    // the response is internally consistent even if a pending cleanup runs
    // during the build.
    uint8_t* s = displayMap;
    uint8_t* p = peakMap;

    // 126 channels * 4 chars ("nnn,") per array + static header/footer
    // overhead is ~1.1 KB worst case. Use a 1280-byte stack buffer rather
    // than a static one so it doesn't consume dram0_0_seg BSS, which is
    // the tight sub-region on ESP32 -- a 2 KB static here overflowed.
    char buf[1280];
    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "{\"s\":[");
    for (int i = 0; i < NUM_CHANNELS && n < (int)sizeof(buf) - 16; i++) {
        n += snprintf(buf + n, sizeof(buf) - n, "%s%u",
                      i ? "," : "", s ? s[i] : 0);
    }
    n += snprintf(buf + n, sizeof(buf) - n, "],\"p\":[");
    for (int i = 0; i < NUM_CHANNELS && n < (int)sizeof(buf) - 16; i++) {
        n += snprintf(buf + n, sizeof(buf) - n, "%s%u",
                      i ? "," : "", p ? p[i] : 0);
    }
    n += snprintf(buf + n, sizeof(buf) - n,
                  "],\"n\":%lu,\"t\":%lu,\"m\":%lu,\"h\":%d,\"v\":%u}",
                  (unsigned long)scanCount, (unsigned long)totalPackets,
                  (unsigned long)scanRateMs, hotChannel, hotStrength);

    hmServer->send(200, "application/json", buf);
}

void setupAP() {
    if (hmServer) { delete hmServer; }
    hmServer = new WebServer(80);

    esp_netif_init();
    esp_event_loop_create_default();

    wifi_mode_t currentMode;
    if (esp_wifi_get_mode(&currentMode) == ESP_OK) {
        esp_wifi_stop();
        delay(50);
        esp_wifi_deinit();
        delay(50);
    }

    if (hmNetif != NULL) {
        esp_netif_destroy(hmNetif);
        hmNetif = NULL;
    }

    hmNetif = esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t ap_config = {};
    memset(&ap_config, 0, sizeof(wifi_config_t));
    strlcpy((char*)ap_config.ap.ssid, "=^..^= HiveMind", sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen((char*)ap_config.ap.ssid);
    strlcpy((char*)ap_config.ap.password, "hackbox1", sizeof(ap_config.ap.password));
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.ssid_hidden = 0;
    ap_config.ap.max_connection = 2;
    ap_config.ap.beacon_interval = 100;

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);

    hmServer->on("/", handleRoot);
    hmServer->on("/api/s", handleScanAPI);
    hmServer->begin();
}

// ===== OLED Display =====

void drawOLED() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    u8g2.drawStr(0, 8, "=^..^= HiveMind");
    for (int x = 0; x < 128; x++) {
        int ch = (x * NUM_CHANNELS) / 128;
        int barH = displayMap ? (displayMap[ch] * 36) / 100 : 0;
        if (barH > 0) u8g2.drawVLine(x, 52 - barH, barH);
        int pH = peakMap ? (peakMap[ch] * 36) / 100 : 0;
        if (pH > 0) u8g2.drawPixel(x, 52 - pH);
    }
    char stats[32];
    snprintf(stats, sizeof(stats), "S:%lu H:%lu %lums", scanCount, totalPackets, scanRateMs);
    u8g2.drawStr(0, 62, stats);
    if (hotChannel >= 0) {
        char hs[20];
        snprintf(hs, sizeof(hs), "Ch%d %dMHz", hotChannel, 2400 + hotChannel);
        u8g2.drawStr(76, 8, hs);
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void hivemindSetup() {
    initAllRadios();

    if (!signalMap) signalMap = (uint8_t*)calloc(NUM_CHANNELS, 1);
    if (!displayMap) displayMap = (uint8_t*)calloc(NUM_CHANNELS, 1);
    if (!peakMap) peakMap = (uint8_t*)calloc(NUM_CHANNELS, 1);
    memset(signalMap, 0, NUM_CHANNELS);
    totalPackets = 0;
    scanCount = 0;
    hotChannel = -1;
    hotStrength = 0;
    scanRateMs = 0;

    setupAP();

    Serial.println();
    Serial.println("# hackbox HiveMind active");
    Serial.println("# AP: =^..^= HiveMind / pw: hackbox1");
    Serial.println("# Dashboard: 192.168.4.1");
}

void hivemindLoop() {
    hmServer->handleClient();
    scanAllChannels();
    drawOLED();
}

void cleanupHivemind() {
    if (hmServer) {
        hmServer->stop();
        delete hmServer;
        hmServer = nullptr;
    }

    if (hmNetif != NULL) {
        esp_netif_destroy(hmNetif);
        hmNetif = NULL;
    }

    esp_wifi_stop();
    esp_wifi_deinit();

    if (signalMap) { free(signalMap); signalMap = nullptr; }
    if (displayMap) { free(displayMap); displayMap = nullptr; }
    if (peakMap) { free(peakMap); peakMap = nullptr; }

    for (int r = 0; r < 3; r++) nrfDisable(r);

    Serial.println("# HiveMind shutdown");
}
