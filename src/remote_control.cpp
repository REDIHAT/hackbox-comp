/*
    hackbox Remote Control
    WiFi AP + Web Dashboard for phone-based control

    Creates AP "hackbox-RC", serves mobile UI at 192.168.4.1
    REST API for launching/stopping tools remotely.
*/

#include "../include/remote_control.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include "../include/level_system.h"

// Tool headers
#include "../include/beacon_spam.h"
#include "../include/ck42x_spam.h"
#include "../include/bee_spam.h"
#include "../include/deauth.h"
#include "../include/deauth_scanner.h"
#include "../include/wifiscan.h"
#include "../include/blescan.h"
#include "../include/ble_spammer.h"
#include "../include/ble_spoofer.h"
#include "../include/evil_portal.h"
#include "../include/evil_twin.h"
#include "../include/packet_logger.h"
#include "../include/probe_logger.h"
#include "../include/traffic_portal.h"
#include "../include/handshake_capture.h"
#include "../include/pmkid_capture.h"
#include "../include/channel_analyzer.h"
#include "../include/mousejack.h"
#include "../include/scanner.h"
#include "../include/analyzer.h"
#include "../include/swiftpair.h"
#include "../include/sourapple.h"
#include "../include/sourdroid.h"
#include "../include/honeyble.h"
#include "../include/drone_detector.h"
#include "../include/drone_spoofer.h"
#include "../include/device_scout.h"
#include "../include/tracking_sweep.h"
#include "../include/mission_mode.h"
#include "../include/airtag_detector.h"
#include "../include/airtag_spoofer.h"
#include "../include/pwnagotchi_spam.h"
#include "../include/wps_scanner.h"
#include "../include/ble_mitm.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_gap_ble_api.h"
#include <WebServer.h>
#include <DNSServer.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

// Cleanup forward declarations (defined in other translation units)
extern void cleanupWiFi();
extern void cleanupBLE();
extern void cleanupRadio();
extern void cleanupMousejack();
extern void cleanupDroneDetector();
extern void cleanupDroneSpoofer();
extern void cleanupFlockDetector();
extern void cleanupDeviceScout();
extern void cleanupProbeLogger();

namespace {

// ==================== Tool Registry ====================

struct ToolEntry {
    const char* id;
    const char* name;
    const char* category;  // "wifi", "ble", "rf", "recon"
    void (*setup)();
    void (*loop)();
    void (*cleanup)();
    bool interactive;      // requires device UI (not remotely launchable)
};

const ToolEntry tools[] = {
    // RF tools - safe to launch remotely (NRF24 radios, fully independent from WiFi/BLE)
    {"scanner",         "RF Scanner",          "rf",    scannerSetup,           scannerLoop,           cleanupRadio,             false},
    {"analyzer",        "RF Analyzer",         "rf",    analyzerSetup,          analyzerLoop,          cleanupRadio,             false},
    {"drone_spoofer",   "Drone Spoofer",       "rf",    droneSpooferSetup,      droneSpooferLoop,      cleanupDroneSpoofer,      false},
    {"mousejack",       "MouseJack",           "rf",    mousejackSetup,         mousejackLoop,         cleanupMousejack,         false},
    // BLE tools - share radio with WiFi AP, device only
    {"ble_spam",        "BLE Spammer",         "ble",   bleSpamSetup,           bleSpamLoop,           cleanupBLE,               true},
    {"bee_spam",        "Bee Spam",            "ble",   beeSpamSetup,           beeSpamLoop,           cleanupBLE,               true},
    {"swift_pair",      "Swift Pair",          "ble",   swiftpairSpamSetup,     swiftpairSpamLoop,     cleanupBLE,               true},
    {"sour_apple",      "Sour Apple",          "ble",   sourappleSetup,         sourappleLoop,         cleanupBLE,               true},
    {"sour_droid",      "Sour Droid",          "ble",   sourDroidSetup,         sourDroidLoop,         cleanupBLE,               true},
    {"honeyble",        "HoneyBLE",            "ble",   honeybleSetup,          honeybleLoop,          cleanupBLE,               true},
    // BLE detectors - share radio with WiFi AP, device only
    {"drone_detector",  "Drone Detector",      "recon", droneDetectorSetup,     droneDetectorLoop,     cleanupDroneDetector,     true},
    {"device_scout",    "Device Scout",        "recon", deviceScoutSetup,       deviceScoutLoop,       cleanupDeviceScout,       true},
    {"tracker_sweep",   "Tracker Sweep",       "recon", trackingSweepSetup,     trackingSweepLoop,     trackingSweepCleanup,     true},
    {"mission_mode",    "Mission Mode",        "recon", missionModeSetup,       missionModeLoop,       missionModeCleanup,       true},
    // WiFi tools - kill the remote AP, device-only
    {"beacon_spam",     "Beacon Spam",        "wifi",  beaconSpamSetup,        beaconSpamLoop,        cleanupWiFi,              true},
    {"ck42x_spam",      "CK42X Spam",         "wifi",  ck42xSpamSetup,         ck42xSpamLoop,         cleanupWiFi,              true},
    {"deauth",          "WiFi Deauther",       "wifi",  deauthSetup,            deauthLoop,            cleanupWiFi,              true},
    {"deauth_scanner",  "Deauth Scanner",      "wifi",  deauthScannerSetup,     deauthScannerLoop,     cleanupWiFi,              true},
    {"pwnagotchi_spam", "Pwnagotchi Spam",     "wifi",  pwnagotchiSpamSetup,    pwnagotchiSpamLoop,    cleanupWiFi,              true},
    {"evil_portal",     "Evil Portal",         "wifi",  evilPortalSetup,        evilPortalLoop,        cleanupEvilPortal,        true},
    {"evil_twin",       "Evil Twin",           "wifi",  evilTwinSetup,          evilTwinLoop,          cleanupEvilTwin,          true},
    {"handshake_cap",   "Handshake Capture",   "wifi",  handshakeCaptureSetup,  handshakeCaptureLoop,  cleanupHandshakeCapture,  true},
    {"pmkid_capture",   "PMKID Capture",       "wifi",  pmkidCaptureSetup,      pmkidCaptureLoop,      cleanupPmkidCapture,      true},
    {"wifi_scan",       "WiFi Scan",           "wifi",  wifiscanSetup,          wifiscanLoop,          wifiscanCleanup,          true},
    {"wps_scanner",     "WPS Auditor",     "wifi",  wpsSetup,               wpsLoop,               cleanupWPS,               true},
    {"channel_analyzer","Channel Analyzer",    "recon", channelAnalyzerSetup,   channelAnalyzerLoop,   cleanupWiFi,              true},
    {"packet_logger",   "Packet Logger",       "recon", packetLoggerSetup,      packetLoggerLoop,      cleanupWiFi,              true},
    {"probe_logger",    "Probe Logger",        "recon", probeLoggerSetup,       probeLoggerLoop,       cleanupProbeLogger,       true},
    {"ble_spoofer",     "BLE Spoofer",         "ble",   bleSpooferSetup,        bleSpooferLoop,        cleanupBLE,               true},
    {"ble_mitm",        "BLE MITM",            "ble",   bleMitmSetup,           bleMitmLoop,           cleanupBleMitm,           true},
    {"airtag_spoofer",  "AirTag Spoofer",      "ble",   airtagSpooferSetup,     airtagSpooferLoop,     cleanupBLE,               true},
};
const int TOOL_COUNT = sizeof(tools) / sizeof(tools[0]);

// ==================== State ====================

WebServer rcServer(80);
DNSServer rcDNS;
esp_netif_t *rc_ap_netif = NULL;
bool rcRunning = false;

// Forward declaration
void setupRCAP();
void softCleanupBLE();

// Active tool state
int activeTool = -1;  // -1 = none
unsigned long toolStartTime = 0;
bool needsRedraw = true;

// Deferred launch/stop (never launch tools inside HTTP handlers)
int pendingLaunch = -1;
bool pendingStop = false;

// ==================== Web UI ====================

const char RC_HTML[] PROGMEM = R"rawhtml(<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>hackbox RC</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,sans-serif;padding:12px;max-width:480px;margin:0 auto}
h1{font-size:20px;color:#f5a623;text-align:center;padding:12px 0;border-bottom:1px solid #222}
.status{background:#111;border:1px solid #222;border-radius:8px;padding:12px;margin:12px 0;font-size:13px}
.status .active{color:#4caf50;font-weight:bold}
.status .idle{color:#666}
.status .time{color:#888;font-size:11px}
.cat{margin:16px 0 8px;font-size:12px;color:#f5a623;text-transform:uppercase;letter-spacing:2px}
.tools{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.btn{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:14px 10px;color:#e0e0e0;font-size:13px;cursor:pointer;text-align:center;transition:all .15s;-webkit-tap-highlight-color:transparent}
.btn:active{background:#333;transform:scale(0.97)}
.btn.wifi{border-color:#2196f355}.btn.wifi:active{background:#2196f322}
.btn.ble{border-color:#9c27b055}.btn.ble:active{background:#9c27b022}
.btn.rf{border-color:#f4433655}.btn.rf:active{background:#f4433622}
.btn.recon{border-color:#4caf5055}.btn.recon:active{background:#4caf5022}
.btn.running{background:#f5a62322;border-color:#f5a623;color:#f5a623}
.btn.disabled{opacity:0.35;pointer-events:none}
.btn .tag{font-size:9px;color:#666;display:block;margin-top:2px}
.stop{background:#f44336;border:none;border-radius:8px;padding:14px;color:#fff;font-size:15px;font-weight:bold;cursor:pointer;width:100%;margin:12px 0}
.stop:active{background:#d32f2f}
.badge{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:6px}
.badge.on{background:#4caf50;box-shadow:0 0 6px #4caf50}
.badge.off{background:#444}
</style>
</head><body>
<h1>hackbox Remote</h1>
<div class="status" id="st">
  <span class="idle">Connecting...</span>
</div>
<div id="app"></div>
<script>
let tools=[];let active=-1;let startTime=0;
function poll(){
  fetch('/api/status').then(r=>r.json()).then(d=>{
    active=d.active;startTime=d.startTime;
    let st=document.getElementById('st');
    if(active>=0){
      let t=tools[active];
      let elapsed=Math.floor((Date.now()/1000)-(startTime/1000));
      let m=Math.floor(elapsed/60);let s=elapsed%60;
      st.innerHTML='<span class="badge on"></span><span class="active">'+t.name+'</span><br><span class="time">Running '+m+'m '+s+'s</span>';
    }else{
      st.innerHTML='<span class="badge off"></span><span class="idle">Idle - Select a tool</span>';
    }
    render();
  }).catch(()=>{
    document.getElementById('st').innerHTML='<span class="idle">Connection lost</span>';
  });
}
function launch(i){
  fetch('/api/launch?id='+i,{method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.wifi_takeover){
      document.getElementById('st').innerHTML='<span class="active">WiFi tool launched on device</span><br><span class="time">Press center button on device to stop and reconnect</span>';
      document.getElementById('app').innerHTML='<div style="text-align:center;padding:40px 0;color:#888">Connection will drop. Reconnect to hackbox-RC after stopping the tool on the device.</div>';
    }else{poll();}
  }).catch(()=>{});
}
function stop(){
  fetch('/api/stop',{method:'POST'}).then(()=>poll()).catch(()=>{});
}
function render(){
  let app=document.getElementById('app');
  let cats={wifi:'WiFi',ble:'Bluetooth',rf:'RF',recon:'Recon'};
  let html='';
  if(active>=0){
    html+='<button class="stop" onclick="stop()">STOP '+tools[active].name.toUpperCase()+'</button>';
  }
  for(let cat in cats){
    let ct=tools.filter(t=>t.cat===cat);
    if(!ct.length)continue;
    html+='<div class="cat">'+cats[cat]+'</div><div class="tools">';
    ct.forEach((t,j)=>{
      let idx=tools.indexOf(t);
      let running=idx===active;
      if(t.interactive){
        html+='<div class="btn '+cat+' disabled">'+t.name+'<span class="tag">Device Only</span></div>';
      }else{
        html+='<div class="btn '+cat+(running?' running':'')+'" onclick="'+(running?'stop()':'launch('+idx+')')+'">'+t.name+'</div>';
      }
    });
    html+='</div>';
  }
  app.innerHTML=html;
}
fetch('/api/tools').then(r=>r.json()).then(d=>{tools=d.map(t=>({...t,interactive:t.interactive||false}));poll();setInterval(poll,2000);});
</script>
</body></html>)rawhtml";

// ==================== API Handlers ====================

void handleRoot() {
    rcServer.send(200, "text/html", RC_HTML);
}

void handleGetTools() {
    String json = "[";
    for (int i = 0; i < TOOL_COUNT; i++) {
        if (i > 0) json += ",";
        json += "{\"id\":\"";
        json += tools[i].id;
        json += "\",\"name\":\"";
        json += tools[i].name;
        json += "\",\"cat\":\"";
        json += tools[i].category;
        json += "\",\"interactive\":";
        json += tools[i].interactive ? "true" : "false";
        json += "}";
    }
    json += "]";
    rcServer.send(200, "application/json", json);
}

void handleGetStatus() {
    String json = "{\"active\":";
    json += String(activeTool);
    json += ",\"startTime\":";
    json += String(toolStartTime);
    json += ",\"uptime\":";
    json += String(millis());
    json += ",\"level\":";
    json += String(getCurrentLevel());
    json += "}";
    rcServer.send(200, "application/json", json);
}

bool isWiFiTool(int idx) {
    return strcmp(tools[idx].category, "wifi") == 0 ||
           strcmp(tools[idx].category, "recon") == 0;
}

void handleLaunch() {
    String idParam = rcServer.arg("id");
    int idx = idParam.toInt();

    if (idx < 0 || idx >= TOOL_COUNT) {
        rcServer.send(400, "application/json", "{\"error\":\"invalid tool index\"}");
        return;
    }

    if (tools[idx].interactive) {
        rcServer.send(400, "application/json", "{\"error\":\"device_only\",\"message\":\"This tool requires on-device interaction. Launch it from the device menu.\"}");
        return;
    }

    // Don't launch inside HTTP handler. Set flag, launch in loop.
    pendingLaunch = idx;
    bool willTakeWifi = isWiFiTool(idx);
    rcServer.send(200, "application/json",
        willTakeWifi
            ? "{\"ok\":true,\"wifi_takeover\":true}"
            : "{\"ok\":true,\"wifi_takeover\":false}");
}

void handleStop() {
    pendingStop = true;
    rcServer.send(200, "application/json", "{\"ok\":true}");
}

// Called from remoteControlLoop, outside any HTTP handler context
void executePendingLaunch() {
    int idx = pendingLaunch;
    pendingLaunch = -1;

    // Stop current tool first
    if (activeTool >= 0) {
        if (strcmp(tools[activeTool].category, "ble") == 0) {
            softCleanupBLE();
        } else if (tools[activeTool].cleanup) {
            tools[activeTool].cleanup();
        }
        activeTool = -1;
        delay(100);
    }

    if (isWiFiTool(idx)) {
        // Tear down AP, then launch
        rcServer.stop();
        rcDNS.stop();
        rcRunning = false;
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
        delay(200);

        if (rc_ap_netif != NULL) {
            esp_netif_destroy(rc_ap_netif);
            rc_ap_netif = NULL;
        }
        delay(100);

        activeTool = idx;
        toolStartTime = millis();
        tools[idx].setup();
    } else {
        // BLE/RF tools: launch without touching WiFi
        activeTool = idx;
        toolStartTime = millis();
        tools[idx].setup();
    }

    needsRedraw = true;
}

// Soft BLE cleanup that doesn't tear down the stack (preserves WiFi coexistence)
void softCleanupBLE() {
    esp_ble_gap_stop_scanning();
    esp_ble_gap_stop_advertising();
    delay(50);
    // Do NOT call btStop() or esp_bluedroid_deinit() - that kills WiFi AP
}

void executePendingStop() {
    pendingStop = false;

    if (activeTool >= 0) {
        // Use soft cleanup for BLE tools to avoid killing WiFi AP
        if (strcmp(tools[activeTool].category, "ble") == 0) {
            softCleanupBLE();
        } else if (tools[activeTool].cleanup) {
            tools[activeTool].cleanup();
        }
        activeTool = -1;
        toolStartTime = 0;
        delay(200);

        // Restart RC AP if it was torn down
        if (!rcRunning) {
            setupRCAP();
        }

        needsRedraw = true;
    }
}

// ==================== AP Setup ====================

void setupRCAP() {
    esp_netif_init();
    esp_event_loop_create_default();

    wifi_mode_t currentMode;
    if (esp_wifi_get_mode(&currentMode) == ESP_OK) {
        esp_wifi_stop();
        delay(50);
        esp_wifi_deinit();
        delay(50);
    }

    if (rc_ap_netif != NULL) {
        esp_netif_destroy(rc_ap_netif);
        rc_ap_netif = NULL;
    }

    rc_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t ap_config = {};
    memset(&ap_config, 0, sizeof(wifi_config_t));
    strlcpy((char*)ap_config.ap.ssid, "hackbox-RC", sizeof(ap_config.ap.ssid));
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

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(rc_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        rcDNS.start(53, "*", apIP);
    }

    rcServer.on("/", handleRoot);
    rcServer.on("/api/tools", handleGetTools);
    rcServer.on("/api/status", handleGetStatus);
    rcServer.on("/api/launch", HTTP_POST, handleLaunch);
    rcServer.on("/api/stop", HTTP_POST, handleStop);
    rcServer.onNotFound(handleRoot);
    rcServer.begin();

    rcRunning = true;
}

// ==================== OLED Display ====================

void drawRCScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    if (activeTool >= 0) {
        u8g2.drawStr(0, 12, "RC: Tool Running");
        u8g2.setFont(u8g2_font_5x8_tr);

        char toolName[24];
        strlcpy(toolName, tools[activeTool].name, sizeof(toolName));
        u8g2.drawStr(0, 26, toolName);

        unsigned long elapsed = (millis() - toolStartTime) / 1000;
        char timeStr[16];
        snprintf(timeStr, sizeof(timeStr), "Time: %lum %lus", elapsed / 60, elapsed % 60);
        u8g2.drawStr(0, 38, timeStr);

        u8g2.drawStr(0, 52, "AP: hackbox-RC");
        u8g2.drawStr(0, 62, "L=Exit (stop)");
    } else {
        u8g2.drawStr(0, 12, "hackbox Remote");
        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 26, "AP: hackbox-RC");
        u8g2.drawStr(0, 38, "PW: hackbox1");
        u8g2.drawStr(0, 50, "Go to: 192.168.4.1");
        u8g2.drawStr(0, 62, "L=Exit");
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ==================== Public API ====================

void remoteControlSetup() {
    activeTool = -1;
    toolStartTime = 0;
    needsRedraw = true;
    rcRunning = false;
    pendingLaunch = -1;
    pendingStop = false;

    setupRCAP();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawRCScreen();
}

void remoteControlLoop() {
    // Service web requests when RC AP is active
    if (rcRunning) {
        rcDNS.processNextRequest();
        rcServer.handleClient();
    }

    // Process deferred launch/stop OUTSIDE HTTP handler context
    if (pendingStop) {
        executePendingStop();
    }
    if (pendingLaunch >= 0) {
        executePendingLaunch();
    }

    // If a tool is running, call its loop
    if (activeTool >= 0 && tools[activeTool].loop) {
        tools[activeTool].loop();
    }

    // LEFT button: stop active tool and restart AP
    static bool leftPrev = false;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;
    if (leftNow && !leftPrev && activeTool >= 0) {
        // Stop the active tool
        if (tools[activeTool].cleanup) {
            tools[activeTool].cleanup();
        }
        activeTool = -1;
        toolStartTime = 0;

        // Restart RC AP if it was torn down
        if (!rcRunning) {
            delay(200);
            setupRCAP();
        }

        needsRedraw = true;
        delay(300);
    }
    leftPrev = leftNow;

    // Redraw OLED periodically
    static unsigned long lastDraw = 0;
    if (millis() - lastDraw > 1000) {
        lastDraw = millis();
        if (activeTool < 0) {
            drawRCScreen();
        }
        // When tool is active, the tool's own loop handles OLED
    }
}

void cleanupRemoteControl() {
    // Stop active tool
    if (activeTool >= 0 && tools[activeTool].cleanup) {
        tools[activeTool].cleanup();
        activeTool = -1;
    }

    // Tear down AP
    rcServer.stop();
    rcDNS.stop();
    rcRunning = false;

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    delay(50);
    esp_wifi_deinit();
    delay(50);

    if (rc_ap_netif != NULL) {
        esp_netif_destroy(rc_ap_netif);
        rc_ap_netif = NULL;
    }
}
