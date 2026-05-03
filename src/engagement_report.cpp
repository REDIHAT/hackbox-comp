/*
    hackbox
    hackbox custom firmware

    Engagement Report
    Session notepad for pentest engagements. Take timestamped notes via phone,
    export as a clean HTML report. Connect phone to AP, add findings as you go,
    download the report when done.
*/

#include "../include/engagement_report.h"
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
#include <vector>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern const char* hackboxVersion;

namespace {

// ===== Notes storage =====
struct EngNote {
    unsigned long timestamp; // millis offset from session start
    char text[128];
};

const int MAX_NOTES = 30;
std::vector<EngNote> notes;
unsigned long sessionStart = 0;

// ===== Web server (heap-allocated to avoid BSS overflow) =====
WebServer *engServer = nullptr;
DNSServer *engDNS = nullptr;
esp_netif_t *eng_ap_netif = NULL;
bool needsRedraw = true;

// ===== Helpers =====

// Format ms offset as MM:SS
void formatTime(unsigned long ms, char *buf, size_t bufLen) {
    unsigned long sec = ms / 1000;
    unsigned long m = sec / 60;
    unsigned long s = sec % 60;
    snprintf(buf, bufLen, "%lu:%02lu", m, s);
}

// HTML-escape a string into a buffer (handles <, >, &, ", ')
void htmlEscape(const char *src, String &out) {
    for (const char *s = src; *s; ++s) {
        switch (*s) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += *s; break;
        }
    }
}

// ===== HTML pages =====

void serveMainPage() {
    unsigned long elapsed = millis() - sessionStart;
    char timeStr[16];
    formatTime(elapsed, timeStr, sizeof(timeStr));

    String html = R"rawhtml(
<!DOCTYPE html>
<html>
<head>
<title>hackbox // report</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:#00ff41;font-family:'Courier New',monospace;min-height:100vh}
.wrap{max-width:500px;margin:0 auto;padding:16px}
h1{font-size:18px;letter-spacing:2px;text-align:center;margin-bottom:4px}
.sub{color:#008f11;font-size:11px;text-align:center;margin-bottom:16px}
.info{background:#0a0a0a;border:1px solid #0d2e0d;padding:12px;margin-bottom:16px;font-size:12px;line-height:1.8}
.info span{color:#008f11}
form{margin-bottom:16px}
textarea{width:100%;height:60px;background:#050505;color:#00ff41;border:1px solid #0d2e0d;font-family:inherit;font-size:13px;padding:8px;resize:vertical;margin-bottom:8px}
textarea:focus{outline:none;border-color:#00ff41}
button{padding:12px 24px;background:#00ff41;color:#050505;font-family:inherit;font-size:13px;font-weight:bold;border:none;letter-spacing:1px;text-transform:uppercase;cursor:pointer;width:100%}
button:hover{background:#00cc33}
.notes{margin-bottom:16px}
.note{background:#0a0a0a;border:1px solid #0d2e0d;padding:8px 12px;margin-bottom:4px;font-size:12px}
.note .ts{color:#008f11;font-size:10px}
.dl{display:block;text-align:center;padding:12px;background:#0d2e0d;color:#00ff41;text-decoration:none;font-size:13px;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}
.dl:hover{background:#1a4a1a}
</style>
</head>
<body>
<div class="wrap">
<h1>hackbox</h1>
<div class="sub">engagement report</div>
<div class="info">
<span>Session:</span> )rawhtml";
    html += timeStr;
    html += R"rawhtml( &middot; <span>Notes:</span> )rawhtml";
    html += String(notes.size());
    html += R"rawhtml( &middot; <span>Level:</span> )rawhtml";
    html += String(getCurrentLevel());
    html += R"rawhtml(
</div>
<form method="POST" action="/note">
<textarea name="n" maxlength="127" placeholder="Add a finding, observation, or note..."></textarea>
<button type="submit">+ ADD NOTE</button>
</form>
)rawhtml";

    if (!notes.empty()) {
        html += "<div class=\"notes\">";
        // Show notes newest first
        for (int i = (int)notes.size() - 1; i >= 0; i--) {
            char ts[16];
            formatTime(notes[i].timestamp, ts, sizeof(ts));
            html += "<div class=\"note\"><div class=\"ts\">[";
            html += ts;
            html += "]</div>";
            htmlEscape(notes[i].text, html);
            html += "</div>";
        }
        html += "</div>";
    }

    html += R"rawhtml(
<a class="dl" href="/report">DOWNLOAD HTML REPORT</a>
<a class="dl" href="/json">DOWNLOAD JSON</a>
</div>
</body>
</html>
)rawhtml";

    engServer->send(200, "text/html", html);
}

void handleAddNote() {
    if (engServer->hasArg("n") && notes.size() < MAX_NOTES) {
        String text = engServer->arg("n");
        text.trim();
        if (text.length() > 0) {
            EngNote note;
            note.timestamp = millis() - sessionStart;
            strncpy(note.text, text.c_str(), sizeof(note.text) - 1);
            note.text[sizeof(note.text) - 1] = '\0';
            notes.push_back(note);
            addXP(3);
            needsRedraw = true;
        }
    }
    engServer->sendHeader("Location", "/");
    engServer->send(302, "text/plain", "");
}

void handleHTMLReport() {
    unsigned long elapsed = millis() - sessionStart;
    char timeStr[16];
    formatTime(elapsed, timeStr, sizeof(timeStr));

    String html = R"rawhtml(<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>hackbox Engagement Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;color:#222;font-family:'Courier New',monospace;max-width:700px;margin:0 auto;padding:32px 16px}
h1{font-size:20px;margin-bottom:4px}
.sub{color:#666;font-size:12px;margin-bottom:24px}
.meta{background:#f5f5f5;padding:12px 16px;margin-bottom:24px;font-size:12px;line-height:2;border-left:3px solid #333}
.meta b{color:#000}
h2{font-size:14px;margin-bottom:12px;border-bottom:1px solid #ddd;padding-bottom:4px}
.note{padding:8px 0;border-bottom:1px solid #eee;font-size:13px}
.note .ts{color:#888;font-size:11px;margin-bottom:2px}
.footer{margin-top:32px;color:#999;font-size:10px;text-align:center}
</style>
</head>
<body>
<h1>hackbox Engagement Report</h1>
<div class="sub">Generated by hackbox firmware</div>
<div class="meta">
<b>Firmware:</b> )rawhtml";
    html += hackboxVersion;
    html += "<br><b>Session Duration:</b> ";
    html += timeStr;
    html += "<br><b>Operator Level:</b> ";
    html += String(getCurrentLevel());
    html += " (";
    html += String(getCurrentXP());
    html += " XP)<br><b>Notes Recorded:</b> ";
    html += String(notes.size());
    html += R"rawhtml(
</div>
<h2>Findings & Notes</h2>
)rawhtml";

    if (notes.empty()) {
        html += "<p style=\"color:#999\">No notes recorded.</p>";
    } else {
        for (size_t i = 0; i < notes.size(); i++) {
            char ts[16];
            formatTime(notes[i].timestamp, ts, sizeof(ts));
            html += "<div class=\"note\"><div class=\"ts\">[";
            html += ts;
            html += "]</div>";
            htmlEscape(notes[i].text, html);
            html += "</div>";
        }
    }

    html += R"rawhtml(
<div class="footer">hackbox // ck42x.com/hackbox</div>
</body>
</html>)rawhtml";

    engServer->sendHeader("Content-Disposition",
        "attachment; filename=\"hackbox-report.html\"");
    engServer->send(200, "text/html", html);
}

void handleJSONReport() {
    unsigned long elapsed = millis() - sessionStart;

    String json = "{\"firmware\":\"";
    json += hackboxVersion;
    json += "\",\"session_seconds\":";
    json += String(elapsed / 1000);
    json += ",\"level\":";
    json += String(getCurrentLevel());
    json += ",\"xp\":";
    json += String(getCurrentXP());
    json += ",\"notes\":[";

    for (size_t i = 0; i < notes.size(); i++) {
        if (i > 0) json += ",";
        char ts[16];
        formatTime(notes[i].timestamp, ts, sizeof(ts));
        json += "{\"time\":\"";
        json += ts;
        json += "\",\"text\":\"";
        // Escape quotes and backslashes in JSON
        for (const char *s = notes[i].text; *s; ++s) {
            if (*s == '"') json += "\\\"";
            else if (*s == '\\') json += "\\\\";
            else if (*s == '\n') json += "\\n";
            else if (*s == '\r') continue;
            else json += *s;
        }
        json += "\"}";
    }

    json += "]}";

    engServer->sendHeader("Content-Disposition",
        "attachment; filename=\"hackbox-report.json\"");
    engServer->send(200, "application/json", json);
}

// ===== OLED =====
void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Engagement Report");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawHLine(0, 12, 128);

    u8g2.drawStr(0, 24, "Connect to WiFi:");
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 38, "hackbox");
    u8g2.setFont(u8g2_font_5x8_tr);

    char buf[32];
    unsigned long elapsed = millis() - sessionStart;
    char timeStr[16];
    formatTime(elapsed, timeStr, sizeof(timeStr));
    snprintf(buf, sizeof(buf), "Notes: %d  Time: %s", (int)notes.size(), timeStr);
    u8g2.drawStr(0, 50, buf);

    u8g2.drawStr(0, 62, "Open browser to add notes");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // anonymous namespace

// ===== Public API =====

void engReportSetup() {
    notes.clear();
    sessionStart = millis();
    needsRedraw = true;
    eng_ap_netif = NULL;

    // Set up WiFi AP
    cleanupWiFi();
    delay(50);

    esp_netif_init();
    esp_event_loop_create_default();

    eng_ap_netif = esp_netif_create_default_wifi_ap();

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

    // DNS captive portal + web server (heap-allocated)
    if (engServer) { delete engServer; engServer = nullptr; }
    if (engDNS) { delete engDNS; engDNS = nullptr; }
    engServer = new WebServer(80);
    engDNS = new DNSServer();

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(eng_ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        engDNS->start(53, "*", apIP);
    }

    engServer->on("/", serveMainPage);
    engServer->on("/note", HTTP_POST, handleAddNote);
    engServer->on("/report", handleHTMLReport);
    engServer->on("/json", handleJSONReport);
    // Captive portal detection
    engServer->on("/generate_204", serveMainPage);
    engServer->on("/hotspot-detect.html", serveMainPage);
    engServer->on("/connecttest.txt", serveMainPage);
    engServer->on("/redirect", serveMainPage);
    engServer->on("/canonical.html", serveMainPage);
    engServer->on("/success.txt", serveMainPage);
    engServer->onNotFound(serveMainPage);
    engServer->begin();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScreen();
}

void engReportLoop() {
    if (engDNS) engDNS->processNextRequest();
    if (engServer) engServer->handleClient();

    // Redraw every 5 seconds to update timer
    static unsigned long lastDraw = 0;
    unsigned long now = millis();
    if (now - lastDraw >= 5000) {
        lastDraw = now;
        needsRedraw = true;
    }

    if (needsRedraw) {
        needsRedraw = false;
        drawScreen();
    }
}

void cleanupEngReport() {
    if (engServer) { engServer->stop(); delete engServer; engServer = nullptr; }
    if (engDNS) { engDNS->stop(); delete engDNS; engDNS = nullptr; }
    notes.clear();
    cleanupWiFi();
    eng_ap_netif = NULL;
}
