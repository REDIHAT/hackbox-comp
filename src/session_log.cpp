/*
    hackbox Session Logger

    Timestamped CSV activity log on SPIFFS. Any tool can call
    sessionLogEvent() to record what happened. The viewer app
    shows the log on the OLED and can export via serial.

    Log format (CSV):
      uptime_sec,category,detail

    SPIFFS file: /session_log.csv
    Max file size: 32KB (truncated on overflow to keep SPIFFS healthy)

    Viewer controls:
      UP/DOWN - scroll log
      CENTER  - export to serial (for copy/paste)
      RIGHT   - clear log
      LEFT    - exit (framework)

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#include "../include/session_log.h"
#include "../include/display_mirror.h"
#include <SPIFFS.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

static const char *LOG_PATH = "/session_log.csv";
static const size_t MAX_LOG_SIZE = 32768;
static bool spiffsReady = false;

// ============================================================
// Log writer (called from any tool)
// ============================================================

void sessionLogEvent(const char *category, const char *detail) {
    if (!spiffsReady) {
        if (!SPIFFS.begin(true)) return;
        spiffsReady = true;
    }

    // Check file size, truncate if too large
    if (SPIFFS.exists(LOG_PATH)) {
        File f = SPIFFS.open(LOG_PATH, FILE_READ);
        if (f) {
            size_t sz = f.size();
            f.close();
            if (sz > MAX_LOG_SIZE) {
                SPIFFS.remove(LOG_PATH);
            }
        }
    }

    File f = SPIFFS.open(LOG_PATH, FILE_APPEND);
    if (!f) return;

    unsigned long uptimeSec = millis() / 1000;
    f.printf("%lu,%s,%s\n", uptimeSec, category, detail);
    f.close();
}

// ============================================================
// Viewer state
// ============================================================

struct LogEntry {
    unsigned long uptime;
    char category[16];
    char detail[32];
};

static const int MAX_VIEW_ENTRIES = 64;
static const unsigned long DEBOUNCE_MS = 150;

struct SessionLogState {
    LogEntry entries[MAX_VIEW_ENTRIES];
    int entryCount;
    int listSelected;
    int listScroll;

    unsigned long lastUp;
    unsigned long lastDown;
    bool rightPrev;
    bool centerPrev;
    bool needsRedraw;
    unsigned long lastRedraw;
};

static SessionLogState *state = nullptr;

// ============================================================
// Load log from SPIFFS
// ============================================================

static void loadLog() {
    if (!state) return;
    state->entryCount = 0;

    if (!spiffsReady) {
        if (!SPIFFS.begin(true)) return;
        spiffsReady = true;
    }

    if (!SPIFFS.exists(LOG_PATH)) return;

    File f = SPIFFS.open(LOG_PATH, FILE_READ);
    if (!f) return;

    // Read lines, keep last MAX_VIEW_ENTRIES
    char lineBuf[80];
    int linePos = 0;

    while (f.available()) {
        char c = (char)f.read();
        if (c == '\n' || c == '\r') {
            if (linePos > 0) {
                lineBuf[linePos] = '\0';
                // Parse: uptime,category,detail
                char *tok1 = strtok(lineBuf, ",");
                char *tok2 = strtok(NULL, ",");
                char *tok3 = strtok(NULL, "\n");
                if (tok1 && tok2) {
                    int idx = state->entryCount;
                    if (idx >= MAX_VIEW_ENTRIES) {
                        // Shift array left to keep newest entries
                        memmove(&state->entries[0], &state->entries[1],
                                (MAX_VIEW_ENTRIES - 1) * sizeof(LogEntry));
                        idx = MAX_VIEW_ENTRIES - 1;
                    } else {
                        state->entryCount++;
                    }
                    state->entries[idx].uptime = strtoul(tok1, NULL, 10);
                    strlcpy(state->entries[idx].category, tok2,
                            sizeof(state->entries[idx].category));
                    strlcpy(state->entries[idx].detail, tok3 ? tok3 : "",
                            sizeof(state->entries[idx].detail));
                }
                linePos = 0;
            }
        } else if (linePos < (int)sizeof(lineBuf) - 1) {
            lineBuf[linePos++] = c;
        }
    }
    f.close();
}

// ============================================================
// Display
// ============================================================

static void drawDisplay() {
    if (!state) return;
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "SESSION LOG");
    char countStr[12];
    snprintf(countStr, sizeof(countStr), "%d", state->entryCount);
    int cx = 128 - u8g2.getStrWidth(countStr);
    u8g2.drawStr(cx, 10, countStr);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    if (state->entryCount == 0) {
        u8g2.drawStr(0, 28, "No events logged.");
        u8g2.drawStr(0, 38, "Tools will log here.");
    } else {
        // 5 visible rows
        const int ROWS_VISIBLE = 5;
        int start = state->listScroll;
        // Show newest first (reverse order)
        for (int r = 0; r < ROWS_VISIBLE; r++) {
            int idx = (state->entryCount - 1) - (start + r);
            if (idx < 0) break;
            const LogEntry &e = state->entries[idx];

            char row[28];
            // Format uptime as Mm:Ss
            unsigned long m = e.uptime / 60;
            unsigned long s = e.uptime % 60;
            snprintf(row, sizeof(row), "%c%lu:%02lu %-6s %s",
                     ((state->entryCount - 1 - start - r) == (state->entryCount - 1 - state->listSelected)) ? '>' : ' ',
                     m, s, e.category, e.detail);
            // Truncate to fit screen
            row[25] = '\0';
            u8g2.drawStr(0, 22 + (r * 8), row);
        }
    }

    u8g2.drawStr(0, 62, "U/D=Scrl C=Exp R=Clr L=Ex");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ============================================================
// Public entry points
// ============================================================

void sessionLogSetup() {
    if (!state) {
        state = (SessionLogState *)calloc(1, sizeof(SessionLogState));
    }
    if (state) {
        state->needsRedraw = true;
    }

    if (!spiffsReady) {
        if (SPIFFS.begin(true)) spiffsReady = true;
    }

    loadLog();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    drawDisplay();
}

void sessionLogLoop() {
    if (!state) return;
    unsigned long now = millis();

    bool upDown     = digitalRead(BUTTON_PIN_UP)     == LOW;
    bool downDown   = digitalRead(BUTTON_PIN_DOWN)   == LOW;
    bool rightDown  = digitalRead(BUTTON_PIN_RIGHT)  == LOW;
    bool centerDown = digitalRead(BUTTON_PIN_CENTER)  == LOW;

    bool rightEdge  = rightDown  && !state->rightPrev;
    bool centerEdge = centerDown && !state->centerPrev;
    state->rightPrev  = rightDown;
    state->centerPrev = centerDown;

    // CENTER: export to serial
    if (centerEdge && state->entryCount > 0) {
        Serial.println();
        Serial.println("# hackbox session log export");
        Serial.println("# uptime_sec,category,detail");
        for (int i = 0; i < state->entryCount; i++) {
            Serial.printf("%lu,%s,%s\n",
                          state->entries[i].uptime,
                          state->entries[i].category,
                          state->entries[i].detail);
        }
        Serial.println("# end");
    }

    // RIGHT: clear log
    if (rightEdge) {
        if (spiffsReady && SPIFFS.exists(LOG_PATH)) {
            SPIFFS.remove(LOG_PATH);
        }
        state->entryCount = 0;
        state->listSelected = 0;
        state->listScroll = 0;
        state->needsRedraw = true;
    }

    // UP/DOWN scroll
    const int ROWS_VISIBLE = 5;
    if (upDown && (now - state->lastUp) > DEBOUNCE_MS) {
        state->lastUp = now;
        if (state->listSelected > 0) {
            state->listSelected--;
            if (state->listSelected < state->listScroll)
                state->listScroll = state->listSelected;
            state->needsRedraw = true;
        }
    }
    if (downDown && (now - state->lastDown) > DEBOUNCE_MS) {
        state->lastDown = now;
        int maxIdx = state->entryCount - 1;
        if (state->listSelected < maxIdx) {
            state->listSelected++;
            if (state->listSelected >= state->listScroll + ROWS_VISIBLE)
                state->listScroll = state->listSelected - (ROWS_VISIBLE - 1);
            state->needsRedraw = true;
        }
    }

    if (state->needsRedraw || (now - state->lastRedraw) > 1000) {
        drawDisplay();
        state->lastRedraw = now;
        state->needsRedraw = false;
    }
}

void sessionLogCleanup() {
    if (state) {
        free(state);
        state = nullptr;
    }
}
