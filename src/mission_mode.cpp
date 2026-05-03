/*
    hackbox Mission Mode

    Guided-checklist workflow app. Walks the user through a preset
    sequence of steps for a common engagement pattern (recon, red
    team, blue team audit) with a short description of what to do
    at each step and a named recommended tool. The user navigates
    to the recommended tool themselves using the main menu, does
    the work, comes back to Mission Mode, and marks the step done.

    Award model: completing all steps in a mission grants a bonus
    XP payout on top of whatever XP the individual tools already
    awarded while the user was in them. Mission Mode also tracks
    a lifetime counter and a per-mission "completed" bitfield in
    EEPROM so the user can see progress across sessions.

    This is the v0.1 shape. A v0.2 pass would wire actual automated
    tool-chain launching from inside Mission Mode -- calling the
    child tool's setup/loop/cleanup from Mission Mode's loop and
    consuming the LEFT edge so the framework's top-level app-exit
    does not tear us down when the user exits a child tool. That's
    tractable but has enough hardware-state-conflict edge cases
    (WiFi init vs BLE init, radio manager ownership, button prev
    flags) to deserve its own pass. For v0.1 the contract is
    simpler: Mission Mode guides, the user drives.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#include "../include/mission_mode.h"
#include "../include/level_system.h"
#include "../include/display_mirror.h"
#include <EEPROM.h>
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

// ============================================================
// EEPROM layout
//
// Addresses 116 - 118 are free in the global EEPROM map (between
// EEPROM_SW_TEAM at 115 and EEPROM_POKEDEX_START at 120). Using
// 3 bytes:
//
//   116 MAGIC  0x4D means mission state has been initialized
//   117 FLAGS  bit 0 = Recon done, bit 1 = Red Team done,
//              bit 2 = Blue Team done
//   118 COUNT  lifetime total missions completed, capped at 255
// ============================================================

#define EEPROM_MISSION_MAGIC  116
#define EEPROM_MISSION_FLAGS  117
#define EEPROM_MISSION_COUNT  118
#define MISSION_MAGIC_VAL     0x4D

// ============================================================
// Mission content
//
// Missions and their steps are const tables that live in .rodata
// (flash) so the full text of every mission does not eat DRAM.
// Each mission carries a string name, short one-line blurb, final
// XP reward, and a pointer into a flat step table. The step table
// itself is const.
// ============================================================

struct MissionStep {
    const char *title;        // short one-line label, ~20 chars
    const char *tool;         // exact menu label of the recommended tool
    const char *instruction;  // 2-3 lines of what to do, ~100 chars
};

struct Mission {
    const char *name;
    const char *blurb;
    const MissionStep *steps;
    uint8_t stepCount;
    uint8_t xpReward;   // granted once on completion
    uint8_t flagBit;    // which bit in EEPROM_MISSION_FLAGS records completion
};

// --- Recon Mission ---
static const MissionStep RECON_STEPS[] = {
    {
        "Sweep the air",
        "WiFi Scan",
        "Open WiFi > WiFi Scan. Note how many APs are in range and "
        "which channels they cluster on."
    },
    {
        "See the hidden",
        "Hidden Networks",
        "Open WiFi > Hidden Networks. Any AP broadcasting without an "
        "SSID shows up here once a client probes it."
    },
    {
        "Inventory BLE",
        "Device Scout",
        "Open Other > Device Scout. Combined WiFi and BLE sweep. "
        "Count unique devices and watch the RSSI ranking."
    },
    {
        "Check for trackers",
        "Tracker Sweep",
        "Open Other > Tracker Sweep. If anything lights up on the "
        "threat banner, drill into the list view with RIGHT."
    }
};

// --- Red Team Mission ---
static const MissionStep REDTEAM_STEPS[] = {
    {
        "Pick a target",
        "WiFi Scan",
        "Open WiFi > WiFi Scan. Identify the AP you are authorized "
        "to engage and write down its BSSID and channel."
    },
    {
        "Test deauth",
        "Deauth Scanner",
        "Open WiFi > Deauth Scanner. Confirm the target is not "
        "PMF-protected before attempting a deauth-based capture."
    },
    {
        "Capture the handshake",
        "Handshake Cap",
        "Open WiFi > Handshake Cap. Select the target, let the tool "
        "deauth a client, and wait for the four EAPOL messages."
    },
    {
        "Audit WPS",
        "WPS Auditor",
        "Open WiFi > WPS Auditor. If the target is WPS-enabled the "
        "default-PIN computation may save you a crack."
    }
};

// --- Blue Team Audit Mission ---
static const MissionStep BLUETEAM_STEPS[] = {
    {
        "Spot rogue APs",
        "Pineapple Detector",
        "Open WiFi > Pineapple Detector. Walk the perimeter of your "
        "site and note anything with a WiFi Pineapple fingerprint."
    },
    {
        "Find Pwnagotchis",
        "Pwnagotchi Detector",
        "Open WiFi > Pwnagotchi Detector. If a Pwnagotchi is present "
        "someone is passively collecting handshakes nearby."
    },
    {
        "Check for trackers",
        "Tracker Sweep",
        "Open Other > Tracker Sweep. Covers AirTags, SmartTags, "
        "Tile, Flipper, Ray-Ban, Axon, and Flock BLE beacons."
    },
    {
        "Document the sweep",
        "Wardriving",
        "Open WiFi > Wardriving. Save a WiGLE-format log of every "
        "AP in range with GPS coordinates for the engagement report."
    }
};

static const Mission MISSIONS[] = {
    {
        "Recon Mission",
        "Passive sweep: what is in the air around you right now",
        RECON_STEPS,
        sizeof(RECON_STEPS) / sizeof(RECON_STEPS[0]),
        20,   // XP reward
        0x01  // flag bit 0
    },
    {
        "Red Team Mission",
        "Authorized engagement: target WiFi capture flow",
        REDTEAM_STEPS,
        sizeof(REDTEAM_STEPS) / sizeof(REDTEAM_STEPS[0]),
        40,
        0x02
    },
    {
        "Blue Team Audit",
        "Perimeter sweep for rogue infrastructure and tracking gear",
        BLUETEAM_STEPS,
        sizeof(BLUETEAM_STEPS) / sizeof(BLUETEAM_STEPS[0]),
        30,
        0x04
    }
};
static const uint8_t MISSION_COUNT =
    sizeof(MISSIONS) / sizeof(MISSIONS[0]);

// ============================================================
// State
//
// Mission Mode runtime state is small enough (~32 bytes) that
// heap allocation is not worth the complexity. It lives in .bss
// directly. If the app budget gets tight later, fold it into a
// heap-allocated struct the same way tracking_sweep.cpp does.
// ============================================================

enum MissionView : uint8_t {
    VIEW_PICK = 0,   // scroll through available missions
    VIEW_RUN,        // mission is active, showing current step
    VIEW_DONE        // summary after the last step was marked
};

static MissionView currentView = VIEW_PICK;
static uint8_t pickIndex = 0;     // selected mission in the picker
static uint8_t activeMission = 0; // which mission is running
static uint8_t currentStep = 0;   // which step within the active mission
static uint32_t missionStartMs = 0;

// Button edge detection. Edge-triggered so a held button does not
// spam actions. Same pattern as tracking_sweep after the cycle 4
// fix. See src/tracking_sweep.cpp for rationale.
static bool upPrev = false, downPrev = false;
static bool leftPrev = false, rightPrev = false;
static bool centerPrev = false;

static bool needsRedraw = true;

// EEPROM accessors. Initialized lazily on first setup so we do not
// clobber whatever was already there if this is a fresh device.
static uint8_t missionFlags = 0;
static uint8_t missionLifetime = 0;

static void loadMissionState() {
    uint8_t magic = EEPROM.read(EEPROM_MISSION_MAGIC);
    if (magic != MISSION_MAGIC_VAL) {
        // First boot: write the magic + zero the counters.
        EEPROM.write(EEPROM_MISSION_MAGIC, MISSION_MAGIC_VAL);
        EEPROM.write(EEPROM_MISSION_FLAGS, 0);
        EEPROM.write(EEPROM_MISSION_COUNT, 0);
        EEPROM.commit();
        missionFlags = 0;
        missionLifetime = 0;
        return;
    }
    missionFlags    = EEPROM.read(EEPROM_MISSION_FLAGS);
    missionLifetime = EEPROM.read(EEPROM_MISSION_COUNT);
}

static void saveMissionState() {
    EEPROM.write(EEPROM_MISSION_FLAGS, missionFlags);
    EEPROM.write(EEPROM_MISSION_COUNT, missionLifetime);
    EEPROM.commit();
}

// ============================================================
// Drawing
// ============================================================

static void drawPickView() {
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "MISSION MODE");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    // Mission list. Three entries fit comfortably. Each row shows
    // a selection caret, the name, and a small checkmark-ish marker
    // if the mission's completion flag is set in EEPROM.
    for (uint8_t i = 0; i < MISSION_COUNT; i++) {
        const Mission &m = MISSIONS[i];
        bool done = (missionFlags & m.flagBit) != 0;

        char line[28];
        snprintf(line, sizeof(line), "%c %s %s",
                 (i == pickIndex) ? '>' : ' ',
                 m.name,
                 done ? "*" : " ");
        u8g2.drawStr(0, 22 + (i * 8), line);
    }

    // Blurb for the currently selected mission so the user knows
    // what they are picking before they press CENTER.
    const Mission &sel = MISSIONS[pickIndex];
    char blurb[32];
    snprintf(blurb, sizeof(blurb), "%.30s", sel.blurb);
    u8g2.drawStr(0, 50, blurb);

    // Lifetime counter on the footer so the user can see progress
    // accumulating across sessions. Keeps the line short.
    char footer[28];
    snprintf(footer, sizeof(footer),
             "Done:%d  C=Start L=Exit", (int)missionLifetime);
    u8g2.drawStr(0, 62, footer);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// Word-wrap a string to fit inside `maxCharsPerLine`, writing up
// to `maxLines` rows into `out[0..maxLines-1]`. Each row is a
// null-terminated string of at most `maxCharsPerLine` chars. This
// is deliberately dumb -- no hyphenation, no trailing-whitespace
// trimming beyond a leading skip. Just enough to render 100-char
// step instructions onto a 128 px wide OLED using the 5x8 font,
// which fits about 25 chars per line.
static void wrapText(const char *src, char out[][26], int maxLines,
                     int maxCharsPerLine) {
    int line = 0;
    int col = 0;
    int srcLen = strlen(src);
    int i = 0;
    while (i < srcLen && line < maxLines) {
        // Skip leading whitespace on a new line.
        if (col == 0) {
            while (i < srcLen && src[i] == ' ') i++;
            if (i >= srcLen) break;
        }
        // Find next word boundary.
        int wordEnd = i;
        while (wordEnd < srcLen && src[wordEnd] != ' ') wordEnd++;
        int wordLen = wordEnd - i;

        // If the word alone is longer than a line, hard-break it.
        if (wordLen > maxCharsPerLine) wordLen = maxCharsPerLine;

        // Will it fit on the current line?
        int spaceNeeded = (col == 0) ? wordLen : (wordLen + 1);
        if (col + spaceNeeded > maxCharsPerLine) {
            out[line][col] = '\0';
            line++;
            col = 0;
            if (line >= maxLines) break;
            continue;
        }

        if (col > 0) out[line][col++] = ' ';
        for (int k = 0; k < wordLen && col < maxCharsPerLine - 1; k++) {
            out[line][col++] = src[i + k];
        }
        i = wordEnd;
    }
    if (line < maxLines) {
        out[line][col] = '\0';
        line++;
    }
    // Empty any remaining unused lines.
    for (int k = line; k < maxLines; k++) out[k][0] = '\0';
}

static void drawRunView() {
    u8g2.clearBuffer();
    const Mission &m = MISSIONS[activeMission];
    const MissionStep &step = m.steps[currentStep];

    // Header: step counter + mission name abbreviated.
    u8g2.setFont(u8g2_font_6x10_tr);
    char hdr[24];
    snprintf(hdr, sizeof(hdr), "%d/%d %.14s",
             (int)(currentStep + 1), (int)m.stepCount, m.name);
    u8g2.drawStr(0, 10, hdr);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    // Step title on its own line.
    char titleLine[26];
    snprintf(titleLine, sizeof(titleLine), "%.25s", step.title);
    u8g2.drawStr(0, 22, titleLine);

    // Tool row: "Tool: <tool name>"
    char toolLine[32];
    snprintf(toolLine, sizeof(toolLine), "Tool: %.19s", step.tool);
    u8g2.drawStr(0, 32, toolLine);

    // Wrapped instruction body, up to 3 lines at ~25 chars.
    static char wrapped[3][26];
    wrapText(step.instruction, wrapped, 3, 25);
    for (int r = 0; r < 3; r++) {
        if (wrapped[r][0]) {
            u8g2.drawStr(0, 42 + (r * 8), wrapped[r]);
        }
    }

    u8g2.drawStr(0, 62, "R=Done C=Skip L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void drawDoneView() {
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "MISSION COMPLETE");
    u8g2.drawHLine(0, 12, 128);

    const Mission &m = MISSIONS[activeMission];
    uint32_t elapsed = (millis() - missionStartMs) / 1000;

    u8g2.setFont(u8g2_font_5x8_tr);
    char line[28];

    snprintf(line, sizeof(line), "%.26s", m.name);
    u8g2.drawStr(0, 24, line);

    snprintf(line, sizeof(line), "Steps: %d/%d",
             (int)m.stepCount, (int)m.stepCount);
    u8g2.drawStr(0, 34, line);

    if (elapsed >= 60) {
        snprintf(line, sizeof(line), "Time: %lum %lus",
                 (unsigned long)(elapsed / 60),
                 (unsigned long)(elapsed % 60));
    } else {
        snprintf(line, sizeof(line), "Time: %lus",
                 (unsigned long)elapsed);
    }
    u8g2.drawStr(0, 44, line);

    snprintf(line, sizeof(line), "+%d XP awarded",
             (int)m.xpReward);
    u8g2.drawStr(0, 54, line);

    u8g2.drawStr(0, 62, "C=Back L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

static void draw() {
    switch (currentView) {
        case VIEW_PICK: drawPickView(); break;
        case VIEW_RUN:  drawRunView();  break;
        case VIEW_DONE: drawDoneView(); break;
    }
}

// ============================================================
// Public entry points
// ============================================================

void missionModeSetup() {
    loadMissionState();

    currentView = VIEW_PICK;
    pickIndex = 0;
    activeMission = 0;
    currentStep = 0;
    missionStartMs = 0;
    needsRedraw = true;

    upPrev = downPrev = leftPrev = rightPrev = centerPrev = false;

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    draw();
}

void missionModeLoop() {
    bool upNow     = digitalRead(BUTTON_PIN_UP)     == LOW;
    bool downNow   = digitalRead(BUTTON_PIN_DOWN)   == LOW;
    bool rightNow  = digitalRead(BUTTON_PIN_RIGHT)  == LOW;
    bool centerNow = digitalRead(BUTTON_PIN_CENTER) == LOW;

    // Edge detection for every button. LEFT is owned by the
    // framework (app-exit); we do not read it here.
    bool upEdge     = upNow     && !upPrev;
    bool downEdge   = downNow   && !downPrev;
    bool rightEdge  = rightNow  && !rightPrev;
    bool centerEdge = centerNow && !centerPrev;
    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;
    centerPrev = centerNow;

    switch (currentView) {
        case VIEW_PICK: {
            if (upEdge && pickIndex > 0) {
                pickIndex--;
                needsRedraw = true;
            }
            if (downEdge && pickIndex < MISSION_COUNT - 1) {
                pickIndex++;
                needsRedraw = true;
            }
            if (centerEdge) {
                // Start the selected mission.
                activeMission = pickIndex;
                currentStep = 0;
                missionStartMs = millis();
                currentView = VIEW_RUN;
                needsRedraw = true;
            }
            break;
        }

        case VIEW_RUN: {
            if (rightEdge) {
                // Mark step done and advance.
                const Mission &m = MISSIONS[activeMission];
                currentStep++;
                if (currentStep >= m.stepCount) {
                    // Mission complete. Grant XP and update EEPROM.
                    addXP(m.xpReward);
                    missionFlags |= m.flagBit;
                    if (missionLifetime < 255) missionLifetime++;
                    saveMissionState();
                    currentView = VIEW_DONE;
                }
                needsRedraw = true;
            }
            if (centerEdge) {
                // Skip: advance without marking done. No XP penalty
                // for v0.1 -- the user is the source of truth on
                // whether a step was actually performed.
                const Mission &m = MISSIONS[activeMission];
                currentStep++;
                if (currentStep >= m.stepCount) {
                    // Skipped the last step -- still bail back to
                    // the picker rather than showing a "complete"
                    // screen, since nothing was completed.
                    currentView = VIEW_PICK;
                }
                needsRedraw = true;
            }
            break;
        }

        case VIEW_DONE: {
            if (centerEdge) {
                currentView = VIEW_PICK;
                pickIndex = activeMission;
                needsRedraw = true;
            }
            break;
        }
    }

    if (needsRedraw) {
        draw();
        needsRedraw = false;
    }
}

void missionModeCleanup() {
    // Nothing to tear down -- no BLE, no WiFi, no radios. Just a
    // UI app. EEPROM is already flushed by saveMissionState() on
    // every completion path.
}
