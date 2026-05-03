/*
    hackbox
    hackbox custom firmware

    Sneaker Mode. Operator stealth toggle.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/sneaker_mode.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include "../include/neopixel.h"
#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>
#include <Arduino.h>
#include <EEPROM.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;
extern uint8_t oledBrightness;

// EEPROM slot. Pick a byte that is not already claimed by settingSetup.
// settingSetup uses bytes 0-5 per include/setting.h; slot 32 is far clear
// of all current consumers.
#define EEPROM_SLOT_SNEAKER 32

static bool s_active = false;
static uint8_t s_savedBrightness = 0;
static uint32_t s_enterMs = 0;
static uint32_t s_exitHoldStart = 0;
static bool s_centerWasHeld = false;

static void applyStealth() {
    s_savedBrightness = oledBrightness;
    // U8G2 does not expose true brightness on this SSD1306 panel, but
    // contrast maps to the display IC's contrast register. Drop to 0 so
    // the visible glow is near-nothing in a dark room.
    u8g2.setContrast(0);
    pixels.setBrightness(0);
    pixels.clear();
    pixels.show();
}

static void restoreNormal() {
    u8g2.setContrast(s_savedBrightness ? s_savedBrightness : oledBrightness);
    pixels.setBrightness(oledBrightness);
    pixels.clear();
    pixels.show();
}

bool sneakerModeActive() {
    return s_active;
}

void sneakerModeSetup() {
    s_enterMs = millis();
    s_exitHoldStart = 0;
    s_centerWasHeld = false;

    // Restore persisted state (if any) on entry. Default: always enter
    // stealth when the operator selects this tool; the persisted bit is
    // used for UX continuity if the device reboots while stealthed.
    uint8_t persisted = EEPROM.read(EEPROM_SLOT_SNEAKER);
    (void)persisted; // informational only. We always activate on entry.

    s_active = true;
    applyStealth();

    EEPROM.write(EEPROM_SLOT_SNEAKER, 1);
    EEPROM.commit();

    // Paint a minimal glance frame once. loop() may refresh sparingly.
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(0, 10, "sneaker mode");
    u8g2.drawStr(0, 22, "hold CENTER to exit");
    u8g2.sendBuffer();
}

void sneakerModeLoop() {
    // Long-hold CENTER for 1.2 seconds to exit.
    const uint32_t HOLD_MS = 1200;
    uint32_t now = millis();
    bool centerDown = (digitalRead(BUTTON_PIN_CENTER) == LOW);

    if (centerDown) {
        if (!s_centerWasHeld) {
            s_exitHoldStart = now;
            s_centerWasHeld = true;
        } else if ((now - s_exitHoldStart) >= HOLD_MS) {
            // Exit requested. The menu framework will call cleanup next.
            // Draw a brief confirmation so the operator knows it took.
            u8g2.setContrast(s_savedBrightness ? s_savedBrightness : oledBrightness);
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_6x10_tf);
            u8g2.drawStr(0, 12, "exiting sneaker");
            u8g2.sendBuffer();
            // Signal to the caller by leaving s_active true; cleanup() will
            // clear it. We rely on the menu framework reading LEFT/CENTER
            // via its own handler, so here we simply keep s_active until
            // cleanup runs. A small delay makes the transition readable.
            delay(400);
            s_centerWasHeld = false;
            s_exitHoldStart = 0;
            return;
        }
    } else {
        s_centerWasHeld = false;
        s_exitHoldStart = 0;
    }

    // Cheap 1Hz heartbeat redraw so the minimal screen does not ghost.
    static uint32_t lastPaint = 0;
    if ((now - lastPaint) >= 1000) {
        lastPaint = now;
        u8g2.setContrast(0);
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_5x7_tf);
        u8g2.drawStr(0, 10, "sneaker mode");
        u8g2.drawStr(0, 22, "hold CENTER to exit");
        // Tiny uptime marker, useful for operator to confirm firmware alive.
        char buf[20];
        uint32_t alive = (now - s_enterMs) / 1000;
        snprintf(buf, sizeof(buf), "alive: %lus", (unsigned long)alive);
        u8g2.drawStr(0, 34, buf);
        u8g2.sendBuffer();
    }
}

void sneakerModeCleanup() {
    s_active = false;
    restoreNormal();
    EEPROM.write(EEPROM_SLOT_SNEAKER, 0);
    EEPROM.commit();
}
