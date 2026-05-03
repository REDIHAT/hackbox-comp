/*
    hackbox NeoPixel Status System

    Drives a single RGB NeoPixel with visual patterns that reflect
    what the device is doing. Tools set a status mode; the loop
    handles the animation.

    Patterns:
      OFF       - LED off
      IDLE      - slow green pulse (2s period)
      RECON     - blue breathe (1.5s period)
      OFFENSIVE - red blink (800ms toggle)
      CAPTURE   - steady yellow
      GAME      - purple breathe (2s period)
      ALERT     - fast red flash (200ms toggle, auto-decays after 3s)
      LEVEL_UP  - rainbow cycle (auto-decays after 4s)

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#include "../include/neopixel.h"
#include "../include/setting.h"
#include "../include/themes.h"
#include <EEPROM.h>
#include "../include/pindefs.h"

extern Adafruit_NeoPixel pixels;

void neopixelSetup() {
    EEPROM.begin(512);
    neoPixelActive = EEPROM.read(0);

    if (neoPixelActive) {
        pixels.begin();
        pixels.setBrightness(8);
        pixels.clear();
        pixels.show();
    }
}

// ============================================================
// Legacy blink API (kept for backward compat)
// ============================================================

static NeoStatus currentStatus = NEO_OFF;
static unsigned long statusSetAt = 0;

static bool isBlinking = false;
static uint8_t baseRed = 0;
static uint8_t baseGreen = 0;
static uint8_t baseBlue = 0;
static unsigned long lastBlinkTime = 0;
static bool blinkState = false;
const int blinkSpeed = 800;

void blinkColor(uint8_t r, uint8_t g, uint8_t b) {
    if (!neoPixelActive) return;
    isBlinking = true;
    baseRed = r;
    baseGreen = g;
    baseBlue = b;
    blinkState = true;
    lastBlinkTime = millis();
}

void stopBlinking() {
    isBlinking = false;
    currentStatus = NEO_OFF;
    if (neoPixelActive) {
        pixels.setPixelColor(0, 0, 0, 0);
        pixels.show();
    }
}

// ============================================================
// Status mode system
// ============================================================

// Auto-decay durations for transient statuses
static const unsigned long ALERT_DECAY_MS = 3000;
static const unsigned long LEVELUP_DECAY_MS = 4000;

void neoSetStatus(NeoStatus status) {
    currentStatus = status;
    statusSetAt = millis();
    isBlinking = false;  // override legacy blink
}

NeoStatus neoGetStatus() {
    return currentStatus;
}

// Compute a breathing value 0-255 for a given period
static uint8_t breathe(unsigned long now, unsigned long periodMs) {
    unsigned long phase = now % periodMs;
    // Triangle wave: ramp up first half, down second half
    if (phase < periodMs / 2) {
        return (uint8_t)((phase * 255) / (periodMs / 2));
    } else {
        return (uint8_t)(((periodMs - phase) * 255) / (periodMs / 2));
    }
}

// Rainbow hue wheel: input 0-255, output RGB
static void wheelColor(uint8_t pos, uint8_t *r, uint8_t *g, uint8_t *b) {
    if (pos < 85) {
        *r = pos * 3;
        *g = 255 - pos * 3;
        *b = 0;
    } else if (pos < 170) {
        pos -= 85;
        *r = 255 - pos * 3;
        *g = 0;
        *b = pos * 3;
    } else {
        pos -= 170;
        *r = 0;
        *g = pos * 3;
        *b = 255 - pos * 3;
    }
}

void neopixelLoop() {
    if (!neoPixelActive) return;

    unsigned long now = millis();

    // Legacy blink path (if a tool called blinkColor directly)
    if (isBlinking && currentStatus == NEO_OFF) {
        if (now - lastBlinkTime >= blinkSpeed) {
            lastBlinkTime = now;
            blinkState = !blinkState;
            if (blinkState) {
                pixels.setPixelColor(0, pixels.Color(baseRed, baseGreen, baseBlue));
            } else {
                pixels.setPixelColor(0, 0, 0, 0);
            }
            pixels.show();
        }
        return;
    }

    // Status mode patterns
    switch (currentStatus) {
        case NEO_OFF:
            // Only update once to avoid spamming show()
            break;

        case NEO_IDLE: {
            uint8_t v = breathe(now, 2000);
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, pixels.Color(
                (th->idle.r * v) / 255 / 3,
                (th->idle.g * v) / 255 / 3,
                (th->idle.b * v) / 255 / 3));
            pixels.show();
            break;
        }

        case NEO_RECON: {
            uint8_t v = breathe(now, 1500);
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, pixels.Color(
                (th->recon.r * v) / 255,
                (th->recon.g * v) / 255,
                (th->recon.b * v) / 255));
            pixels.show();
            break;
        }

        case NEO_OFFENSIVE: {
            bool on = ((now / 400) % 2) == 0;
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, on
                ? pixels.Color(th->offensive.r, th->offensive.g, th->offensive.b)
                : 0);
            pixels.show();
            break;
        }

        case NEO_CAPTURE: {
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, pixels.Color(
                th->capture.r, th->capture.g, th->capture.b));
            pixels.show();
            break;
        }

        case NEO_GAME: {
            uint8_t v = breathe(now, 2000);
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, pixels.Color(
                (th->game.r * v) / 255 / 2,
                (th->game.g * v) / 255 / 2,
                (th->game.b * v) / 255 / 2));
            pixels.show();
            break;
        }

        case NEO_ALERT: {
            // Fast red flash, auto-decays. Theme chooses the alert hue so
            // Stealth users do not get a 255-bright red strobe on their hip.
            if ((now - statusSetAt) > ALERT_DECAY_MS) {
                currentStatus = NEO_OFF;
                pixels.setPixelColor(0, 0);
                pixels.show();
                break;
            }
            bool on = ((now / 100) % 2) == 0;
            const Theme* th = themeCurrent();
            pixels.setPixelColor(0, on
                ? pixels.Color(th->alert.r, th->alert.g, th->alert.b)
                : 0);
            pixels.show();
            break;
        }

        case NEO_LEVEL_UP: {
            // Rainbow cycle, auto-decays
            if ((now - statusSetAt) > LEVELUP_DECAY_MS) {
                currentStatus = NEO_OFF;
                pixels.setPixelColor(0, 0);
                pixels.show();
                break;
            }
            uint8_t pos = (uint8_t)((now / 10) % 256);
            uint8_t r, g, b;
            wheelColor(pos, &r, &g, &b);
            pixels.setPixelColor(0, pixels.Color(r, g, b));
            pixels.show();
            break;
        }
    }
}
