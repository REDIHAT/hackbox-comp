/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/
#ifndef NEOPIXEL_H
#define NEOPIXEL_H

#include <Adafruit_NeoPixel.h>

extern Adafruit_NeoPixel pixels;

void neopixelSetup();
void neopixelLoop();

void blinkColor(uint8_t r, uint8_t g, uint8_t b);
void stopBlinking();

// Status mode system -- richer visual patterns per app category
enum NeoStatus : uint8_t {
    NEO_OFF = 0,        // LED off
    NEO_IDLE,           // slow green pulse (menu browsing)
    NEO_RECON,          // blue breathe (scanning/detecting)
    NEO_OFFENSIVE,      // red blink (attack tools)
    NEO_CAPTURE,        // yellow steady (capturing data)
    NEO_GAME,           // purple breathe (games)
    NEO_ALERT,          // fast red flash (threat detected, auto-decays)
    NEO_LEVEL_UP,       // rainbow cycle (XP level up, auto-decays)
};

void neoSetStatus(NeoStatus status);
NeoStatus neoGetStatus();

#endif // NEOPIXEL_H
