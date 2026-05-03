/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/honey_flood.h"
#include "../include/pindefs.h"
#include "../include/neopixel.h"
#include <U8g2lib.h>
#include <Arduino.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

// Konami: UP UP DOWN DOWN LEFT RIGHT LEFT RIGHT SELECT
static const HoneyButton KONAMI[] = {
    HONEY_UP, HONEY_UP,
    HONEY_DOWN, HONEY_DOWN,
    HONEY_LEFT, HONEY_RIGHT,
    HONEY_LEFT, HONEY_RIGHT,
    HONEY_SELECT
};
static const int KONAMI_LEN = 9;

// matchIndex lives in RTC slow memory — free from DRAM BSS budget
RTC_DATA_ATTR static int8_t matchIndex = 0;

bool honeyFloodPush(HoneyButton b) {
    if (b == KONAMI[matchIndex]) {
        matchIndex++;
        if (matchIndex >= KONAMI_LEN) {
            matchIndex = 0;
            return true;
        }
    } else {
        matchIndex = (b == KONAMI[0]) ? 1 : 0;
    }
    return false;
}

// 5x5 pixel bee sprite (row-major, LSB first)
static const uint8_t BEE_W = 5;
static const uint8_t BEE_H = 5;
static const uint8_t beeBitmap[5] = {
    0b01010,
    0b11111,
    0b01110,
    0b11111,
    0b01010,
};

static void drawBee(int x, int y) {
    for (int row = 0; row < BEE_H; row++) {
        for (int col = 0; col < BEE_W; col++) {
            if (beeBitmap[row] & (1 << (BEE_W - 1 - col))) {
                u8g2.drawPixel(x + col, y + row);
            }
        }
    }
}

void honeyFloodRun() {
    const unsigned long duration = 2000;
    const unsigned long frameDelay = 35;
    unsigned long start = millis();
    uint8_t hue = 0;

    // 16 bees with staggered column and speed offsets
    const int NUM_BEES = 16;
    int beeX[NUM_BEES];
    int beeY[NUM_BEES];
    int beeSpeed[NUM_BEES];

    for (int i = 0; i < NUM_BEES; i++) {
        beeX[i] = (i * 8) % 120;
        beeY[i] = -BEE_H - (i * 3);
        beeSpeed[i] = 1 + (i % 3);
    }

    while (millis() - start < duration) {
        u8g2.clearBuffer();

        for (int i = 0; i < NUM_BEES; i++) {
            beeY[i] += beeSpeed[i];
            if (beeY[i] > 64) beeY[i] = -BEE_H;
            drawBee(beeX[i], beeY[i]);
        }

        u8g2.setFont(u8g2_font_5x8_tr);
        const char* label = "*** HONEY FLOOD ***";
        int lw = u8g2.getUTF8Width(label);
        u8g2.drawStr((128 - lw) / 2, 38, label);

        u8g2.sendBuffer();

        // NeoPixel rainbow cycle
        uint16_t numPix = pixels.numPixels();
        for (uint16_t p = 0; p < numPix; p++) {
            pixels.setPixelColor(p, pixels.ColorHSV((uint16_t)((hue + p * (65536 / numPix)) & 0xFFFF)));
        }
        pixels.show();
        hue += 8;

        delay(frameDelay);
    }

    pixels.clear();
    pixels.show();
    u8g2.clearBuffer();
    u8g2.sendBuffer();
}
