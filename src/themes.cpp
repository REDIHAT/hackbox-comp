/*
    hackbox Themes implementation

    Four built-in color palettes for the onboard NeoPixel. Persisted at
    EEPROM byte 20 (former dangerous-actions toggle, unused since the
    toggle was removed). Default theme is Hive to preserve behavior for
    users upgrading from v1.1.x.

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#include "../include/themes.h"

#include <EEPROM.h>

#define EEPROM_ADDRESS_THEME 20

static const Theme THEMES[THEME_COUNT] = {
    // THEME_HIVE , classic green IDLE, blue RECON, red OFFENSIVE, amber CAPTURE,
    // purple GAME, red ALERT. Matches v1.1.x colors exactly.
    {
        "Hive",
        {  0,  85,   0}, // idle
        {  0,   0, 255}, // recon
        {255,   0,   0}, // offensive
        {255, 140,   0}, // capture
        {128,   0, 255}, // game
        {255,   0,   0}, // alert
    },
    // THEME_STEALTH , everything dim red. Low visual signature for
    // field operators who do not want a flashing beacon on their hip.
    {
        "Stealth",
        { 30,   0,   0},
        { 30,   0,   0},
        { 40,   0,   0},
        { 40,   0,   0},
        { 30,   0,   0},
        { 60,   0,   0},
    },
    // THEME_SUNSET , warm amber and magenta. Vibe palette for content.
    {
        "Sunset",
        {255, 100,   0}, // amber breathe
        {200,   0, 120}, // magenta
        {200,  30,  30}, // deep red
        {255, 180,   0}, // bright orange
        {180,   0, 200}, // magenta-purple
        {255,  40,   0}, // red-orange alert
    },
    // THEME_ARCTIC , cool cyan and white. Minimalist winter palette.
    {
        "Arctic",
        {  0, 200, 255}, // cyan breathe
        {200, 200, 255}, // icy white
        {255,   0, 180}, // hot pink offensive
        {180, 220, 255}, // pale blue capture
        {100, 160, 255}, // blue game
        {255,  60, 180}, // pink alert
    },
};

static ThemeId g_currentTheme = THEME_HIVE;

void themesSetup() {
    EEPROM.begin(512);
    uint8_t stored = EEPROM.read(EEPROM_ADDRESS_THEME);
    if (stored >= THEME_COUNT) {
        // 0xFF (erased) or stale byte from the old dangerous-actions
        // toggle. Fall back to default Hive and write it out so
        // subsequent reads are clean.
        g_currentTheme = THEME_HIVE;
        EEPROM.write(EEPROM_ADDRESS_THEME, (uint8_t)THEME_HIVE);
        EEPROM.commit();
    } else {
        g_currentTheme = (ThemeId)stored;
    }
}

ThemeId themeCurrentId() {
    return g_currentTheme;
}

const Theme* themeCurrent() {
    return &THEMES[g_currentTheme];
}

const char* themeCurrentName() {
    return THEMES[g_currentTheme].name;
}

void themeCycle() {
    g_currentTheme = (ThemeId)(((int)g_currentTheme + 1) % THEME_COUNT);
    EEPROM.write(EEPROM_ADDRESS_THEME, (uint8_t)g_currentTheme);
    EEPROM.commit();
}
