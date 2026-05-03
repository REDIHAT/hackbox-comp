/*
    hackbox Themes

    NeoPixel color palette packs. Each theme maps the six NeoStatus values
    (IDLE, RECON, OFFENSIVE, CAPTURE, GAME, ALERT) to an RGB triple. Tools
    keep calling neoSetStatus() with semantic modes; the palette layer
    turns that into the right hue for the selected theme.

    LEVEL_UP keeps its rainbow cycle, themes do not override rainbow.

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#ifndef THEMES_H
#define THEMES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} ThemeColor;

typedef struct {
    const char* name;
    ThemeColor idle;
    ThemeColor recon;
    ThemeColor offensive;
    ThemeColor capture;
    ThemeColor game;
    ThemeColor alert;
} Theme;

typedef enum {
    THEME_HIVE = 0,
    THEME_STEALTH,
    THEME_SUNSET,
    THEME_ARCTIC,
    THEME_COUNT
} ThemeId;

// Initializes theme subsystem from EEPROM. Call from setup().
void themesSetup();

// Returns the currently selected theme id.
ThemeId themeCurrentId();

// Returns a pointer to the currently selected theme (never null).
const Theme* themeCurrent();

// Returns the theme name for display.
const char* themeCurrentName();

// Cycles to the next theme, persists to EEPROM.
void themeCycle();

#ifdef __cplusplus
}
#endif

#endif
