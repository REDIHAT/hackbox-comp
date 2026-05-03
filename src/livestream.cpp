/*
    hackbox Livestream implementation

    Emits newline-delimited JSON events on Serial. Scope is deliberately
    small: one emit helper, EEPROM-persisted on/off flag. The companion
    overlay lives outside firmware.

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#include "../include/livestream.h"

#include <Arduino.h>
#include <EEPROM.h>

#define EEPROM_ADDRESS_LIVESTREAM 2

static bool g_livestreamEnabled = false;

void livestreamSetup() {
    EEPROM.begin(512);
    uint8_t stored = EEPROM.read(EEPROM_ADDRESS_LIVESTREAM);
    if (stored == 0xFF) {
        // Erased or fresh board. Default to OFF so shipped devices do not
        // spam the serial console for users who just want to read boot logs.
        g_livestreamEnabled = false;
        EEPROM.write(EEPROM_ADDRESS_LIVESTREAM, 0);
        EEPROM.commit();
    } else {
        g_livestreamEnabled = (stored == 1);
    }
}

bool livestreamEnabled() {
    return g_livestreamEnabled;
}

void livestreamToggle() {
    g_livestreamEnabled = !g_livestreamEnabled;
    EEPROM.write(EEPROM_ADDRESS_LIVESTREAM, g_livestreamEnabled ? 1 : 0);
    EEPROM.commit();
}

// Escape a string for embedding inside a JSON string literal. Minimal
// escaping: quote, backslash, control chars. Writes up to outCap bytes
// including the final null. Returns bytes written excluding the null.
static size_t jsonEscape(char* out, size_t outCap, const char* in) {
    if (!out || outCap == 0) return 0;
    size_t w = 0;
    if (in) {
        for (size_t i = 0; in[i] != '\0' && w + 2 < outCap; i++) {
            char c = in[i];
            if (c == '"' || c == '\\') {
                out[w++] = '\\';
                out[w++] = c;
            } else if ((unsigned char)c < 0x20) {
                // Replace control chars with a space rather than carry them
                // through into the JSON stream. Keeps parsers happy.
                out[w++] = ' ';
            } else {
                out[w++] = c;
            }
        }
    }
    out[w] = '\0';
    return w;
}

void livestreamEmit(const char* type, const char* data) {
    if (!g_livestreamEnabled) return;
    if (!type) return;

    char typeBuf[32];
    char dataBuf[96];
    jsonEscape(typeBuf, sizeof(typeBuf), type);
    jsonEscape(dataBuf, sizeof(dataBuf), data);

    if (data && dataBuf[0] != '\0') {
        Serial.printf("{\"t\":%lu,\"ev\":\"%s\",\"d\":\"%s\"}\n",
            (unsigned long)millis(), typeBuf, dataBuf);
    } else {
        Serial.printf("{\"t\":%lu,\"ev\":\"%s\"}\n",
            (unsigned long)millis(), typeBuf);
    }
}
