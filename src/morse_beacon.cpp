/*
    hackbox
    hackbox custom firmware

    Morse Beacon. NeoPixel blinks a selected message in Morse code.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/morse_beacon.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>
#include <Arduino.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;
extern uint8_t oledBrightness;

namespace {

struct Message {
    const char* name;
    const char* text;
};

const Message MESSAGES[] = {
    { "CK42X",   "CK42X" },
    { "HACK",    "HACKBOX" },
    { "SOS",     "SOS" },
    { "HIVE",    "HIVE" },
    { "BUZZ",    "STAY BUZZY" },
};
const uint8_t NUM_MESSAGES = sizeof(MESSAGES) / sizeof(MESSAGES[0]);

struct ColorEntry {
    const char* name;
    uint32_t color;
};

const ColorEntry COLORS[] = {
    { "red",    0xFF0000 },
    { "amber",  0xFFB300 },
    { "green",  0x00FF00 },
    { "cyan",   0x00C8FF },
    { "violet", 0x8800FF },
};
const uint8_t NUM_COLORS = sizeof(COLORS) / sizeof(COLORS[0]);

struct SpeedEntry {
    const char* name;
    uint16_t unit_ms; // length of a "dot"
};

const SpeedEntry SPEEDS[] = {
    { "slow", 220 },
    { "med",  130 },
    { "fast",  70 },
};
const uint8_t NUM_SPEEDS = sizeof(SPEEDS) / sizeof(SPEEDS[0]);

uint8_t s_msgIdx = 0;
uint8_t s_colorIdx = 1;
uint8_t s_speedIdx = 1;

// Current transmission state machine.
const char* s_currentText = nullptr;
size_t s_textPos = 0;
const char* s_currentSymbol = nullptr;
size_t s_symbolPos = 0;
uint32_t s_stateStartMs = 0;
enum Phase { PHASE_IDLE, PHASE_ON, PHASE_OFF_INTRA, PHASE_OFF_LETTER, PHASE_OFF_WORD };
Phase s_phase = PHASE_IDLE;

// Debounce.
uint32_t s_lastUpMs = 0;
uint32_t s_lastDownMs = 0;
uint32_t s_lastLeftMs = 0;
uint32_t s_lastRightMs = 0;
const uint32_t DEBOUNCE_MS = 250;

const char* MORSE_TABLE[26] = {
    ".-",    "-...",  "-.-.",  "-..",   ".",
    "..-.",  "--.",   "....",  "..",    ".---",
    "-.-",   ".-..",  "--",    "-.",    "---",
    ".--.",  "--.-",  ".-.",   "...",   "-",
    "..-",   "...-",  ".--",   "-..-",  "-.--",
    "--.."
};

const char* MORSE_DIGITS[10] = {
    "-----", ".----", "..---", "...--", "....-",
    ".....", "-....", "--...", "---..", "----."
};

const char* morseOf(char c) {
    if (c >= 'A' && c <= 'Z') return MORSE_TABLE[c - 'A'];
    if (c >= 'a' && c <= 'z') return MORSE_TABLE[c - 'a'];
    if (c >= '0' && c <= '9') return MORSE_DIGITS[c - '0'];
    return nullptr;
}

void setPixelOn() {
    pixels.setPixelColor(0, COLORS[s_colorIdx].color);
    pixels.setBrightness(oledBrightness);
    pixels.show();
}

void setPixelOff() {
    pixels.setPixelColor(0, 0);
    pixels.show();
}

void startNextSymbolElement(uint32_t now) {
    uint16_t unit = SPEEDS[s_speedIdx].unit_ms;
    // Advance within the current letter's dots/dashes.
    if (s_currentSymbol == nullptr) {
        // Pick up a new character from s_currentText.
        if (s_currentText == nullptr || s_currentText[s_textPos] == '\0') {
            // End of message. Restart after a word gap.
            setPixelOff();
            s_phase = PHASE_OFF_WORD;
            s_stateStartMs = now;
            s_textPos = 0;
            s_currentText = MESSAGES[s_msgIdx].text;
            return;
        }
        char c = s_currentText[s_textPos++];
        if (c == ' ') {
            setPixelOff();
            s_phase = PHASE_OFF_WORD;
            s_stateStartMs = now;
            return;
        }
        const char* m = morseOf(c);
        if (m == nullptr) {
            // Skip unsupported chars silently.
            return;
        }
        s_currentSymbol = m;
        s_symbolPos = 0;
    }

    char elt = s_currentSymbol[s_symbolPos];
    if (elt == '\0') {
        // Letter done, inter-letter gap.
        s_currentSymbol = nullptr;
        s_symbolPos = 0;
        setPixelOff();
        s_phase = PHASE_OFF_LETTER;
        s_stateStartMs = now;
        return;
    }

    setPixelOn();
    s_phase = PHASE_ON;
    s_stateStartMs = now;
    (void)unit; // duration applied in the tick step, not here.
}

void restartTransmission() {
    s_currentText = MESSAGES[s_msgIdx].text;
    s_textPos = 0;
    s_currentSymbol = nullptr;
    s_symbolPos = 0;
    s_phase = PHASE_IDLE;
    s_stateStartMs = millis();
    setPixelOff();
}

void paintScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 10, "Morse Beacon");

    char line[24];
    snprintf(line, sizeof(line), "msg:   %s", MESSAGES[s_msgIdx].name);
    u8g2.drawStr(0, 24, line);

    snprintf(line, sizeof(line), "color: %s", COLORS[s_colorIdx].name);
    u8g2.drawStr(0, 36, line);

    snprintf(line, sizeof(line), "speed: %s", SPEEDS[s_speedIdx].name);
    u8g2.drawStr(0, 48, line);

    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(0, 60, "UP/DOWN msg  L color  R spd");
    u8g2.sendBuffer();
}

} // namespace

void morseBeaconSetup() {
    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    pixels.begin();
    pixels.setBrightness(oledBrightness);
    pixels.clear();
    pixels.show();

    restartTransmission();
    paintScreen();
}

void morseBeaconLoop() {
    uint32_t now = millis();
    uint16_t unit = SPEEDS[s_speedIdx].unit_ms;

    // Handle inputs.
    if (digitalRead(BUTTON_PIN_UP) == LOW && (now - s_lastUpMs) > DEBOUNCE_MS) {
        s_lastUpMs = now;
        s_msgIdx = (s_msgIdx + 1) % NUM_MESSAGES;
        restartTransmission();
        paintScreen();
        return;
    }
    if (digitalRead(BUTTON_PIN_DOWN) == LOW && (now - s_lastDownMs) > DEBOUNCE_MS) {
        s_lastDownMs = now;
        s_msgIdx = (s_msgIdx == 0) ? (NUM_MESSAGES - 1) : (s_msgIdx - 1);
        restartTransmission();
        paintScreen();
        return;
    }
    if (digitalRead(BUTTON_PIN_LEFT) == LOW && (now - s_lastLeftMs) > DEBOUNCE_MS) {
        s_lastLeftMs = now;
        s_colorIdx = (s_colorIdx + 1) % NUM_COLORS;
        paintScreen();
        return;
    }
    if (digitalRead(BUTTON_PIN_RIGHT) == LOW && (now - s_lastRightMs) > DEBOUNCE_MS) {
        s_lastRightMs = now;
        s_speedIdx = (s_speedIdx + 1) % NUM_SPEEDS;
        paintScreen();
        return;
    }

    // Drive state machine.
    uint32_t elapsed = now - s_stateStartMs;

    switch (s_phase) {
        case PHASE_IDLE:
            startNextSymbolElement(now);
            break;

        case PHASE_ON: {
            char elt = s_currentSymbol ? s_currentSymbol[s_symbolPos] : '\0';
            uint32_t dur = (elt == '-') ? (unit * 3) : unit;
            if (elapsed >= dur) {
                setPixelOff();
                s_phase = PHASE_OFF_INTRA;
                s_stateStartMs = now;
            }
            break;
        }

        case PHASE_OFF_INTRA:
            if (elapsed >= unit) {
                s_symbolPos++;
                startNextSymbolElement(now);
            }
            break;

        case PHASE_OFF_LETTER:
            if (elapsed >= (unit * 3)) {
                startNextSymbolElement(now);
            }
            break;

        case PHASE_OFF_WORD:
            if (elapsed >= (unit * 7)) {
                startNextSymbolElement(now);
            }
            break;
    }
}

void morseBeaconCleanup() {
    setPixelOff();
    s_phase = PHASE_IDLE;
    s_currentText = nullptr;
    s_currentSymbol = nullptr;
}
