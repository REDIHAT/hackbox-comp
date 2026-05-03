/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include <Arduino.h>
#include "about.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "snake.h"

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

#define KONAMI_LENGTH 10
static const uint8_t konamiSequence[KONAMI_LENGTH] = {
  BUTTON_PIN_UP,
  BUTTON_PIN_UP,
  BUTTON_PIN_DOWN,
  BUTTON_PIN_DOWN,
  BUTTON_PIN_LEFT,
  BUTTON_PIN_RIGHT,
  BUTTON_PIN_LEFT,
  BUTTON_PIN_RIGHT,
  BUTTON_PIN_LEFT,
  BUTTON_PIN_RIGHT
};

static uint8_t konamiIndex = 0;
static bool    snakeMode   = false;

static bool needsRedraw = true;

void aboutSetup() {
  pinMode(BUTTON_PIN_UP,    INPUT_PULLUP);
  pinMode(BUTTON_PIN_DOWN,  INPUT_PULLUP);
  pinMode(BUTTON_PIN_LEFT,  INPUT_PULLUP);
  pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

  snakeSetup();
  snakeMode = false;
  needsRedraw = true;
}

void aboutLoop() {
  const uint8_t arrows[] = {
    BUTTON_PIN_UP,
    BUTTON_PIN_DOWN,
    BUTTON_PIN_LEFT,
    BUTTON_PIN_RIGHT
  };
  for (auto pin : arrows) {
    if (digitalRead(pin) == LOW) {
      bool matchedKonami = (pin == konamiSequence[konamiIndex]);
      if (matchedKonami) {
        konamiIndex++;
        if (konamiIndex == KONAMI_LENGTH) {
          snakeMode   = true;
          konamiIndex = 0;
        }
        // Wait for release so that runApp()'s global LEFT=exit edge detector
        // doesn't tear the app down mid-Konami-sequence when the current step
        // is LEFT. Only consume the press on a successful match. A mismatched
        // LEFT press should still fall through and let runApp exit the app.
        while (digitalRead(pin) == LOW) delay(10);
      } else {
        konamiIndex = (pin == konamiSequence[0]) ? 1 : 0;
      }
      delay(150);
      break;
    }
  }

  if (snakeMode) {
    snakeLoop();
    return;
  }

  if (!needsRedraw) {
    return;
  }

  needsRedraw = false;
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_helvB14_tr);
  const char* title = "hackbox";
  int16_t titleW = u8g2.getUTF8Width(title);
  u8g2.setCursor((128 - titleW) / 2, 16);
  u8g2.print(title);

  u8g2.setFont(u8g2_font_helvR08_tr);
  // Compact build marker: e.g. "built Apr 17" from __DATE__ "Apr 17 2026".
  // Lets the user confirm fresh flash without drilling to a logs screen.
  char buildLine[20];
  snprintf(buildLine, sizeof(buildLine), "built %.6s", __DATE__);
  int16_t urlW = u8g2.getUTF8Width(buildLine);
  u8g2.setCursor((128 - urlW) / 2, 32);
  u8g2.print(buildLine);

  u8g2.setFont(u8g2_font_helvR08_tr);
  int16_t creditWidth = u8g2.getUTF8Width("the hive is watching");
  int16_t creditX = (128 - creditWidth) / 2;
  u8g2.setCursor(creditX, 50);
  u8g2.print("the hive is watching");

  u8g2.setFont(u8g2_font_helvR08_tr);
  int16_t verW = u8g2.getUTF8Width(hackboxVersion);
  u8g2.setCursor((128 - verW) / 2, 62);
  u8g2.print(hackboxVersion);

  u8g2.sendBuffer();
  displayMirrorSend(u8g2);
}

void aboutCleanup() {
  if (snakeMode) {
    snakeCleanup();
  }
}
