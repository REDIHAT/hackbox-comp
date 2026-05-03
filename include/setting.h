/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef setting_H
#define setting_H

#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>

extern bool neoPixelActive;
extern bool continuousScanEnabled;
extern bool privacyModeEnabled;

extern const unsigned long sleepTimeouts[];
extern const char* sleepTimeoutNames[];
extern const int sleepTimeoutCount;
#define EEPROM_ADDRESS_SLEEP_TIMEOUT 3

void settingSetup();
void settingLoop();
bool isContinuousScanEnabled();
bool isPrivacyModeEnabled();

void maskMAC(const char* original, char* masked);
void maskName(const char* original, char* masked, int maxLen);
void maskNameEvilPortal(const char* original, char* masked, int maxLen, const char* customSSIDs[], int customSSIDCount);

#endif
