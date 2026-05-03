/*
    hackbox Rogue AP Detector
    Scans for duplicate SSIDs on different BSSIDs/channels to detect
    evil twin attacks. Blue team defensive tool.

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#ifndef ROGUE_AP_H
#define ROGUE_AP_H

#include <Arduino.h>
#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>
#include "pindefs.h"

void rogueApSetup();
void rogueApLoop();
void rogueApCleanup();

#endif
