/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HACKBOX_DETECTOR_H
#define HACKBOX_DETECTOR_H

#include <esp_bt.h>
#include <U8g2lib.h>
#include "neopixel.h"
#include "pindefs.h"

void hackboxDetectorSetup();
void hackboxDetectorLoop();

#endif