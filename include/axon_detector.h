/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef AXON_DETECTOR_H
#define AXON_DETECTOR_H

#include <Arduino.h>
#include <U8g2lib.h>
#include "pindefs.h"

void axonDetectorSetup();
void axonDetectorLoop();

#endif