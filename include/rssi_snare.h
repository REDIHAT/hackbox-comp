/*
    hackbox
    hackbox custom firmware

    RSSI Snare: single-target WiFi proximity tripwire.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#ifndef RSSI_SNARE_H
#define RSSI_SNARE_H

#include <Arduino.h>

void rssiSnareSetup();
void rssiSnareLoop();
void rssiSnareCleanup();

#endif
