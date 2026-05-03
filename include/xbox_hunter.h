/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HACKBOX_XBOX_HUNTER_H
#define HACKBOX_XBOX_HUNTER_H

#include <Arduino.h>

void xboxHunterSetup();
void xboxHunterLoop();
void xboxHunterCleanup();

bool isXboxOUI(const uint8_t mac[6]);

#endif
