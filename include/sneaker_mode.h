/*
    hackbox
    hackbox custom firmware

    Sneaker Mode — global stealth toggle.
    Drops OLED brightness to minimum, turns NeoPixel off, and locks the
    device into a minimal glance screen. Long-hold CENTER to exit.

    Use: covert reconnaissance, SIGINT in spaces where a glowing LED or a
    bright OLED would expose the operator.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef SNEAKER_MODE_H
#define SNEAKER_MODE_H

#include <stdint.h>

void sneakerModeSetup();
void sneakerModeLoop();
void sneakerModeCleanup();

// True while the stealth toggle is active. Other tools may query this
// to suppress their own audio/LED/screen flourishes when they render.
bool sneakerModeActive();

#endif
