/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HONEY_FLOOD_H
#define HONEY_FLOOD_H

enum HoneyButton { HONEY_UP = 0, HONEY_DOWN, HONEY_LEFT, HONEY_RIGHT, HONEY_SELECT };

// Feed the next button in the Konami sequence.
// Returns true when the full sequence is matched (caller should run honeyFloodRun).
bool honeyFloodPush(HoneyButton b);

// Execute the Honey Flood animation (2-second cascading bee OLED + NeoPixel rainbow).
void honeyFloodRun();

#endif
