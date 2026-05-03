/*
    hackbox
    hackbox custom firmware

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef MISSION_MODE_H
#define MISSION_MODE_H

#include <U8g2lib.h>
#include "pindefs.h"

void missionModeSetup();
void missionModeLoop();
void missionModeCleanup();

#endif
