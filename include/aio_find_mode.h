/*
    hackbox
    hackbox custom firmware

    AIO Find Mode: passive WiFi camera + BLE tracker/security locator.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#ifndef AIO_FIND_MODE_H
#define AIO_FIND_MODE_H

#include <U8g2lib.h>
#include "pindefs.h"

void aioFindModeSetup();
void aioFindModeLoop();
void aioFindModeCleanup();

#endif
