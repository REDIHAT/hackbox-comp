/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef ABOUT_H
#define ABOUT_H

#include <U8g2lib.h>
#include "pindefs.h"

#define HACKBOX_VERSION_NUMBER "1.4.0"

#ifdef HACKBOX_SCOUT_BUILD
#define HACKBOX_VERSION "v" HACKBOX_VERSION_NUMBER "-scout"
#else
#define HACKBOX_VERSION "v" HACKBOX_VERSION_NUMBER
#endif
extern const char* hackboxVersion;

void aboutSetup();
void aboutLoop();
void aboutCleanup();

#endif
