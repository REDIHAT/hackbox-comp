/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HACKBOX_ADVERTISER_H
#define HACKBOX_ADVERTISER_H

#include "level_system.h"
#include "about.h"

void initHackboxAdvertiser();
void startHackboxAdvertiser();
void stopHackboxAdvertiser();
void updateHackboxAdvertiser();
bool isHackboxAdvertising();

#endif