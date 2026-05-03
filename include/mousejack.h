/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef MOUSEJACK_H
#define MOUSEJACK_H

#include <Arduino.h>

void mousejackSetup();
void mousejackLoop();
void cleanupMousejack();

#endif
