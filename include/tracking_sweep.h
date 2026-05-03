/*
    hackbox
    hackbox custom firmware

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef TRACKING_SWEEP_H
#define TRACKING_SWEEP_H

#include <U8g2lib.h>
#include "pindefs.h"
#include "esp_gap_ble_api.h"

struct TrackerAdvMatch {
    uint8_t category;
    const char *label;
    const char *wire;
    uint8_t weight;
};

void trackingSweepSetup();
void trackingSweepLoop();
void trackingSweepCleanup();

// Stateless classifier used by combo tools. It returns true when an
// advertisement matches the same BLE tracker/security signatures shown
// by Tracker Sweep.
bool trackerSweepClassifyAdv(esp_ble_gap_cb_param_t *param,
                             TrackerAdvMatch *out);

#endif
