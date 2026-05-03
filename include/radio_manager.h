/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#pragma once

#include "esp_wifi.h"
#include "esp_bt_main.h"

bool initBLE();
void cleanupBLE();

// @note Modules that enable esp_wifi_set_promiscuous(true) must pass
// WIFI_MODE_AP (not WIFI_MODE_STA): promiscuous RX silently fails on
// WIFI_MODE_STA across several ESP-IDF builds shipped by arduino-esp32.
// AP mode without an esp_wifi_set_config() call leaves SSID length zero,
// so no beacon is transmitted.
bool initWiFi(wifi_mode_t mode);
void cleanupWiFi();
void cleanupRadio();