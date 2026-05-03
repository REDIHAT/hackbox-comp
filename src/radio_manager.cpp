/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2026 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/radio_manager.h"

#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include <Arduino.h>
#include <RF24.h>

extern RF24 radios[3];

static bool classicBtMemReleased = false;

bool initBLE() {
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE) {
        if (!classicBtMemReleased) {
            esp_bt_mem_release(ESP_BT_MODE_CLASSIC_BT); // Release Classic Bluetooth memory to free up resources for BLE operations
            classicBtMemReleased = true;
        }
    }

    if (!btStarted()) {
        btStart();
        delay(50);
    }

    esp_bluedroid_status_t bt_state = esp_bluedroid_get_status();
    if (bt_state == ESP_BLUEDROID_STATUS_UNINITIALIZED) {
        if (esp_bluedroid_init() != ESP_OK) return false;
        delay(50);
    }

    bt_state = esp_bluedroid_get_status();
    if (bt_state != ESP_BLUEDROID_STATUS_ENABLED) {
        if (esp_bluedroid_enable() != ESP_OK) return false;
        delay(50);
    }

    return true;
}

void cleanupBLE() {
    // Stop scan/advert cleanly, then give the controller a beat to drain any
    // in-flight HCI events before we start tearing the stack down. Without
    // this, pending GAP events can fire against freed state after bluedroid
    // deinit and crash the BT task.
    esp_ble_gap_stop_scanning();
    esp_ble_gap_stop_advertising();
    delay(100);

    esp_bluedroid_status_t bt_state = esp_bluedroid_get_status();
    if (bt_state == ESP_BLUEDROID_STATUS_ENABLED) {
        esp_bluedroid_disable();
        delay(100);
    }

    if (esp_bluedroid_get_status() != ESP_BLUEDROID_STATUS_UNINITIALIZED) {
        esp_bluedroid_deinit();
        delay(100);
    }

    if (btStarted()) {
        btStop();
        delay(100);
    }
}

bool initWiFi(wifi_mode_t mode) {
    wifi_mode_t currentMode;
    if (esp_wifi_get_mode(&currentMode) != ESP_OK) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        if (esp_wifi_init(&cfg) != ESP_OK) return false;
    }

    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(mode);
    if (esp_wifi_start() != ESP_OK) return false;

    return true;
}

void cleanupRadio() {
    for (auto &r : radios) r.powerDown();
    cleanupWiFi();
    cleanupBLE();
}

void cleanupWiFi() {
    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) == ESP_OK) {
        // Clear the promiscuous RX callback BEFORE disabling promiscuous mode.
        // Without this, the last registered sniffer function pointer survives
        // across the deinit/reinit cycle, and the next module to flip
        // promiscuous back on can have the ISR dispatch to a callback whose
        // code has been unloaded -- classic IllegalInstruction crash after
        // 2-3 tool switches. Fixes the "walks 2-3 menus and reboots" bug.
        esp_wifi_set_promiscuous_rx_cb(NULL);
        esp_wifi_set_promiscuous(false);

        // Force disconnect any lingering STA association so the supplicant
        // isn't holding state across the stop.
        esp_wifi_disconnect();
        delay(50);

        esp_wifi_stop();
        delay(100);
        esp_wifi_deinit();
        delay(150);
    }

    esp_netif_t* sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif != NULL) {
        esp_netif_destroy(sta_netif);
    }

    esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif != NULL) {
        esp_netif_destroy(ap_netif);
    }

    delay(150);
}