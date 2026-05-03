#ifndef WIFI_UTILS_H
#define WIFI_UTILS_H
#include <Arduino.h>
#include "esp_wifi.h"

// Send a deauth frame from src to dst on the current channel
void sendDeauthFrame(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason = 0x0007);

#endif
