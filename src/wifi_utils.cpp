#include "../include/wifi_utils.h"

void sendDeauthFrame(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason) {
    uint8_t frame[26] = {
        0xC0, 0x00,                         // Frame control: deauth
        0x00, 0x00,                         // Duration
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00,                         // Sequence
        0x00, 0x00                          // Reason code
    };
    memcpy(frame + 4, dst, 6);
    memcpy(frame + 10, src, 6);
    memcpy(frame + 16, bssid, 6);
    frame[24] = reason & 0xFF;
    frame[25] = (reason >> 8) & 0xFF;

    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}
