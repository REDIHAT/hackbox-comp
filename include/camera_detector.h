/*
    hackbox
    hackbox custom firmware

    Camera Detector: passive WiFi camera fingerprinting.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT
    SPDX-License-Identifier: MIT
*/

#ifndef CAMERA_DETECTOR_H
#define CAMERA_DETECTOR_H

#include <Arduino.h>
#include "esp_wifi.h"

enum CameraFrameEvidence : uint8_t {
    CAMERA_FRAME_PREFIX  = 1 << 0,
    CAMERA_FRAME_NAME    = 1 << 1,
    CAMERA_FRAME_TRAFFIC = 1 << 2,
    CAMERA_FRAME_SETUP   = 1 << 3
};

struct CameraFrameMatch {
    uint8_t mac[6];
    const char *brand;
    uint8_t baseScore;
    uint8_t evidence;
    int8_t rssi;
    uint8_t channel;
    bool isMgmt;
    bool isData;
    bool seenAsAp;
    bool seenAsStation;
    bool uplink;
    bool downlink;
    uint16_t frameLen;
    char ssid[17];
};

void cameraDetectorSetup();
void cameraDetectorLoop();
void cameraDetectorCleanup();

// Lightweight stateless classifier used by combo tools. It parses one
// promiscuous WiFi packet and returns true only when the existing Camera
// Detector OUI/name/traffic rules consider it a plausible camera.
bool cameraDetectorClassifyPromiscPacket(void *buf,
                                         wifi_promiscuous_pkt_type_t type,
                                         CameraFrameMatch *out);

#endif
