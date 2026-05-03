/*
    hackbox
    hackbox custom firmware

    Licensed under the MIT License
*/

#ifndef WIFI_GRAFFITI_H
#define WIFI_GRAFFITI_H

#include "esp_wifi.h"
#include "pindefs.h"
#include <U8g2lib.h>

void wifiGraffitiSetup();
void wifiGraffitiLoop();
void cleanupWifiGraffiti();

#endif
