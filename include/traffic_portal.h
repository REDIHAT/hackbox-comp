#ifndef TRAFFIC_PORTAL_H
#define TRAFFIC_PORTAL_H

#include "esp_wifi.h"
#include "pindefs.h"
#include <U8g2lib.h>

void trafficPortalSetup();
void trafficPortalLoop();
void cleanupTrafficPortal();

#endif
