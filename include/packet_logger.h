#ifndef PACKET_LOGGER_H
#define PACKET_LOGGER_H

#include "esp_wifi.h"
#include "pindefs.h"
#include <U8g2lib.h>

void packetLoggerSetup();
void packetLoggerLoop();

#endif
