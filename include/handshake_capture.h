/*
    hackbox
    hackbox custom firmware

    Licensed under the MIT License
*/

#ifndef HANDSHAKE_CAPTURE_H
#define HANDSHAKE_CAPTURE_H

#include "esp_wifi.h"
#include "pindefs.h"
#include <U8g2lib.h>

void handshakeCaptureSetup();
void handshakeCaptureLoop();
void cleanupHandshakeCapture();

#endif
