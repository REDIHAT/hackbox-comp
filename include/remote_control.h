#ifndef REMOTE_CONTROL_H
#define REMOTE_CONTROL_H

#include "esp_wifi.h"
#include "pindefs.h"
#include <U8g2lib.h>

void remoteControlSetup();
void remoteControlLoop();
void cleanupRemoteControl();

#endif
