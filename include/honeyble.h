/*
    hackbox HoneyBLE
    Apple Continuity advertisement parser fuzzer for robustness testing.
*/

#ifndef honeyble_H
#define honeyble_H

#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>
#include "neopixel.h"
#include "pindefs.h"
#include "sleep_manager.h"

void honeybleSetup();
void honeybleLoop();

#endif
