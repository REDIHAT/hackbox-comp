/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

// pindefs.h
#ifndef PINDEFS_H
#define PINDEFS_H

// Button Pin Definitions
#define BUTTON_PIN_UP      26
#define BUTTON_PIN_DOWN    33
#define BUTTON_PIN_CENTER  32  // Back (physical center button)
#define BUTTON_PIN_LEFT    25  // Left
#define BUTTON_PIN_RIGHT   27  // Select

// Radio Pins
#define RADIO_CE_PIN_1      5
#define RADIO_CSN_PIN_1    17
#define RADIO_CE_PIN_2     16
#define RADIO_CSN_PIN_2     4
#define RADIO_CE_PIN_3     15
#define RADIO_CSN_PIN_3     2

// NeoPixel
#define NEOPIXEL_PIN       14

// Optional GPS module for Wardriving -> WiGle upload.
// GPIO 34 is input-only, no pull-up required; any NMEA-0183 GPS (NEO-6M,
// BN-220, etc.) can be wired 3.3V + GND + GPS TX -> GPIO 34 at 9600 baud.
// If no module is connected, wardriver still works with 0.0,0.0 coords
// and WiGle-compatible schema so tracks can be merged post-hoc.
#define GPS_UART_RX_PIN    34
#define GPS_BAUD           9600

#endif // PINDEFS_H
