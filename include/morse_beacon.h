/*
    hackbox
    hackbox custom firmware

    Morse Beacon. NeoPixel blinks a selectable message in Morse code
    for covert operator-to-operator visual signaling across a room.

    UP/DOWN cycles messages. LEFT cycles NeoPixel color. RIGHT changes
    speed (slow / medium / fast). The OLED shows the current message,
    the letter currently being sent, and the speed setting.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef MORSE_BEACON_H
#define MORSE_BEACON_H

void morseBeaconSetup();
void morseBeaconLoop();
void morseBeaconCleanup();

#endif
