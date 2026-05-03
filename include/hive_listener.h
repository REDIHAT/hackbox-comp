/*
    hackbox
    hackbox custom firmware

    Hive Listener. NRF24 passive receiver for Hive Signal packets
    emitted by a Flipper Zero (or any HiveSignalProtocol-compatible
    device). Displays opcode history, flashes NeoPixel on PING/ALERT,
    and suggests the mapped tool for TRIGGER_* opcodes.

    This is a display-and-suggest tool. It does NOT auto-launch
    hackbox tools when it sees a TRIGGER_* opcode, to avoid cross-
    tool state corruption. The operator reads the OLED and navigates
    manually.

    See include/hive_signal_protocol.h for the wire format.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HIVE_LISTENER_H
#define HIVE_LISTENER_H

void hiveListenerSetup();
void hiveListenerLoop();
void hiveListenerCleanup();

#endif
