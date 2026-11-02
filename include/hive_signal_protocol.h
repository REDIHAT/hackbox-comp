/*
    hackbox
    hackbox custom firmware

    Hive Signal Protocol. Shared wire format between a Flipper Zero
    (or any NRF24-capable emitter) and hackbox's Hive Listener.

    Channel: 76 (2476 MHz). Out of the WiFi-1/6/11 mess, matches
    standard convention of using high-numbered NRF24 channels for
    custom payloads.

    Address: "HIVE1" (5 bytes, little-endian on the wire).

    Payload layout (32 bytes max, typical 8 bytes used):
        [0..3]   magic = "HIVE" (0x48 0x49 0x56 0x45)
        [4]      opcode (HiveSignalOpcode)
        [5]      seq (monotonic, wraps on 255)
        [6..7]   reserved, set 0
        [8..31]  opcode-specific args

    Receivers must verify the 4-byte magic before acting on the opcode.
    Unknown opcodes MUST be logged as "unknown" and ignored, never
    silently discarded.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#ifndef HIVE_SIGNAL_PROTOCOL_H
#define HIVE_SIGNAL_PROTOCOL_H

#include <stdint.h>

#define HIVE_SIGNAL_CHANNEL    76
#define HIVE_SIGNAL_ADDR_BYTES { 'H', 'I', 'V', 'E', '1' }
#define HIVE_SIGNAL_MAGIC_0    0x48 /* 'H' */
#define HIVE_SIGNAL_MAGIC_1    0x49 /* 'I' */
#define HIVE_SIGNAL_MAGIC_2    0x56 /* 'V' */
#define HIVE_SIGNAL_MAGIC_3    0x45 /* 'E' */

#define HIVE_SIGNAL_PROTO_VERSION 1

enum HiveSignalOpcode {
    HIVE_OP_NOP              = 0x00,
    HIVE_OP_PING             = 0x01,

    HIVE_OP_TRIGGER_EVIL_TWIN    = 0x10,
    HIVE_OP_TRIGGER_DEAUTH       = 0x11,
    HIVE_OP_TRIGGER_HONEYBLE     = 0x12,
    HIVE_OP_TRIGGER_BEACON_SPAM  = 0x13,
    HIVE_OP_TRIGGER_BEE_SPAM     = 0x14,
    HIVE_OP_TRIGGER_HANDSHAKE    = 0x15,
    HIVE_OP_TRIGGER_TRACKER_SWEEP = 0x16,

    HIVE_OP_SIGNAL_OPERATOR  = 0x20, /* arg[0..15] = ASCII callsign */

    HIVE_OP_ALERT            = 0x30, /* priority: drives NeoPixel red */
    HIVE_OP_CANCEL           = 0x31, /* clear any active alert */

    HIVE_OP_RESERVED         = 0xFF,
};

typedef struct __attribute__((packed)) {
    uint8_t magic[4];
    uint8_t opcode;
    uint8_t seq;
    uint8_t reserved[2];
    uint8_t arg[24];
} HiveSignalPacket;

#endif
