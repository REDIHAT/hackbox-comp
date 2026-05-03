/*
    hackbox
    hackbox custom firmware

    Hive Listener. NRF24 passive receiver for Hive Signal Protocol.

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/hive_listener.h"
#include "../include/hive_signal_protocol.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include <Arduino.h>
#include <SPI.h>
#include <RF24.h>
#include <U8g2lib.h>
#include <Adafruit_NeoPixel.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;
extern uint8_t oledBrightness;

namespace {

static RF24 hl_radio(RADIO_CE_PIN_1, RADIO_CSN_PIN_1, 16000000);

struct HistoryEntry {
    uint8_t opcode;
    uint8_t seq;
    uint32_t atMs;
    char note[10]; // short label, opcode-specific
};

const uint8_t HISTORY_SIZE = 3;
HistoryEntry s_history[HISTORY_SIZE];
uint8_t s_historyLen = 0;

uint32_t s_totalRx = 0;
uint32_t s_validRx = 0;
uint32_t s_invalidRx = 0;
uint8_t s_lastSeenSeq = 0;
bool s_radioOk = false;

uint32_t s_neoUntilMs = 0;
uint32_t s_neoColor = 0;

uint32_t s_lastPaintMs = 0;

const char* opcodeLabel(uint8_t op) {
    switch (op) {
        case HIVE_OP_NOP: return "nop";
        case HIVE_OP_PING: return "ping";
        case HIVE_OP_TRIGGER_EVIL_TWIN: return "evil_twin";
        case HIVE_OP_TRIGGER_DEAUTH: return "deauth";
        case HIVE_OP_TRIGGER_HONEYBLE: return "honeyble";
        case HIVE_OP_TRIGGER_BEACON_SPAM: return "beacon_spam";
        case HIVE_OP_TRIGGER_BEE_SPAM: return "bee_spam";
        case HIVE_OP_TRIGGER_HANDSHAKE: return "handshake";
        case HIVE_OP_TRIGGER_TRACKER_SWEEP: return "tracker";
        case HIVE_OP_SIGNAL_OPERATOR: return "operator";
        case HIVE_OP_ALERT: return "ALERT";
        case HIVE_OP_CANCEL: return "cancel";
        default: return "unknown";
    }
}

void pushHistory(uint8_t opcode, uint8_t seq, const char* note) {
    if (s_historyLen < HISTORY_SIZE) {
        s_history[s_historyLen].opcode = opcode;
        s_history[s_historyLen].seq = seq;
        s_history[s_historyLen].atMs = millis();
        strncpy(s_history[s_historyLen].note, note, sizeof(s_history[0].note) - 1);
        s_history[s_historyLen].note[sizeof(s_history[0].note) - 1] = '\0';
        s_historyLen++;
    } else {
        // Shift left, drop oldest.
        for (uint8_t i = 1; i < HISTORY_SIZE; i++) {
            s_history[i - 1] = s_history[i];
        }
        s_history[HISTORY_SIZE - 1].opcode = opcode;
        s_history[HISTORY_SIZE - 1].seq = seq;
        s_history[HISTORY_SIZE - 1].atMs = millis();
        strncpy(s_history[HISTORY_SIZE - 1].note, note, sizeof(s_history[0].note) - 1);
        s_history[HISTORY_SIZE - 1].note[sizeof(s_history[0].note) - 1] = '\0';
    }
}

void flashNeo(uint32_t color, uint32_t durMs) {
    s_neoColor = color;
    s_neoUntilMs = millis() + durMs;
    pixels.setPixelColor(0, color);
    pixels.setBrightness(oledBrightness);
    pixels.show();
}

void tickNeo(uint32_t now) {
    if (s_neoUntilMs != 0 && now >= s_neoUntilMs) {
        pixels.setPixelColor(0, 0);
        pixels.show();
        s_neoUntilMs = 0;
    }
}

void handlePacket(const HiveSignalPacket* p) {
    s_totalRx++;
    if (p->magic[0] != HIVE_SIGNAL_MAGIC_0 ||
        p->magic[1] != HIVE_SIGNAL_MAGIC_1 ||
        p->magic[2] != HIVE_SIGNAL_MAGIC_2 ||
        p->magic[3] != HIVE_SIGNAL_MAGIC_3) {
        s_invalidRx++;
        return;
    }
    s_validRx++;
    s_lastSeenSeq = p->seq;

    const char* label = opcodeLabel(p->opcode);

    switch (p->opcode) {
        case HIVE_OP_PING:
            flashNeo(0x00C800, 120); // green
            break;
        case HIVE_OP_ALERT:
            flashNeo(0xFF0000, 800); // red, long
            break;
        case HIVE_OP_CANCEL:
            pixels.setPixelColor(0, 0);
            pixels.show();
            s_neoUntilMs = 0;
            break;
        case HIVE_OP_SIGNAL_OPERATOR:
            flashNeo(0x00C8FF, 300); // cyan
            break;
        default:
            // TRIGGER_* and everything else: brief amber wink. Operator
            // sees the suggestion on OLED and navigates manually.
            flashNeo(0xFFB300, 200);
            break;
    }

    pushHistory(p->opcode, p->seq, label);
}

void paintScreen(uint32_t now) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 10, "Hive Listener");

    char line[28];
    if (!s_radioOk) {
        u8g2.setFont(u8g2_font_5x7_tf);
        u8g2.drawStr(0, 24, "radio init FAILED");
        u8g2.drawStr(0, 36, "check CE/CSN wiring");
        u8g2.sendBuffer();
        return;
    }

    snprintf(line, sizeof(line), "ch %u  ok %lu/%lu",
             HIVE_SIGNAL_CHANNEL,
             (unsigned long)s_validRx,
             (unsigned long)s_totalRx);
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(0, 20, line);

    if (s_historyLen == 0) {
        u8g2.drawStr(0, 34, "awaiting signal...");
    } else {
        int y = 34;
        for (int i = s_historyLen - 1; i >= 0 && y <= 62; i--) {
            uint32_t age = (now - s_history[i].atMs) / 1000;
            snprintf(line, sizeof(line), "%s #%u  %lus",
                     s_history[i].note,
                     (unsigned)s_history[i].seq,
                     (unsigned long)age);
            u8g2.drawStr(0, y, line);
            y += 9;
        }
    }

    u8g2.sendBuffer();
}

} // namespace

void hiveListenerSetup() {
    s_historyLen = 0;
    s_totalRx = 0;
    s_validRx = 0;
    s_invalidRx = 0;
    s_lastSeenSeq = 0;
    s_neoUntilMs = 0;
    s_lastPaintMs = 0;

    SPI.begin();
    s_radioOk = hl_radio.begin();

    if (s_radioOk) {
        hl_radio.setPALevel(RF24_PA_LOW);
        hl_radio.setDataRate(RF24_2MBPS);
        hl_radio.setChannel(HIVE_SIGNAL_CHANNEL);
        hl_radio.setAutoAck(false);
        hl_radio.disableCRC(); // match flexible emitters
        hl_radio.setPayloadSize(sizeof(HiveSignalPacket));

        const uint8_t addr[5] = HIVE_SIGNAL_ADDR_BYTES;
        hl_radio.openReadingPipe(1, addr);
        hl_radio.startListening();
    }

    pixels.begin();
    pixels.setBrightness(oledBrightness);
    pixels.clear();
    pixels.show();

    paintScreen(millis());
}

void hiveListenerLoop() {
    uint32_t now = millis();
    tickNeo(now);

    if (s_radioOk && hl_radio.available()) {
        HiveSignalPacket pkt;
        memset(&pkt, 0, sizeof(pkt));
        hl_radio.read(&pkt, sizeof(pkt));
        handlePacket(&pkt);
    }

    if ((now - s_lastPaintMs) >= 500) {
        s_lastPaintMs = now;
        paintScreen(now);
    }
}

void hiveListenerCleanup() {
    if (s_radioOk) {
        hl_radio.stopListening();
        hl_radio.powerDown();
    }
    pixels.setPixelColor(0, 0);
    pixels.show();
    s_neoUntilMs = 0;
}
