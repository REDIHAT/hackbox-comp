/*
    hackbox - RF Roulette

    NRF24 gambling game between two nearby hackbox devices.
    One hosts, one joins. Host hides a signal on a random channel.
    Challenger gets 5 guesses. Winner takes the XP pot.

    Uses Radio 1 (RX) for listening and Radio 2 (TX) for transmitting.
    Handshake on channel 108.

    States: RR_MENU, RR_HOST_WAIT, RR_JOIN_WAIT, RR_BET, RR_PLAYING, RR_RESULT
    Controls: UP/DOWN = adjust, CENTER = confirm, RIGHT = host
    LEFT is reserved globally as the exit-app button by runApp().
*/

#include "../include/rf_roulette.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include "../include/neopixel.h"
#include <SPI.h>
#include <RF24.h>
#include <EEPROM.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

extern RF24 radios[];

namespace {

// ===== Radios (reuse global instances) =====
#define rr_radio1 radios[0]
#define rr_radio2 radios[1]

// ===== EEPROM =====
#define EEPROM_RR_WINS   106  // 16-bit
#define EEPROM_RR_LOSSES 108  // 16-bit

// ===== Protocol =====
const uint8_t SYNC_ADDR[] = {0xAA, 0x00, 0x11, 0x22, 0x33};
const uint8_t HANDSHAKE_CHANNEL = 108;

// Packet types
#define PKT_HELLO    0x01
#define PKT_ACK      0x02
#define PKT_BET      0x03
#define PKT_HIDE     0x04
#define PKT_GUESS    0x05
#define PKT_RESULT   0x06

struct Packet {
    uint8_t type;
    uint8_t data[7];  // 8 byte payloads total
};

// ===== State Machine =====
enum RRState {
    RR_MENU,
    RR_HOST_WAIT,
    RR_JOIN_WAIT,
    RR_BET,
    RR_HIDE,
    RR_GUESS,
    RR_RESULT
};

RRState rrState = RR_MENU;

// ===== Game State =====
bool isHost = false;
int betAmount = 10;
int hiddenChannel = 0;
int currentGuess = 64;
int guessesLeft = 5;
bool won = false;
int xpGained = 0;

// ===== Stats =====
uint16_t wins = 0;
uint16_t losses = 0;

// ===== UI =====
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;
unsigned long waitStartTime = 0;
bool peerConnected = false;

// ===== Radio Helpers =====

void initHandshakeRadio() {
    SPI.begin();
    delay(50);
    rr_radio1.begin();
    rr_radio1.setAutoAck(true);
    rr_radio1.setRetries(5, 15);
    rr_radio1.setPALevel(RF24_PA_MAX, true);
    rr_radio1.setDataRate(RF24_1MBPS);
    rr_radio1.setPayloadSize(sizeof(Packet));
    rr_radio1.setChannel(HANDSHAKE_CHANNEL);
}

void sendPacket(Packet &pkt) {
    rr_radio2.begin();
    rr_radio2.setAutoAck(true);
    rr_radio2.setRetries(5, 15);
    rr_radio2.setPALevel(RF24_PA_MAX, true);
    rr_radio2.setDataRate(RF24_1MBPS);
    rr_radio2.setPayloadSize(sizeof(Packet));
    rr_radio2.setChannel(HANDSHAKE_CHANNEL);
    rr_radio2.stopListening();
    rr_radio2.openWritingPipe(SYNC_ADDR);
    rr_radio2.write(&pkt, sizeof(Packet));
}

bool receivePacket(Packet &pkt, unsigned long timeoutMs) {
    rr_radio1.openReadingPipe(0, SYNC_ADDR);
    rr_radio1.startListening();
    unsigned long start = millis();
    while (millis() - start < timeoutMs) {
        if (rr_radio1.available()) {
            rr_radio1.read(&pkt, sizeof(Packet));
            return true;
        }
        delay(1);
    }
    return false;
}

uint16_t loadWins() {
    return (EEPROM.read(EEPROM_RR_WINS + 1) << 8) | EEPROM.read(EEPROM_RR_WINS);
}

uint16_t loadLosses() {
    return (EEPROM.read(EEPROM_RR_LOSSES + 1) << 8) | EEPROM.read(EEPROM_RR_LOSSES);
}

void saveWins(uint16_t val) {
    EEPROM.write(EEPROM_RR_WINS, val & 0xFF);
    EEPROM.write(EEPROM_RR_WINS + 1, (val >> 8) & 0xFF);
    EEPROM.commit();
}

void saveLosses(uint16_t val) {
    EEPROM.write(EEPROM_RR_LOSSES, val & 0xFF);
    EEPROM.write(EEPROM_RR_LOSSES + 1, (val >> 8) & 0xFF);
    EEPROM.commit();
}

// ===== Drawing =====

void drawMenu() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "RF Roulette");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    wins = loadWins();
    losses = loadLosses();
    char statsLine[28];
    snprintf(statsLine, sizeof(statsLine), "W: %u  L: %u", wins, losses);
    u8g2.drawStr(0, 24, statsLine);

    int lvl = getCurrentLevel();
    uint16_t xp = getCurrentXP();
    char xpLine[28];
    snprintf(xpLine, sizeof(xpLine), "Level %d  XP: %u", lvl, xp);
    u8g2.drawStr(0, 34, xpLine);

    u8g2.drawStr(0, 46, "R=Host Game");
    u8g2.drawStr(0, 54, "C=Join Game");
    u8g2.drawStr(0, 62, "L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawWaiting(const char* role) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "RF Roulette");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char roleLine[24];
    snprintf(roleLine, sizeof(roleLine), "Mode: %s", role);
    u8g2.drawStr(0, 26, roleLine);

    unsigned long elapsed = (millis() - waitStartTime) / 1000;
    char waitLine[24];
    snprintf(waitLine, sizeof(waitLine), "Waiting for peer... %lus", elapsed);
    u8g2.drawStr(0, 38, waitLine);

    u8g2.drawStr(0, 50, "Channel 108 (NRF24)");
    u8g2.drawStr(0, 62, "L=Cancel");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawBet() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Place Your Bet");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    uint16_t xp = getCurrentXP();
    char xpLine[20];
    snprintf(xpLine, sizeof(xpLine), "Your XP: %u", xp);
    u8g2.drawStr(0, 26, xpLine);

    u8g2.setFont(u8g2_font_helvB14_tr);
    char betLine[12];
    snprintf(betLine, sizeof(betLine), "%d XP", betAmount);
    u8g2.drawStr(30, 46, betLine);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 62, "U/D=Adjust  C=Lock In");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawGuess() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    char title[20];
    snprintf(title, sizeof(title), "Find the Signal!");
    u8g2.drawStr(0, 10, title);
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char guessLine[24];
    snprintf(guessLine, sizeof(guessLine), "Guesses left: %d / 5", guessesLeft);
    u8g2.drawStr(0, 24, guessLine);

    u8g2.setFont(u8g2_font_helvB14_tr);
    char chLine[12];
    snprintf(chLine, sizeof(chLine), "Ch %d", currentGuess);
    u8g2.drawStr(30, 44, chLine);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 56, "U/D=Channel  C=Guess!");
    char betLine[20];
    snprintf(betLine, sizeof(betLine), "Pot: %d XP", betAmount * 2);
    u8g2.drawStr(0, 64, betLine);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawHide() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "Signal Hidden!");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    char chLine[24];
    snprintf(chLine, sizeof(chLine), "Your channel: %d", hiddenChannel);
    u8g2.drawStr(0, 26, chLine);

    u8g2.drawStr(0, 38, "Transmitting signal...");
    u8g2.drawStr(0, 48, "Opponent is guessing.");

    char betLine[20];
    snprintf(betLine, sizeof(betLine), "Pot: %d XP", betAmount * 2);
    u8g2.drawStr(0, 62, betLine);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawResult() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    if (won) {
        u8g2.drawStr(20, 10, "YOU WIN!");
        blinkColor(0, 255, 0);
    } else {
        u8g2.drawStr(20, 10, "YOU LOSE");
        blinkColor(255, 0, 0);
    }
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_helvB14_tr);
    char xpLine[16];
    snprintf(xpLine, sizeof(xpLine), "%s%d XP",
             won ? "+" : "-", won ? xpGained : betAmount);
    u8g2.drawStr(20, 36, xpLine);

    u8g2.setFont(u8g2_font_5x8_tr);
    if (!isHost) {
        char chLine[28];
        snprintf(chLine, sizeof(chLine), "Hidden channel was: %d", hiddenChannel);
        u8g2.drawStr(0, 50, chLine);
    }

    u8g2.drawStr(0, 62, "C=Again  L=Exit");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void rfRouletteSetup() {
    rrState = RR_MENU;
    isHost = false;
    betAmount = 10;
    guessesLeft = 5;
    currentGuess = 64;
    peerConnected = false;
    needsRedraw = true;
    lastButtonPress = 0;

    Serial.println();
    Serial.println("# hackbox RF Roulette v1.0");

    drawMenu();
}

void rfRouletteLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (rrState) {
        case RR_MENU: {
            if (now - lastButtonPress > debounceDelay) {
                if (right) {
                    // Host
                    isHost = true;
                    initHandshakeRadio();
                    waitStartTime = millis();
                    rrState = RR_HOST_WAIT;
                    needsRedraw = true;
                    lastButtonPress = now;

                    // Send HELLO packets
                    Packet hello;
                    hello.type = PKT_HELLO;
                    sendPacket(hello);
                } else if (center) {
                    // Join
                    isHost = false;
                    initHandshakeRadio();
                    waitStartTime = millis();
                    rrState = RR_JOIN_WAIT;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawMenu(); }
            break;
        }

        case RR_HOST_WAIT: {
            // Keep sending HELLO, wait for ACK
            static unsigned long lastHello = 0;
            if (now - lastHello > 500) {
                Packet hello;
                hello.type = PKT_HELLO;
                sendPacket(hello);
                lastHello = now;
            }

            Packet rx;
            if (receivePacket(rx, 100) && rx.type == PKT_ACK) {
                peerConnected = true;
                rrState = RR_BET;
                needsRedraw = true;
            }

            // Timeout after 30s
            if (now - waitStartTime > 30000) {
                rrState = RR_MENU;
                needsRedraw = true;
            }

            static unsigned long lastWaitDraw = 0;
            if (now - lastWaitDraw > 1000) { lastWaitDraw = now; needsRedraw = true; }
            if (needsRedraw) { needsRedraw = false; drawWaiting("HOST"); }
            break;
        }

        case RR_JOIN_WAIT: {
            // Listen for HELLO, send ACK
            Packet rx;
            if (receivePacket(rx, 200) && rx.type == PKT_HELLO) {
                Packet ack;
                ack.type = PKT_ACK;
                sendPacket(ack);
                peerConnected = true;
                rrState = RR_BET;
                needsRedraw = true;
            }

            if (now - waitStartTime > 30000) {
                rrState = RR_MENU;
                needsRedraw = true;
            }

            static unsigned long lastJoinDraw = 0;
            if (now - lastJoinDraw > 1000) { lastJoinDraw = now; needsRedraw = true; }
            if (needsRedraw) { needsRedraw = false; drawWaiting("JOIN"); }
            break;
        }

        case RR_BET: {
            if (now - lastButtonPress > debounceDelay) {
                if (up && betAmount < 50) {
                    betAmount += 5;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && betAmount > 5) {
                    betAmount -= 5;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center) {
                    // Lock in bet
                    if (isHost) {
                        // Host hides the signal
                        hiddenChannel = random(0, 126);
                        rrState = RR_HIDE;

                        // Start transmitting on hidden channel
                        rr_radio2.begin();
                        rr_radio2.setAutoAck(false);
                        rr_radio2.setPALevel(RF24_PA_MAX, true);
                        rr_radio2.setDataRate(RF24_1MBPS);
                        rr_radio2.setChannel(hiddenChannel);
                        rr_radio2.stopListening();
                        rr_radio2.openWritingPipe(SYNC_ADDR);
                        // Continuous transmit
                    } else {
                        // Challenger guesses
                        guessesLeft = 5;
                        currentGuess = 64;
                        rrState = RR_GUESS;
                    }
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawBet(); }
            break;
        }

        case RR_HIDE: {
            // Host: transmit beacon on hidden channel continuously
            uint8_t signal[] = {0xBE, 0xE5, 0xFF, 0xFF};
            rr_radio2.write(signal, sizeof(signal), true);  // non-blocking

            // Wait for guess result from challenger via handshake channel
            Packet rx;
            if (receivePacket(rx, 50)) {
                if (rx.type == PKT_RESULT) {
                    bool challengerWon = rx.data[0];
                    won = !challengerWon;  // Host wins if challenger fails
                    xpGained = betAmount;
                    if (won) {
                        addXP(xpGained);
                        wins = loadWins() + 1;
                        saveWins(wins);
                    } else {
                        losses = loadLosses() + 1;
                        saveLosses(losses);
                    }
                    rr_radio2.powerDown();
                    rrState = RR_RESULT;
                    needsRedraw = true;
                }
            }

            static unsigned long lastHideDraw = 0;
            if (now - lastHideDraw > 1000) { lastHideDraw = now; needsRedraw = true; }
            if (needsRedraw) { needsRedraw = false; drawHide(); }
            break;
        }

        case RR_GUESS: {
            if (now - lastButtonPress > debounceDelay) {
                if (up && currentGuess < 125) {
                    currentGuess++;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (down && currentGuess > 0) {
                    currentGuess--;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else if (center && guessesLeft > 0) {
                    // Make a guess — listen on guessed channel
                    rr_radio1.begin();
                    rr_radio1.setAutoAck(false);
                    rr_radio1.setDataRate(RF24_1MBPS);
                    rr_radio1.setChannel(currentGuess);
                    rr_radio1.setPayloadSize(4);
                    rr_radio1.openReadingPipe(0, SYNC_ADDR);
                    rr_radio1.startListening();

                    delay(200);  // Listen for 200ms

                    bool found = rr_radio1.available();
                    rr_radio1.stopListening();
                    guessesLeft--;

                    if (found) {
                        // Won!
                        won = true;
                        xpGained = betAmount;
                        addXP(xpGained);
                        wins = loadWins() + 1;
                        saveWins(wins);

                        // Tell host
                        Packet result;
                        result.type = PKT_RESULT;
                        result.data[0] = 1;  // challenger won
                        rr_radio2.setChannel(HANDSHAKE_CHANNEL);
                        sendPacket(result);

                        rrState = RR_RESULT;
                    } else if (guessesLeft == 0) {
                        // Out of guesses — lost
                        won = false;
                        losses = loadLosses() + 1;
                        saveLosses(losses);

                        Packet result;
                        result.type = PKT_RESULT;
                        result.data[0] = 0;  // challenger lost
                        rr_radio2.setChannel(HANDSHAKE_CHANNEL);
                        sendPacket(result);

                        rrState = RR_RESULT;
                    }
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawGuess(); }
            break;
        }

        case RR_RESULT: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    stopBlinking();
                    rrState = RR_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawResult(); }
            break;
        }
    }
}

void rfRouletteCleanup() {
    rr_radio1.stopListening();
    rr_radio1.powerDown();
    rr_radio2.stopListening();
    rr_radio2.powerDown();
    stopBlinking();
    Serial.println("# RF Roulette session ended");
}
