/*
    hackbox - Bee Cipher

    Crypto puzzle game. The hive's comms are encrypted ,decode them
    before time runs out. Puzzles generated locally via seeded PRNG.

    Puzzle types:
      HEX_DECODE:   hex bytes → ASCII char
      XOR_KEY:      find single-byte XOR key given plain + cipher
      CAESAR_SHIFT: find the Caesar shift for an encrypted word
      BINARY_BEE:   8 bits → decimal
      MAC_MATCH:    fill missing MAC octet

    Timer starts at 30s. Wrong answer = -5s penalty.
    Score = puzzles solved × speed bonus.

    Controls: UP/DOWN = adjust answer, CENTER = submit, RIGHT = skip (-10s)
    LEFT is reserved globally as the exit-app button by runApp().
*/

#include "../include/bee_cipher.h"
#include "../include/level_system.h"
#include "../include/pindefs.h"
#include "../include/display_mirror.h"
#include <EEPROM.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ===== EEPROM =====
#define BC_HIGHSCORE_LO  350
#define BC_HIGHSCORE_HI  351
#define BC_LIFETIME_LO   352
#define BC_LIFETIME_HI   353

// ===== State Machine =====
enum BCState {
    BC_MENU,
    BC_PLAYING,
    BC_RESULT
};

BCState bcState = BC_MENU;

// ===== Puzzle Types =====
enum PuzzleType {
    PUZZLE_HEX,
    PUZZLE_XOR,
    PUZZLE_CAESAR,
    PUZZLE_BINARY,
    PUZZLE_MAC,
    PUZZLE_TYPE_COUNT
};

// ===== Puzzle Data =====
PuzzleType currentPuzzleType;
char puzzleText[32];
char puzzleHint[24];
int correctAnswer;
int playerAnswer;
int answerMin;
int answerMax;

// ===== Game State =====
int score = 0;
int puzzlesSolved = 0;
unsigned long timerMs = 30000;
unsigned long puzzleStartTime = 0;
unsigned long gameStartTime = 0;
uint16_t highScore = 0;
uint16_t lifetimeSolved = 0;
uint32_t rngState = 0;

// ===== UI =====
bool needsRedraw = true;
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 150;
bool holdingUp = false;
bool holdingDown = false;
unsigned long holdStartTime = 0;

// ===== PRNG =====
uint32_t nextRng() {
    rngState = rngState * 1103515245 + 12345;
    return (rngState >> 16) & 0x7FFF;
}

// ===== Puzzle Generation =====

void generatePuzzle() {
    currentPuzzleType = (PuzzleType)(nextRng() % PUZZLE_TYPE_COUNT);

    switch (currentPuzzleType) {
        case PUZZLE_HEX: {
            // Random printable ASCII char
            int ch = 33 + (nextRng() % 94);  // '!' to '~'
            snprintf(puzzleText, sizeof(puzzleText), "Hex: 0x%02X = ?", ch);
            snprintf(puzzleHint, sizeof(puzzleHint), "ASCII character");
            correctAnswer = ch;
            playerAnswer = 65;  // 'A'
            answerMin = 33;
            answerMax = 126;
            break;
        }

        case PUZZLE_XOR: {
            // Single-byte XOR: given plain + cipher, find key
            int key = 1 + (nextRng() % 254);
            int plain = 65 + (nextRng() % 26);  // A-Z
            int cipher = plain ^ key;
            snprintf(puzzleText, sizeof(puzzleText), "'%c' XOR ? = 0x%02X", plain, cipher);
            snprintf(puzzleHint, sizeof(puzzleHint), "Find the XOR key");
            correctAnswer = key;
            playerAnswer = 0;
            answerMin = 0;
            answerMax = 255;
            break;
        }

        case PUZZLE_CAESAR: {
            // Caesar cipher on a short word
            const char* words[] = {
                "HONEY", "QUEEN", "DRONE", "SWARM", "STING",
                "DANCE", "COMB", "ROYAL", "JELLY", "LARVA",
                "POLLEN", "NECTAR", "HIVE", "WASP", "BUZZ"
            };
            int wordIdx = nextRng() % 15;
            int shift = 1 + (nextRng() % 25);
            const char* word = words[wordIdx];
            char encrypted[8];
            int wLen = strlen(word);
            if (wLen > 7) wLen = 7;
            for (int i = 0; i < wLen; i++) {
                encrypted[i] = 'A' + ((word[i] - 'A' + shift) % 26);
            }
            encrypted[wLen] = '\0';
            snprintf(puzzleText, sizeof(puzzleText), "Caesar: %s", encrypted);
            snprintf(puzzleHint, sizeof(puzzleHint), "Shift = ?");
            correctAnswer = shift;
            playerAnswer = 1;
            answerMin = 1;
            answerMax = 25;
            break;
        }

        case PUZZLE_BINARY: {
            // 8 bits to decimal
            int val = nextRng() % 256;
            char bits[9];
            for (int i = 7; i >= 0; i--) {
                bits[7 - i] = (val >> i) & 1 ? '1' : '0';
            }
            bits[8] = '\0';
            snprintf(puzzleText, sizeof(puzzleText), "Bin: %s", bits);
            snprintf(puzzleHint, sizeof(puzzleHint), "Decimal = ?");
            correctAnswer = val;
            playerAnswer = 0;
            answerMin = 0;
            answerMax = 255;
            break;
        }

        case PUZZLE_MAC: {
            // Fill in missing MAC octet
            int octets[6];
            for (int i = 0; i < 6; i++) octets[i] = nextRng() % 256;
            int missing = nextRng() % 6;
            correctAnswer = octets[missing];

            char macStr[20] = "";
            for (int i = 0; i < 6; i++) {
                char octet[4];
                if (i == missing) {
                    snprintf(octet, sizeof(octet), "??");
                } else {
                    snprintf(octet, sizeof(octet), "%02X", octets[i]);
                }
                if (i > 0) strcat(macStr, ":");
                strcat(macStr, octet);
            }
            snprintf(puzzleText, sizeof(puzzleText), "%s", macStr);
            snprintf(puzzleHint, sizeof(puzzleHint), "Missing = 0x??");
            playerAnswer = 0;
            answerMin = 0;
            answerMax = 255;
            break;
        }

        default:
            currentPuzzleType = PUZZLE_BINARY;
            generatePuzzle();
            return;
    }

    puzzleStartTime = millis();
}

// ===== Drawing =====

void drawMenu() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "{Bee Cipher}");
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_5x8_tr);

    highScore = EEPROM.read(BC_HIGHSCORE_LO) | (EEPROM.read(BC_HIGHSCORE_HI) << 8);
    if (highScore == 0xFFFF) highScore = 0;
    lifetimeSolved = EEPROM.read(BC_LIFETIME_LO) | (EEPROM.read(BC_LIFETIME_HI) << 8);
    if (lifetimeSolved == 0xFFFF) lifetimeSolved = 0;

    char hsLine[24];
    snprintf(hsLine, sizeof(hsLine), "High Score: %u", highScore);
    u8g2.drawStr(0, 26, hsLine);

    char ltLine[24];
    snprintf(ltLine, sizeof(ltLine), "Lifetime:   %u solved", lifetimeSolved);
    u8g2.drawStr(0, 36, ltLine);

    u8g2.drawStr(0, 50, "Decrypt the hive comms!");

    u8g2.drawStr(0, 62, "C=Start  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawPuzzle() {
    u8g2.clearBuffer();

    // Header with puzzle type
    u8g2.setFont(u8g2_font_5x8_tr);
    const char* typeLabel;
    switch (currentPuzzleType) {
        case PUZZLE_HEX:    typeLabel = "HEX DECODE"; break;
        case PUZZLE_XOR:    typeLabel = "XOR KEY"; break;
        case PUZZLE_CAESAR: typeLabel = "CAESAR SHIFT"; break;
        case PUZZLE_BINARY: typeLabel = "BINARY"; break;
        case PUZZLE_MAC:    typeLabel = "MAC MATCH"; break;
        default:            typeLabel = "CIPHER"; break;
    }

    char header[28];
    snprintf(header, sizeof(header), "#%d  %s", puzzlesSolved + 1, typeLabel);
    u8g2.drawStr(0, 8, header);
    u8g2.drawHLine(0, 10, 128);

    // Challenge text
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 24, puzzleText);

    // Hint
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 34, puzzleHint);

    // Player answer
    u8g2.setFont(u8g2_font_helvB14_tr);
    char ansStr[16];
    if (currentPuzzleType == PUZZLE_HEX) {
        snprintf(ansStr, sizeof(ansStr), "'%c' (%d)", (char)playerAnswer, playerAnswer);
    } else if (currentPuzzleType == PUZZLE_XOR || currentPuzzleType == PUZZLE_MAC) {
        snprintf(ansStr, sizeof(ansStr), "0x%02X (%d)", playerAnswer, playerAnswer);
    } else {
        snprintf(ansStr, sizeof(ansStr), "%d", playerAnswer);
    }
    u8g2.drawStr(10, 52, ansStr);

    // Timer bar
    unsigned long elapsed = millis() - gameStartTime;
    long remaining = (long)timerMs - (long)elapsed;
    if (remaining < 0) remaining = 0;
    int barW = (remaining * 120) / 30000;
    if (barW > 120) barW = 120;
    u8g2.drawFrame(4, 56, 120, 6);
    if (barW > 0) u8g2.drawBox(4, 56, barW, 6);

    // Score
    u8g2.setFont(u8g2_font_5x8_tr);
    char scoreLine[12];
    snprintf(scoreLine, sizeof(scoreLine), "S:%d", score);
    u8g2.drawStr(96, 8, scoreLine);

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawResult() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);

    bool isNewHigh = score > highScore;
    if (isNewHigh) {
        u8g2.drawStr(10, 10, "NEW HIGH SCORE!");
    } else {
        u8g2.drawStr(20, 10, "Time's Up!");
    }
    u8g2.drawHLine(0, 12, 128);

    u8g2.setFont(u8g2_font_helvB14_tr);
    char scoreLine[12];
    snprintf(scoreLine, sizeof(scoreLine), "%d", score);
    u8g2.drawStr(40, 32, scoreLine);

    u8g2.setFont(u8g2_font_5x8_tr);

    char solvedLine[24];
    snprintf(solvedLine, sizeof(solvedLine), "Puzzles: %d", puzzlesSolved);
    u8g2.drawStr(0, 44, solvedLine);

    if (isNewHigh) {
        char oldLine[24];
        snprintf(oldLine, sizeof(oldLine), "Previous: %u", highScore);
        u8g2.drawStr(0, 52, oldLine);
    }

    u8g2.drawStr(0, 62, "C=Again  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ===== Public API =====

void beeCipherSetup() {
    bcState = BC_MENU;
    score = 0;
    puzzlesSolved = 0;
    needsRedraw = true;
    lastButtonPress = 0;

    Serial.println();
    Serial.println("# hackbox Bee Cipher v1.0");

    drawMenu();
}

void beeCipherLoop() {
    unsigned long now = millis();
    bool up = digitalRead(BUTTON_PIN_UP) == LOW;
    bool down = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool right = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool center = digitalRead(BUTTON_PIN_CENTER) == LOW;

    switch (bcState) {
        case BC_MENU: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    // Start game
                    score = 0;
                    puzzlesSolved = 0;
                    timerMs = 30000;
                    rngState = now ^ (analogRead(0) << 16);
                    gameStartTime = millis();
                    generatePuzzle();
                    bcState = BC_PLAYING;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawMenu(); }
            break;
        }

        case BC_PLAYING: {
            // Check timer
            unsigned long elapsed = now - gameStartTime;
            if (elapsed >= timerMs) {
                // Game over
                // Save high score
                highScore = EEPROM.read(BC_HIGHSCORE_LO) | (EEPROM.read(BC_HIGHSCORE_HI) << 8);
                if (highScore == 0xFFFF) highScore = 0;
                if (score > highScore) {
                    EEPROM.write(BC_HIGHSCORE_LO, score & 0xFF);
                    EEPROM.write(BC_HIGHSCORE_HI, (score >> 8) & 0xFF);
                    EEPROM.commit();
                    highScore = score;
                }
                // Update lifetime
                lifetimeSolved = EEPROM.read(BC_LIFETIME_LO) | (EEPROM.read(BC_LIFETIME_HI) << 8);
                if (lifetimeSolved == 0xFFFF) lifetimeSolved = 0;
                lifetimeSolved += puzzlesSolved;
                EEPROM.write(BC_LIFETIME_LO, lifetimeSolved & 0xFF);
                EEPROM.write(BC_LIFETIME_HI, (lifetimeSolved >> 8) & 0xFF);
                EEPROM.commit();

                addXP(score / 10);

                bcState = BC_RESULT;
                needsRedraw = true;
                break;
            }

            if (now - lastButtonPress > debounceDelay) {
                // Fast repeat for holding UP/DOWN
                int step = 1;
                if (up && holdingUp && (now - holdStartTime > 500)) step = 5;
                if (down && holdingDown && (now - holdStartTime > 500)) step = 5;

                if (up) {
                    if (!holdingUp) { holdingUp = true; holdStartTime = now; }
                    playerAnswer += step;
                    if (playerAnswer > answerMax) playerAnswer = answerMin;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else {
                    holdingUp = false;
                }

                if (down) {
                    if (!holdingDown) { holdingDown = true; holdStartTime = now; }
                    playerAnswer -= step;
                    if (playerAnswer < answerMin) playerAnswer = answerMax;
                    needsRedraw = true;
                    lastButtonPress = now;
                } else {
                    holdingDown = false;
                }

                if (center) {
                    // Submit answer
                    if (playerAnswer == correctAnswer) {
                        // Correct!
                        unsigned long solveTime = now - puzzleStartTime;
                        int speedBonus = (solveTime < 5000) ? 3 :
                                         (solveTime < 10000) ? 2 : 1;
                        int points = 10 * speedBonus;
                        score += points;
                        puzzlesSolved++;

                        // Flash green feedback
                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_helvB14_tr);
                        char correct[16];
                        snprintf(correct, sizeof(correct), "+%d!", points);
                        u8g2.drawStr(40, 35, correct);
                        u8g2.sendBuffer();
                        displayMirrorSend(u8g2);
                        delay(400);

                        generatePuzzle();
                    } else {
                        // Wrong ,penalty
                        timerMs -= 5000;

                        u8g2.clearBuffer();
                        u8g2.setFont(u8g2_font_6x10_tr);
                        u8g2.drawStr(30, 30, "WRONG!");
                        u8g2.setFont(u8g2_font_5x8_tr);
                        u8g2.drawStr(30, 42, "-5 seconds");
                        u8g2.sendBuffer();
                        displayMirrorSend(u8g2);
                        delay(400);
                    }
                    needsRedraw = true;
                    lastButtonPress = now;
                }

                if (right) {
                    // Skip puzzle ,bigger penalty
                    timerMs -= 10000;
                    generatePuzzle();
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }

            // Redraw frequently for timer bar
            static unsigned long lastPuzzleDraw = 0;
            if (now - lastPuzzleDraw > 200) {
                lastPuzzleDraw = now;
                needsRedraw = true;
            }

            if (needsRedraw) { needsRedraw = false; drawPuzzle(); }
            break;
        }

        case BC_RESULT: {
            if (now - lastButtonPress > debounceDelay) {
                if (center) {
                    bcState = BC_MENU;
                    needsRedraw = true;
                    lastButtonPress = now;
                }
            }
            if (needsRedraw) { needsRedraw = false; drawResult(); }
            break;
        }
    }
}

void beeCipherCleanup() {
    Serial.println("# Bee Cipher session ended");
}
