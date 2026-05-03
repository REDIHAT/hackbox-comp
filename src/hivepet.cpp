/*
    hackbox
    hackbox custom firmware

    HivePet - Virtual Bee Tamagotchi
    Your bee companion that feeds on pollen (XP) from device activity.
    The more you use hackbox tools, the happier your pet becomes.
    Pet it, play with it, watch it bounce around.
*/

#include "../include/hivepet.h"
#include "../include/level_system.h"
#include "../include/neopixel.h"
#include "../include/display_mirror.h"
#include "../include/sleep_manager.h"
#include "../include/setting.h"
#include "../include/pindefs.h"
#include <EEPROM.h>
#include <U8g2lib.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern Adafruit_NeoPixel pixels;

namespace {

// ===== EEPROM =====
const uint8_t PET_MAGIC_ADDR     = 110;
const uint8_t PET_LAST_XP_LOW    = 111;
const uint8_t PET_LAST_XP_HIGH   = 112;
const uint8_t PET_VISITS_LOW     = 113;
const uint8_t PET_VISITS_HIGH    = 114;
const uint8_t PET_MAGIC          = 0xBB;

// ===== Mood =====
enum PetMood {
    MOOD_ECSTATIC,
    MOOD_HAPPY,
    MOOD_CONTENT,
    MOOD_BORED,
    MOOD_HUNGRY
};

// ===== Screens =====
enum PetScreen { SCREEN_MAIN, SCREEN_STATS };

// ===== State =====
PetMood mood = MOOD_CONTENT;
PetScreen screen = SCREEN_MAIN;
int xpDelta = 0;
int lastVisitXP = 0;
uint16_t lifetimeVisits = 0;
bool needsRedraw = true;

// Animation
int bounceFrame = 0;
unsigned long lastBounce = 0;
const int bounceTable[] = {0, -1, -2, -2, -1, 0, 1, 1};
const int BOUNCE_FRAMES = 8;
const unsigned long BOUNCE_SPEED = 180;

// Reaction overlay (hearts / sparkles)
bool reacting = false;
unsigned long reactionStart = 0;
const unsigned long REACTION_DURATION = 1200;
int reactionType = 0; // 0 = pet (hearts), 1 = play (sparkles)

// ===== EEPROM helpers =====
void loadPetData() {
    uint8_t magic = EEPROM.read(PET_MAGIC_ADDR);
    if (magic != PET_MAGIC) {
        lastVisitXP = 0;
        lifetimeVisits = 0;
        return;
    }
    lastVisitXP = EEPROM.read(PET_LAST_XP_LOW) |
                  (EEPROM.read(PET_LAST_XP_HIGH) << 8);
    lifetimeVisits = EEPROM.read(PET_VISITS_LOW) |
                     (EEPROM.read(PET_VISITS_HIGH) << 8);
}

void savePetData() {
    int xp = getCurrentXP();
    EEPROM.write(PET_MAGIC_ADDR, PET_MAGIC);
    EEPROM.write(PET_LAST_XP_LOW, xp & 0xFF);
    EEPROM.write(PET_LAST_XP_HIGH, (xp >> 8) & 0xFF);
    EEPROM.write(PET_VISITS_LOW, lifetimeVisits & 0xFF);
    EEPROM.write(PET_VISITS_HIGH, (lifetimeVisits >> 8) & 0xFF);
    EEPROM.commit();
}

// ===== Mood calculation =====
void calculateMood() {
    int xp = getCurrentXP();
    int level = getCurrentLevel();
    xpDelta = xp - lastVisitXP;
    if (xpDelta < 0) xpDelta = 0; // XP was reset

    if (reacting) {
        mood = MOOD_ECSTATIC;
    } else if (xpDelta > 50) {
        mood = MOOD_ECSTATIC;
    } else if (xpDelta > 20 || level > 40) {
        mood = MOOD_HAPPY;
    } else if (xpDelta > 5 || level > 15) {
        mood = MOOD_CONTENT;
    } else if (level > 3) {
        mood = MOOD_BORED;
    } else {
        mood = MOOD_HUNGRY;
    }
}

void setMoodLED() {
    if (!neoPixelActive) return;
    switch (mood) {
        case MOOD_ECSTATIC: pixels.setPixelColor(0, pixels.Color(0, 255, 50));  break;
        case MOOD_HAPPY:    pixels.setPixelColor(0, pixels.Color(50, 200, 0));  break;
        case MOOD_CONTENT:  pixels.setPixelColor(0, pixels.Color(200, 200, 0)); break;
        case MOOD_BORED:    pixels.setPixelColor(0, pixels.Color(200, 100, 0)); break;
        case MOOD_HUNGRY:   pixels.setPixelColor(0, pixels.Color(200, 0, 0));   break;
    }
    pixels.show();
}

const char* moodText() {
    switch (mood) {
        case MOOD_ECSTATIC: return "Ecstatic!";
        case MOOD_HAPPY:    return "Happy";
        case MOOD_CONTENT:  return "Content";
        case MOOD_BORED:    return "Bored...";
        case MOOD_HUNGRY:   return "Hungry!";
    }
    return "?";
}

// ===== Drawing =====

void drawBee(int cx, int cy) {
    int yOff = bounceTable[bounceFrame];
    bool wingsUp = (bounceFrame % 2 == 0);
    int wingY = wingsUp ? -5 : -2;

    // Wings (outline ellipses, flap with bounce)
    u8g2.drawEllipse(cx - 14, cy + wingY + yOff, 6, 3, U8G2_DRAW_ALL);
    u8g2.drawEllipse(cx + 14, cy + wingY + yOff, 6, 3, U8G2_DRAW_ALL);

    // Antennae
    u8g2.drawLine(cx - 3, cy - 12 + yOff, cx - 7, cy - 18 + yOff);
    u8g2.drawLine(cx + 3, cy - 12 + yOff, cx + 7, cy - 18 + yOff);
    u8g2.drawDisc(cx - 7, cy - 18 + yOff, 1, U8G2_DRAW_ALL);
    u8g2.drawDisc(cx + 7, cy - 18 + yOff, 1, U8G2_DRAW_ALL);

    // Head
    u8g2.drawDisc(cx, cy - 7 + yOff, 6, U8G2_DRAW_ALL);

    // Eyes (draw black on white head)
    u8g2.setDrawColor(0);
    switch (mood) {
        case MOOD_ECSTATIC:
            // ^ ^ eyes
            u8g2.drawLine(cx - 5, cy - 7 + yOff, cx - 3, cy - 9 + yOff);
            u8g2.drawLine(cx - 1, cy - 7 + yOff, cx - 3, cy - 9 + yOff);
            u8g2.drawLine(cx + 1, cy - 7 + yOff, cx + 3, cy - 9 + yOff);
            u8g2.drawLine(cx + 5, cy - 7 + yOff, cx + 3, cy - 9 + yOff);
            break;
        case MOOD_HAPPY:
            u8g2.drawDisc(cx - 3, cy - 8 + yOff, 1, U8G2_DRAW_ALL);
            u8g2.drawDisc(cx + 3, cy - 8 + yOff, 1, U8G2_DRAW_ALL);
            break;
        case MOOD_CONTENT:
            u8g2.drawHLine(cx - 4, cy - 8 + yOff, 3);
            u8g2.drawHLine(cx + 2, cy - 8 + yOff, 3);
            break;
        case MOOD_BORED:
            u8g2.drawDisc(cx - 3, cy - 6 + yOff, 1, U8G2_DRAW_ALL);
            u8g2.drawDisc(cx + 3, cy - 6 + yOff, 1, U8G2_DRAW_ALL);
            break;
        case MOOD_HUNGRY:
            // X X eyes
            u8g2.drawLine(cx - 5, cy - 9 + yOff, cx - 2, cy - 7 + yOff);
            u8g2.drawLine(cx - 2, cy - 9 + yOff, cx - 5, cy - 7 + yOff);
            u8g2.drawLine(cx + 2, cy - 9 + yOff, cx + 5, cy - 7 + yOff);
            u8g2.drawLine(cx + 5, cy - 9 + yOff, cx + 2, cy - 7 + yOff);
            break;
    }
    u8g2.setDrawColor(1);

    // Smile (happy/ecstatic only)
    if (mood == MOOD_ECSTATIC || mood == MOOD_HAPPY) {
        u8g2.setDrawColor(0);
        u8g2.drawPixel(cx - 2, cy - 4 + yOff);
        u8g2.drawHLine(cx - 1, cy - 3 + yOff, 3);
        u8g2.drawPixel(cx + 2, cy - 4 + yOff);
        u8g2.setDrawColor(1);
    }

    // Body - thorax + abdomen
    u8g2.drawDisc(cx, cy + 4 + yOff, 8, U8G2_DRAW_ALL);
    u8g2.drawDisc(cx, cy + 14 + yOff, 7, U8G2_DRAW_ALL);

    // Stripes (black bands on white body)
    u8g2.setDrawColor(0);
    u8g2.drawHLine(cx - 7, cy + 2 + yOff, 14);
    u8g2.drawHLine(cx - 7, cy + 6 + yOff, 14);
    u8g2.drawHLine(cx - 6, cy + 12 + yOff, 12);
    u8g2.drawHLine(cx - 5, cy + 16 + yOff, 10);
    u8g2.setDrawColor(1);

    // Tail
    u8g2.drawLine(cx, cy + 21 + yOff, cx - 1, cy + 24 + yOff);
    u8g2.drawLine(cx, cy + 21 + yOff, cx + 1, cy + 24 + yOff);
    u8g2.drawPixel(cx, cy + 25 + yOff);
}

void drawReaction(int cx, int cy) {
    unsigned long elapsed = millis() - reactionStart;
    int phase = elapsed / 300;
    if (phase > 3) phase = 3;

    if (reactionType == 0) {
        // Hearts around the bee
        const int hx[] = {-22, 20, -18, 24};
        const int hy[] = {-14, -8, 8, 2};
        u8g2.setFont(u8g2_font_4x6_tr);
        for (int i = 0; i <= phase; i++) {
            u8g2.drawStr(cx + hx[i], cy + hy[i], "<3");
        }
    } else {
        // Sparkles around the bee
        const int sx[] = {-22, 20, -18, 24};
        const int sy[] = {-12, -6, 10, 4};
        for (int i = 0; i <= phase; i++) {
            int px = cx + sx[i];
            int py = cy + sy[i];
            u8g2.drawPixel(px, py);
            u8g2.drawPixel(px - 2, py);
            u8g2.drawPixel(px + 2, py);
            u8g2.drawPixel(px, py - 2);
            u8g2.drawPixel(px, py + 2);
        }
    }
}

void drawMainScreen() {
    u8g2.clearBuffer();

    int beeCX = 32;
    int beeCY = 26;

    drawBee(beeCX, beeCY);

    if (reacting) {
        drawReaction(beeCX, beeCY);
    }

    // Right panel
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(70, 10, "HivePet");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawHLine(70, 12, 58);

    u8g2.drawStr(70, 22, moodText());

    char buf[20];
    snprintf(buf, sizeof(buf), "Lv.%d", getCurrentLevel());
    u8g2.drawStr(70, 32, buf);

    u8g2.drawStr(70, 42, getRankName(getCurrentLevel()));

    snprintf(buf, sizeof(buf), "+%d pollen", xpDelta);
    u8g2.drawStr(70, 52, buf);

    u8g2.setFont(u8g2_font_4x6_tr);
    u8g2.drawStr(0, 62, "U=Pet R=Play D=Stats");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawStatsScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(0, 10, "HivePet Stats");
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawHLine(0, 12, 128);

    char buf[28];

    snprintf(buf, sizeof(buf), "Mood: %s", moodText());
    u8g2.drawStr(0, 24, buf);

    snprintf(buf, sizeof(buf), "Level: %d", getCurrentLevel());
    u8g2.drawStr(0, 34, buf);

    snprintf(buf, sizeof(buf), "Rank: %s", getRankName(getCurrentLevel()));
    u8g2.drawStr(0, 44, buf);

    snprintf(buf, sizeof(buf), "Pollen: %d (+%d new)", getCurrentXP(), xpDelta);
    u8g2.drawStr(0, 54, buf);

    u8g2.drawStr(0, 62, "D=Back");

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // anonymous namespace

// ===== Public API =====

void hivepetSetup() {
    EEPROM.begin(512);
    loadPetData();
    calculateMood();

    screen = SCREEN_MAIN;
    needsRedraw = true;
    reacting = false;
    bounceFrame = 0;
    lastBounce = millis();

    if (lifetimeVisits < 65535) lifetimeVisits++;

    // Take over NeoPixel (stop any blink in progress)
    stopBlinking();
    setMoodLED();

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawMainScreen();
}

void hivepetLoop() {
    unsigned long now = millis();

    // Bounce animation
    if (now - lastBounce >= BOUNCE_SPEED) {
        lastBounce = now;
        bounceFrame = (bounceFrame + 1) % BOUNCE_FRAMES;
        if (screen == SCREEN_MAIN) needsRedraw = true;
    }

    // Reaction timer
    if (reacting && now - reactionStart >= REACTION_DURATION) {
        reacting = false;
        calculateMood();
        setMoodLED();
        needsRedraw = true;
    }

    // Buttons
    static bool upPrev = false, downPrev = false, rightPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;

    if (upNow && !upPrev && screen == SCREEN_MAIN) {
        // Pet the bee
        reacting = true;
        reactionType = 0;
        reactionStart = now;
        mood = MOOD_ECSTATIC;
        setMoodLED();
        addXP(2);
        needsRedraw = true;
        delay(150);
    }

    if (rightNow && !rightPrev && screen == SCREEN_MAIN) {
        // Play with the bee
        reacting = true;
        reactionType = 1;
        reactionStart = now;
        mood = MOOD_ECSTATIC;
        setMoodLED();
        addXP(2);
        needsRedraw = true;
        delay(150);
    }

    if (downNow && !downPrev) {
        screen = (screen == SCREEN_MAIN) ? SCREEN_STATS : SCREEN_MAIN;
        needsRedraw = true;
        delay(200);
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;

    if (needsRedraw) {
        needsRedraw = false;
        if (screen == SCREEN_MAIN) drawMainScreen();
        else drawStatsScreen();
    }
}

void hivepetCleanup() {
    savePetData();
    if (neoPixelActive) {
        pixels.setPixelColor(0, 0, 0, 0);
        pixels.show();
    }
}
