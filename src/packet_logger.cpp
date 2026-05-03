/*
    Packet Logger + Serial Export
    Custom tool for hackbox

    Sniffs all WiFi management and data frames in promiscuous mode.
    - OLED: rolling log of last 5 packets (type, MAC, RSSI, size)
    - Serial: CSV line per packet for real-time capture on laptop

    Serial CSV format (115200 baud):
    timestamp_ms,channel,type,subtype,src_mac,dst_mac,bssid,rssi_dbm,length
*/

#include "../include/packet_logger.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/setting.h"
#include "esp_wifi.h"
#include <string.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

namespace {

// ==================== Data Structures ====================

struct PacketEntry {
    unsigned long timestamp;
    uint8_t channel;
    uint8_t frameType;     // 2-bit 802.11 type
    uint8_t frameSubtype;  // 4-bit 802.11 subtype
    uint8_t srcMAC[6];
    uint8_t dstMAC[6];
    uint8_t bssid[6];
    int8_t  rssi;
    uint16_t length;
};

// Ring buffer for OLED display
const int RING_SIZE = 20;
PacketEntry ring[RING_SIZE];
volatile int ringHead = 0;
volatile uint32_t totalPackets = 0;
volatile uint32_t mgmtCount = 0;
volatile uint32_t dataCount = 0;

// State
uint8_t currentChannel = 1;
bool autoHop = true;
bool paused = false;
unsigned long lastHop = 0;
unsigned long lastDraw = 0;
const unsigned long HOP_INTERVAL = 500;
const unsigned long DRAW_INTERVAL = 200;

bool needsRedraw = true;
uint32_t lastDisplayedTotal = 0;
uint8_t lastDisplayedChannel = 0;
bool lastPaused = false;

// Output mode: CSV (text) or PCAP (binary)
bool pcapMode = false;
bool pcapHeaderSent = false;

// PCAP global header (24 bytes) — libpcap format
void writePcapGlobalHeader() {
    uint8_t hdr[24];
    // Magic number
    hdr[0] = 0xD4; hdr[1] = 0xC3; hdr[2] = 0xB2; hdr[3] = 0xA1;
    // Version 2.4
    hdr[4] = 0x02; hdr[5] = 0x00; hdr[6] = 0x04; hdr[7] = 0x00;
    // Timezone offset (0)
    memset(&hdr[8], 0, 4);
    // Timestamp accuracy (0)
    memset(&hdr[12], 0, 4);
    // Snap length (2500)
    hdr[16] = 0xC4; hdr[17] = 0x09; hdr[18] = 0x00; hdr[19] = 0x00;
    // Link-layer type: 802.11 (105)
    hdr[20] = 0x69; hdr[21] = 0x00; hdr[22] = 0x00; hdr[23] = 0x00;
    Serial.write(hdr, 24);
    Serial.flush();
}

// PCAP record header (16 bytes) + raw frame
void writePcapPacket(const uint8_t *frame, uint16_t len) {
    uint32_t ts_sec = millis() / 1000;
    uint32_t ts_usec = (millis() % 1000) * 1000;
    uint32_t capLen = len;
    uint32_t origLen = len;

    uint8_t rechdr[16];
    memcpy(&rechdr[0], &ts_sec, 4);
    memcpy(&rechdr[4], &ts_usec, 4);
    memcpy(&rechdr[8], &capLen, 4);
    memcpy(&rechdr[12], &origLen, 4);
    Serial.write(rechdr, 16);
    Serial.write(frame, len);
    Serial.flush();
}

// ==================== Frame Type Decoder ====================

// Short 1-2 char label for OLED (fits tight columns)
const char* subtypeShort(uint8_t type, uint8_t subtype) {
    if (type == 0) { // Management
        switch (subtype) {
            case 0:  return "AQ"; // Assoc Request
            case 1:  return "AR"; // Assoc Response
            case 2:  return "RQ"; // Reassoc Request
            case 3:  return "RR"; // Reassoc Response
            case 4:  return "PQ"; // Probe Request
            case 5:  return "PR"; // Probe Response
            case 8:  return "Bc"; // Beacon
            case 9:  return "AT"; // ATIM
            case 10: return "Di"; // Disassoc
            case 11: return "Au"; // Auth
            case 12: return "DA"; // Deauth
            case 13: return "Ac"; // Action
            default: return "M?";
        }
    } else if (type == 1) { // Control
        switch (subtype) {
            case 8:  return "BA"; // Block Ack Req
            case 9:  return "Bk"; // Block Ack
            case 10: return "PS"; // PS-Poll
            case 11: return "RT"; // RTS
            case 12: return "CT"; // CTS
            case 13: return "Ak"; // ACK
            default: return "C?";
        }
    } else if (type == 2) { // Data
        switch (subtype) {
            case 0:  return "Dt"; // Data
            case 4:  return "Nl"; // Null
            case 8:  return "QD"; // QoS Data
            case 12: return "QN"; // QoS Null
            default: return "D?";
        }
    }
    return "??";
}

// Full name for serial CSV
const char* subtypeName(uint8_t type, uint8_t subtype) {
    if (type == 0) {
        switch (subtype) {
            case 0:  return "AssocReq";
            case 1:  return "AssocResp";
            case 2:  return "ReassocReq";
            case 3:  return "ReassocResp";
            case 4:  return "ProbeReq";
            case 5:  return "ProbeResp";
            case 8:  return "Beacon";
            case 9:  return "ATIM";
            case 10: return "Disassoc";
            case 11: return "Auth";
            case 12: return "Deauth";
            case 13: return "Action";
            default: return "MgmtOther";
        }
    } else if (type == 1) {
        switch (subtype) {
            case 8:  return "BlockAckReq";
            case 9:  return "BlockAck";
            case 10: return "PSPoll";
            case 11: return "RTS";
            case 12: return "CTS";
            case 13: return "ACK";
            default: return "CtrlOther";
        }
    } else if (type == 2) {
        switch (subtype) {
            case 0:  return "Data";
            case 4:  return "Null";
            case 8:  return "QoSData";
            case 12: return "QoSNull";
            default: return "DataOther";
        }
    }
    return "Unknown";
}

const char* typeName(uint8_t type) {
    switch (type) {
        case 0: return "MGMT";
        case 1: return "CTRL";
        case 2: return "DATA";
        default: return "UNK";
    }
}

// ==================== MAC Formatting ====================

void macToStr(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void macToShort(const uint8_t *mac, char *buf) {
    // Last 3 octets only for OLED
    snprintf(buf, 9, "%02X%02X%02X", mac[3], mac[4], mac[5]);
}

// ==================== Promiscuous Callback ====================

void IRAM_ATTR packetSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (paused) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 24) return; // Need at least the 802.11 header

    // Parse frame control
    uint8_t fc0 = frame[0];
    uint8_t ftype = (fc0 >> 2) & 0x03;    // Type: 2 bits
    uint8_t fsubtype = (fc0 >> 4) & 0x0F; // Subtype: 4 bits

    // Build ring buffer entry
    PacketEntry entry;
    entry.timestamp = millis();
    entry.channel = currentChannel;
    entry.frameType = ftype;
    entry.frameSubtype = fsubtype;
    entry.rssi = pkt->rx_ctrl.rssi;
    entry.length = len;

    // addr1 = destination, addr2 = source, addr3 = BSSID
    memcpy(entry.dstMAC, &frame[4], 6);
    memcpy(entry.srcMAC, &frame[10], 6);
    memcpy(entry.bssid, &frame[16], 6);

    // Store in ring buffer
    ring[ringHead] = entry;
    ringHead = (ringHead + 1) % RING_SIZE;
    totalPackets++;

    if (ftype == 0) mgmtCount++;
    else if (ftype == 2) dataCount++;

    if (pcapMode) {
        // Binary pcap output — raw 802.11 frames
        writePcapPacket(frame, len);
    } else {
        // CSV text output
        char src[18], dst[18], bss[18];
        macToStr(entry.srcMAC, src);
        macToStr(entry.dstMAC, dst);
        macToStr(entry.bssid, bss);

        Serial.printf("%lu,%u,%s,%s,%s,%s,%s,%d,%u\n",
            entry.timestamp,
            entry.channel,
            typeName(ftype),
            subtypeName(ftype, fsubtype),
            src, dst, bss,
            entry.rssi,
            len);
    }
}

// ==================== Display ====================

void drawScreen() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);

    // Header line
    char header[32];
    if (paused) {
        snprintf(header, sizeof(header), "PAUSED  Ch:%02d #%lu", currentChannel, (unsigned long)totalPackets);
    } else if (autoHop) {
        snprintf(header, sizeof(header), "Pkt Log Ch:%02d #%lu", currentChannel, (unsigned long)totalPackets);
    } else {
        snprintf(header, sizeof(header), "LOCKED  Ch:%02d #%lu", currentChannel, (unsigned long)totalPackets);
    }
    u8g2.drawStr(0, 8, header);

    // Draw thin separator
    u8g2.drawHLine(0, 10, 128);

    // Show last 5 packets from ring buffer
    // Format: "Bc AABBCC -65 142"
    int displayRows = 5;
    for (int i = 0; i < displayRows; i++) {
        // Walk backwards from head
        int idx = (ringHead - 1 - i + RING_SIZE) % RING_SIZE;

        // Check if this entry has been written (timestamp != 0)
        if (ring[idx].timestamp == 0) continue;

        const PacketEntry &e = ring[idx];
        char srcShort[9];

        // Apply privacy masking on OLED only
        if (privacyModeEnabled) {
            snprintf(srcShort, sizeof(srcShort), "XX:XX:XX");
        } else {
            macToShort(e.srcMAC, srcShort);
        }

        char line[28];
        snprintf(line, sizeof(line), "%-2s %s %3d %4u",
                 subtypeShort(e.frameType, e.frameSubtype),
                 srcShort,
                 e.rssi,
                 e.length);

        int y = 20 + (i * 8);
        u8g2.drawStr(0, y, line);
    }

    if (paused) {
        char stats[32];
        snprintf(stats, sizeof(stats), "M:%lu D:%lu [%s]",
                 (unsigned long)mgmtCount, (unsigned long)dataCount,
                 pcapMode ? "PCAP" : "CSV");
        u8g2.drawStr(0, 62, stats);
    } else {
        char hint[32];
        snprintf(hint, sizeof(hint), "R=Pause [%s]  L=Exit", pcapMode ? "PCAP" : "CSV");
        u8g2.drawStr(0, 62, hint);
    }

    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

} // namespace

// ==================== Public API ====================

void packetLoggerSetup() {
    // Reset state
    memset(ring, 0, sizeof(ring));
    ringHead = 0;
    totalPackets = 0;
    mgmtCount = 0;
    dataCount = 0;
    currentChannel = 1;
    autoHop = true;
    paused = false;
    lastHop = 0;
    lastDraw = 0;
    needsRedraw = true;
    lastDisplayedTotal = 0;
    lastDisplayedChannel = 0;
    lastPaused = false;
    pcapMode = false;
    pcapHeaderSent = false;

    initWiFi(WIFI_MODE_AP);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(packetSniffer);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.println();
    Serial.println("# hackbox Packet Logger v1.0");
    Serial.println("# CSV mode (press RIGHT to pause, DOWN while paused to switch to PCAP)");
    Serial.println("# timestamp_ms,channel,type,subtype,src_mac,dst_mac,bssid,rssi_dbm,length");

    // Buttons
    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);

    drawScreen();
}

void packetLoggerLoop() {
    unsigned long now = millis();

    // --- Button handling ---
    static bool upPrev = false, downPrev = false, rightPrev = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;

    // RIGHT: toggle pause
    if (rightNow && !rightPrev) {
        paused = !paused;
        if (!paused && pcapMode && !pcapHeaderSent) {
            writePcapGlobalHeader();
            pcapHeaderSent = true;
        }
        needsRedraw = true;
        delay(200);
    }

    // DOWN while paused: toggle CSV/PCAP mode
    if (downNow && !downPrev && paused) {
        pcapMode = !pcapMode;
        if (pcapMode) {
            pcapHeaderSent = false; // Will send header on unpause
        }
        needsRedraw = true;
        delay(200);
    }

    // UP: channel up (disables auto-hop) or re-enable auto-hop if at ch13
    if (upNow && !upPrev && !paused) {
        if (autoHop) {
            autoHop = false;
            needsRedraw = true;
        } else {
            currentChannel++;
            if (currentChannel > 13) {
                currentChannel = 1;
                autoHop = true;
            }
            esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            needsRedraw = true;
        }
        delay(200);
    }

    // DOWN: channel down (disables auto-hop) or re-enable auto-hop if at ch1
    if (downNow && !downPrev && !paused) {
        if (autoHop) {
            autoHop = false;
            needsRedraw = true;
        } else {
            currentChannel--;
            if (currentChannel < 1) {
                currentChannel = 13;
                autoHop = true;
            }
            esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            needsRedraw = true;
        }
        delay(200);
    }

    upPrev = upNow;
    downPrev = downNow;
    rightPrev = rightNow;

    // --- Channel hopping ---
    if (autoHop && !paused && (now - lastHop >= HOP_INTERVAL)) {
        lastHop = now;
        currentChannel++;
        if (currentChannel > 13) currentChannel = 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }

    // --- Display update ---
    // Redraw if state changed or on interval
    if (totalPackets != lastDisplayedTotal ||
        currentChannel != lastDisplayedChannel ||
        paused != lastPaused) {
        needsRedraw = true;
        lastDisplayedTotal = totalPackets;
        lastDisplayedChannel = currentChannel;
        lastPaused = paused;
    }

    if (needsRedraw && (now - lastDraw >= DRAW_INTERVAL)) {
        needsRedraw = false;
        lastDraw = now;
        drawScreen();
    }
}
