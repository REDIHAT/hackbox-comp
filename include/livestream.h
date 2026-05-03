/*
    hackbox Livestream

    Structured newline-delimited JSON event stream on Serial at 115200.
    Designed so a companion OBS overlay / streaming tool can parse events
    and render animations in real time. Default OFF so shipped devices do
    not spam the serial console when plugged into a terminal.

    Event shape:
      {"t":<millis>,"ev":"<type>","d":"<data>"}

    Example events:
      {"t":1234,"ev":"boot","d":"v1.2.0"}
      {"t":5678,"ev":"app_enter","d":"WiFi Scan"}
      {"t":9999,"ev":"app_exit","d":"WiFi Scan"}

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#ifndef LIVESTREAM_H
#define LIVESTREAM_H

#ifdef __cplusplus
extern "C" {
#endif

// Load persisted state from EEPROM.
void livestreamSetup();

// Whether livestream is currently emitting.
bool livestreamEnabled();

// Toggle and persist.
void livestreamToggle();

// Emit a single event. No-op when disabled. Safe to call from anywhere.
// data may be nullptr; it is then omitted from the JSON.
void livestreamEmit(const char* type, const char* data);

#ifdef __cplusplus
}
#endif

#endif
