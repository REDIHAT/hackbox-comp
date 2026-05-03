/*
    hackbox Session Logger
    Timestamped activity log stored on SPIFFS. Professional pentest
    engagement documentation.

    Licensed under the MIT License
    SPDX-License-Identifier: MIT
*/

#ifndef SESSION_LOG_H
#define SESSION_LOG_H

#include <Arduino.h>
#include <U8g2lib.h>
#include "pindefs.h"

// Call from any tool to log an event. Category is the tool name,
// detail is a short description. Events are timestamped and stored
// on SPIFFS at /session_log.csv.
void sessionLogEvent(const char *category, const char *detail);

// Viewer app for the Other menu
void sessionLogSetup();
void sessionLogLoop();
void sessionLogCleanup();

#endif
