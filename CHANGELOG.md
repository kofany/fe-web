# Changelog

## Version 1.0.0 - 2025-01-15

### Improvements from erssi development

This standalone irssi module incorporates bugfixes and improvements developed 
during erssi evolution, while remaining fully compatible with standard irssi.

---

## Critical Bugfixes

### JSON Unescape (fe-web-json.c)
- Added proper handling of escaped characters in JSON strings
- Supports: \n, \", \\, \t, \r, \b, \f
- Supports Unicode escape sequences: \uXXXX
- WITHOUT THIS FIX: strings with special characters don't work correctly

### TCP Send Buffer (fe-web-server.c)
- Increased TCP send buffer from default to 2MB
- Improves performance for large state dumps
- Uses setsockopt(fd, SOL_SOCKET, SO_SNDBUF)

### Error Handling (fe-web-server.c)
- Fixed connection error checking
- Changed from checking (ret == 0) to (ret < 0)
- Improves connection stability

---

## New Features

### Highlight Detection (fe-web-signals.c)
- Automatic detection of mentions in public messages
- Uses hilight_match() from irssi core
- Sets is_highlight flag in web messages
- Requires: hilight-text.h

### ACTION Message Support (fe-web-signals.c)
- Full support for /me commands
- New handler: sig_message_irc_action() for others
- New handler: sig_message_irc_own_action() for own actions
- Messages marked with MSGLEVEL_ACTIONS

### Own Nick Changes (fe-web-signals.c)
- Proper handling of user's own nick changes
- New handler: sig_message_own_nick()
- Sends nicklist updates for all channels
- Previously only handled other users' nick changes

---

## Code Improvements

### Cleaner Code (fe-web-crypto.c, fe-web-server.c)
- Removed debug print statements
- Reduces console spam
- Cleaner output during normal operation

### Better ABI Compatibility (fe-web.c)
- Use MODULE_ABICHECK(fe_web) macro
- More consistent with irssi codebase
- Replaces manual abicheck function

### Additional Headers
- Added: settings.h
- Added: hilight-text.h
- Added: irc-queries.h
- Added: sys/socket.h
- Added: stdlib.h

---

## Compatibility Notes

### Standard irssi
This version works with standard irssi (version 1.2 or higher).
All erssi-specific features have been removed.

### Removed erssi-only features
- Sidepanel integration (sidepanels-activity.h)
- Sidepanel rendering (sidepanels-render.h)
- Functions: reset_window_priority()
- Functions: redraw_left_panels_only()

---

## Testing

Tested on:
- irssi 1.4.x
- Operating systems: macOS, Linux (Debian, Ubuntu, Arch)
- Compilers: gcc, clang

---

## Credits

- Original irssi-fe-web: irssi community
- Bugfixes and improvements: erssi development team
- Standalone packaging: 2025
