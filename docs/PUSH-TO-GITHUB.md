# How to Push to GitHub

## Step 1: Create GitHub Repository

Go to GitHub and create new repository:
- Name: fe-web
- Description: WebSocket-based web frontend module for irssi
- Public repository
- Do NOT initialize with README (we have our own)

URL will be: https://github.com/kofany/fe-web

## Step 2: Push from /tmp/fe-web

```bash
cd /tmp/fe-web

# Add GitHub remote
git remote add origin https://github.com/kofany/fe-web.git

# Push to GitHub
git push -u origin main
```

## Step 3: Verify on GitHub

Visit: https://github.com/kofany/fe-web

You should see:
- README.md as main page
- 20 files
- 6254+ lines of code
- LICENSE (GPL-2.0)
- CHANGELOG.md

## Repository Contents

```
fe-web/
├── README.md              (306 lines - installation guide)
├── CHANGELOG.md           (103 lines - improvements list)
├── LICENSE                (GPL-2.0)
├── .gitignore
├── Makefile               (standalone build)
├── meson.build            (meson build)
├── fe-web.c               (main module)
├── fe-web.h               (public API)
├── fe-web-client.c        (client handling)
├── fe-web-server.c        (WebSocket server)
├── fe-web-signals.c       (IRC event handlers - 55KB)
├── fe-web-websocket.c     (RFC 6455 protocol)
├── fe-web-ssl.c/h         (TLS/SSL support)
├── fe-web-crypto.c/h      (AES-256-GCM)
├── fe-web-json.c          (JSON serialization)
├── fe-web-netserver.c     (network API)
├── fe-web-utils.c         (utilities)
└── module.h               (module header)
```

## After Push

1. Add topics on GitHub:
   - irssi
   - irc
   - websocket
   - web-frontend
   - irssi-module

2. Add description:
   "WebSocket-based web frontend module for irssi IRC client"

3. Enable Issues and Discussions

4. Consider adding:
   - GitHub Actions for CI/CD
   - Pre-built binaries in Releases
   - Screenshots in README

Done!
