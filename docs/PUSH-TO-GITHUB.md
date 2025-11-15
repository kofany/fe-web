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
- Proper irssi module structure
- Meson build system
- LICENSE (GPL-2.0)
- CHANGELOG.md

## Repository Structure

```
fe-web/
├── README.md              # Main documentation
├── CHANGELOG.md           # Improvements list
├── LICENSE                # GPL-2.0
├── meson.build            # Main build configuration
├── meson.options          # Build options
├── .gitignore
├── src/                   # Source code
│   ├── meson.build        # Source build config
│   ├── fe-web.c
│   ├── fe-web.h
│   ├── fe-web-client.c
│   ├── fe-web-server.c
│   ├── fe-web-signals.c
│   ├── fe-web-websocket.c
│   ├── fe-web-ssl.c/h
│   ├── fe-web-crypto.c/h
│   ├── fe-web-json.c
│   ├── fe-web-netserver.c
│   ├── fe-web-utils.c
│   └── module.h
├── docs/                  # Documentation
│   └── PUSH-TO-GITHUB.md
└── help/                  # irssi help files

Total: 22 files, 6300+ lines
```

## After Push

### 1. Add repository topics on GitHub:
- irssi
- irc
- websocket
- web-frontend
- irssi-module
- c
- meson

### 2. Add description:
"WebSocket-based web frontend module for irssi IRC client with AES-256-GCM encryption"

### 3. Enable features:
- Issues
- Discussions
- Wiki (optional)

### 4. Consider adding:
- GitHub Actions for CI/CD
- Pre-built binaries in Releases
- Screenshots/demo in README
- Protocol documentation

## Building the Module

Users will build with:

```bash
git clone https://github.com/kofany/fe-web.git
cd fe-web
meson setup build
ninja -C build
ninja -C build install
```

## Release Process

When ready for first release:

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

Then create GitHub Release with:
- Release notes from CHANGELOG.md
- Tarball: `meson dist -C build`
- Optional: pre-built binaries for common platforms

Done!
