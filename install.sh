#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  LocalSIEM – One-line installer for macOS
#  Usage: curl -sSL https://raw.githubusercontent.com/sagar12-web/SIEM-Monitor/main/install.sh | bash
# ─────────────────────────────────────────────────────────────

set -e

REPO="https://github.com/sagar12-web/SIEM-Monitor"
RAW="https://raw.githubusercontent.com/sagar12-web/SIEM-Monitor/main"
INSTALL_DIR="$HOME/LocalSIEM"
PORT=5555

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       LocalSIEM – Blue Team Monitor      ║"
echo "║            macOS Installer               ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Check macOS ────────────────────────────────────────────
if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "❌  This app requires macOS. Exiting."
  exit 1
fi

# ── 2. Check Python 3 ────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "❌  Python 3 not found."
  echo "    Install it from https://www.python.org/downloads/ then re-run this script."
  exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅  Python $PYTHON_VERSION found"

# ── 3. Create install directory ───────────────────────────────
echo "📁  Installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"

# ── 4. Download app files ─────────────────────────────────────
echo "⬇️   Downloading files..."
curl -sSL "$RAW/siem_server.py"   -o "$INSTALL_DIR/siem_server.py"
curl -sSL "$RAW/dashboard.html"   -o "$INSTALL_DIR/dashboard.html"
curl -sSL "$RAW/requirements.txt" -o "$INSTALL_DIR/requirements.txt"

# ── 5. Install Python dependencies ───────────────────────────
echo "📦  Installing Python dependencies..."
python3 -m pip install -q -r "$INSTALL_DIR/requirements.txt" --user

# ── 6. Create launcher script ─────────────────────────────────
LAUNCHER="$INSTALL_DIR/start.sh"
cat > "$LAUNCHER" << EOF
#!/bin/bash
echo "🛡️  Starting LocalSIEM..."
cd "$INSTALL_DIR"
python3 -m pip install -q -r requirements.txt --user 2>/dev/null
sleep 1
open "http://localhost:$PORT"
python3 siem_server.py
EOF
chmod +x "$LAUNCHER"

# ── 7. Create macOS app shortcut (double-click to launch) ─────
APP_DIR="$HOME/Applications/LocalSIEM.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

cat > "$APP_DIR/Contents/MacOS/LocalSIEM" << EOF
#!/bin/bash
osascript -e 'tell application "Terminal" to do script "bash $LAUNCHER"'
EOF
chmod +x "$APP_DIR/Contents/MacOS/LocalSIEM"

cat > "$APP_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>          <string>LocalSIEM</string>
  <key>CFBundleExecutable</key>    <string>LocalSIEM</string>
  <key>CFBundleIdentifier</key>    <string>com.localsiem.app</string>
  <key>CFBundleVersion</key>       <string>1.0</string>
  <key>CFBundlePackageType</key>   <string>APPL</string>
</dict>
</plist>
EOF

# ── 8. Create Desktop shortcut ────────────────────────────────
DESKTOP_LINK="$HOME/Desktop/LocalSIEM.command"
cat > "$DESKTOP_LINK" << EOF
#!/bin/bash
bash "$LAUNCHER"
EOF
chmod +x "$DESKTOP_LINK"

# ── Done ──────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ✅  Installation Complete!       ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Launch options:"
echo "  1. Double-click 'LocalSIEM' on your Desktop"
echo "  2. Run in terminal:  bash $LAUNCHER"
echo "  3. Open ~/Applications/LocalSIEM.app"
echo ""
echo "  Dashboard → http://localhost:$PORT"
echo ""

# ── 9. Ask to launch now ──────────────────────────────────────
read -p "🚀  Launch LocalSIEM now? (y/n): " LAUNCH
if [[ "$LAUNCH" == "y" || "$LAUNCH" == "Y" ]]; then
  bash "$LAUNCHER"
fi
