#!/bin/bash
# ═══════════════════════════════════════════════
#  CISA IT Audit Toolkit — macOS Launcher
# ═══════════════════════════════════════════════

clear
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   🛡  CISA IT Audit Toolkit  v2.0        ║"
echo "  ║   Professional Edition                    ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Python kontrolü
if ! command -v python3 &> /dev/null; then
    echo "  ❌ Python3 bulunamadı!"
    echo "  → brew install python3"
    echo ""
    read -p "  Devam etmek için Enter..."
    exit 1
fi

echo "  📦 Bağımlılıklar kontrol ediliyor..."

# Flask
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "  ⏳ Flask yükleniyor..."
    pip3 install flask --quiet
fi

# PyWebView
python3 -c "import webview" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "  ⏳ PyWebView yükleniyor..."
    pip3 install pywebview --quiet
    if [ $? -ne 0 ]; then
        echo "  ⚠️  PyWebView yüklenemedi — Tarayıcı modunda çalışacak"
    fi
fi

echo "  ✅ Bağımlılıklar hazır"
echo ""
echo "  🚀 Toolkit başlatılıyor..."
echo ""

python3 app.py
