#!/bin/bash
# CISA IT Audit Toolkit - macOS başlatıcı
# Finder'dan çift tıklayarak açmak için. İlk çalıştırmada proje
# klasöründe .venv sanal ortamını kurar (Homebrew Python sistem geneline
# pip install yapılmasına izin vermediği için).

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 bulunamadı. Kurmak için: brew install python3"
    read -p "Kapatmak için Enter..."
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    echo "İlk kurulum: sanal ortam oluşturuluyor..."
    python3 -m venv .venv || { echo "venv oluşturulamadı"; read -p "Enter..."; exit 1; }
    .venv/bin/python -m pip install --quiet --upgrade pip
    .venv/bin/python -m pip install --quiet -r requirements.txt || { echo "Flask kurulamadı"; read -p "Enter..."; exit 1; }
    .venv/bin/python -m pip install --quiet pywebview || echo "pywebview kurulamadı, tarayıcı modunda açılacak"
fi

.venv/bin/python app.py
