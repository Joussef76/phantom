#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
#  PHANTOM — Cross-Platform Build Script
#  كل نظام تشغيل في فولدر منفصل، والملف التنفيذي اسمه phantom دايماً
# ════════════════════════════════════════════════════════════════════════════

set -e

APP="phantom"
SRC="."
DIST="dist"

GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "  #########################################"
echo "  #       PHANTOM — Build System          #"
echo "  #########################################"
echo -e "${RESET}"

# ── التأكد من وجود Go ────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo -e "${RED}[✘] Go is not installed. Please install Go 1.21+${RESET}"
    exit 1
fi

echo -e "${YELLOW}[*] Go version: $(go version)${RESET}"
echo -e "${YELLOW}[*] Tidying dependencies...${RESET}"
go mod tidy

# ── حذف dist القديم وإعادة إنشاؤه ───────────────────────────────────────────
rm -rf "$DIST"
mkdir -p "$DIST"

# ── دالة البناء ──────────────────────────────────────────────────────────────
# build <GOOS> <GOARCH> <folder_name> <binary_suffix>
build() {
    local GOOS=$1
    local GOARCH=$2
    local FOLDER="${DIST}/$3"
    local SUFFIX=$4
    local BIN="${FOLDER}/${APP}${SUFFIX}"

    mkdir -p "$FOLDER"

    echo -e "${YELLOW}[*] Building → ${FOLDER}/${APP}${SUFFIX}${RESET}"

    GOOS=$GOOS GOARCH=$GOARCH go build \
        -trimpath \
        -ldflags="-s -w" \
        -o "$BIN" \
        "$SRC"

    echo -e "${GREEN}[✔] Done: ${BIN}${RESET}"
}

# ════════════════════════════════════════════════════════════════════════════
#  Windows
# ════════════════════════════════════════════════════════════════════════════
build windows amd64  "windows-64bit"   ".exe"
build windows 386    "windows-32bit"   ".exe"
build windows arm64  "windows-arm64"   ".exe"

# ════════════════════════════════════════════════════════════════════════════
#  Linux
# ════════════════════════════════════════════════════════════════════════════
build linux amd64  "linux-64bit"   ""
build linux 386    "linux-32bit"   ""
build linux arm64  "linux-arm64"   ""
build linux arm    "linux-arm32"   ""

# ════════════════════════════════════════════════════════════════════════════
#  macOS
# ════════════════════════════════════════════════════════════════════════════
build darwin amd64  "macos-intel"          ""
build darwin arm64  "macos-apple-silicon"  ""

# ════════════════════════════════════════════════════════════════════════════
#  النتيجة
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}[*] Build complete. Output:${RESET}"
echo ""

find "$DIST" -type f | sort | while read -r f; do
    SIZE=$(du -sh "$f" | cut -f1)
    printf "    ${GREEN}%-45s${RESET} %s\n" "$f" "$SIZE"
done

echo ""
echo -e "${GREEN}[✔] All binaries ready in ./${DIST}/${RESET}"
