#!/bin/bash
# Zoltraak Build Script - with ASCII magic
# Usage: ./build.sh [debug|release]

set -e

BUILD_TYPE="${1:-release}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Art - Zoltraak title
ZOLTRAAK_ART="
${CYAN}
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ${MAGENTA}  ..      s                                               ..     ${CYAN}  ║
║   ${MAGENTA} :~\"\"\"88hx.                x .d88\"      :8                                         < .z@8\"\` ${CYAN}  ║
║   ${MAGENTA}.~      ?888x          u.    5888R      .88       .u    .                            !@88E ${CYAN}  ║
║   ${MAGENTA} X       '8888k   ...ue888b   '888R     :888ooo  .d88B :@8c        u           u      '888E   u ${CYAN}  ║
║   ${MAGENTA}   H8h    8888X   888R Y888r   888R   -*8888888 =\"8888f8888r    us888u.     us888u.    888E u@8NL ${CYAN}  ║
║   ${MAGENTA}  ?888~   8888    888R I888>   888R     8888      4888>'88\"  .@88 \"8888\" .@88 \"8888\"   888E\`\"88*\" ${CYAN}  ║
║   ${MAGENTA}   %X   .X8*\"     888R I888>   888R     8888      4888> '    9888  9888  9888  9888    888E .dN. ${CYAN}  ║
║   ${MAGENTA}   .-\"\`\"tnx.     888R I888>   888R     8888      4888>      9888  9888  9888  9888    888E~8888 ${CYAN}  ║
║   ${MAGENTA}  :~      8888.  u8888cJ888    888R    .8888Lu=  .d888L .+   9888  9888  9888  9888    888E '888& ${CYAN}  ║
║   ${MAGENTA}  ~       X8888   \"*888*P\"    .888B .  ^%888*    ^\"8888*\"    9888  9888  9888  9888    888E  9888. ${CYAN}  ║
║   ${MAGENTA} ...      '8888L    'Y\"       ^*888%     'Y\"        \"Y\"      \"888*\"\"888\" \"888*\"\"888\" '\"888*\" 4888\" ${CYAN}  ║
║   ${MAGENTA}'888k     '8888f                \"%                            ^Y\"   ^Y'   ^Y\"   ^Y'     \"\"    \"\" ${CYAN}  ║
║   ${MAGENTA} 8888>    <8888                                                                   ${CYAN}  ║
║   ${MAGENTA} \`888>    X888~                                                                   ${CYAN}  ║
║   ${MAGENTA}  '\"88...x8\"\"                                                                     ${CYAN}  ║
║   ${MAGENTA}                                                                                         ${CYAN}  ║
║   ${MAGENTA}                           EVM \u{2022} STARK \u{2022} GPU${CYAN}                                           ${MAGENTA}  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
${NC}"

# Magic circle frames (8 frames for animation)
MAGIC_CIRCLE_FRAMES=(
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◯ ╚╗ ╔╝ ◯ ╚╗ ╔╝ ◯ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ● ╚╗ ╔╝ ● ╚╗ ╔╝ ● ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◈ ╚╗ ╔╝ ◈ ╚╗ ╔╝ ◈ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◎ ╚╗ ╔╝ ◎ ╚╗ ╔╝ ◎ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◉ ╚╗ ╔╝ ◉ ╚╗ ╔╝ ◉ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◯ ╚╗ ╔╝ ◯ ╚╗ ╔╝ ◯ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ● ╚╗ ╔╝ ● ╚╗ ╔╝ ● ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
"${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}
${MAGENTA}   ╱                           ╲    ${NC}
${MAGENTA}  ║    ╔═══╗   ╔═══╗   ╔═══╗    ║    ${NC}
${MAGENTA}  ║   ╔╝ ◈ ╚╗ ╔╝ ◈ ╚╗ ╔╝ ◈ ╚╗   ║    ${NC}
${MAGENTA}  ║   ╚╗   ╔╝ ╚╗   ╔╝ ╚╗   ╔╝   ║    ${NC}
${MAGENTA}  ║    ╚═══╝   ╚═══╝   ╚═══╝    ║    ${NC}
${MAGENTA}   ╲                           ╱    ${NC}
${MAGENTA}    ✦ ════════════════ ════════════════ ✦    ${NC}"
)

SPINNER_CHARS="/-\\|"

# Print header
echo -e "$ZOLTRAAK_ART"
echo ""
echo -e "${YELLOW}  ⚡ GPU-accelerated ZK proving for Ethereum${NC}"
echo ""

# Check for required tools
if ! command -v swift &> /dev/null; then
    echo -e "${RED}  ✗ Error: Swift is required but not installed.${NC}"
    echo -e "    Install Xcode or Swift from https://swift.org/download/"
    exit 1
fi

# Initialize submodules if needed
if [ -d "foundry" ] && [ ! -f "foundry/foundry.toml" ]; then
    echo -e "${YELLOW}  ⟳ Initializing foundry submodule...${NC}"
    git submodule update --init foundry
fi

# Build with animation
echo -e "${CYAN}  Channeling Zoltraak...${NC}"
echo ""

# Start build in background
swift build -c "$BUILD_TYPE" > /tmp/build_output.txt 2>&1 &
BUILD_PID=$!

# Animated magic circle + spinner
frame=0
count=0
while kill -0 $BUILD_PID 2>/dev/null; do
    spin=${SPINNER_CHARS:$count:1}
    # Clear screen and home cursor before each frame for smooth animation
    # Using $'\033' syntax ensures proper escape sequence interpretation
    printf $'\033[2J\033[H'
    printf "  %s %s\n" "$spin" "${MAGIC_CIRCLE_FRAMES[$frame]}"
    frame=$(( (frame + 1) % 8 ))
    count=$(( (count + 1) % 4 ))
    sleep 0.12
done

wait $BUILD_PID
BUILD_RESULT=$?

echo ""
echo ""

if [ $BUILD_RESULT -eq 0 ]; then
    # Success animation
    echo -e "${GREEN}"
    echo "  ╔════════════════════════════════════════╗"
    echo "  ║  ${YELLOW}✓${GREEN}  Build Complete!                      ║"
    echo "  ╚════════════════════════════════════════╝"
    echo -e "${NC}"

    # Verify binary
    BINARY=".build/$BUILD_TYPE/ZoltraakRunner"
    if [ -f "$BINARY" ]; then
        SIZE=$(du -h "$BINARY" 2>/dev/null | cut -f1 || echo "unknown")
        echo -e "  ${GREEN}▸${NC} Binary: ${CYAN}$BINARY${NC}"
        echo -e "  ${GREEN}▸${NC} Size:   ${CYAN}$SIZE${NC}"
        echo ""
        echo -e "  ${YELLOW}Run with:${NC}"
        echo -e "    ${MAGENTA}./$BINARY benchmarks${NC}"
        echo -e "    ${MAGENTA}./$BINARY eth-live 1${NC}"
    fi
else
    # Error animation
    echo -e "${RED}"
    echo "  ╔════════════════════════════════════════╗"
    echo "  ║  ${YELLOW}✗${RED}  Build Failed!                       ║"
    echo "  ╚════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${RED}Check output above for errors.${NC}"
    exit 1
fi