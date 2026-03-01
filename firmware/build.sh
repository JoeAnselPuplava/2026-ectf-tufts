#!/bin/bash
set -eo pipefail

cd "$(dirname "$0")"

#########################
# Basic configuration   #
#########################

BUILD_DIR=/out
DOCKER_IMAGE=build-hsm
GLOBAL_SECRETS=/global.secrets

#####################
# Toolchain & paths #
#####################

MSPM0_SDK_INSTALL_DIR=${MSPM0_SDK_INSTALL_DIR:-$(cd ../../../../../.. && pwd)}

CC="$TICLANG_ARMCOMPILER/bin/tiarmclang"
LD="$TICLANG_ARMCOMPILER/bin/tiarmclang"
OBJCOPY="$TICLANG_ARMCOMPILER/bin/tiarmobjcopy"
FORMAT=clang-format-19

# BUILD_DIR=${BUILD_DIR:-/build}
NAME=hsm
LINKERFILE=firmware.ld

##################
# Compiler flags #
##################

CFLAGS=(
    -I..
    -I./inc
    "-I$MSPM0_SDK_INSTALL_DIR/source"
    "-I$MSPM0_SDK_INSTALL_DIR/source/third_party/CMSIS/Core/Include"
    -D__MSPM0L2228__
    # -Os
    -O2
    -gdwarf-3
    -mcpu=cortex-m0plus
    -march=thumbv6m
    -mfloat-abi=soft
    -mthumb
)

WOLFSSL_DIR=/opt/wolfssl
WOLFCRYPT_SRC="$WOLFSSL_DIR/wolfcrypt/src"

WOLFCRYPT_SOURCES=(
    hash.c
    cryptocb.c
    sha256.c
    cmac.c
    asn.c
    ecc.c
    coding.c 
    aes.c
    random.c
    wolfmath.c
    memory.c
    sp_int.c
    sp_c32.c
)

CFLAGS+=(
    # 1. Include Paths
    "-I./inc"
    "-I/opt/wolfssl"
    
    # 2. Enable User Settings
    -DWOLFSSL_USER_SETTINGS
    
    # 4. FIX: Silence the 'deprecated' warning from WolfSSL internals
    -Wno-deprecated-declarations
    
    # 5. Ensure your RNG prototype is seen everywhere
    "-includeboard_random.h"
)


LFLAGS=(
    "-l$MSPM0_SDK_INSTALL_DIR/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a"
    "-l$MSPM0_SDK_INSTALL_DIR/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a"
    "-l$MSPM0_SDK_INSTALL_DIR/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a"
    "-L$MSPM0_SDK_INSTALL_DIR/source"
    -L..
    "$LINKERFILE"
    "-Wl,-m,$BUILD_DIR/$NAME.map"
    -Wl,--rom_model
    -Wl,--warn_sections
    "-L$TICLANG_ARMCOMPILER/lib"
    -llibc.a
)

PROJ_FILES=(
    src/*.c
    inc/*.h
)

####################
# Build operations #
####################

function build() {
    echo "Compiling sources..."

    OBJECTS=()

    python3 secrets_to_c_header.py "/secrets$GLOBAL_SECRETS" $HSM_PIN "$PERMISSIONS"
    echo "Forcing clean build of WolfSSL..."
    rm -f "$WOLFCRYPT_SRC"/*.o
    rm -f "$WOLFSSL_DIR/wolfcrypt"/*.o

    for src in src/*.c; do
        obj="$BUILD_DIR/$(basename "${src%.c}.o")"
        echo "  CC $src"
        "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
        OBJECTS+=("$obj")
    done

    # ---- Build wolfCrypt sources ----
    for src in "${WOLFCRYPT_SOURCES[@]}"; do
        src_path="$WOLFCRYPT_SRC/$src"
        obj="$WOLFSSL_DIR/wolfcrypt/${src%.c}.o"

        echo "  CC $src_path"
        "$CC" "${CFLAGS[@]}" -c "$src_path" -o "$obj"
        OBJECTS+=("$obj")
    done

    echo "Linking ELF..."
    "$LD" -Wl,-u,_c_int00 "${OBJECTS[@]}" "${LFLAGS[@]}" \
        -o "$BUILD_DIR/$NAME.elf"

    echo "Generating BIN..."
    "$OBJCOPY" -O binary \
        "$BUILD_DIR/$NAME.elf" \
        "$BUILD_DIR/$NAME.bin"

    echo "Cleaning up intermediate objects..."
    rm -f $BUILD_DIR/*.o $BUILD_DIR/*.map $WOLFSSL_DIR/wolfcrypt/*.o

    echo "Build complete:"
    echo "  $BUILD_DIR/$NAME.elf"
    echo "  $BUILD_DIR/$NAME.bin"
}

function clean() {
    echo "Cleaning build directory"
    rm -rf "$BUILD_DIR"
}

function format() {
    for file in "${PROJ_FILES[@]}"; do
        echo "format: $(basename "$file")"
        "$FORMAT" -i "$file"
    done
}

function check-format() {
    "$FORMAT" --dry-run -Werror "${PROJ_FILES[@]}"
}

##################
# Entry point    #
##################
case "${1:-build}" in
    build|all)      build ;;
    clean)          clean ;;
    format)         format ;;
    check-format)   check-format ;;
    *)
        echo "Usage: $0 [build|clean|format|check-format]"
        exit 1
        ;;
esac
