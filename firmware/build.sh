#!/bin/bash
set -eo pipefail

cd "$(dirname "$0")"

#########################
# Basic configuration   #
#########################

BUILD_DIR=/out
DOCKER_IMAGE=build-hsm
GLOBAL_SECRETS=/global.secrets

##########################
# Enter docker container #
##########################

# if [[ -z "${IN_CONTAINER:-}" ]]; then
#     echo 'entering docker container'

#     cd .. # at root of code repo
#     # mkdir -p "$BUILD_DIR"
#     echo "ARGS: $@"
#     # bear --version
#             #   -v ./wolfssl_patch/src/random.c:opt/wolfssl/wolfcrypt/src/random.c:ro \
#     if docker run \
#               --rm \
#               -v ./firmware:/hsm \
#               -v ."$GLOBAL_SECRETS":/secrets"$GLOBAL_SECRETS":ro \
#               -v ./build:/out \
#               -e HSM_PIN="$HSM_PIN" \
#               -e PERMISSIONS="$PERMISSIONS" \
#               -e IN_CONTAINER=1 \
#               "$DOCKER_IMAGE" \
#             #   bear \
#             #        --output "${BUILD_DIR}/compile_commands_tmp.json" \
#             #        -- \
#             #        ./build.sh "$@"
#     then
#         # Only save compile commands if we actually built anything
#         case "${1:-build}" in
#             build|all|'')
#                 sed "s#/hsm#$PWD/firmware#g" \
#                     "./firmware/$BUILD_DIR/compile_commands_tmp.json" \
#                     > "./firmware/$BUILD_DIR/compile_commands.json"
#                 ;;
#         esac
#     fi

#     exit 0
# fi

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
    -O2
    -gdwarf-3
    -mcpu=cortex-m0plus
    -march=thumbv6m
    -mfloat-abi=soft
    -mthumb
)

# WOLFSSL_DIR=wolfssl
WOLFSSL_DIR=/opt/wolfssl
WOLFCRYPT_SRC="$WOLFSSL_DIR/wolfcrypt/src"

WOLFCRYPT_SOURCES=(
    hash.c
    md5.c
    cryptocb.c
    sha.c
    sha256.c
    cmac.c
    # --- Add these for ECC ---
    asn.c       
    ecc.c
    coding.c 
    aes.c
    rsa.c
    tfm.c       # Fast math library required for ECC
    random.c    # Required for key generation and signing
    # hmac.c      # Required for HKDF
    wolfmath.c
    memory.c
    # Speed up
    sp_int.c
    sp_c32.c
    # sp_armthumb.c
)

# --- UPDATED CFLAGS ---
# CFLAGS+=(
#     -DUSE_FAST_MATH
#     -DTFM_ECC256
#     -DFP_MAX_BITS=512
#     -DWOLFSSL_SMALL_STACK

#     -DTFM_TIMING_RESISTANT     # Safety for timing attacks
#     -DECC_TIMING_RESISTANT     # Ecc timing protection
#     -DTFM_TIMING_RESISTANT     # Forces constant-time math operations

#     -DWOLFCRYPT_ONLY           # Only build the wolfCrypt portion
#     -DHAVE_ECC                 # Enable ECC support
#     -DHAVE_COMP_KEY            # Enable Compressed (33-byte) Keys
#     -DWOLFSSL_SECP256R1        # Explicitly enable P-256 Curve
#     -DWOLFSSL_SHA256           # Ensure SHA256 is linked for KDF
#     -DECC_TIMING_RESISTANT     # Recommended for security
#     -DUSE_FAST_MATH            # Enables the 'tfm.c' math library
#     -DTFM_ECC256               # Optimizes for the 256-bit curves used in eCTF
#     -DSINGLE_THREADED          # Prevents reliance on pthreads.h
#     -DNO_FILESYSTEM            # Prevents reliance on standard I/O
#     -DNO_DEV_RANDOM            # You must provide your own TRNG seed
#     -DWOLFSSL_USER_IO          # Allows you to define custom I/O if needed
#     -DWC_NO_DEFAULT_DEVID      # Standard for embedded targets
#     "-I/opt/wolfssl"           # Ensure the internal headers are reachable

#     -DWOLFSSL_USER_SETTINGS

#     -DWOLFSSL_AES_DIRECT
#     -DCUSTOM_RAND_GENERATE_SEED_OS=my_trng_seed_gen
#     "-includeboard_random.h"
# )
CFLAGS+=(
    # 1. Include Paths
    "-I./inc"
    "-I/opt/wolfssl"
    
    # 2. Enable User Settings
    -DWOLFSSL_USER_SETTINGS
    
    # 3. FIX: Enable POSIX standards (Fixes 'strcasecmp' warning)
    -D_POSIX_C_SOURCE=200809L
    
    # 4. FIX: Silence the 'deprecated' warning from WolfSSL internals
    -Wno-deprecated-declarations
    
    # 5. Ensure your RNG prototype is seen everywhere
    "-includeboard_random.h"
)
# CFLAGS+=("-I/opt/wolfssl")

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
    # # cat src/random.c
    # echo "These are permissions"
    # echo $PERMISSIONS
    python3 secrets_to_c_header.py "/secrets$GLOBAL_SECRETS" $HSM_PIN "$PERMISSIONS"
    echo "Forcing clean build of WolfSSL..."
    rm -f "$WOLFCRYPT_SRC"/*.o
    rm -f "$WOLFSSL_DIR/wolfcrypt"/*.o
    # mkdir -p "$BUILDDIR/wolfcrypt"
    # echo "==========="
    # cd ../opt/wolfssl/
    # # pwd
    # echo "==========="
    # ls src
    # echo "==========="
    for src in src/*.c; do
        obj="$BUILD_DIR/$(basename "${src%.c}.so")"
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
    rm -f $BUILD_DIR/*.so $WOLFSSL_DIR/wolfcrypt/*.o

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
