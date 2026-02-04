#!/bin/bash
set -eo pipefail

cd "$(dirname "$0")"

#########################
# Basic configuration   #
#########################

BUILD_DIR=build
DOCKER_IMAGE=build-hsm
GLOBAL_SECRETS=/global.secrets

##########################
# Enter docker container #
##########################

if [[ -z "${IN_CONTAINER:-}" ]]; then
    echo 'entering docker container'

    cd .. # at root of code repo
    mkdir -p "$BUILD_DIR"
    echo "ARGS: $@"
    # bear --version
    if docker run \
              --rm \
              -v ./firmware:/hsm \
              -v ."$GLOBAL_SECRETS":/secrets"$GLOBAL_SECRETS":ro \
              -v ./build:/out \
              -e HSM_PIN="$HSM_PIN" \
              -e PERMISSIONS="$PERMISSIONS" \
              -e IN_CONTAINER=1 \
              "$DOCKER_IMAGE" \
              bear \
                   --output "${BUILD_DIR}/compile_commands_tmp.json" \
                   -- \
                   ./build.sh "$@"
    then
        # Only save compile commands if we actually built anything
        case "${1:-build}" in
            build|all|'')
                sed "s#/hsm#$PWD/firmware#g" \
                    "./firmware/$BUILD_DIR/compile_commands_tmp.json" \
                    > "./firmware/$BUILD_DIR/compile_commands.json"
                ;;
        esac
    fi

    exit 0
fi

#####################
# Toolchain & paths #
#####################

MSPM0_SDK_INSTALL_DIR=${MSPM0_SDK_INSTALL_DIR:-$(cd ../../../../../.. && pwd)}

CC="$TICLANG_ARMCOMPILER/bin/tiarmclang"
LD="$TICLANG_ARMCOMPILER/bin/tiarmclang"
OBJCOPY="$TICLANG_ARMCOMPILER/bin/tiarmobjcopy"
FORMAT=clang-format-19

# BUILDDIR=${BUILDDIR:-/build}
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

LFLAGS=(
    "-l$MSPM0_SDK_INSTALL_DIR/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a"
    "-l$MSPM0_SDK_INSTALL_DIR/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a"
    "-l$MSPM0_SDK_INSTALL_DIR/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a"
    "-L$MSPM0_SDK_INSTALL_DIR/source"
    -L..
    "$LINKERFILE"
    "-Wl,-m,$BUILDDIR/$NAME.map"
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

    for src in src/*.c; do
        obj="$BUILDDIR/$(basename "${src%.c}.so")"
        echo "  CC $src"
        "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
        OBJECTS+=("$obj")
    done

    echo "Linking ELF..."
    "$LD" -Wl,-u,_c_int00 "${OBJECTS[@]}" "${LFLAGS[@]}" \
        -o "$BUILDDIR/$NAME.elf"

    echo "Generating BIN..."
    "$OBJCOPY" -O binary \
        "$BUILDDIR/$NAME.elf" \
        "$BUILDDIR/$NAME.bin"

    echo "Build complete:"
    echo "  $BUILDDIR/$NAME.elf"
    echo "  $BUILDDIR/$NAME.bin"
}

function clean() {
    echo "Cleaning build directory"
    rm -rf "$BUILDDIR"
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
