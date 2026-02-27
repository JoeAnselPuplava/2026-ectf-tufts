docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=R-C' build-hsm
uvx ectf hw /dev/tty.usbmodemM43210051 erase
uvx ectf hw /dev/tty.usbmodemM43210051 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodemM43210051 start
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=RW-:1112=RWC' build-hsm
uvx ectf hw /dev/tty.usbmodem9 erase
uvx ectf hw /dev/tty.usbmodem9 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodem9 start