docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=RWC' build-hsm
uvx ectf hw /dev/tty.usbmodemM43210051 erase
uvx ectf hw /dev/tty.usbmodemM43210051 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodemM43210051 start
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=RW-' build-hsm
uvx ectf hw /dev/tty.usbmodem10 erase
uvx ectf hw /dev/tty.usbmodem10 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodem10 start