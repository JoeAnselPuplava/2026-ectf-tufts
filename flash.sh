# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1111=RWC:1112=RWC:1113=RWC:1114=RWC:1121=RWC:1122=RWC:1123=RWC:1124=RWC' build-hsm
uvx ectf hw /dev/tty.usbmodemM43210051 erase
uvx ectf hw /dev/tty.usbmodemM43210051 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodemM43210051 start
# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='1cb3dd' -e PERMISSIONS='1344=---:3d09=R--:f703=-W-:b0e1=RW-:de87=--C:6706=R-C:1df2=-WC:a71b=RWC' build-hsm
# uvx ectf hw /dev/tty.usbmodem9 erase
# uvx ectf hw /dev/tty.usbmodem9 flash ./build/hsm.bin -n hsm
# uvx ectf hw /dev/tty.usbmodem9 start
# fi