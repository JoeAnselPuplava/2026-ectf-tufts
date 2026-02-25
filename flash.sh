# docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='1cb3dd' -e PERMISSIONS='1344=---:3d09=R--:f703=-W-:b0e1=RW-:de87=--C:6706=R-C:1df2=-WC:a71b=RWC' build-hsm
# if [$? -ne 1]; then
uvx ectf hw /dev/tty.usbmodemM43210051 erase
uvx ectf hw /dev/tty.usbmodemM43210051 flash ./build/hsm.bin -n hsm
uvx ectf hw /dev/tty.usbmodemM43210051 start
# fi