qemu-system-mips64el \
    -cpu    5KEf \
    -m      128M \
    -kernel vmlinuz \
    -initrd initrd \
    -append "console=ttyS0 pti=on quiet panic=1" \
    -device e1000,netdev=hacknd \
    -netdev user,id=hacknd,hostfwd=tcp::1337-:1337 \
    -nographic \
    -no-reboot
