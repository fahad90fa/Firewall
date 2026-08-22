savedcmd_ufw.o := x86_64-linux-gnu-ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o ufw.o @ufw.mod  ; /usr/src/linux-headers-7.0.13+parrot7-amd64/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module ufw.o

ufw.o: $(wildcard /usr/src/linux-headers-7.0.13+parrot7-amd64/tools/objtool/objtool)
