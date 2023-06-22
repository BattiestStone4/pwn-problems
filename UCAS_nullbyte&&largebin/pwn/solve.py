#!/usr/bin/env python3

from pwn import *

exe = ELF("pwn_patched")
libc = ELF("./libc6_2.36-3_amd64.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
