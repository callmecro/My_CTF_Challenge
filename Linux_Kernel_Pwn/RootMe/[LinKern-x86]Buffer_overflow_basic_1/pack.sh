#/bin/bash
gcc -static -m32 exp.c -o exp
chmod 777 exp
name="$1"
new_name=$name".gz"
mv $name $new_name
mkdir tmp
cpio -idmv < $name -D ./tmp
mv exp ./tmp/
cd ./tmp && find . |cpio -ov -H newc |gzip > ../$name
cd ..
