default:
	gcc -fPIC -fno-stack-protector -c  PPHpam.c -lpolypasswordhasher
	sudo ld -x --shared -o mypam.so PPHpam.o libpolypasswordhasher.o libgfshare.o -lssl -lcrypto

install: default
	sudo cp mypam.so /lib/security/
