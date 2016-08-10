default:
	gcc -g -fPIC -fno-stack-protector -c  PPHpam.c -lpolypasswordhasher
	sudo ld -x --shared -o PPHpam.so PPHpam.o libgfshare.o -lc -lssl -lcrypto -lpolypasswordhasher

install: default
	sudo cp PPHpam.so /lib/security/
