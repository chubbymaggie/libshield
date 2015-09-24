all:
	cd mbedtls-2.1.1; make
	mkdir -p bin
	cc -c -Wall -W -Wdeclaration-after-statement -O2 -fno-stack-protector -nostdlib main.c -o bin/main.o
	cc -c -Wall -W -Wdeclaration-after-statement -O2 -fno-stack-protector -nostdlib test_dhm.c -Imbedtls-2.1.1/include -o bin/test_dhm.o
	cc -O2 bin/test_dhm.o bin/main.o -o bin/app -Lmbedtls-2.1.1/library/ -lmbedcrypto

run:
	./bin/app

clean:
	rm -r bin

oldcmds:
	#gcc -g -nostdlib stubstart.S -o hello hello.c
	#cc -O2 test_dhm.o dhm.o -o app -Lmbedtls-2.1.1/library/ -lmbedtls -lmbedx509 -lmbedcrypto
