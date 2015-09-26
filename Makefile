all:
	make -C mbedtls-2.1.1 all
	mkdir -p bin
	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib main.c -o bin/main.o
	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib intdiv/div.c -o bin/div.o
	cc -O3 -c -std=c89 -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib -maes aesrng/rand.c -o bin/rand.o
	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib libstring/libstring.c -o bin/libmem.o
	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib test_dhm.c -Imbedtls-2.1.1/include -o bin/test_dhm.o
	cc -O2 stubstart.S bin/libmem.o bin/test_dhm.o bin/main.o bin/rand.o bin/div.o -o bin/app -nostdlib -Lmbedtls-2.1.1/library/ -lmbedcrypto -Xlinker -T enclave.lds

run:
	./bin/app

clean:
	rm -r bin
