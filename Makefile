shared:
	@mkdir -p bin
	@make -C src/sir/crypto all
	@cd src/sir/rand; ./configure; make
	@cc -std=c99 -O2 -c -Wall -Wextra -pedantic -fPIC -fno-stack-protector -nostdlib src/sir/platform.c -o bin/platform.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/sir_main.c -o bin/sir_main.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/math/div.c -o bin/div.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/string/libstring.c -o bin/libmem.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/sir_dhm.c -Isrc/sir/crypto/include -o bin/sir_dhm.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/sir_aes_gcm.c -Isrc/sir/crypto/include -o bin/sir_aes_gcm.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/sir_channel.c -o bin/sir_channel.o
	@cc -std=c99 -O2 -c -Wall -W -Wdeclaration-after-statement -fPIC -fno-stack-protector -nostdlib src/sir/sir_memory.c -o bin/sir_memory.o
	@cc -std=c99 -O2 -shared -fPIC -Wl,-soname,libsir.so -o bin/libsir.so bin/platform.o bin/libmem.o bin/sir_dhm.o bin/sir_aes_gcm.o bin/sir_memory.o bin/sir_channel.o bin/sir_main.o bin/div.o -nostdlib -Lsrc/sir/crypto/library/ -lmbedcrypto -Lsrc/sir/rand -ldrng
	@cc src/host_app/host_app_server.c -ldl -lzmq -lczmq -o bin/host_server_app
	@cc src/host_app/host_app_client.c -ldl -lzmq -lczmq -o bin/host_client_app
	@echo "Build completed successfully and produced app and libsir.so"

#static:
#	make -C mbedtls-2.1.1 all
#	mkdir -p bin
#	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib sir_main.c -o bin/sir_main.o
#	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib intdiv/div.c -o bin/div.o
#	cc -O3 -c -std=c89 -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib -maes -mrdrnd aesrng/rand.c -o bin/rand.o
#	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib libstring/libstring.c -o bin/libmem.o
#	cc -O2 -c -Wall -W -Wdeclaration-after-statement -fno-stack-protector -nostdlib test_dhm.c -Imbedtls-2.1.1/include -o bin/test_dhm.o
#	cc -O2 stubstart.S bin/libmem.o bin/test_dhm.o bin/sir_main.o bin/rand.o bin/div.o -o bin/app -nostdlib -Lmbedtls-2.1.1/library/ -lmbedcrypto -Xlinker -T enclave.lds

run:
	./bin/app

clean:
	rm -r bin

prove:
	frama-c -wp -wp-invariants -wp-prover "why3:z3,alt-ergo" -wp-model "Typed,int,real" -main main -lib-entry -wp-par 8 -wp-timeout 10 -wp-out wp.out src/sir/string/libstring.c 
