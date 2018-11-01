all: 
	g++ -O2 -std=c++11 sha512EL.c select.c ed25519_ref10.c crypto_verify.c crypto_vrf.c randombytes.c verify.c keypair.c prove.c convert.c test.c -o test
	
clean:
	rm -f *.o test

run:
	./test