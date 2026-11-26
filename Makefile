main: src/main.c
	gcc src/main.c src/chacha.c src/sha256.c -O2
