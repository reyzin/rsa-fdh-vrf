CC=g++
CFLAGS=-I. -std=c++11
LFLAGS=-lntl -lgmp
DEPS = sha256.h sha512.h

all: vrf
sha256.o: sha256.c sha256.h
	$(CC) -c -o $@ $< $(CFLAGS)
sha512.o: sha512.c sha512.h
	$(CC) -c -o $@ $< $(CFLAGS)
vrf.o: vrf.cpp sha256.h sha512.h
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

vrf: sha512.o sha256.o vrf.o
	$(CC) $(LFLAGS) -o vrf vrf.o sha256.o sha512.o

