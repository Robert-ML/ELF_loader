CC = gcc
CFLAGS = -fPIC -m32 -Wall -Wextra -g
LDFLAGS = -m32 -Wl,--enable-new-dtags -Wl,-rpath=$(shell pwd)/_test

all: build

.PHONY: build
build: libso_stdio.so libso_loader.so

libso_loader.so: loader.o exec_parser.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ -L. -lso_stdio

libso_stdio.so:
	cd ./so_stdio/ && make -f ./GNUmakefile
	cp ./so_stdio/libso_stdio.so ./libso_stdio.so
	mkdir -p _test
	cp ./so_stdio/libso_stdio.so ./_test/libso_stdio.so

exec_parser.o: loader/exec_parser.c loader/exec_parser.h
	$(CC) $(CFLAGS) -o $@ -c $<

loader.o: loader/loader.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	cd ./so_stdio/ && make -f ./GNUmakefile clean
	-rm -f exec_parser.o loader.o libso_loader.so libso_stdio.so
