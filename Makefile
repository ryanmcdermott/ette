CC=g++
CFLAGS=-std=c++17 -Wextra -Wshadow -Wnon-virtual-dtor -Wpedantic

OBJS_CRYPTO=./dist/crypto.o 
OBJS_EDITOR=./dist/editor.o
OBJS_ETTE=./dist/ette.o

all: ette

./dist/crypto.o: crypto.cc crypto.h third_party/picosha2/picosha2.h third_party/plusaes/plusaes.h constants.h
	$(CC) $(CFLAGS) -c crypto.cc -o $(OBJS_CRYPTO)

./dist/editor.o: editor.cc editor.h 
	$(CC) $(CFLAGS) -c editor.cc -o $(OBJS_EDITOR)

./dist/ette.o: ette.cc
	$(CC) $(CFLAGS) -c ette.cc -o $(OBJS_ETTE)

ette: $(OBJS_CRYPTO) $(OBJS_EDITOR) $(OBJS_ETTE)
	$(CC) $(CFLAGS) $(OBJS_CRYPTO) $(OBJS_EDITOR) $(OBJS_ETTE) -o ./dist/ette

install: ette
	install -m 755 ./dist/ette /usr/local/bin/

clean:
	rm -f ./dist/*.o ./dist/ette