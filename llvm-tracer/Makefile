CC := clang
CFLAGS := -O3 -g

all: weizz-llvm-rt.a

memorycmp.o: memorycmp.c weizz-llvm.h
	$(CC) $(CFLAGS) -c -fPIC -fno-stack-protector memorycmp.c

instrument.o: instrument.c weizz-llvm.h
	$(CC) $(CFLAGS) -c -fPIC -fno-stack-protector instrument.c

weizz-llvm-rt.a: instrument.o memorycmp.o
	$(AR) rcs weizz-llvm-rt.a instrument.o memorycmp.o

clean:
	rm -f instrument.o memorycmp.o instrument.a
