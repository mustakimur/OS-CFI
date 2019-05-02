CC=$(OSCFI_PATH)/llvm-obj/bin/clang
CXX=$(OSCFI_PATH)/llvm-obj/bin/clang++
CFLAGS=-Xclang -disable-O0-optnone -flto -std=gnu89 -D_GNU_SOURCE -fpermissive -Wno-return-type -include oscfi.h -mmpx -pthread
CXXFLAGS=-Xclang -disable-O0-optnone -flto -std=c++03 -D_GNU_SOURCE -fpermissive -Wno-return-type -include oscfi.h -mmpx -pthread
OPT=-O0

all:
	$(CC) $(CFLAGS) $(OPT) -c oscfi.c -o oscfi.o
	$(CC) $(CFLAGS) $(OPT) -c mpxrt.c  -o mpxrt.o
	$(CC) $(CFLAGS) $(OPT) -c mpxrt-utils.c -o mpxrt-utils.o
	$(CXX) $(CXXFLAGS) $(OPT) -c sample.cpp -o sample.o
	$(CXX) $(CXXFLAGS) $(OPT) oscfi.o mpxrt.o mpxrt-utils.o sample.o -o sample

clean:
	rm *.o sample