CC = gcc
CFLAGS = -O2 -Wl,-O2 -ggdb -flto -Wall $(shell pkg-config --cflags gmodule-2.0)
LDFLAGS = $(shell pkg-config --libs gmodule-2.0 libbpf libxdp)

BPFPROG = bobby.bpf.o
BPFSKEL = bobby.bpf.skel.h
TARGET = bobby

all: $(BPFPROG) $(BPFSKEL) $(TARGET) 

$(BPFPROG): bobby.bpf.c
	clang -O2 -g -Wall -target bpf -c $< -o $(BPFPROG) 

$(BPFSKEL): $(BPFPROG)
	bpftool gen skel $< > $(BPFSKEL)

$(TARGET): bobby.c $(BPFSKEL)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET) $(BPFPROG) $(BPFSKEL)
