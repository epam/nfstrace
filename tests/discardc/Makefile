TARGET:=discardc

CC:=g++
CFLAGS:=-O3
LIBS:=-lpcap -lpthread

EXTERNAL:=  ../../src/filter/common/pcap_error.h \
            ../../src/auxiliary/spinlock.h \


.PHONY: all
all: $(TARGET)

$(TARGET): discardc.cpp headers.h $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
