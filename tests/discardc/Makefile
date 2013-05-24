TARGET:=discardc

CC:=g++
CFLAGS:=-O3
LIBS:=-lpcap -lpthread

EXTERNAL:=  ../../src/controller/cmdline_parser.h \
            ../../src/filter/common/pcap_error.h \
            ../../src/filter/common/packet_capture.h \
            ../../src/filter/common/packet_capture.cpp \
            ../../src/auxiliary/spinlock.h \


.PHONY: all
all: $(TARGET)

$(TARGET): discardc.cpp headers.h $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
