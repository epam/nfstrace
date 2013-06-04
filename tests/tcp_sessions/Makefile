TARGET:=tcp_sessions

CC:=g++
CFLAGS:=-O3
LIBS:=-lpcap -lpthread

EXTERNAL:=  ../../src/controller/cmdline_parser.h \
            ../../src/filter/pcap/pcap_error.h \
            ../../src/filter/common/packet_capture.h \
            ../../src/filter/common/packet_capture.cpp \
            ../../src/filter/common/packet_dumper.h \
            ../../src/filter/ethernet/ethernet_header.h \
            ../../src/filter/ip/ipv4_header.h \
            ../../src/filter/tcp/tcp_header.h \
            ../../src/auxiliary/spinlock.h \

.PHONY: all clean



all: $(TARGET)

$(TARGET): tcp_sessions.cpp $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

clean:
	rm -rf *.o $(TARGET)
