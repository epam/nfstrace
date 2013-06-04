TARGET:=pcap_if

CC:=g++
CFLAGS:=-O3
LIBS:=-lpcap

EXTERNAL:=  ../../src/filter/pcap/network_interfaces.h \
            ../../src/filter/pcap/network_interfaces.cpp \
            ../../src/filter/pcap/pcap_error.h \


.PHONY: all clean

all: $(TARGET)

$(TARGET): pcap_if.cpp $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

clean:
	rm -rf *.o $(TARGET)
