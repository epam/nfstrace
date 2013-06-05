TARGET:=reader

CC:=g++
CFLAGS:=-g -O0
LIBS:=-lpcap -lpthread
HEADERS:=../../src/
SOURCES:=main.cpp \
		../../src/filter/pcap/packet_reader.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): 
	$(CC) $(SOURCES) $(CFLAGS) -I$(HEADERS) $(LIBS) -o $(TARGET)

clean:
	rm -rf *.o $(TARGET)
