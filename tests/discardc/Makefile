TARGET:=discardc

CC:=g++
CFLAGS:=-O3
LIBS:=-lpcap -lpthread


.PHONY: all
all: $(TARGET)

$(TARGET): discardc.cpp headers.h
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean
clean:
	rm -rf *.o $(TARGET)
