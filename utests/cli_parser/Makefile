TARGET:=cli_parser

CC:=g++
CFLAGS:=-g -O3
LIBS:=-lpcap -lpthread

EXTERNAL:=  ../../src/controller/cmdline_parser.h

.PHONY: all test clean
all: $(TARGET) test


$(TARGET): cli_parser.cpp $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

test: $(TARGET)
	./$(TARGET)

clean:
	rm -rf *.o $(TARGET)
