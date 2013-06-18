TARGET:=fill_queue

CC:=g++
CFLAGS:=-O3 -lpthread

EXTERNAL:=  ../../src/auxiliary/queue.h \
            ../../src/auxiliary/block_allocator.h \
            ../../src/auxiliary/spinlock.h \

.PHONY: all clean

all: $(TARGET)

$(TARGET): fill_queue.cpp $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

clean:
	rm -rf *.o $(TARGET)
