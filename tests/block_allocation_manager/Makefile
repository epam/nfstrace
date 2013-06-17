TARGET:=manager

CC:=g++
CFLAGS:=-O0 -g
LIBS:= -lpthread

EXTERNAL:=  ../../src/auxiliary/block_allocator.h \
            ../../src/auxiliary/block_allocation_manager.h \
            ../../src/auxiliary/spinlock.h \

.PHONY: all clean



all: $(TARGET)

$(TARGET): main.cpp $(EXTERNAL)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

clean:
	rm -rf *.o $(TARGET)
