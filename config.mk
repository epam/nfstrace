TARGET:=nfstrace
CC:=g++

LIBS   += -lstdc++ -lpthread -lpcap
CFLAGS += -static-libgcc -Wall

RELEASE_FLAGS += -O3 -DNDEBUG
DEBUG_FLAGS   += -O0 -g -DDEBUG

