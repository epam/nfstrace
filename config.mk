TARGET:=nfstrace
CC:=g++

LIBS   += -lstdc++ -lpthread -lpcap
CFLAGS += -static-libgcc -Wall -pedantic -Wno-variadic-macros

RELEASE_FLAGS += -O3 -DNDEBUG
DEBUG_FLAGS   += -O0 -g -DDEBUG

