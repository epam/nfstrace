TARGET:=nfstrace
CC:=g++
OS:=$(shell uname -s)

LIBS   += -lstdc++ -lpthread -lpcap
CFLAGS += -static-libgcc -Wall -pedantic -Wno-variadic-macros -Wno-long-long

ifeq ($(OS),Linux)
    LIBS += -ldl # dynamic linking loader on GNU/Linux
endif

RELEASE_FLAGS += -O3 -DNDEBUG
DEBUG_FLAGS   += -O0 -g -DDEBUG

