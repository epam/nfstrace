CC:=g++

INCLUDES+=-Isrc
INCLUDES+=-I../src/
LIBS    +=-lstdc++ -lpthread
CFLAGS  +=-Wall -pedantic -Wno-variadic-macros -Wno-long-long -shared -fPIC

DEBUG_FLAGS   += -O0 -g -DDEBUG
RELEASE_FLAGS += -O3 -DNDEBUG

ifeq "$(MAKECMDGOALS)" "debug"
CFLAGS +=$(DEBUG_FLAGS)
OUT_DIR:=debug
else
CFLAGS +=$(RELEASE_FLAGS)
OUT_DIR:=release
endif

SRC_DIR:=src
OBJ_DIR:=$(OUT_DIR)/obj
DEP_DIR:=$(OUT_DIR)/dep
