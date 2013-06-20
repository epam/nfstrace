include ../config.mk

TESTS_DIR:=.
SRC_DIR:=../src/
OBJ_DIR:=../debug/obj/


# list of all tests directories
DIRS:=$(shell find $(TESTS_DIR) -maxdepth 1 -type d ! -name ".*" -printf "%f\n")

# find all object files in OBJ_DIR folder
OBJS:=$(shell find $(OBJ_DIR) -type f -name "*.o" )
# exclude main.o with main() function
OBJS:=$(filter-out %/main.o, $(OBJS))


.PHONY: all clean $(DIRS)

all: $(DIRS)

$(OBJ_DIR):
	@echo Tests requre debug objects of main sources. Please do: \'make debug\' for root of the sources.

$(DIRS): $(OBJ_DIR)
	@rm -f $@/$@
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $@/$@ $(shell find $@/ -type f -name "*.cpp" -o -name "*.h" )

clean:
	rm -f $(shell find $(TESTS_DIR) -maxdepth 1 -type d ! -name ".*" -printf "%f/%f\n")
