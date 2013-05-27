ROOT_DIRECTORY:=.
#get list of subdirectories
DIRS:=$(shell find $(ROOT_DIRECTORY) -maxdepth 1 -type d ! -name ".*" -print)


.PHONY: all
all:
	@for dir in $(DIRS); do \
		$(MAKE) -C $$dir; \
	done

.PHONY: clean
clean:
	@for dir in $(DIRS); do \
		$(MAKE) -C $$dir clean; \
	done

