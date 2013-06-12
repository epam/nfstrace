-include config.mk
SRC_DIR:=src
DEPS_DIR:=deps
OBJ_DIR:=obj

ifndef TARGET
TARGET:=out
endif

SRCS:=$(shell find $(SRC_DIR)/ -type f -name *.cpp)
DEPS:=$(patsubst $(SRC_DIR)/%.cpp, $(DEPS_DIR)/%.d, $(SRCS))
OBJS:=$(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

CC:=gcc
CFLAGS+=-Wall
LIBS+=-lstdc++

#builds release version in release folder with command 'make release' or just 'make'
.PHONY: release
release: CFLAGS+=$(RELEASE_FLAGS)
release: OBJ_DIR:=obj
release: OUT_DIR=release
release: all

#does the same thing that release target, but with -g flag and in debug folder
.PHONY: debug
debug: OBJ_DIR:=obj-debug
debug: CFLAGS+=$(DEBUG_FLAGS)
debug: OUT_DIR=debug
debug: all

.PHONY: all
all: $(TARGET)

$(TARGET):$(OBJS)
	@mkdir -p $(OUT_DIR)
	@cd $(OUT_DIR);\
	$(CC) $(CFLAGS) -o $@ $(addprefix ../,$^) $(LIBS)

.SECONDEXPANSION:
$(OBJS): $$(patsubst $(OBJ_DIR)/%.o, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@ $(LIBS)

.SECONDEXPANSION:
$(DEPS): $$(patsubst $(DEPS_DIR)/%.d, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -MM -MF $@ \
		-MT $(patsubst $(DEPS_DIR)/%.d, $(OBJ_DIR)/%.o, $@) -MT $@ $(LIBS)

.PHONY: clean
clean:
	@rm -rf debug release obj $(OBJ_DIR) $(DEPS_DIR)

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPS)
endif


