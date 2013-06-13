include config.mk

ifndef TARGET
TARGET:=out
endif

ifeq "$(MAKECMDGOALS)" "debug"
CFLAGS+=$(DEBUG_FLAGS)
OUT_DIR:=debug
else
CFLAGS+=$(RELEASE_FLAGS)
OUT_DIR:=release
endif


SRC_DIR:=src
OBJ_DIR:=$(OUT_DIR)/obj
DEP_DIR:=$(OUT_DIR)/dep

SRCS:=$(shell find $(SRC_DIR)/ -type f -name *.cpp)
DEPS:=$(patsubst $(SRC_DIR)/%.cpp, $(DEP_DIR)/%.d, $(SRCS))
OBJS:=$(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))
CC:=g++

.PHONY: release debug clean

release: $(TARGET)
debug: $(TARGET)

$(TARGET):$(OBJS)
	@mkdir -p $(OUT_DIR)
	@cd $(OUT_DIR);\
	$(CC) $(CFLAGS) -o $@ $(addprefix ../,$^) $(LIBS)

.SECONDEXPANSION:
$(OBJS): $$(patsubst $(OBJ_DIR)/%.o, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@ $(LIBS)

.SECONDEXPANSION:
$(DEPS): $$(patsubst $(DEP_DIR)/%.d, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) $< -MM -MF $@ \
		-MT $(patsubst $(DEP_DIR)/%.d, $(OBJ_DIR)/%.o, $@) -MT $@

clean:
	@rm -rf debug release

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPS)
endif


