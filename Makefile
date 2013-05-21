-include config.mk
BUILD_DIR:=build
SRC_DIR:=src
OBJ_DIR:=obj
DEPS_DIR:=deps

ifndef TARGET
TARGET:=out
endif

SRCS:=$(shell find $(SRC_DIR)/ -type f -name *.cpp)
DEPS:=$(patsubst $(SRC_DIR)/%.cpp, $(DEPS_DIR)/%.d, $(SRCS))
OBJS:=$(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

CC:=gcc
CFLAGS+=-Wall
LIBS+=-lstdc++

.PHONY: all
all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

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
	@rm -rf $(BUILD_DIR) $(OBJ_DIR) $(DEPS_DIR)

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPS)
endif

