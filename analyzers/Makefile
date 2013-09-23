include config.mk

.PHONY: release debug clean

PLUGS:=$(shell find $(SRC_DIR) -maxdepth 1 -type d ! -name ".*" ! -name "utils" ! -name "src" -exec basename {} \;)

SRCS:=$(shell find $(SRC_DIR) -type f -name "*.cpp")
OBJS:=$(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

U_SRCS:=$(shell find $(SRC_DIR)/utils -type f -name "*.cpp")
U_OBJS:=$(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(U_SRCS))

release: $(PLUGS)
debug: $(PLUGS)

$(PLUGS): $(OBJS)
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(shell find $(OBJ_DIR)/$@ -name "*.o") $(U_OBJS) -o $(OUT_DIR)/lib$@.so $(LIBS) 

.SECONDEXPANSION:
$(OBJS): $$(patsubst $(OBJ_DIR)/%.o, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

.SECONDEXPANSION:
$(DEPS): $$(patsubst $(DEP_DIR)/%.d, $(SRC_DIR)/%.cpp, $$@)
	@mkdir -p $(dir $@)
	$(CC) $< -MM -MF $@ -MT $@ -MT $(patsubst $(DEP_DIR)/%.d, $(OBJ_DIR)/%.o, $@)

clean:
	@rm -rf debug release

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPS)
endif
