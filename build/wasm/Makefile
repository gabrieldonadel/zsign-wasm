EMSDK_ENV ?=
OPENSSL_WASM ?= ../../../openssl-wasm/precompiled

ifneq ($(strip $(EMSDK_ENV)),)
EMXX := bash -lc '. "$(EMSDK_ENV)" >/dev/null 2>&1 && exec em++ "$$@"' --
else
EMXX := em++
endif
CXXFLAGS = -std=c++17 -O3 -Wno-unused-result
CXXFLAGS += -I../../native -I../../native/common
CXXFLAGS += -I$(OPENSSL_WASM)/include

LDFLAGS = $(OPENSSL_WASM)/lib/libcrypto.a $(OPENSSL_WASM)/lib/libssl.a
LDFLAGS += -sERROR_ON_UNDEFINED_SYMBOLS=1
LDFLAGS += -sALLOW_MEMORY_GROWTH=1
LDFLAGS += -sENVIRONMENT=web,worker,node
LDFLAGS += -sFORCE_FILESYSTEM=1
LDFLAGS += -sMODULARIZE=1
LDFLAGS += -sEXPORT_NAME=createZsignModule
LDFLAGS += -sEXPORT_ALL=1
LDFLAGS += --post-js ../../native/wasm_post.js

OBJDIR = .build
BINDIR = ../../binary
TARGET = $(BINDIR)/zsign-wasm.js
CLIENT = ZsignWasmClient.js
CLIENT_OUT = $(BINDIR)/ZsignWasmClient.js
SINGLE = $(BINDIR)/zsign-wasm.min.js
PACKER = pack-single.cjs

SRCS = ../../native/archo.cpp
SRCS += ../../native/macho.cpp
SRCS += ../../native/openssl.cpp
SRCS += ../../native/signing.cpp
SRCS += ../../native/bundle.cpp
SRCS += ../../native/zsign_export.cpp
SRCS += ../../native/common/base64.cpp
SRCS += ../../native/common/fs.cpp
SRCS += ../../native/common/json.cpp
SRCS += ../../native/common/log.cpp
SRCS += ../../native/common/sha.cpp
SRCS += ../../native/common/timer.cpp
SRCS += ../../native/common/util.cpp
SRCS += ../../native/common/wasm_compat.cpp

LDFLAGS += -sEXPORTED_FUNCTIONS='["_zsign_version","_zsign_set_log_level","_zsign_sign_macho","_zsign_sign_bundle","_zsign_sign_bundle_multi","_zsign_sign_macho_mem","_zsign_free_buffer","_malloc","_free"]'
LDFLAGS += -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","lengthBytesUTF8","HEAPU8","HEAPU32"]'

OBJS = $(SRCS:../../native/%.cpp=$(OBJDIR)/%.o)

all: $(TARGET)
	@echo ">>> Build OK -> $(abspath $(TARGET))"

bundle: $(TARGET) $(SINGLE)
	@mkdir -p $(BINDIR)
	@cp -f $(CLIENT) $(CLIENT_OUT)
	@echo ">>> Bundle OK -> $(abspath $(BINDIR))"

$(SINGLE): $(TARGET) $(TARGET:.js=.wasm) $(CLIENT) $(PACKER)
	@mkdir -p $(BINDIR)
	@node $(PACKER) $(TARGET) $(TARGET:.js=.wasm) $(CLIENT) $(SINGLE)
	@echo ">>> Single File OK -> $(abspath $(SINGLE))"

$(TARGET): $(OBJS)
	@mkdir -p $(BINDIR)
	@$(EMXX) $(OBJS) $(LDFLAGS) -o $(TARGET)

$(OBJDIR)/%.o: ../../native/%.cpp
	@mkdir -p $(dir $@)
	@$(EMXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET) $(TARGET:.js=.wasm) $(CLIENT_OUT) $(SINGLE)
	@echo ">>> Clean OK"

.PHONY: all bundle clean
