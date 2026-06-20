# iOS build for zsign — static library + xcframework
#
# Produces a self-contained C-ABI static library (libzsign.a, with OpenSSL
# merged in) for:
#   - iphoneos        (arm64)            device
#   - iphonesimulator (arm64 + x86_64)   simulator
# and packages both slices into dist/zsign.xcframework.
#
# Requirements:
#   - Xcode + command line tools (xcrun, clang++, libtool, xcodebuild)
#   - Prebuilt OpenSSL static libs for iOS (libcrypto.a, libssl.a).
#     See README.md for where to get them.
#
# Usage:
#   make OPENSSL_DEVICE=/path/to/openssl/ios-arm64 \
#        OPENSSL_SIM=/path/to/openssl/ios-sim
#
# Each OpenSSL dir must contain include/ (openssl headers) and
# lib/{libcrypto.a,libssl.a} built for that slice. If your simulator libs live
# in the same tree, just pass OPENSSL_DEVICE and OPENSSL_SIM will default to it
# (only correct if that build is a fat/simulator-compatible archive).

NATIVE    := ../../native
BUILD     := .build
DIST      := dist
LIBNAME   := libzsign.a
FRAMEWORK := $(DIST)/zsign.xcframework
HEADERS   := $(BUILD)/include

MIN_IOS   ?= 13.0

OPENSSL_DEVICE ?=
OPENSSL_SIM    ?= $(OPENSSL_DEVICE)

# Source set mirrors the wasm build: no CLI main (zsign.cpp) and no archive.cpp
# (IPA zip/unzip is the host app's responsibility, exactly as the JS resigner
# does it for wasm). OpenSSL is the only third-party dependency.
SRCS := \
  archo.cpp \
  macho.cpp \
  openssl.cpp \
  signing.cpp \
  bundle.cpp \
  zsign_export.cpp \
  common/base64.cpp \
  common/fs.cpp \
  common/json.cpp \
  common/log.cpp \
  common/sha.cpp \
  common/timer.cpp \
  common/util.cpp \
  common/wasm_compat.cpp

CXXFLAGS := -std=c++17 -O3 -fvisibility=hidden -Wno-unused-result \
            -I$(NATIVE) -I$(NATIVE)/common

# --- Device slice (arm64) ---------------------------------------------------
DEV_SDK   := iphoneos
DEV_FLAGS := -arch arm64 -mios-version-min=$(MIN_IOS)
DEV_DIR   := $(BUILD)/device
DEV_OBJS  := $(SRCS:%.cpp=$(DEV_DIR)/%.o)

# --- Simulator slice (arm64 + x86_64) --------------------------------------
SIM_SDK   := iphonesimulator
SIM_FLAGS := -arch arm64 -arch x86_64 -mios-simulator-version-min=$(MIN_IOS)
SIM_DIR   := $(BUILD)/sim
SIM_OBJS  := $(SRCS:%.cpp=$(SIM_DIR)/%.o)

.PHONY: all clean check-openssl
all: $(FRAMEWORK)
	@echo ">>> Build OK -> $(abspath $(FRAMEWORK))"

check-openssl:
	@test -n "$(OPENSSL_DEVICE)" || { echo "ERROR: set OPENSSL_DEVICE=/path/to/openssl/ios-arm64 (must contain include/ and lib/)"; exit 1; }
	@test -n "$(OPENSSL_SIM)"    || { echo "ERROR: set OPENSSL_SIM=/path/to/openssl/ios-sim (must contain include/ and lib/)"; exit 1; }

# Compile rules (clang emits a fat object directly when several -arch are given)
$(DEV_DIR)/%.o: $(NATIVE)/%.cpp | check-openssl
	@mkdir -p $(dir $@)
	xcrun --sdk $(DEV_SDK) clang++ $(CXXFLAGS) $(DEV_FLAGS) -I$(OPENSSL_DEVICE)/include -c $< -o $@

$(SIM_DIR)/%.o: $(NATIVE)/%.cpp | check-openssl
	@mkdir -p $(dir $@)
	xcrun --sdk $(SIM_SDK) clang++ $(CXXFLAGS) $(SIM_FLAGS) -I$(OPENSSL_SIM)/include -c $< -o $@

# Merge our objects + OpenSSL into one static archive per slice.
$(DEV_DIR)/$(LIBNAME): $(DEV_OBJS)
	xcrun --sdk $(DEV_SDK) libtool -static -o $@ $(DEV_OBJS) \
	  $(OPENSSL_DEVICE)/lib/libssl.a $(OPENSSL_DEVICE)/lib/libcrypto.a

$(SIM_DIR)/$(LIBNAME): $(SIM_OBJS)
	xcrun --sdk $(SIM_SDK) libtool -static -o $@ $(SIM_OBJS) \
	  $(OPENSSL_SIM)/lib/libssl.a $(OPENSSL_SIM)/lib/libcrypto.a

# Public headers exposed by the xcframework. Single source of truth is
# native/zsign_export.h, copied here as zsign.h alongside the module map.
$(HEADERS): module.modulemap $(NATIVE)/zsign_export.h
	@rm -rf $(HEADERS)
	@mkdir -p $(HEADERS)
	cp $(NATIVE)/zsign_export.h $(HEADERS)/zsign.h
	cp module.modulemap $(HEADERS)/module.modulemap

$(FRAMEWORK): $(DEV_DIR)/$(LIBNAME) $(SIM_DIR)/$(LIBNAME) $(HEADERS)
	@rm -rf $(FRAMEWORK)
	@mkdir -p $(DIST)
	xcodebuild -create-xcframework \
	  -library $(DEV_DIR)/$(LIBNAME) -headers $(HEADERS) \
	  -library $(SIM_DIR)/$(LIBNAME) -headers $(HEADERS) \
	  -output $(FRAMEWORK)

clean:
	rm -rf $(BUILD) $(DIST)
	@echo ">>> Clean OK"
