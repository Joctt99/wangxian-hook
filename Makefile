# WangXianHook Makefile - Using OFFICIAL fishhook (C++ support)
# Builds WangXianHook.dylib for iOS arm64

TARGET = WangXianHook.dylib
SOURCE = WangXianHook.m
PROTO = ProtocolPatcher.m
FISHHOOK = fishhook.c

SDK_PATH  = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC        = $(shell xcrun --sdk iphoneos --find clang)
ARCH      = arm64
MIN_IOS   = 12.0

CFLAGS  = -arch $(ARCH)
CFLAGS += -isysroot $(SDK_PATH)
CFLAGS += -miphoneos-version-min=$(MIN_IOS)
CFLAGS += -framework Foundation
CFLAGS += -framework UIKit
CFLAGS += -framework CoreFoundation
CFLAGS += -framework Security
CFLAGS += -framework CoreGraphics
CFLAGS += -lobjc
CFLAGS += -lz
CFLAGS += -lc++
CFLAGS += -dynamiclib
CFLAGS += -O0
CFLAGS += -fobjc-arc
CFLAGS += -fno-exceptions
CFLAGS += -fno-rtti
CFLAGS += -install_name @executable_path/Frameworks/WangXianHook.dylib

all: clean $(TARGET)

$(TARGET): $(SOURCE) $(PROTO) $(FISHHOOK)
	@echo "=== Source verification ==="
	@grep -c "FIX53C" $(SOURCE) || echo "WARNING: FIX53C not found in source!"
	@grep -c "LOG_SIZE_LIMIT" $(SOURCE) || echo "WARNING: LOG_SIZE_LIMIT macro not found in source!"
	@grep -c "FIX39" $(SOURCE) || echo "WARNING: FIX39 not found in source!"
	@grep -c "0 && fffWhich" $(SOURCE) || echo "WARNING: 0 and fffWhich not found!"
	@echo "=== Building ==="
	$(CC) $(CFLAGS) -fexceptions -frtti -x objective-c++ $(SOURCE) -x objective-c++ $(PROTO) -x c $(FISHHOOK) -o $(TARGET)
	@echo "Built: $(TARGET)"
	@echo "=== Binary verification ==="
	@strings $(TARGET) | grep -c "FIX53C" || echo "WARNING: FIX53C not in binary!"
	@strings $(TARGET) | grep -c "LOG_MAX_KB" || echo "WARNING: LOG_MAX_KB not in binary (macro not referenced?)"
	@strings $(TARGET) | grep -c "FIX39" || echo "WARNING: FIX39 not in binary!"
	@ls -la $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean