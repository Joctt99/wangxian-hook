# WangXianHook Makefile
# Builds WangXianHook.dylib for iOS arm64

TARGET = WangXianHook.dylib
SOURCE = WangXianHook.m

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
CFLAGS += -framework CommonCrypto
CFLAGS += -lobjc
CFLAGS += -lz
CFLAGS += -dynamiclib
CFLAGS += -O2
CFLAGS += -fobjc-arc

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)
	@echo "Built: $(TARGET)"
	@ls -la $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
