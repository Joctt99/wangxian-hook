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
	@grep -c "FIX53L" $(SOURCE) || echo "WARNING: FIX53L not found in source!"
	@grep -c "FIX53L-REENC" $(SOURCE) || echo "WARNING: FIX53L-REENC not found!"
	@grep -c "newPkt\[12\]=p\[12\]" $(SOURCE) || echo "WARNING: fmtFlag copy from original not found!"
	@grep -c "g_l4_safe_fallback = NO;" $(SOURCE) || echo "WARNING: g_l4_safe_fallback reset not found!"
	@grep -c "verifyFlag" $(SOURCE) || echo "WARNING: flag reset verification not found!"
	@grep -c "dmGenericDelta" $(SOURCE) || echo "WARNING: dmGenericDelta (generic fallback) not found!"
	@grep -c "iPhone " $(SOURCE) || echo "WARNING: iPhone prefix fallback not found!"
	@grep -c "iPad" $(SOURCE) || echo "WARNING: iPad fallback not found!"
	@grep -c "Apple Inc. Apple A" $(SOURCE) || echo "WARNING: GPU prefix fallback not found!"
	@grep -c "FIX53G-DM-GENERIC" $(SOURCE) || echo "WARNING: FIX53G-DM-GENERIC not found!"
	@grep -c "FIX53H-CH-RELAX" $(SOURCE) || echo "WARNING: FIX53H bounded-check relax not found!"
	@grep -c "g_l4_safe_fallback" $(SOURCE) || echo "WARNING: g_l4_safe_fallback (SAFE FALLBACK flag) not found!"
	@grep -c "FIX53I-REENC" $(SOURCE) || echo "WARNING: FIX53I-REENC not found!"
	@grep -c "fffWhich == 1 || fffWhich == 2" $(SOURCE) || echo "WARNING: FIX53J open block not found!"
	@grep -c "wxhook_nolimit" $(SOURCE) || echo "WARNING: wxhook_nolimit not found!"
	@grep -c "FIX39" $(SOURCE) || echo "WARNING: FIX39 not found in source!"
	@echo "=== Building ==="
	$(CC) $(CFLAGS) -fexceptions -frtti -x objective-c++ $(SOURCE) -x objective-c++ $(PROTO) -x c $(FISHHOOK) -o $(TARGET)
	@echo "Built: $(TARGET)"
	@echo "=== Binary verification ==="
	@strings $(TARGET) | grep -c "FIX53L" || echo "WARNING: FIX53L not in binary!"
	@strings $(TARGET) | grep -c "FIX53L-REENC" || echo "WARNING: FIX53L-REENC not in binary!"
	@strings $(TARGET) | grep -c "newPkt\[12\]=p\[12\]" || echo "WARNING: fmtFlag copy not in binary!"
	@strings $(TARGET) | grep -c "NOT hardcoded 0x0001" || echo "WARNING: fmtFlag comment not in binary!"
	@strings $(TARGET) | grep -c "dmGenericDelta" || echo "WARNING: dmGenericDelta not in binary!"
	@strings $(TARGET) | grep -c "FIX53H-CH-RELAX" || echo "WARNING: FIX53H bounded checks not in binary!"
	@strings $(TARGET) | grep -c "FIX53I-REENC" || echo "WARNING: FIX53I-REENC not in binary!"
	@strings $(TARGET) | grep -c "fffWhich == 1 || fffWhich == 2" || echo "WARNING: FIX53J open block not in binary!"
	@strings $(TARGET) | grep -c "FIX39" || echo "WARNING: FIX39 not in binary!"
	@ls -la $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean