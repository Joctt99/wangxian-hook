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
	@grep -c "FIX53N" $(SOURCE) || echo "WARNING: FIX53N not found in source!"
	@grep -c "FIX53N-REENC" $(SOURCE) || echo "WARNING: FIX53N-REENC not found!"
	@grep -c "FIX53N-SEND" $(SOURCE) || echo "WARNING: FIX53N-SEND not found!"
	@grep -c "FIX53N-NOPATCH" $(SOURCE) || echo "WARNING: FIX53N-NOPATCH not found!"
	@grep -c "doReencrypt" $(SOURCE) || echo "WARNING: doReencrypt not found!"
	@grep -c "needReencrypt" $(SOURCE) || echo "WARNING: needReencrypt not found!"
	@grep -c "iPhone7Plus" $(SOURCE) || echo "WARNING: iPhone7Plus check not found!"
	@grep -c "g_l4_saved_valid" $(SOURCE) || echo "WARNING: g_l4_saved_valid check not found!"
	@grep -c "newPkt\[12\]=p\[12\]" $(SOURCE) || echo "WARNING: fmtFlag copy from original not found!"
	@grep -c "Apple Inc. Apple A10 GPU" $(SOURCE) || echo "WARNING: GPU check not found!"
	@grep -c "DYanyou0040_MIESHI" $(SOURCE) || echo "WARNING: Channel check not found!"
	@grep -c "dmGenericDelta" $(SOURCE) || echo "WARNING: dmGenericDelta (generic fallback) not found!"
	@grep -c "iPhone " $(SOURCE) || echo "WARNING: iPhone prefix fallback not found!"
	@grep -c "iPad" $(SOURCE) || echo "WARNING: iPad fallback not found!"
	@grep -c "Apple Inc. Apple A" $(SOURCE) || echo "WARNING: GPU prefix fallback not found!"
	@grep -c "FIX53G-DM-GENERIC" $(SOURCE) || echo "WARNING: FIX53G-DM-GENERIC not found!"
	@grep -c "FIX53H-CH-RELAX" $(SOURCE) || echo "WARNING: FIX53H bounded-check relax not found!"
	@grep -c "fffWhich == 1 || fffWhich == 2" $(SOURCE) || echo "WARNING: FIX53J open block not found!"
	@grep -c "wxhook_nolimit" $(SOURCE) || echo "WARNING: wxhook_nolimit not found!"
	@grep -c "FIX39" $(SOURCE) || echo "WARNING: FIX39 not found in source!"
	@echo "=== Building ==="
	$(CC) $(CFLAGS) -fexceptions -frtti -x objective-c++ $(SOURCE) -x objective-c++ $(PROTO) -x c $(FISHHOOK) -o $(TARGET)
	@echo "Built: $(TARGET)"
	@echo "=== Binary verification ==="
	@strings $(TARGET) | grep -c "FIX53N" || echo "WARNING: FIX53N not in binary!"
	@strings $(TARGET) | grep -c "FIX53N-REENC" || echo "WARNING: FIX53N-REENC not in binary!"
	@strings $(TARGET) | grep -c "doReencrypt" || echo "WARNING: doReencrypt not in binary!"
	@strings $(TARGET) | grep -c "iPhone7Plus" || echo "WARNING: iPhone7Plus check not in binary!"
	@strings $(TARGET) | grep -c "FIX53H-CH-RELAX" || echo "WARNING: FIX53H bounded checks not in binary!"
	@strings $(TARGET) | grep -c "fffWhich == 1 || fffWhich == 2" || echo "WARNING: FIX53J open block not in binary!"
	@strings $(TARGET) | grep -c "FIX39" || echo "WARNING: FIX39 not in binary!"
	@ls -la $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean