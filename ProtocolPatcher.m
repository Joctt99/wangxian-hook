#import "ProtocolPatcher.h"
#import <CoreFoundation/CoreFoundation.h> // For byte swapping

// Assuming DLOG is defined elsewhere, if not, it should be defined here or replaced with NSLog
#ifndef DLOG
#define DLOG(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#endif

@implementation ProtocolPatcher

+ (NSData *)patchServerResponse:(NSData *)response {
    if (!response || response.length < 12) { // Assuming at least pktLen(4) + cmd(4) + errorCode(4)
        return response;
    }

    NSMutableData *mutableResponse = [response mutableCopy];
    uint32_t cmd_be; // Big-endian command
    uint32_t errorCode_be; // Big-endian error code

    // Read cmd and errorCode in big-endian format
    // Assuming cmd is at offset 4 and errorCode is at offset 8
    [mutableResponse getBytes:&cmd_be range:NSMakeRange(4, 4)];
    [mutableResponse getBytes:&errorCode_be range:NSMakeRange(8, 4)];

    // Convert to host byte order for comparison
    uint32_t cmd_host = CFSwapInt32BigToHost(cmd_be);
    uint32_t errorCode_host = CFSwapInt32BigToHost(errorCode_be);

    if (errorCode_host != 0) {
        // Modify errorCode to 0 (in big-endian for network)
        uint32_t patchedErrorCode_be = CFSwapInt32HostToBig(0);
        [mutableResponse replaceBytesInRange:NSMakeRange(8, 4) withBytes:&patchedErrorCode_be];

        // Clear errorMessage: Assuming errorMessage starts immediately after errorCode (offset 12)
        // and extends to the end of the packet. Fill with zeros.
        NSRange errorMessageRange = NSMakeRange(12, mutableResponse.length - 12);
        if (errorMessageRange.length > 0) {
            void *zeroBytes = calloc(1, errorMessageRange.length);
            [mutableResponse replaceBytesInRange:errorMessageRange withBytes:zeroBytes];
            free(zeroBytes);
        }
        DLOG(@"[PROTO-PATCH] Patched cmd=0x%08X, errorCode from 0x%08X to 0x00000000. Cleared error message.", cmd_host, errorCode_host);
    }

    return mutableResponse;
}

@end
