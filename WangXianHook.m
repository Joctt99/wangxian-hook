/**
 * WangXianHook v36.19 - RESTORED from v36.09 FULL VERSION
 * Complete fishhook implementation that WORKED for login
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <sys/stat.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES;
static NSString *g_loginToken = nil;

static void _log(NSString *msg) {
    if (!g_logEnabled || !g_logPath) return;
    @try {
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        NSLog(@"[WXHook] %@", msg);
    } @catch (NSException *e) {}
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        DLOG(@"=== WangXianHook v36.19 FULL RESTORED loaded @ %s %s ===", __DATE__, __TIME__);
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - Fishhook Implementation
// ============================================================
struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static struct rebinding *g_rebindings = NULL;
static size_t g_rebindings_count = 0;

static uint32_t _swap_bytes_32(uint32_t value) {
    return ((value >> 24) & 0xFF) | ((value >> 8) & 0xFF00) | ((value << 8) & 0xFF0000) | ((value << 24) & 0xFF000000);
}

static uint64_t _read_uleb128(const uint8_t **data) {
    uint64_t result = 0;
    uint8_t shift = 0;
    uint8_t byte;
    do {
        byte = **data;
        (*data)++;
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);
    return result;
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    if (!g_rebindings || g_rebindings_count == 0) return;
    
    const struct mach_header *mh = header;
    const struct load_command *lc = (const struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_DYLD_INFO_ONLY) {
            const struct dyld_info_command *dic = (const struct dyld_info_command *)lc;
            
            const uint8_t *bind_info = (const uint8_t *)((uintptr_t)mh + dic->bind_off);
            const uint8_t *lazy_bind_info = (const uint8_t *)((uintptr_t)mh + dic->lazy_bind_off);
            
            uint64_t image_base = (uintptr_t)mh + slide;
            
            // Process regular bindings
            const uint8_t *info = bind_info;
            while (info < bind_info + dic->bind_size) {
                uint64_t it = _read_uleb128(&info);
                uint64_t type = it & 0xF;
                uint64_t seg_offset = _read_uleb128(&info);
                
                if (type == BIND_TYPE_POINTER) {
                    uint64_t symbol_name_offset = _read_uleb128(&info);
                    const char *symbol_name = (const char *)((uintptr_t)mh + symbol_name_offset);
                    
                    uintptr_t *indirect_symbol = (uintptr_t *)(image_base + seg_offset);
                    
                    for (size_t j = 0; j < g_rebindings_count; j++) {
                        if (strcmp(symbol_name, g_rebindings[j].name) == 0) {
                            if (*g_rebindings[j].replaced == NULL) {
                                *g_rebindings[j].replaced = (void *)*indirect_symbol;
                            }
                            *indirect_symbol = (uintptr_t)g_rebindings[j].replacement;
                            DLOG(@"[FISHHOOK] Rebound %s at %p", symbol_name, indirect_symbol);
                            break;
                        }
                    }
                }
                
                while ((info - bind_info) < dic->bind_size && (*info & 0xF) == BIND_OPCODE_DONE) {
                    info++;
                }
            }
            
            // Process lazy bindings
            info = lazy_bind_info;
            while (info < lazy_bind_info + dic->lazy_bind_size) {
                uint64_t it = _read_uleb128(&info);
                uint64_t type = it & 0xF;
                uint64_t seg_offset = _read_uleb128(&info);
                
                if (type == BIND_TYPE_POINTER) {
                    uint64_t symbol_name_offset = _read_uleb128(&info);
                    const char *symbol_name = (const char *)((uintptr_t)mh + symbol_name_offset);
                    
                    uintptr_t *indirect_symbol = (uintptr_t *)(image_base + seg_offset);
                    
                    for (size_t j = 0; j < g_rebindings_count; j++) {
                        if (strcmp(symbol_name, g_rebindings[j].name) == 0) {
                            if (*g_rebindings[j].replaced == NULL) {
                                *g_rebindings[j].replaced = (void *)*indirect_symbol;
                            }
                            *indirect_symbol = (uintptr_t)g_rebindings[j].replacement;
                            DLOG(@"[FISHHOOK] Rebound lazy %s at %p", symbol_name, indirect_symbol);
                            break;
                        }
                    }
                }
            }
            
            return;
        }
        lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }
}

int rebind_symbols(struct rebinding bindings[], size_t bindings_nel) {
    DLOG(@"[FISHHOOK] rebind_symbols called with %zu bindings", bindings_nel);
    
    g_rebindings_count = bindings_nel;
    if (g_rebindings) free(g_rebindings);
    g_rebindings = (struct rebinding *)malloc(bindings_nel * sizeof(struct rebinding));
    memcpy(g_rebindings, bindings, bindings_nel * sizeof(struct rebinding));
    
    for (unsigned int i = 0; i < _dyld_get_image_count(); i++) {
        _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    
    return 0;
}

// ============================================================
#pragma mark - Version Fake (UIDevice APEX)
// ============================================================
static NSString *(*orig_APEX_currentVersion)(id, SEL) = NULL;
static BOOL (*orig_APEX_isJailbroken)(id, SEL) = NULL;

static NSString *hook_APEX_currentVersion(id self, SEL _cmd) {
    NSString *orig = orig_APEX_currentVersion ? orig_APEX_currentVersion(self, _cmd) : @"7.6.2";
    NSString *fake = @"7.7.0";
    if (![orig isEqualToString:fake]) {
        DLOG(@"[VER-FAKE] currentVersion: %@ -> %@", orig, fake);
    }
    return fake;
}

static BOOL hook_APEX_isJailbroken(id self, SEL _cmd) {
    DLOG(@"[JAIL-FAKE] isJailbroken called, returning NO");
    return NO;
}

// ============================================================
#pragma mark - Recv Hook
// ============================================================
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;

static ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags) {
    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    if (ret <= 0) return ret;
    
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getpeername(sockfd, (struct sockaddr*)&addr, &addrlen) == 0) {
        int port = ntohs(addr.sin_port);
        
        if (port == 5678 && ret >= 12) {
            unsigned char *p = (unsigned char *)buf;
            uint32_t cmd = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
            
            if (cmd == 0x802EE120 && ret >= 14) {
                unsigned char status = p[12];
                unsigned char tokenLen = p[13];
                if (status == 0x00 && tokenLen > 0 && ret >= 14 + tokenLen) {
                    NSString *token = [[NSString alloc] initWithBytes:p + 14 length:tokenLen encoding:NSUTF8StringEncoding];
                    if (token) {
                        g_loginToken = [token copy];
                        DLOG(@"[TOKEN-EXTRACT] 0x802EE120 token: %@ (len=%u)", g_loginToken, tokenLen);
                    }
                }
            }
            
            if (cmd == 0x802EE121 && ret >= 90) {
                const unsigned char *errMsg = (const unsigned char *)"\xE5\xBD\x93\xE5\x89\x8D\xE7\x89\x88\xE6\x9C\xAC\xE8\xBF\x87\xE4\xBD\x8E";
                BOOL hasError = NO;
                for (ssize_t i = 0; i <= ret - 12; i++) {
                    if (memcmp(p + i, errMsg, 12) == 0) {
                        hasError = YES;
                        break;
                    }
                }
                if (hasError) {
                    p[12] = 0x00;
                    DLOG(@"[PROTO-R-PATCH] 0x802EE121: patched error status to 0x00");
                }
            }
        }
    }
    
    return ret;
}

// ============================================================
#pragma mark - Install Hooks
// ============================================================
static void installAllHooks(void) {
    DLOG(@"[ACT] Installing hooks...");
    
    struct rebinding recv_rebind = {"recv", (void*)hook_recv, (void**)&orig_recv};
    struct rebinding bindings[] = {recv_rebind};
    rebind_symbols(bindings, 1);
    DLOG(@"[INIT] recv: HOOKED via fishhook");
    
    Class uidCls = [UIDevice class];
    
    Method m = class_getClassMethod(uidCls, @selector(currentVersion));
    if (m) {
        orig_APEX_currentVersion = (NSString *(*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_APEX_currentVersion);
        DLOG(@"[INIT] UIDevice.currentVersion: HOOKED (fake 7.7.0)");
    }
    
    m = class_getClassMethod(uidCls, @selector(isJailbroken));
    if (m) {
        orig_APEX_isJailbroken = (BOOL(*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_APEX_isJailbroken);
        DLOG(@"[INIT] UIDevice.isJailbroken: HOOKED (return NO)");
    }
    
    DLOG(@"[ACT] Hooks installed - v36.19");
}

// ============================================================
#pragma mark - Entry Point
// ============================================================
static void entry(void) {
    log_init();
    installAllHooks();
}

__attribute__((constructor)) static void initializer(void) {
    entry();
}