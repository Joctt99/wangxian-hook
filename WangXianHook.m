/**
 * WangXianHook v36.11 - MINIMAL VERSION
 * Only keep: recv hook (login patch), version fake, jailbreak bypass
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

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES;

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
        DLOG(@"=== WangXianHook v36.11 MINIMAL loaded @ %s %s ===", __DATE__, __TIME__);
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
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
#pragma mark - Recv Hook (login response patch)
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
#pragma mark - Fishhook-style rebind
// ============================================================
struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

extern int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

// ============================================================
#pragma mark - Install Hooks
// ============================================================
static void installAllHooks(void) {
    DLOG(@"[ACT] Installing MINIMAL hooks...");
    
    struct rebinding recv_rebind = {"recv", (void *)hook_recv, (void **)&orig_recv};
    struct rebinding bindings[] = {recv_rebind};
    rebind_symbols(bindings, 1);
    DLOG(@"[INIT] recv: HOOKED via rebind_symbols");
    
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
    
    DLOG(@"[ACT] MINIMAL hooks installed - v36.11");
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