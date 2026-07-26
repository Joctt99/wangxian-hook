#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>

#define DLOG(fmt, ...) do { \
    NSLog(@"[WX] " fmt, ##__VA_ARGS__); \
} while (0)

static NSString *fakeVersion = @"7.7.0";

#pragma mark - UIDevice Hooks

static NSString *hook_currentVersion(id self, SEL _cmd) {
    DLOG(@"[VER-FAKE] currentVersion -> '%@'", fakeVersion);
    return fakeVersion;
}

static BOOL hook_isJailbroken(id self, SEL _cmd) {
    DLOG(@"[JAIL-FAKE] isJailbroken -> NO");
    return NO;
}

#pragma mark - Recv Hook (for protocol patching only)

typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
static RecvFunc orig_recv = NULL;

static void patchLoginResponse(unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    
    if (cmd == 0x802EE121) {
        uint32_t status = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
        if (status != 0) {
            buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00;
            DLOG(@"[PROTO-PATCH] Login response patched: status %u -> 0", status);
        }
    }
}

static ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv) return -1;
    
    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    
    if (ret > 0) {
        patchLoginResponse((unsigned char *)buf, ret);
    }
    
    return ret;
}

#pragma mark - SignatureKit Hooks

typedef void (*ShowAlertIMP)(id, SEL, NSString *);
static ShowAlertIMP orig_showAlert = NULL;

static void hook_showAlert(id self, SEL _cmd, NSString *msg) {
    DLOG(@"[SK] showAlert BLOCKED: '%@'", msg);
}

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;

static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

#pragma mark - Fishhook

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

extern int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#pragma mark - Entry

__attribute__((constructor))
static void entry() {
    DLOG(@"=== WangXianHook v36.17 MINIMAL (v36.16 restored) ===");
    
    @autoreleasepool {
        DLOG(@"[ACT] Installing MINIMAL hooks...");
        
        Class deviceCls = [UIDevice class];
        if (deviceCls) {
            Method m = class_getInstanceMethod(deviceCls, @selector(currentVersion));
            if (m) {
                method_setImplementation(m, (IMP)hook_currentVersion);
                DLOG(@"[INIT] UIDevice.currentVersion: HOOKED (fake 7.7.0)");
            } else {
                class_addMethod(deviceCls, @selector(currentVersion), (IMP)hook_currentVersion, "@@:");
                DLOG(@"[INIT] UIDevice.currentVersion: ADDED (fake 7.7.0)");
            }
            
            m = class_getInstanceMethod(deviceCls, @selector(isJailbroken));
            if (m) {
                method_setImplementation(m, (IMP)hook_isJailbroken);
                DLOG(@"[INIT] UIDevice.isJailbroken: HOOKED (return NO)");
            } else {
                class_addMethod(deviceCls, @selector(isJailbroken), (IMP)hook_isJailbroken, "B@:");
                DLOG(@"[INIT] UIDevice.isJailbroken: ADDED (return NO)");
            }
        }
        
        struct rebinding recv_rebinding = {"recv", (void *)hook_recv, (void **)&orig_recv};
        rebind_symbols(&recv_rebinding, 1);
        if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
        DLOG(@"[INIT] recv hook: INSTALLED (protocol patching only)");
        
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            Method m = class_getClassMethod(skCls, @selector(showAlert:));
            if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SK.showAlert: HOOKED"); }
            m = class_getClassMethod(skCls, @selector(exitApplication));
            if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SK.exitApplication: HOOKED"); }
        }
        
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            Method m = class_getClassMethod(scCls, @selector(exitApplication));
            if (m) { method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SC.exitApplication: HOOKED"); }
        }
        
        Class apsCls = NSClassFromString(@"APSecurity");
        if (apsCls) {
            DLOG(@"[INIT] APSecurity class FOUND - hooking security methods");
            
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(apsCls, &methodCount);
            if (methods) {
                for (unsigned int i = 0; i < methodCount; i++) {
                    SEL sel = method_getName(methods[i]);
                    NSString *selStr = NSStringFromSelector(sel);
                    if ([selStr containsString:@"showAlert"] || [selStr containsString:@"alert"] ||
                        [selStr containsString:@"exit"] || [selStr containsString:@"crash"]) {
                        method_setImplementation(methods[i], (IMP)hook_showAlert);
                        DLOG(@"[INIT] APSecurity.%@: HOOKED", selStr);
                    }
                }
                free(methods);
            }
            
            Method m = class_getInstanceMethod(apsCls, @selector(isJailbroken));
            if (m) { method_setImplementation(m, (IMP)hook_isJailbroken); DLOG(@"[INIT] APSecurity.isJailbroken: HOOKED"); }
            m = class_getInstanceMethod(apsCls, @selector(checkSecurity));
            if (m) { class_replaceMethod(apsCls, @selector(checkSecurity), (IMP)hook_isJailbroken, "B@:"); DLOG(@"[INIT] APSecurity.checkSecurity: HOOKED"); }
        }
        
        DLOG(@"[ACT] MINIMAL hooks installed - v36.17");
    }
}