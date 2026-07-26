/**
 * WangXianHook v36.16 - NO RECV HOOK
 * Only keep: version fake + jailbreak bypass
 * Remove: all socket hooks (recv, send, etc.)
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>

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
        DLOG(@"=== WangXianHook v36.16 NO RECV HOOK loaded @ %s %s ===", __DATE__, __TIME__);
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
#pragma mark - Install Hooks
// ============================================================
static void installAllHooks(void) {
    DLOG(@"[ACT] Installing MINIMAL hooks...");
    
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
    
    DLOG(@"[ACT] MINIMAL hooks installed - v36.16");
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