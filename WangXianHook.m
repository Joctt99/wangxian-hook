/**
 * WangXianHook.dylib v6.0 - Smart signature bypass
 *
 * Key insight: DO NOT hook +load (triggers anti-tamper detection)
 * Instead: let the check run, but BLOCK the exit/alert actions.
 *
 * Only hooks:
 *   - exitApplication (prevent forced quit)
 *   - showAlert: (prevent error popup)
 *   - showTipViewEND: (prevent tip view)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// Block: prevent exit
static void block_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED [%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

// Block: prevent alert with 1 arg
static void block_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED [%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static BOOL tryHook(Class cls, SEL sel, IMP imp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    method_setImplementation(m, imp);
    return YES;
}

static int installHooks(void) {
    int count = 0;
    
    // SignatureCheck - ONLY action methods, NOT +load
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        count += tryHook(sigChk, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigChk, @selector(showTipViewEND:), (IMP)block_void_1);
    }
    
    // SignatureKit - ONLY action methods, NOT +load
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        count += tryHook(sigKit, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigKit, @selector(showAlert:), (IMP)block_void_1);
    }
    
    return count;
}

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"WangXianHook v6.0 starting");
    
    int count = installHooks();
    WXLOG(@"Initial hooks: %d", count);
    
    // Retry after delays (classes might load later)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        int c = installHooks();
        WXLOG(@"0.5s retry: %d hooks", c);
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        int c = installHooks();
        WXLOG(@"2s retry: %d hooks", c);
    });
}
