/**
 * WangXianHook.dylib v8.0
 *
 * Based on v6.0 (proven safe, no crash):
 *   - NO +load hook (avoids anti-tamper)
 *   - Blocks exitApplication, showAlert:, showTipViewEND:
 *
 * New in v8.0:
 *   - Also blocks JudgeApp/GetApp/PostApp (prevent sending signature data to server)
 *   - Also blocks judgeNet/handleAppInfoResult (prevent processing verification results)
 *   - This way the server never receives the modified signature info
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Replacement IMPs
// ============================================================

static void block_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED [%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static void block_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED [%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

// Return nil for methods that return objects
static id block_nil(id self, SEL _cmd) { return nil; }
static id block_nil_1(id self, SEL _cmd, id a1) { return nil; }

// Return empty dict for methods that return dictionaries
static id block_dict(id self, SEL _cmd) { return @{}; }
static id block_dict_1(id self, SEL _cmd, id a1) { return @{}; }

static BOOL tryHook(Class cls, SEL sel, IMP imp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    method_setImplementation(m, imp);
    return YES;
}

static int installHooks(void) {
    int count = 0;
    
    // SignatureCheck - block ALL methods except +load
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        WXLOG(@"Found SignatureCheck");
        count += tryHook(sigChk, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigChk, @selector(showTipViewEND:), (IMP)block_void_1);
        count += tryHook(sigChk, @selector(JudgeApp), (IMP)block_void);
        count += tryHook(sigChk, @selector(GetApp), (IMP)block_void);
        count += tryHook(sigChk, @selector(PostApp), (IMP)block_void);
    }
    
    // SignatureKit - block ALL methods except +load
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        WXLOG(@"Found SignatureKit");
        count += tryHook(sigKit, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigKit, @selector(showAlert:), (IMP)block_void_1);
        count += tryHook(sigKit, @selector(judgeNet), (IMP)block_void);
        count += tryHook(sigKit, @selector(judgeAppInfoWithBaseUrl:), (IMP)block_nil_1);
        count += tryHook(sigKit, @selector(handleAppInfoResult:), (IMP)block_void_1);
        count += tryHook(sigKit, @selector(verifySignatureFromParameters:), (IMP)block_nil_1);
        count += tryHook(sigKit, @selector(generateRequestParams), (IMP)block_dict);
        count += tryHook(sigKit, @selector(createSignatureParams:), (IMP)block_dict_1);
    }
    
    // LCNetworking - block network requests
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"Found LCNetworking");
        count += tryHook(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)block_nil);
        count += tryHook(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)block_nil);
    }
    
    return count;
}

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v8.0");
    WXLOG(@"========================================");
    
    // Immediate hooks
    int count = installHooks();
    WXLOG(@"Installed %d hooks", count);
    
    // Retry (classes might load later)
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
