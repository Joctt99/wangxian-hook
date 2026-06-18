/**
 * WangXianHook.dylib v4.0 - Anti-injection bypass for WangXian (忘仙)
 *
 * v4.0: Minimal & safe approach
 *   - SignatureKit/SignatureCheck method hooks (same as v1.0, proven safe)
 *   - UIAlertController intercept (deferred to app launch)
 *   - UIViewController presentVC intercept (deferred to app launch)
 *   - NO NSURLSession hooks (caused crash in v3.0)
 *   - NO PLT rebinding (caused crash in v2.0)
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Replacement IMPs for SignatureKit/SignatureCheck
// ============================================================

static void rep_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static void rep_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static id rep_nil(id self, SEL _cmd) { return nil; }
static id rep_nil_1(id self, SEL _cmd, id a1) { return nil; }
static id rep_dict(id self, SEL _cmd) { return @{}; }
static id rep_dict_1(id self, SEL _cmd, id a1) { return @{}; }
static id rep_md5(id self, SEL _cmd, id a1) { return @"d41d8cd98f00b204e9800998ecf8427e"; }
static id rep_str_1(id self, SEL _cmd, id a1) { return @""; }
static id rep_str_0(id self, SEL _cmd) { return @""; }

// ============================================================
#pragma mark - UIAlertController hook (deferred)
// ============================================================

typedef UIAlertController *(*AlertCreateIMP)(id, SEL, NSString *, NSString *, NSInteger);
static AlertCreateIMP orig_alertControllerWithTitle = NULL;

static UIAlertController *hooked_alertControllerWithTitle(id self, SEL _cmd,
                                                           NSString *title,
                                                           NSString *message,
                                                           NSInteger style) {
    if ([message containsString:@"版本过低"] ||
        [message containsString:@"下载最新版本"] ||
        [message containsString:@"联系客服"] ||
        [message containsString:@"下载最新的版本"] ||
        [title containsString:@"版本过低"]) {
        WXLOG(@"BLOCKED alert: '%@' / '%@'", title, message);
        // Return a real empty alert that won't crash
        return [UIAlertController alertControllerWithTitle:@"" message:@"" preferredStyle:UIAlertControllerStyleAlert];
    }
    return orig_alertControllerWithTitle(self, _cmd, title, message, style);
}

// ============================================================
#pragma mark - UIViewController presentViewController hook (deferred)
// ============================================================

typedef void (*PresentVCIMP)(id, SEL, UIViewController *, BOOL, void (^)(void));
static PresentVCIMP orig_presentViewController = NULL;

static void hooked_presentViewController(id self, SEL _cmd,
                                          UIViewController *vc,
                                          BOOL animated,
                                          void (^completion)(void)) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *msg = alert.message ?: @"";
        NSString *title = alert.title ?: @"";
        if ([msg containsString:@"版本过低"] ||
            [msg containsString:@"下载最新版本"] ||
            [msg containsString:@"联系客服"] ||
            [msg containsString:@"下载最新的版本"] ||
            [title containsString:@"版本过低"]) {
            WXLOG(@"BLOCKED present: '%@' / '%@'", title, msg);
            if (completion) completion();
            return;
        }
    }
    orig_presentViewController(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark - Install hooks
// ============================================================

static BOOL safeHookClassMethod(Class cls, SEL sel, IMP newImp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    method_setImplementation(m, newImp);
    return YES;
}

static void installSignatureHooks(void) {
    int count = 0;
    
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        WXLOG(@"Hooking SignatureKit...");
        count += safeHookClassMethod(sigKit, @selector(load), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(judgeNet), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(judgeAppInfoWithBaseUrl:), (IMP)rep_nil_1);
        count += safeHookClassMethod(sigKit, @selector(generateRequestParams), (IMP)rep_dict);
        count += safeHookClassMethod(sigKit, @selector(handleAppInfoResult:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigKit, @selector(showAlert:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigKit, @selector(exitApplication), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(verifySignatureFromParameters:), (IMP)rep_nil_1);
        count += safeHookClassMethod(sigKit, @selector(createSignatureParams:), (IMP)rep_dict_1);
        count += safeHookClassMethod(sigKit, @selector(calculateMD5WithString:), (IMP)rep_md5);
        count += safeHookClassMethod(sigKit, @selector(stringFromHex:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(generateRandomStringWithLength:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(getCurrentTimestampInBeijingTimezone), (IMP)rep_str_0);
        count += safeHookClassMethod(sigKit, @selector(base64EncodeString:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(base64DecodeString:), (IMP)rep_str_1);
    }
    
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        WXLOG(@"Hooking SignatureCheck...");
        count += safeHookClassMethod(sigChk, @selector(load), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(JudgeApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(GetApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(PostApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(showTipViewEND:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigChk, @selector(exitApplication), (IMP)rep_void);
    }
    
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"Hooking LCNetworking...");
        count += safeHookClassMethod(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)rep_nil);
        count += safeHookClassMethod(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)rep_nil);
    }
    
    WXLOG(@"Signature hooks installed: %d methods", count);
}

static void installUIKitHooks(void) {
    WXLOG(@"Installing UIKit hooks...");
    
    Class alertCls = [UIAlertController class];
    if (alertCls) {
        Method m = class_getClassMethod(alertCls, @selector(alertControllerWithTitle:message:preferredStyle:));
        if (m) {
            orig_alertControllerWithTitle = (AlertCreateIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_alertControllerWithTitle);
            WXLOG(@"[OK] UIAlertController");
        }
    }
    
    Class vcCls = [UIViewController class];
    if (vcCls) {
        Method m = class_getInstanceMethod(vcCls, @selector(presentViewController:animated:completion:));
        if (m) {
            orig_presentViewController = (PresentVCIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_presentViewController);
            WXLOG(@"[OK] UIViewController");
        }
    }
}

// ============================================================
#pragma mark - Constructor (SAFE: only proven-safe operations)
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v4.0");
    WXLOG(@"========================================");
    
    // Phase 1: Signature hooks (same as v1.0, proven safe)
    installSignatureHooks();
    
    // Phase 2: UIKit hooks deferred to app launch (safe timing)
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            WXLOG(@"App launched - installing UIKit hooks");
            installUIKitHooks();
            // Re-apply signature hooks in case classes loaded late
            installSignatureHooks();
        }];
    
    WXLOG(@"Constructor done.");
}
