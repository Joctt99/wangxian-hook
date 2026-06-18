/**
 * WangXianHook.dylib v7.0
 *
 * Strategy:
 *   - DO NOT hook +load (triggers anti-tamper)
 *   - Hook exitApplication/showAlert (prevent exit/alert from dylibs)
 *   - Hook UIAlertController (block "版本过低" alert from main binary)
 *   - Hook UIViewController presentVC (block alert presentation)
 *   - ALL UIKit hooks deferred to after app launches
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Signature action blockers
// ============================================================

static void block_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED [%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

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

static int installSignatureHooks(void) {
    int count = 0;
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        count += tryHook(sigChk, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigChk, @selector(showTipViewEND:), (IMP)block_void_1);
    }
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        count += tryHook(sigKit, @selector(exitApplication), (IMP)block_void);
        count += tryHook(sigKit, @selector(showAlert:), (IMP)block_void_1);
    }
    return count;
}

// ============================================================
#pragma mark - UIAlertController blocker (deferred)
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
        return [UIAlertController alertControllerWithTitle:@"" message:@"" preferredStyle:UIAlertControllerStyleAlert];
    }
    return orig_alertControllerWithTitle(self, _cmd, title, message, style);
}

// ============================================================
#pragma mark - UIViewController presentVC blocker (deferred)
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
            WXLOG(@"[OK] UIViewController presentVC");
        }
    }
}

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"WangXianHook v7.0 starting");
    
    // Immediate: signature action blockers (safe, no +load hook)
    int count = installSignatureHooks();
    WXLOG(@"Signature hooks: %d", count);
    
    // Deferred: UIKit hooks after app launches
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            WXLOG(@"App launched");
            installUIKitHooks();
            installSignatureHooks(); // retry
        }];
    
    // Extra retry
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        int c = installSignatureHooks();
        WXLOG(@"1s retry: %d", c);
        installUIKitHooks();
    });
}
