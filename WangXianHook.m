/**
 * WangXianHook.dylib v3.0 - Anti-injection bypass for WangXian (忘仙)
 *
 * v3.0 fixes:
 *   - Removed dangerous PLT rebinding of exit() (caused crash in constructor)
 *   - Defer ALL UIKit hooks until after UIApplicationDidFinishLaunching
 *   - NSURLSession hooks installed early but safely
 *   - UIAlertController intercept returns proper dummy alert
 *   - UIViewController presentVC only blocks alerts with detection keywords
 *   - Keep SignatureKit/SignatureCheck method hooks as backup
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Replacement IMPs
// ============================================================

static void rep_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static void rep_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static id rep_nil(id self, SEL _cmd) { return nil; }
static id rep_nil_1(id self, SEL _cmd, id a1) { return nil; }
static id rep_nil_2(id self, SEL _cmd, id a1, id a2) { return nil; }
static id rep_dict(id self, SEL _cmd) { return @{}; }
static id rep_dict_1(id self, SEL _cmd, id a1) { return @{}; }
static id rep_md5(id self, SEL _cmd, id a1) { return @"d41d8cd98f00b204e9800998ecf8427e"; }
static id rep_str_1(id self, SEL _cmd, id a1) { return @""; }
static id rep_str_0(id self, SEL _cmd) { return @""; }

// ============================================================
#pragma mark - NSURLSession Hook (early, in constructor)
// ============================================================

static BOOL isVerificationURL(NSString *url) {
    if (!url) return NO;
    return [url containsString:@"9iy.com"] ||
           [url containsString:@"ln_sign_cert"] ||
           [url containsString:@"cert/judgeApp"] ||
           [url containsString:@"cert/postApp"] ||
           [url containsString:@"cert/getApp"] ||
           [url containsString:@"sign_cert"];
}

// Hook: -[NSURLSession dataTaskWithRequest:]
typedef NSURLSessionDataTask *(*DataTaskReqIMP)(id, SEL, NSURLRequest *);
static DataTaskReqIMP orig_dataTaskWithRequest = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    if (isVerificationURL(request.URL.absoluteString)) {
        WXLOG(@"BLOCKED dataTaskWithRequest: %@", request.URL);
        // Don't return nil - create a dummy completed task instead
        NSURLSessionDataTask *dummyTask = nil;
        if (orig_dataTaskWithRequest) {
            // Create a request to a non-existent local URL that will fail silently
            NSURL *localURL = [NSURL URLWithString:@"http://127.0.0.1:1/blocked"];
            NSMutableURLRequest *fakeReq = [NSMutableURLRequest requestWithURL:localURL];
            dummyTask = orig_dataTaskWithRequest(self, _cmd, fakeReq);
        }
        return dummyTask;
    }
    return orig_dataTaskWithRequest ? orig_dataTaskWithRequest(self, _cmd, request) : nil;
}

// Hook: -[NSURLSession dataTaskWithURL:]
typedef NSURLSessionDataTask *(*DataTaskURLIMP)(id, SEL, NSURL *);
static DataTaskURLIMP orig_dataTaskWithURL = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    if (isVerificationURL(url.absoluteString)) {
        WXLOG(@"BLOCKED dataTaskWithURL: %@", url);
        NSURL *localURL = [NSURL URLWithString:@"http://127.0.0.1:1/blocked"];
        return orig_dataTaskWithURL ? orig_dataTaskWithURL(self, _cmd, localURL) : nil;
    }
    return orig_dataTaskWithURL ? orig_dataTaskWithURL(self, _cmd, url) : nil;
}

// Hook: -[NSURLSession dataTaskWithRequest:completionHandler:]
typedef void (^DTaskCompletion)(NSData * _Nullable, NSURLResponse * _Nullable, NSError * _Nullable);
typedef NSURLSessionDataTask *(*DataTaskReqCompIMP)(id, SEL, NSURLRequest *, DTaskCompletion);
static DataTaskReqCompIMP orig_dataTaskWithRequestComp = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithRequestComp(id self, SEL _cmd,
                                                              NSURLRequest *request,
                                                              DTaskCompletion handler) {
    if (isVerificationURL(request.URL.absoluteString)) {
        WXLOG(@"BLOCKED dataTaskWithRequest:completionHandler: %@", request.URL);
        // Call completion with fake success response
        if (handler) {
            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc]
                initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1"
                headerFields:@{@"Content-Type": @"application/json"}];
            NSData *fakeData = [@"{\"code\":0,\"data\":{\"status\":\"pass\"},\"msg\":\"ok\"}"
                                dataUsingEncoding:NSUTF8StringEncoding];
            handler(fakeData, fakeResp, nil);
        }
        // Return a dummy task (already completed)
        NSURL *localURL = [NSURL URLWithString:@"http://127.0.0.1:1/blocked"];
        NSMutableURLRequest *fakeReq = [NSMutableURLRequest requestWithURL:localURL];
        return orig_dataTaskWithRequestComp ?
            orig_dataTaskWithRequestComp(self, _cmd, fakeReq, ^(NSData *d, NSURLResponse *r, NSError *e){}) :
            nil;
    }
    return orig_dataTaskWithRequestComp ?
        orig_dataTaskWithRequestComp(self, _cmd, request, handler) : nil;
}

// Hook: -[NSURLSession dataTaskWithURL:completionHandler:]
typedef NSURLSessionDataTask *(*DataTaskURLCompIMP)(id, SEL, NSURL *, DTaskCompletion);
static DataTaskURLCompIMP orig_dataTaskWithURLComp = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithURLComp(id self, SEL _cmd,
                                                          NSURL *url,
                                                          DTaskCompletion handler) {
    if (isVerificationURL(url.absoluteString)) {
        WXLOG(@"BLOCKED dataTaskWithURL:completionHandler: %@", url);
        if (handler) {
            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc]
                initWithURL:url statusCode:200 HTTPVersion:@"HTTP/1.1"
                headerFields:@{@"Content-Type": @"application/json"}];
            NSData *fakeData = [@"{\"code\":0,\"data\":{\"status\":\"pass\"},\"msg\":\"ok\"}"
                                dataUsingEncoding:NSUTF8StringEncoding];
            handler(fakeData, fakeResp, nil);
        }
        NSURL *localURL = [NSURL URLWithString:@"http://127.0.0.1:1/blocked"];
        return orig_dataTaskWithURLComp ?
            orig_dataTaskWithURLComp(self, _cmd, localURL, ^(NSData *d, NSURLResponse *r, NSError *e){}) :
            nil;
    }
    return orig_dataTaskWithURLComp ?
        orig_dataTaskWithURLComp(self, _cmd, url, handler) : nil;
}

static void installNSURLSessionHooks(void) {
    WXLOG(@"=== Hooking NSURLSession ===");
    Class cls = [NSURLSession class];
    if (!cls) { WXLOG(@"NSURLSession not available yet"); return; }
    
    Method m;
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
    if (m) {
        orig_dataTaskWithRequest = (DataTaskReqIMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_dataTaskWithRequest);
        WXLOG(@"[OK] dataTaskWithRequest:");
    }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
    if (m) {
        orig_dataTaskWithURL = (DataTaskURLIMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_dataTaskWithURL);
        WXLOG(@"[OK] dataTaskWithURL:");
    }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (m) {
        orig_dataTaskWithRequestComp = (DataTaskReqCompIMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_dataTaskWithRequestComp);
        WXLOG(@"[OK] dataTaskWithRequest:completionHandler:");
    }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (m) {
        orig_dataTaskWithURLComp = (DataTaskURLCompIMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_dataTaskWithURLComp);
        WXLOG(@"[OK] dataTaskWithURL:completionHandler:");
    }
}

// ============================================================
#pragma mark - UIKit Hooks (deferred until app launches)
// ============================================================

// Hook: UIAlertController alertControllerWithTitle:message:preferredStyle:
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
        WXLOG(@"BLOCKED alert: title='%@' msg='%@'", title, message);
        // Return a real but empty alert (won't crash when adding actions)
        return [UIAlertController alertControllerWithTitle:@"" message:@"" preferredStyle:UIAlertControllerStyleAlert];
    }
    return orig_alertControllerWithTitle ?
        orig_alertControllerWithTitle(self, _cmd, title, message, style) : nil;
}

// Hook: UIViewController presentViewController:animated:completion:
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
            WXLOG(@"BLOCKED present: title='%@' msg='%@'", title, msg);
            if (completion) completion();
            return; // Don't present
        }
    }
    if (orig_presentViewController) {
        orig_presentViewController(self, _cmd, vc, animated, completion);
    }
}

static void installUIKitHooks(void) {
    WXLOG(@"=== Installing UIKit hooks (deferred) ===");
    
    // UIAlertController
    Class alertCls = [UIAlertController class];
    if (alertCls) {
        Method m = class_getClassMethod(alertCls, @selector(alertControllerWithTitle:message:preferredStyle:));
        if (m) {
            orig_alertControllerWithTitle = (AlertCreateIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_alertControllerWithTitle);
            WXLOG(@"[OK] +[UIAlertController alertControllerWithTitle:...]");
        }
    }
    
    // UIViewController presentViewController:
    Class vcCls = [UIViewController class];
    if (vcCls) {
        Method m = class_getInstanceMethod(vcCls, @selector(presentViewController:animated:completion:));
        if (m) {
            orig_presentViewController = (PresentVCIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_presentViewController);
            WXLOG(@"[OK] -[UIViewController presentViewController:...]");
        }
    }
}

// ============================================================
#pragma mark - SignatureKit / SignatureCheck hooks
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
        WXLOG(@"=== Hooking SignatureKit ===");
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
        WXLOG(@"=== Hooking SignatureCheck ===");
        count += safeHookClassMethod(sigChk, @selector(load), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(JudgeApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(GetApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(PostApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(showTipViewEND:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigChk, @selector(exitApplication), (IMP)rep_void);
    }
    
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"=== Hooking LCNetworking ===");
        count += safeHookClassMethod(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)rep_nil);
        count += safeHookClassMethod(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)rep_nil);
    }
    
    WXLOG(@"Signature hooks: %d methods", count);
}

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v3.0 - Safe Anti-inject");
    WXLOG(@"========================================");
    
    // Phase 1: IMMEDIATE — hook NSURLSession (Foundation is loaded)
    installNSURLSessionHooks();
    
    // Phase 2: IMMEDIATE — hook SignatureKit/SignatureCheck (they exist)
    installSignatureHooks();
    
    // Phase 3: DEFERRED — UIKit hooks after app launches
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            WXLOG(@"App launched, installing UIKit hooks...");
            installUIKitHooks();
            // Re-check signature hooks (in case classes loaded late)
            installSignatureHooks();
        }];
    
    // Phase 4: EXTRA SAFETY — retry all hooks after delays
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WXLOG(@"1s retry pass...");
        installSignatureHooks();
        installUIKitHooks();
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WXLOG(@"3s final retry...");
        installSignatureHooks();
    });
    
    WXLOG(@"Constructor done. UIKit hooks deferred.");
}
