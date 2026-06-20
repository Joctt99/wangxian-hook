/**
 * WangXianHook v6.0 - Full Diagnostic
 * Logs: SignatureCheck methods, SignatureKit methods, network, alerts, all UI
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;

static void _log(NSString *msg) {
    if (!g_logPath) return;
    NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
    }
    NSLog(@"[WXHook] %@", msg);
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        _log(@"=== WXHook v6.0 Full Diagnostic ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - ispass patch
// ============================================================

static NSData *patchIspass(NSData *data, NSString *url) {
    if (!data) return data;
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!str) return data;
    NSString *patched = str;
    patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\"" withString:@"\"ispass\":\"YES\""];
    patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\": \"NO\"" withString:@"\"ispass\": \"YES\""];
    patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\":false" withString:@"\"ispass\":true"];
    patched = [patched stringByReplacingOccurrencesOfString:@"\"test\":\"NO\"" withString:@"\"test\":\"YES\""];
    NSData *newData = [patched dataUsingEncoding:NSUTF8StringEncoding];
    if (newData && ![str isEqualToString:patched]) {
        DLOG(@"[PATCH] ispass patched: %@", url);
        return newData;
    }
    return data;
}

// ============================================================
#pragma mark - NSURLConnection sync hook
// ============================================================

typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);
static SyncReqIMP orig_syncReq = NULL;

static NSData *hook_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **error) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] NSURLConnection sync: %@", u);
    NSData *data = orig_syncReq ? orig_syncReq(self, _cmd, req, resp, error) : nil;
    if (data) {
        NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (r && r.length < 1500) DLOG(@"[NET] sync resp: %@", r);
    }
    if (error && *error) DLOG(@"[NET] sync error: %@", (*error).localizedDescription);
    return patchIspass(data, u);
}

// ============================================================
#pragma mark - NSURLConnection async hook
// ============================================================

typedef void (^NSURLConnComp)(NSURLResponse *, NSData *, NSError *);
typedef id (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, NSURLConnComp);
static AsyncReqIMP orig_asyncReq = NULL;

static id hook_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *queue, NSURLConnComp handler) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] NSURLConnection async: %@", u);
    NSURLConnComp wrapped = ^(NSURLResponse *resp, NSData *data, NSError *error) {
        if (data) {
            NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (r && r.length < 1500) DLOG(@"[NET] async resp: %@", r);
        }
        if (handler) handler(resp, patchIspass(data, u), error);
    };
    return orig_asyncReq ? orig_asyncReq(self, _cmd, req, queue, wrapped) : nil;
}

// ============================================================
#pragma mark - NSURLSession hooks
// ============================================================

typedef void (^CompHandler)(NSData *, NSURLResponse *, NSError *);
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, CompHandler);
static DTReqCompIMP orig_dtwrc = NULL;

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, CompHandler handler) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] NSURLSession req: %@", u);
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (r && r.length < 1500) DLOG(@"[NET] session resp: %@", r);
        }
        if (handler) handler(patchIspass(data, u), response, error);
    };
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, wrapped) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlCompIMP)(id, SEL, NSURL *, CompHandler);
static DTUrlCompIMP orig_dtwuc = NULL;

static NSURLSessionDataTask *hook_dtwuc(id self, SEL _cmd, NSURL *url, CompHandler handler) {
    NSString *u = url.absoluteString ?: @"(null)";
    DLOG(@"[NET] NSURLSession url: %@", u);
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (r && r.length < 1500) DLOG(@"[NET] session resp: %@", r);
        }
        if (handler) handler(patchIspass(data, u), response, error);
    };
    return orig_dtwuc ? orig_dtwuc(self, _cmd, url, wrapped) : nil;
}

// ============================================================
#pragma mark - SignatureCheck method hooks (log only, pass through)
// ============================================================

static void hook_sig_method(Class cls, SEL sel, const char *label) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP origImp = method_getImplementation(m);
    IMP newImp = imp_implementationWithBlock(^(id self) {
        DLOG(@"[SIG] +[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
        // Call original
        void (*fp)(id, SEL) = (void *)origImp;
        fp(self, sel);
    });
    method_setImplementation(m, newImp);
    DLOG(@"[INIT] Hooked +%s", label);
}

static void hook_sig_method_arg(Class cls, SEL sel, const char *label) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    IMP origImp = method_getImplementation(m);
    IMP newImp = imp_implementationWithBlock(^(id self, id arg) {
        DLOG(@"[SIG] +[%@ %@] arg=%@", NSStringFromClass(cls), NSStringFromSelector(sel), arg);
        void (*fp)(id, SEL, id) = (void *)origImp;
        fp(self, sel, arg);
    });
    method_setImplementation(m, newImp);
    DLOG(@"[INIT] Hooked +%s", label);
}

// ============================================================
#pragma mark - UIAlertController hook
// ============================================================

typedef void (*PresentVC_IMP)(id, SEL, id, BOOL, id);
static PresentVC_IMP orig_presentVC = NULL;

static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        DLOG(@"[ALERT] UIAlertController presented!");
        DLOG(@"[ALERT] title: %@", alert.title ?: @"(nil)");
        DLOG(@"[ALERT] message: %@", alert.message ?: @"(nil)");
        for (UIAlertAction *action in alert.actions) {
            DLOG(@"[ALERT] action: %@", action.title ?: @"(nil)");
        }
    }
    if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark - UIView addSubview hook (catch popup views)
// ============================================================

typedef void (*AddSubviewIMP)(id, SEL, UIView *);
static AddSubviewIMP orig_addSubview = NULL;

static void hook_addSubview(id self, SEL _cmd, UIView *view) {
    NSString *cls = NSStringFromClass([view class]);
    if ([cls containsString:@"Alert"] || [cls containsString:@"Tip"] || 
        [cls containsString:@"Dialog"] || [cls containsString:@"Modal"] ||
        [cls containsString:@"Popup"] || [cls containsString:@"Banner"]) {
        DLOG(@"[UI] addSubview: %@", cls);
    }
    if (orig_addSubview) orig_addSubview(self, _cmd, view);
}

// ============================================================
#pragma mark - Floating LOG button
// ============================================================

@class WXHandler;
static UIButton *g_btn = nil;
static UITextView *g_tv = nil;
static UIView *g_panel = nil;
static WXHandler *g_handler = nil;

@interface WXHandler : NSObject
- (void)toggle;
- (void)copyLog;
@end

@implementation WXHandler
- (void)toggle {
    UIWindow *w = nil;
    for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (s.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *win in s.windows) { if (win.isKeyWindow) { w = win; break; } }
        }
    }
    if (!w) return;
    if (g_panel) { [g_panel removeFromSuperview]; g_panel = nil; return; }
    
    CGRect f = w.bounds;
    g_panel = [[UIView alloc] initWithFrame:f];
    g_panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 54, f.size.width - 32, 24)];
    lbl.text = @"WXHook v6.0 Diagnostic";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont boldSystemFontOfSize:16];
    [g_panel addSubview:lbl];
    
    UIButton *cp = [UIButton buttonWithType:UIButtonTypeSystem];
    cp.frame = CGRectMake(16, 84, 90, 34);
    [cp setTitle:@"Copy" forState:UIControlStateNormal];
    [cp setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    cp.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:1];
    cp.layer.cornerRadius = 8;
    [cp addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:cp];
    
    UIButton *cl = [UIButton buttonWithType:UIButtonTypeSystem];
    cl.frame = CGRectMake(f.size.width - 106, 84, 90, 34);
    [cl setTitle:@"Close" forState:UIControlStateNormal];
    [cl setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    cl.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1];
    cl.layer.cornerRadius = 8;
    [cl addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:cl];
    
    g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 126, f.size.width - 16, f.size.height - 170)];
    g_tv.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.05 alpha:1];
    g_tv.textColor = [UIColor greenColor];
    g_tv.font = [UIFont fontWithName:@"Menlo" size:10];
    g_tv.editable = NO;
    g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"Empty";
    [g_panel addSubview:g_tv];
    [w addSubview:g_panel];
}

- (void)copyLog {
    [UIPasteboard generalPasteboard].string = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_tv.text = @">>> COPIED <<<";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    });
}
@end

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    // Hook NSURLConnection sync
    Class connCls = [NSURLConnection class];
    if (connCls) {
        Method sm = class_getClassMethod(connCls, @selector(sendSynchronousRequest:returningResponse:error:));
        if (sm) { orig_syncReq = (SyncReqIMP)method_getImplementation(sm); method_setImplementation(sm, (IMP)hook_sync); _log(@"[INIT] NSURLConnection sync hooked"); }
        Method am = class_getClassMethod(connCls, @selector(sendAsynchronousRequest:queue:completionHandler:));
        if (am) { orig_asyncReq = (AsyncReqIMP)method_getImplementation(am); method_setImplementation(am, (IMP)hook_async); _log(@"[INIT] NSURLConnection async hooked"); }
    }
    
    // Hook NSURLSession
    Class cls = [NSURLSession class];
    if (cls) {
        Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
        if (m1) { orig_dtwrc = (DTReqCompIMP)method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_dtwrc); }
        Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
        if (m2) { orig_dtwuc = (DTUrlCompIMP)method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_dtwuc); }
        _log(@"[INIT] NSURLSession hooked");
    }
    
    // Hook UIAlertController presentation
    Class vcCls = [UIViewController class];
    Method pm = class_getInstanceMethod(vcCls, @selector(presentViewController:animated:completion:));
    if (pm) {
        orig_presentVC = (PresentVC_IMP)method_getImplementation(pm);
        method_setImplementation(pm, (IMP)hook_presentVC);
        _log(@"[INIT] UIAlertController hook installed");
    }
    
    // Hook UIView addSubview for popup detection
    Class viewCls = [UIView class];
    Method asv = class_getInstanceMethod(viewCls, @selector(addSubview:));
    if (asv) {
        orig_addSubview = (AddSubviewIMP)method_getImplementation(asv);
        method_setImplementation(asv, (IMP)hook_addSubview);
    }
    
    // Deferred: hook SignatureCheck/SignatureKit + create UI
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // Hook SignatureCheck class methods
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            hook_sig_method(scCls, @selector(load), "[SignatureCheck load]");
            hook_sig_method(scCls, @selector(JudgeApp), "[SignatureCheck JudgeApp]");
            hook_sig_method(scCls, @selector(GetApp), "[SignatureCheck GetApp]");
            hook_sig_method(scCls, @selector(PostApp), "[SignatureCheck PostApp]");
            hook_sig_method_arg(scCls, @selector(showTipViewEND:), "[SignatureCheck showTipViewEND:]");
            hook_sig_method(scCls, @selector(exitApplication), "[SignatureCheck exitApplication]");
            DLOG(@"[INIT] SignatureCheck hooks installed (6 methods)");
        } else {
            _log(@"[INIT] WARNING: SignatureCheck class NOT found!");
        }
        
        // Hook SignatureKit class methods
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(object_getClass(skCls), &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                SEL sel = method_getName(methods[i]);
                NSString *selStr = NSStringFromSelector(sel);
                DLOG(@"[INIT] SignatureKit +[%@]", selStr);
            }
            if (methods) free(methods);
            _log(@"[INIT] SignatureKit hooks installed");
        } else {
            _log(@"[INIT] WARNING: SignatureKit class NOT found!");
        }
        
        // Scan all loaded classes for signing-related ones
        int total = objc_getClassList(NULL, 0);
        Class *classes = (Class *)malloc(sizeof(Class) * total);
        objc_getClassList(classes, total);
        for (int i = 0; i < total; i++) {
            NSString *name = NSStringFromClass(classes[i]);
            NSString *lower = [name lowercaseString];
            if ([lower containsString:@"anyou"] || [lower containsString:@"md5xor"] ||
                [lower containsString:@"licensecheck"] || [lower containsString:@"signcheck"]) {
                DLOG(@"[SCAN] Found suspicious class: %@", name);
            }
        }
        free(classes);
        
        // Create floating button
        UIWindow *w = nil;
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *win in s.windows) { if (win.isKeyWindow) { w = win; break; } }
            }
        }
        if (!w) return;
        
        g_handler = [[WXHandler alloc] init];
        g_btn = [UIButton buttonWithType:UIButtonTypeCustom];
        g_btn.frame = CGRectMake(w.bounds.size.width - 60, 200, 50, 50);
        g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
        g_btn.layer.cornerRadius = 25;
        g_btn.titleLabel.font = [UIFont systemFontOfSize:10];
        [g_btn setTitle:@"LOG" forState:UIControlStateNormal];
        [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [g_btn addTarget:g_handler action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:g_btn];
        _log(@"[UI] Button created");
    });
}
