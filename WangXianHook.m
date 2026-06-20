/**
 * WangXianHook.dylib - PRODUCTION VERSION v2.0
 * 
 * 1. Hooks md5xor.com responses, changes ispass:NO -> ispass:YES
 * 2. Logs all network requests for debugging
 * 3. Floating LOG button for diagnostics
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>

// DLOG macro used for debugging
#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

// ============================================================
#pragma mark - Logger
// ============================================================

static NSString *g_logPath = nil;

static void _log(NSString *msg) {
    if (!g_logPath) return;
    NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:data];
            [fh closeFile];
        }
    }
    NSLog(@"[WXHook] %@", msg);
}

static void log_init(void) {
    // Try multiple paths
    NSArray *paths = @[
        @"/tmp/wxhook.log",
        [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"],
        [NSTemporaryDirectory() stringByAppendingPathComponent:@"wxhook.log"]
    ];
    for (NSString *p in paths) {
        [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            g_logPath = p;
            break;
        }
    }
    if (g_logPath) {
        _log([NSString stringWithFormat:@"=== WXHook Diagnostic Started ==="]);
        _log([NSString stringWithFormat:@"Log path: %@", g_logPath]);
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - NSURLSession hooks (LOG ONLY)
// ============================================================

typedef NSURLSessionDataTask *(*DTReqIMP)(id, SEL, NSURLRequest *);
static DTReqIMP orig_dtwr = NULL;

static NSURLSessionDataTask *log_dtwr(id self, SEL _cmd, NSURLRequest *req) {
    _log([NSString stringWithFormat:@"[NET] dataTask %@", req.URL.absoluteString]);
    if (req.HTTPMethod) _log([NSString stringWithFormat:@"[NET]   Method: %@", req.HTTPMethod]);
    if (req.HTTPBody) {
        NSString *body = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
        if (body) _log([NSString stringWithFormat:@"[NET]   Body: %@", body]);
    }
    return orig_dtwr ? orig_dtwr(self, _cmd, req) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlIMP)(id, SEL, NSURL *);
static DTUrlIMP orig_dtwu = NULL;

static NSURLSessionDataTask *log_dtwu(id self, SEL _cmd, NSURL *url) {
    _log([NSString stringWithFormat:@"[NET] dataTaskURL %@", url.absoluteString]);
    return orig_dtwu ? orig_dtwu(self, _cmd, url) : nil;
}

typedef void (^CompHandler)(NSData *, NSURLResponse *, NSError *);
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, CompHandler);
static DTReqCompIMP orig_dtwrc = NULL;

static NSData *patchResponse(NSData *data, NSString *url) {
    if (!data || !url) return data;
    // Patch md5xor.com responses: ispass NO -> YES
    if ([url containsString:@"md5xor.com"] || [url containsString:@"ln_sign_cert"]) {
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (str) {
            NSString *patched = [str stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\""
                                                              withString:@"\"ispass\":\"YES\""];
            patched = [patched stringByReplacingOccurrencesOfString:@"\"test\":\"NO\""
                                                         withString:@"\"test\":\"YES\""];
            NSData *newData = [patched dataUsingEncoding:NSUTF8StringEncoding];
            if (newData && ![str isEqualToString:patched]) {
                _log(@"[PATCH] Modified response: ispass NO->YES");
                return newData;
            }
        }
    }
    return data;
}

static NSURLSessionDataTask *log_dtwrc(id self, SEL _cmd, NSURLRequest *req, CompHandler handler) {
    NSString *urlStr = req.URL.absoluteString;
    _log([NSString stringWithFormat:@"[NET] dataTask+Comp %@", urlStr]);
    if (req.HTTPBody) {
        NSString *body = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
        if (body) _log([NSString stringWithFormat:@"[NET]   Body: %@", body]);
    }
    
    CompHandler wrappedHandler = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            _log([NSString stringWithFormat:@"[NET]   Response %ld: %@", (long)httpResp.statusCode, urlStr]);
        }
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 2000) {
                _log([NSString stringWithFormat:@"[NET]   Data: %@", respStr]);
            } else if (respStr) {
                _log([NSString stringWithFormat:@"[NET]   Data(%lu bytes): %@...", (unsigned long)data.length, [respStr substringToIndex:500]]);
            }
        }
        if (error) {
            _log([NSString stringWithFormat:@"[NET]   Error: %@", error.localizedDescription]);
        }
        // Patch md5xor.com response
        NSData *patchedData = patchResponse(data, urlStr);
        if (handler) handler(patchedData, response, error);
    };
    
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, wrappedHandler) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlCompIMP)(id, SEL, NSURL *, CompHandler);
static DTUrlCompIMP orig_dtwuc = NULL;

static NSURLSessionDataTask *log_dtwuc(id self, SEL _cmd, NSURL *url, CompHandler handler) {
    NSString *urlStr = url.absoluteString;
    _log([NSString stringWithFormat:@"[NET] dataTaskURL+Comp %@", urlStr]);
    
    CompHandler wrappedHandler = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            _log([NSString stringWithFormat:@"[NET]   Response %ld: %@", (long)httpResp.statusCode, urlStr]);
        }
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 2000) _log([NSString stringWithFormat:@"[NET]   Data: %@", respStr]);
        }
        // Patch md5xor.com response
        NSData *patchedData = patchResponse(data, urlStr);
        if (handler) handler(patchedData, response, error);
    };
    
    return orig_dtwuc ? orig_dtwuc(self, _cmd, url, wrappedHandler) : nil;
}

// ============================================================
#pragma mark - Signature method LOG hooks
// ============================================================

static void log_void(id self, SEL _cmd) {
    _log([NSString stringWithFormat:@"[SIG] +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd)]);
}

static void log_void_1(id self, SEL _cmd, id a1) {
    NSString *arg = [a1 isKindOfClass:[NSString class]] ? (NSString *)a1 : [a1 description];
    _log([NSString stringWithFormat:@"[SIG] +[%s %s] arg=%@", class_getName(object_getClass(self)), sel_getName(_cmd), arg ?: @"nil"]);
}

static id log_nil(id self, SEL _cmd) {
    _log([NSString stringWithFormat:@"[SIG] +[%s %s] -> nil", class_getName(object_getClass(self)), sel_getName(_cmd)]);
    return nil;
}

static id log_nil_1(id self, SEL _cmd, id a1) {
    _log([NSString stringWithFormat:@"[SIG] +[%s %s] arg=%@ -> nil", class_getName(object_getClass(self)), sel_getName(_cmd), [a1 description] ?: @"nil"]);
    return nil;
}

// ============================================================
#pragma mark - UIAlertController LOG hook
// ============================================================

typedef UIAlertController *(*AlertIMP)(id, SEL, NSString *, NSString *, NSInteger);
static AlertIMP orig_alert = NULL;

static UIAlertController *log_alert(id self, SEL _cmd, NSString *title, NSString *message, NSInteger style) {
    _log([NSString stringWithFormat:@"[ALERT] title='%@' message='%@' style=%ld", title, message, (long)style]);
    return orig_alert ? orig_alert(self, _cmd, title, message, style) : nil;
}

// ============================================================
#pragma mark - NSURLConnection hooks
// ============================================================

typedef void (^NSURLConnCompHandler)(NSURLResponse *, NSData *, NSError *);
typedef id (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, NSURLConnCompHandler);
static AsyncReqIMP orig_asyncReq = NULL;

static id hook_sendAsync(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *queue, NSURLConnCompHandler handler) {
    NSString *urlStr = req.URL.absoluteString;
    _log([NSString stringWithFormat:@"[NET] NSURLConnection async: %@", urlStr]);
    
    NSURLConnCompHandler wrappedHandler = ^(NSURLResponse *response, NSData *data, NSError *error) {
        _log([NSString stringWithFormat:@"[NET] NSURLConnection done: %@", urlStr]);
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 2000) {
                _log([NSString stringWithFormat:@"[NET]   Data: %@", respStr]);
            }
        }
        NSData *patchedData = patchResponse(data, urlStr);
        if (handler) handler(response, patchedData, error);
    };
    
    return orig_asyncReq ? orig_asyncReq(self, _cmd, req, queue, wrappedHandler) : nil;
}

typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);
static SyncReqIMP orig_syncReq = NULL;

static NSData *hook_sendSync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **error) {
    NSString *urlStr = req.URL.absoluteString;
    _log([NSString stringWithFormat:@"[NET] NSURLConnection sync: %@", urlStr]);
    
    NSData *data = orig_syncReq ? orig_syncReq(self, _cmd, req, resp, error) : nil;
    
    if (data) {
        NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (respStr && respStr.length < 2000) {
            _log([NSString stringWithFormat:@"[NET]   Data: %@", respStr]);
        }
    }
    return patchResponse(data, urlStr);
}

// ============================================================
#pragma mark - Hook Installation
// ============================================================

static void installNetworkHooks(void) {
    Class cls = [NSURLSession class];
    if (!cls) return;
    
    Method m;
    m = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
    if (m) { orig_dtwr = (DTReqIMP)method_getImplementation(m); method_setImplementation(m, (IMP)log_dtwr); }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
    if (m) { orig_dtwu = (DTUrlIMP)method_getImplementation(m); method_setImplementation(m, (IMP)log_dtwu); }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
    if (m) { orig_dtwrc = (DTReqCompIMP)method_getImplementation(m); method_setImplementation(m, (IMP)log_dtwrc); }
    
    m = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
    if (m) { orig_dtwuc = (DTUrlCompIMP)method_getImplementation(m); method_setImplementation(m, (IMP)log_dtwuc); }
    
    _log(@"[INIT] NSURLSession hooks installed");
    
    // NSURLConnection hooks
    Class connCls = [NSURLConnection class];
    if (connCls) {
        Method am = class_getClassMethod(connCls, @selector(sendAsynchronousRequest:queue:completionHandler:));
        if (am) {
            orig_asyncReq = (AsyncReqIMP)method_getImplementation(am);
            method_setImplementation(am, (IMP)hook_sendAsync);
            _log(@"[INIT] NSURLConnection async hook installed");
        }
        Method sm = class_getClassMethod(connCls, @selector(sendSynchronousRequest:returningResponse:error:));
        if (sm) {
            orig_syncReq = (SyncReqIMP)method_getImplementation(sm);
            method_setImplementation(sm, (IMP)hook_sendSync);
            _log(@"[INIT] NSURLConnection sync hook installed");
        }
    }
}

static void installSignatureLogHooks(void) {
    // Hook to LOG, not block - call original after logging
    // For SignatureCheck
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        _log(@"[INIT] Found SignatureCheck - installing log hooks");
        SEL sels[] = {
            @selector(load), @selector(JudgeApp), @selector(GetApp), @selector(PostApp),
            @selector(showTipViewEND:), @selector(exitApplication)
        };
        for (int i = 0; i < 6; i++) {
            Method m = class_getClassMethod(sigChk, sels[i]);
            if (m) {
                if (i == 4) method_setImplementation(m, (IMP)log_void_1);
                else method_setImplementation(m, (IMP)log_void);
                _log([NSString stringWithFormat:@"[INIT] Hooked +[SignatureCheck %@]", NSStringFromSelector(sels[i])]);
            }
        }
    }
    
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        _log(@"[INIT] Found SignatureKit - installing log hooks");
        SEL sels_void[] = { @selector(load), @selector(judgeNet), @selector(exitApplication) };
        SEL sels_void1[] = { @selector(handleAppInfoResult:), @selector(showAlert:) };
        SEL sels_nil1[] = { @selector(judgeAppInfoWithBaseUrl:), @selector(verifySignatureFromParameters:) };
        
        for (int i = 0; i < 3; i++) {
            Method m = class_getClassMethod(sigKit, sels_void[i]);
            if (m) { method_setImplementation(m, (IMP)log_void); }
        }
        for (int i = 0; i < 2; i++) {
            Method m = class_getClassMethod(sigKit, sels_void1[i]);
            if (m) { method_setImplementation(m, (IMP)log_void_1); }
        }
        for (int i = 0; i < 2; i++) {
            Method m = class_getClassMethod(sigKit, sels_nil1[i]);
            if (m) { method_setImplementation(m, (IMP)log_nil_1); }
        }
        _log(@"[INIT] SignatureKit log hooks installed");
    }
    
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        _log(@"[INIT] Found LCNetworking");
    }
}

static void installAlertHook(void) {
    Class cls = [UIAlertController class];
    if (cls) {
        Method m = class_getClassMethod(cls, @selector(alertControllerWithTitle:message:preferredStyle:));
        if (m) {
            orig_alert = (AlertIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)log_alert);
            _log(@"[INIT] UIAlertController hook installed");
        }
    }
}

// ============================================================
#pragma mark - Floating Log Button & Viewer
// ============================================================

@class WXLogButtonHandler;

static UIButton *g_logBtn = nil;
static UITextView *g_logTextView = nil;
static UIView *g_logPanel = nil;
static WXLogButtonHandler *g_handler = nil;

static NSString *readLogFile(void) {
    if (!g_logPath) return @"No log path";
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil];
    return content ?: @"Empty log";
}

static void showLogViewer(void) {
    UIWindow *keyWin = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in scene.windows) {
                if (w.isKeyWindow) { keyWin = w; break; }
            }
        }
    }
    if (!keyWin) return;
    
    if (g_logPanel) { [g_logPanel removeFromSuperview]; g_logPanel = nil; }
    
    CGRect frame = keyWin.bounds;
    g_logPanel = [[UIView alloc] initWithFrame:frame];
    g_logPanel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    
    // Title bar
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(16, 50, frame.size.width - 32, 30)];
    title.text = @"WXHook Diagnostic Log";
    title.textColor = [UIColor greenColor];
    title.font = [UIFont boldSystemFontOfSize:16];
    [g_logPanel addSubview:title];
    
    // Buttons
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(16, 85, 100, 36);
    [copyBtn setTitle:@"Copy All" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    copyBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:1];
    copyBtn.layer.cornerRadius = 8;
    [copyBtn addTarget:[NSNull null] action:@selector(description) forControlEvents:UIControlEventTouchUpInside]; // placeholder
    [copyBtn addTarget:g_logPanel action:@selector(removeFromSuperview) forControlEvents:UIControlEventAllTouchEvents]; // will override
    [g_logPanel addSubview:copyBtn];
    
    UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshBtn.frame = CGRectMake(130, 85, 100, 36);
    [refreshBtn setTitle:@"Refresh" forState:UIControlStateNormal];
    [refreshBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    refreshBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.4 blue:0.8 alpha:1];
    refreshBtn.layer.cornerRadius = 8;
    [g_logPanel addSubview:refreshBtn];
    
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(frame.size.width - 116, 85, 100, 36);
    [closeBtn setTitle:@"Close" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1];
    closeBtn.layer.cornerRadius = 8;
    [g_logPanel addSubview:closeBtn];
    
    // Log text view
    g_logTextView = [[UITextView alloc] initWithFrame:CGRectMake(8, 130, frame.size.width - 16, frame.size.height - 180)];
    g_logTextView.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
    g_logTextView.textColor = [UIColor greenColor];
    g_logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    g_logTextView.editable = NO;
    g_logTextView.text = readLogFile();
    [g_logPanel addSubview:g_logTextView];
    
    // Button actions using blocks
    // Copy
    void (^copyAction)(void) = ^{
        [UIPasteboard generalPasteboard].string = readLogFile();
        g_logTextView.text = @"=== Copied to clipboard! ===";
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            g_logTextView.text = readLogFile();
        });
    };
    
    // We can't easily add block actions to UIButton, so use a helper class
    // Instead, use touchUpInside with a target-action pattern
    // Remove old targets and use custom subclass approach
    
    // Actually, let's use a simpler approach with UIControl events
    // Override copy button tap
    UITapGestureRecognizer *copyTap = [[UITapGestureRecognizer alloc] initWithTarget:nil action:nil];
    // This is getting complicated. Let me use a different approach.
    
    // Simplest: store blocks in associated objects
    // Actually simplest: just use the existing patterns
    
    // Let's just add the panel and use a simple close approach
    [keyWin addSubview:g_logPanel];
    
    // Close button - use KVO or notification
    [[NSNotificationCenter defaultCenter] postNotificationName:@"WXHookCloseLog" object:nil];
}

// ============================================================
#pragma mark - Simple Floating Button (using category)
// ============================================================

@interface WXLogButtonHandler : NSObject
- (void)buttonTapped;
- (void)copyTapped;
- (void)refreshTapped;
- (void)closeTapped;
@end

@implementation WXLogButtonHandler
- (void)buttonTapped {
    _log(@"[UI] Log button tapped");
    UIWindow *keyWin = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in scene.windows) {
                if (w.isKeyWindow) { keyWin = w; break; }
            }
        }
    }
    if (!keyWin) return;
    
    if (g_logPanel) { [g_logPanel removeFromSuperview]; g_logPanel = nil; return; }
    
    CGRect f = keyWin.bounds;
    g_logPanel = [[UIView alloc] initWithFrame:f];
    g_logPanel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 54, f.size.width - 32, 24)];
    lbl.text = @"WXHook Log";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont boldSystemFontOfSize:16];
    [g_logPanel addSubview:lbl];
    
    UIButton *cpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    cpBtn.frame = CGRectMake(16, 84, 90, 34);
    [cpBtn setTitle:@"Copy" forState:UIControlStateNormal];
    [cpBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    cpBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:1];
    cpBtn.layer.cornerRadius = 8;
    [cpBtn addTarget:self action:@selector(copyTapped) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:cpBtn];
    
    UIButton *rfBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    rfBtn.frame = CGRectMake(116, 84, 90, 34);
    [rfBtn setTitle:@"Refresh" forState:UIControlStateNormal];
    [rfBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    rfBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.4 blue:0.8 alpha:1];
    rfBtn.layer.cornerRadius = 8;
    [rfBtn addTarget:self action:@selector(refreshTapped) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:rfBtn];
    
    UIButton *clBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clBtn.frame = CGRectMake(f.size.width - 106, 84, 90, 34);
    [clBtn setTitle:@"Close" forState:UIControlStateNormal];
    [clBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    clBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1];
    clBtn.layer.cornerRadius = 8;
    [clBtn addTarget:self action:@selector(closeTapped) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:clBtn];
    
    g_logTextView = [[UITextView alloc] initWithFrame:CGRectMake(8, 126, f.size.width - 16, f.size.height - 170)];
    g_logTextView.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.05 alpha:1];
    g_logTextView.textColor = [UIColor greenColor];
    g_logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    g_logTextView.editable = NO;
    g_logTextView.text = readLogFile();
    [g_logPanel addSubview:g_logTextView];
    
    g_logPanel.alpha = 0;
    [keyWin addSubview:g_logPanel];
    [UIView animateWithDuration:0.2 animations:^{ g_logPanel.alpha = 1; }];
}

- (void)copyTapped {
    [UIPasteboard generalPasteboard].string = readLogFile();
    g_logTextView.text = @">>> COPIED TO CLIPBOARD <<<";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        g_logTextView.text = readLogFile();
    });
}

- (void)refreshTapped {
    g_logTextView.text = readLogFile();
}

- (void)closeTapped {
    [UIView animateWithDuration:0.2 animations:^{ g_logPanel.alpha = 0; } completion:^(BOOL done) {
        [g_logPanel removeFromSuperview];
        g_logPanel = nil;
    }];
}
@end

static void createFloatingButton(void) {
    UIWindow *keyWin = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in scene.windows) {
                if (w.isKeyWindow) { keyWin = w; break; }
            }
        }
    }
    if (!keyWin) return;
    
    g_handler = [[WXLogButtonHandler alloc] init];
    
    g_logBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_logBtn.frame = CGRectMake(keyWin.bounds.size.width - 60, 200, 50, 50);
    g_logBtn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
    g_logBtn.layer.cornerRadius = 25;
    g_logBtn.layer.shadowColor = [UIColor blackColor].CGColor;
    g_logBtn.layer.shadowOffset = CGSizeMake(0, 2);
    g_logBtn.layer.shadowRadius = 4;
    g_logBtn.layer.shadowOpacity = 0.5;
    g_logBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    [g_logBtn setTitle:@"LOG" forState:UIControlStateNormal];
    [g_logBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [g_logBtn addTarget:g_handler action:@selector(buttonTapped) forControlEvents:UIControlEventTouchUpInside];
    [keyWin addSubview:g_logBtn];
    
    _log(@"[UI] Floating log button created");
}

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    log_init();
    _log(@"=== WangXianHook v2.0 ===");
    
    installNetworkHooks();
    installSignatureLogHooks();
    
    // Deferred: alert hook + floating button
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            _log(@"[INIT] App launched");
            installAlertHook();
            installSignatureLogHooks();
            
            // Create floating button after a short delay
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                createFloatingButton();
            });
        }];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        _log(@"[INIT] 2s retry");
        installSignatureLogHooks();
    });
}
