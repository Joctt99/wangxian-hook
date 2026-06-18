/**
 * WangXianHook.dylib - DIAGNOSTIC VERSION
 * 
 * Does NOT block anything. Only OBSERVES and LOGS:
 *   1. ALL NSURLSession network requests (URL, method, headers, body)
 *   2. ALL NSURLSession responses (status code, data)
 *   3. SignatureKit/SignatureCheck method calls
 *   4. UIAlertController creation/presentation
 *   5. exit() calls
 *
 * Log file: /tmp/wxhook.log
 * Read via: cat /tmp/wxhook.log (from device or iFile)
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

static NSURLSessionDataTask *log_dtwrc(id self, SEL _cmd, NSURLRequest *req, CompHandler handler) {
    _log([NSString stringWithFormat:@"[NET] dataTask+Comp %@", req.URL.absoluteString]);
    if (req.HTTPBody) {
        NSString *body = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
        if (body) _log([NSString stringWithFormat:@"[NET]   Body: %@", body]);
    }
    
    // Wrap completion handler to log response
    CompHandler wrappedHandler = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            _log([NSString stringWithFormat:@"[NET]   Response %ld: %@", (long)httpResp.statusCode, req.URL.absoluteString]);
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
        if (handler) handler(data, response, error);
    };
    
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, wrappedHandler) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlCompIMP)(id, SEL, NSURL *, CompHandler);
static DTUrlCompIMP orig_dtwuc = NULL;

static NSURLSessionDataTask *log_dtwuc(id self, SEL _cmd, NSURL *url, CompHandler handler) {
    _log([NSString stringWithFormat:@"[NET] dataTaskURL+Comp %@", url.absoluteString]);
    
    CompHandler wrappedHandler = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            _log([NSString stringWithFormat:@"[NET]   Response %ld: %@", (long)httpResp.statusCode, url.absoluteString]);
        }
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 2000) _log([NSString stringWithFormat:@"[NET]   Data: %@", respStr]);
        }
        if (handler) handler(data, response, error);
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
#pragma mark - Hook installation
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
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    log_init();
    _log(@"=== WangXianHook Diagnostic v1.0 ===");
    
    installNetworkHooks();
    installSignatureLogHooks();
    
    // Deferred: alert hook
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:[NSOperationQueue mainQueue]
        usingBlock:^(NSNotification *note) {
            _log(@"[INIT] App launched, installing alert hook");
            installAlertHook();
            installSignatureLogHooks(); // retry
        }];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        _log(@"[INIT] 2s retry");
        installSignatureLogHooks();
    });
}
