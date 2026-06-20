/**
 * WangXianHook v3.0 - Minimal + ispass patch
 * Only hooks NSURLSession completionHandler methods
 * Patches md5xor.com ispass:NO -> YES
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
        _log(@"=== WXHook v3.0 ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - NSURLSession completionHandler hook + ispass patch
// ============================================================

typedef void (^CompHandler)(NSData *, NSURLResponse *, NSError *);
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, CompHandler);
static DTReqCompIMP orig_dtwrc = NULL;

static NSData *patchIspass(NSData *data, NSString *url) {
    if (!data || !url) return data;
    if ([url containsString:@"md5xor"] || [url containsString:@"ln_sign_cert"] || [url containsString:@"ispass"]) {
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (str && [str containsString:@"\"ispass\""]) {
            NSString *patched = [str stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\"" withString:@"\"ispass\":\"YES\""];
            patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\": \"NO\"" withString:@"\"ispass\": \"YES\""];
            patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\":false" withString:@"\"ispass\":true"];
            patched = [patched stringByReplacingOccurrencesOfString:@"\"ispass\": false" withString:@"\"ispass\": true"];
            NSData *newData = [patched dataUsingEncoding:NSUTF8StringEncoding];
            if (newData && ![str isEqualToString:patched]) {
                _log([NSString stringWithFormat:@"[PATCH] ispass NO->YES: %@", url]);
                return newData;
            }
        }
    }
    return data;
}

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, CompHandler handler) {
    NSString *urlStr = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] req: %@", urlStr);
    
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 1000) {
                DLOG(@"[NET] resp: %@", respStr);
            }
        }
        NSData *patched = patchIspass(data, urlStr);
        if (handler) handler(patched, response, error);
    };
    
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, wrapped) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlCompIMP)(id, SEL, NSURL *, CompHandler);
static DTUrlCompIMP orig_dtwuc = NULL;

static NSURLSessionDataTask *hook_dtwuc(id self, SEL _cmd, NSURL *url, CompHandler handler) {
    NSString *urlStr = url.absoluteString ?: @"(null)";
    DLOG(@"[NET] url: %@", urlStr);
    
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) {
            NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (respStr && respStr.length < 1000) {
                DLOG(@"[NET] resp: %@", respStr);
            }
        }
        NSData *patched = patchIspass(data, urlStr);
        if (handler) handler(patched, response, error);
    };
    
    return orig_dtwuc ? orig_dtwuc(self, _cmd, url, wrapped) : nil;
}

// ============================================================
#pragma mark - Floating LOG button (minimal)
// ============================================================

@class WXHandler;
static UIButton *g_btn = nil;
static UITextView *g_tv = nil;
static UIView *g_panel = nil;
static WXHandler *g_handler = nil;

@interface WXHandler : NSObject
- (void)toggle;
- (void)copyLog;
- (void)close;
@end

@implementation WXHandler
- (void)toggle {
    _log(@"[UI] toggle");
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
    lbl.text = @"WXHook v3.0 Log";
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
    [cl addTarget:self action:@selector(close) forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:cl];
    
    g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 126, f.size.width - 16, f.size.height - 170)];
    g_tv.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.05 alpha:1];
    g_tv.textColor = [UIColor greenColor];
    g_tv.font = [UIFont fontWithName:@"Menlo" size:11];
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

- (void)close {
    [g_panel removeFromSuperview];
    g_panel = nil;
}
@end

// ============================================================
#pragma mark - Constructor
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    // Hook NSURLSession completionHandler methods ONLY
    Class cls = [NSURLSession class];
    if (cls) {
        Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
        if (m1) {
            orig_dtwrc = (DTReqCompIMP)method_getImplementation(m1);
            method_setImplementation(m1, (IMP)hook_dtwrc);
            _log(@"[INIT] Hooked dataTaskWithRequest:completionHandler:");
        }
        Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
        if (m2) {
            orig_dtwuc = (DTUrlCompIMP)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)hook_dtwuc);
            _log(@"[INIT] Hooked dataTaskWithURL:completionHandler:");
        }
    }
    
    // Deferred: floating button
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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
