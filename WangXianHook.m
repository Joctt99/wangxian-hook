/**
 * WangXianHook v34.89 - Fix server list with correct class names
 * FIX: Changed MieshiServerInfo to ServerInfoForClient (real class name)
 * FIX: Added hook for LoginModuleMessageHandlerImpl.handle_NEW_QUERY_SERVER_LIST_RES
 * FIX: Updated CLogin class hooks for server list management
 * Tracks: Signature, Environment, Debug, Security, Ban detection
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <zlib.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES; // logging toggle

static void _log(NSString *msg) {
    if (!g_logPath || !g_logEnabled) return;
    
    @try {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        if (size > 5 * 1024 * 1024) {
            NSString *oldLogPath = [g_logPath stringByAppendingString:@".old"];
            [[NSFileManager defaultManager] removeItemAtPath:oldLogPath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:g_logPath toPath:oldLogPath error:nil];
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            _log(@"[LOG] File too large (>5MB), rotated to .old");
            return;
        }
        
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
        if (data) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        }
        NSLog(@"[WXHook] %@", msg);
    } @catch (NSException *e) {}
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        _log(@"=== WXHook v34.89 Server Info Fix ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - SignatureKit hooks
// ============================================================

// 1. showAlert: - SUPPRESS
typedef void (*ShowAlertIMP)(id, SEL, id);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, id msg) {
    DLOG(@"[SK] showAlert: SUPPRESSED: %@", msg);
}

// 2. exitApplication - BLOCK
typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

// 3. handleAppInfoResult: - LOG + pass through (call original to process fake result)
typedef void (*HandleResultIMP)(id, SEL, id);
static HandleResultIMP orig_handleResult = NULL;
static void hook_handleResult(id self, SEL _cmd, id result) {
    DLOG(@"[SK] handleAppInfoResult: %@", result);
    if (orig_handleResult) {
        orig_handleResult(self, _cmd, result);
    }
}

// 4. judgeAppInfoWithBaseUrl: - BYPASS
typedef void (*JudgeBaseIMP)(id, SEL, id);
static JudgeBaseIMP orig_judgeBase = NULL;
static void hook_judgeBase(id self, SEL _cmd, id baseUrl) {
    DLOG(@"[SK] judgeAppInfoWithBaseUrl: %@ (BYPASSING)", baseUrl);
    @try {
        NSDictionary *fakeResult = @{@"status":@200,@"ispass":@"YES",@"pass":@"YES",@"result":@"pass",@"code":@0,@"verify":@"YES",@"data":@{@"status":@1,@"ispass":@"YES"},@"msg":@"success"};
        ((void (*)(id, SEL, id))objc_msgSend)(self, @selector(handleAppInfoResult:), fakeResult);
        DLOG(@"[SK] handleAppInfoResult: called OK");
    } @catch (NSException *e) {
        DLOG(@"[SK] Exception in bypass: %@", e);
        if (orig_judgeBase) orig_judgeBase(self, _cmd, baseUrl);
    }
}

// 5. judgeNet - Call original to let it complete
typedef void (*JudgeNetIMP)(id, SEL);
static JudgeNetIMP orig_judgeNet = NULL;
static void hook_judgeNet(id self, SEL _cmd) {
    DLOG(@"[SK] judgeNet called, calling original");
    if (orig_judgeNet) orig_judgeNet(self, _cmd);
}

// 6. verifySignatureFromParameters: - LOG only
typedef id (*VerifySigIMP)(id, SEL, id);
static VerifySigIMP orig_verifySig = NULL;
static id hook_verifySig(id self, SEL _cmd, id params) {
    DLOG(@"[SK] verifySignatureFromParameters: BLOCKED: %@", params);
    return @{@"status":@200,@"ispass":@"YES",@"pass":@"YES"};
}

// 7. generateRequestParams - LOG only
typedef id (*GenParamsIMP)(id, SEL);
static GenParamsIMP orig_genParams = NULL;
static id hook_genParams(id self, SEL _cmd) {
    DLOG(@"[SK] generateRequestParams called");
    if (orig_genParams) return orig_genParams(self, _cmd);
    return nil;
}

// 8. createSignatureParams: - LOG only
typedef id (*CreateSigParamsIMP)(id, SEL, id);
static CreateSigParamsIMP orig_createSigParams = NULL;
static id hook_createSigParams(id self, SEL _cmd, id arg) {
    DLOG(@"[SK] createSignatureParams: %@", arg);
    if (orig_createSigParams) return orig_createSigParams(self, _cmd, arg);
    return nil;
}

// ============================================================
#pragma mark - SignatureCheck hooks (stub class - prevent HTTP calls)
// ============================================================

// Hook SignatureCheck.JudgeApp - call original
typedef void (*JudgeAppIMP)(id, SEL);
static JudgeAppIMP orig_judgeApp = NULL;
static void hook_judgeApp(id self, SEL _cmd) {
    DLOG(@"[SC] SignatureCheck.JudgeApp called, calling original");
    if (orig_judgeApp) orig_judgeApp(self, _cmd);
}

typedef void (*ShowTipIMP)(id, SEL, id);
static ShowTipIMP orig_showTip = NULL;
static void hook_showTip(id self, SEL _cmd, id arg) {
    DLOG(@"[SC] SignatureCheck.showTipViewEND: SUPPRESSED: %@", arg);
    // Don't call original - suppress the "版本过低" popup
}

typedef void (*SCExitIMP)(id, SEL);
static SCExitIMP orig_scExit = NULL;
static void hook_scExit(id self, SEL _cmd) {
    DLOG(@"[SC] SignatureCheck.exitApplication BLOCKED");
    // Don't call original
}

// ============================================================
#pragma mark - Log Panel UI
// ============================================================

@interface WXHandler : NSObject
@property (nonatomic) BOOL showing;
- (void)toggle;
- (void)clearLog;
- (void)toggleLogging;
@end

static UIButton *g_btn = nil;
static UIView *g_panel = nil;
static UITextView *g_tv = nil;
static WXHandler *g_handler = nil;
static UILabel *g_statusLbl = nil;

@implementation WXHandler
- (void)toggle {
    self.showing = !self.showing;
    if (self.showing) {
        if (!g_panel) {
            UIWindow *w = g_btn.window;
            CGFloat pw = w.bounds.size.width - 32;
            CGFloat ph = w.bounds.size.height - 150;
            g_panel = [[UIView alloc] initWithFrame:CGRectMake(16, 100, pw, ph)];
            g_panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
            g_panel.layer.cornerRadius = 12;
            
            UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, pw - 200, 24)];
            lbl.text = @"WXHook v34.89 诊断面板";
            lbl.textColor = [UIColor greenColor];
            lbl.font = [UIFont boldSystemFontOfSize:14];
            [g_panel addSubview:lbl];
            
            // Status label (shows ON/OFF)
            g_statusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];
            g_statusLbl.text = @"日志: 开";
            g_statusLbl.textColor = [UIColor greenColor];
            g_statusLbl.font = [UIFont boldSystemFontOfSize:12];
            [g_panel addSubview:g_statusLbl];
            
            // Button row 1
            CGFloat bx = pw - 270;
            UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            onOffBtn.frame = CGRectMake(bx, 8, 50, 28);
            [onOffBtn setTitle:@"开关" forState:UIControlStateNormal];
            [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];
            [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:onOffBtn];
            
            UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            clearBtn.frame = CGRectMake(bx + 55, 8, 50, 28);
            [clearBtn setTitle:@"清除" forState:UIControlStateNormal];
            [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
            [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:clearBtn];
            
            UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            copyBtn.frame = CGRectMake(bx + 110, 8, 50, 28);
            [copyBtn setTitle:@"复制" forState:UIControlStateNormal];
            [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
            [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:copyBtn];
            
            UIButton *shareBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            shareBtn.frame = CGRectMake(bx + 165, 8, 50, 28);
            [shareBtn setTitle:@"导出" forState:UIControlStateNormal];
            [shareBtn setTitleColor:[UIColor magentaColor] forState:UIControlStateNormal];
            shareBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            [shareBtn addTarget:self action:@selector(shareLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:shareBtn];
            
            UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            refreshBtn.frame = CGRectMake(bx + 220, 8, 50, 28);
            [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];
            [refreshBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
            [refreshBtn addTarget:self action:@selector(refreshLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:refreshBtn];
            
            // Row 2: Dump button
            UIButton *dumpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            dumpBtn.frame = CGRectMake(bx, 34, 80, 24);
            [dumpBtn setTitle:@"视图树" forState:UIControlStateNormal];
            [dumpBtn setTitleColor:[UIColor orangeColor] forState:UIControlStateNormal];
            dumpBtn.titleLabel.font = [UIFont systemFontOfSize:12];
            [dumpBtn addTarget:self action:@selector(dumpViews) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:dumpBtn];
            
            g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 62, pw - 16, ph - 72)];
            g_tv.backgroundColor = [UIColor blackColor];
            g_tv.textColor = [UIColor greenColor];
            g_tv.font = [UIFont fontWithName:@"Menlo" size:11];
            g_tv.editable = NO;
            [g_panel addSubview:g_tv];
            
            [w addSubview:g_panel];
        }
        g_panel.hidden = NO;
        g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
        [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];
        // Ensure LOG button stays on top
        if (g_btn.superview) [g_btn.superview bringSubviewToFront:g_btn];
    } else {
        g_panel.hidden = YES;
    }
}
- (void)clearLog {
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_tv.text = @"(cleared)";
    g_logEnabled = YES;
    g_statusLbl.text = @"日志: 开";
    g_statusLbl.textColor = [UIColor greenColor];
    DLOG(@"=== Log cleared ===");
}
- (void)toggleLogging {
    g_logEnabled = !g_logEnabled;
    g_statusLbl.text = g_logEnabled ? @"日志: 开" : @"日志: 关";
    g_statusLbl.textColor = g_logEnabled ? [UIColor greenColor] : [UIColor redColor];
    if (g_logEnabled) {
        DLOG(@"=== Logging resumed ===");
    }
}
- (void)dumpViews {
    DLOG(@"=== View Dump ===");
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        [self dumpView:w indent:0];
    }
    DLOG(@"=== End Dump ===");
    g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];
}
- (void)dumpView:(UIView *)v indent:(int)indent {
    NSMutableString *prefix = [NSMutableString string];
    for (int i = 0; i < indent; i++) [prefix appendString:@"  "];
    NSString *cls = NSStringFromClass([v class]);
    NSString *text = @"";
    if ([v isKindOfClass:[UILabel class]]) text = ((UILabel *)v).text ?: @"";
    else if ([v isKindOfClass:[UIButton class]]) {
        text = [(UIButton *)v titleLabel].text ?: @"";
    }
    if (text.length > 50) text = [text substringToIndex:50];
    DLOG(@"[VIEW] %@%@ frame=%.0fx%.0f text='%@'", prefix, cls, v.frame.size.width, v.frame.size.height, text);
    for (UIView *sub in v.subviews) {
        [self dumpView:sub indent:indent + 1];
    }
}
- (void)copyLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [UIPasteboard generalPasteboard].string = content;
    DLOG(@">>> COPIED %lu chars >>>", (unsigned long)content.length);
    g_tv.text = [NSString stringWithFormat:@">>> COPIED %lu chars to clipboard <<<", (unsigned long)content.length];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self refreshLog];
    });
}
- (void)shareLog {
    @try {
        if (!g_logPath) {
            DLOG(@"[SHARE] Error: log path is nil");
            return;
        }
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:g_logPath]) {
            DLOG(@"[SHARE] Error: log file does not exist");
            return;
        }
        
        // Truncate to last 200KB to avoid crash with large files
        NSData *fullData = [NSData dataWithContentsOfFile:g_logPath];
        NSData *exportData = fullData;
        if (fullData.length > 200 * 1024) {
            exportData = [fullData subdataWithRange:NSMakeRange(fullData.length - 200 * 1024, 200 * 1024)];
            DLOG(@"[SHARE] Log truncated from %lu to 200KB", (unsigned long)fullData.length);
        }
        
        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wxhook_export.log"];
        [exportData writeToFile:tempPath atomically:YES];
        DLOG(@"[SHARE] Export file size: %lu bytes", (unsigned long)exportData.length);
        
        NSURL *fileURL = [NSURL fileURLWithPath:tempPath];
        if (!fileURL) {
            DLOG(@"[SHARE] Error: file URL is nil");
            return;
        }
        
        NSArray *items = @[fileURL];
        UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
        
        // Find top view controller safely
        UIWindow *keyWin = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in scene.windows) {
                        if (win.isKeyWindow) { keyWin = win; break; }
                    }
                    if (keyWin) break;
                }
            }
        }
        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
        if (!keyWin) keyWin = [UIApplication sharedApplication].windows.firstObject;
        
        if (!keyWin) {
            DLOG(@"[SHARE] Error: no key window found");
            return;
        }
        
        UIViewController *topVC = keyWin.rootViewController;
        if (!topVC) {
            DLOG(@"[SHARE] Error: rootViewController is nil");
            return;
        }
        while (topVC.presentedViewController && 
               ![topVC.presentedViewController isBeingDismissed]) {
            topVC = topVC.presentedViewController;
        }
        
        // Set popover for iPad only (safe check)
        if ([avc respondsToSelector:@selector(popoverPresentationController)] &&
            avc.popoverPresentationController) {
            avc.popoverPresentationController.sourceView = keyWin;
            avc.popoverPresentationController.sourceRect = CGRectMake(keyWin.bounds.size.width / 2, keyWin.bounds.size.height / 2, 1, 1);
            avc.popoverPresentationController.permittedArrowDirections = 0;
        }
        
        // Use completion block to detect presentation issues
        avc.completionWithItemsHandler = ^(UIActivityType activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
            if (activityError) {
                DLOG(@"[SHARE] Activity error: %@", activityError);
            }
            DLOG(@"[SHARE] Activity completed: %d type: %@", completed, activityType);
        };
        
        DLOG(@"[SHARE] Presenting from %@", NSStringFromClass([topVC class]));
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                [topVC presentViewController:avc animated:YES completion:^{
                    DLOG(@"[SHARE] Presented successfully");
                }];
            } @catch (NSException *e) {
                DLOG(@"[SHARE] Present exception: %@", e);
            }
        });
    } @catch (NSException *e) {
        DLOG(@"[SHARE] Exception: %@", e);
    }
}
- (void)refreshLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_tv.text = content;
    if (content.length > 0) {
        [g_tv scrollRangeToVisible:NSMakeRange(content.length - 1, 0)];
    }
}
@end

// ============================================================
#pragma mark - NSArray count hook (FORCE non-empty server list)
// ============================================================

static NSUInteger (*orig_arrayCount)(id, SEL) = NULL;

static NSUInteger hook_arrayCount(id self, SEL _cmd) {
    NSUInteger (*origFunc)(id, SEL) = (NSUInteger(*)(id, SEL))orig_arrayCount;
    NSUInteger ret = origFunc(self, _cmd);
    
    if (ret == 0) {
        @try {
            void *caller = __builtin_return_address(0);
            DLOG(@"[ARRAY-COUNT-ZERO] Array count=0 at %p", caller);
            
            NSArray *arr = (NSArray *)self;
            for (NSString *key in arr) {
                if ([key isKindOfClass:[NSString class]] && 
                    ([key containsString:@"server"] || [key containsString:@"Server"] || 
                     [key containsString:@"ip"] || [key containsString:@"port"])) {
                    DLOG(@"[ARRAY-COUNT-ZERO] Contains server-related key: %@", key);
                    ret = 3;
                    DLOG(@"[ARRAY-PATCH] Array count forced to 3");
                    break;
                }
            }
        } @catch (NSException *e) {}
    }
    return ret;
}

static void installNSArrayCountHook(void) {
    Class arrayCls = [NSArray class];
    Method countMethod = class_getInstanceMethod(arrayCls, @selector(count));
    if (countMethod) {
        orig_arrayCount = (NSUInteger(*)(id, SEL))method_getImplementation(countMethod);
        method_setImplementation(countMethod, (IMP)hook_arrayCount);
        DLOG(@"[ARRAY-HOOK] Installed NSArray count hook");
    } else {
        DLOG(@"[ARRAY-HOOK] NSArray count method not found");
    }
}

// ============================================================
#pragma mark - NSURLSession hooks (HTTP response manipulation)
// ============================================================

static id (*orig_JSONObjectWithData)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);

static id hook_JSONObjectWithData(Class self, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **error) {
    id ret = orig_JSONObjectWithData(self, _cmd, data, opt, error);
    
    @try {
        if (ret && [ret isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)ret;
            NSNumber *status = dict[@"status"];
            NSString *msg = dict[@"msg"] ?: @"";
            NSString *result = dict[@"result"] ?: @"";
            
            DLOG(@"[JSON-PARSE] JSONObjectWithData: status=%@ msg=%@ result=%@", status, msg, result);
            
            if ([msg containsString:@"版本"] || [msg containsString:@"更新"] || 
                [msg containsString:@"升级"] || [result containsString:@"fail"]) {
                DLOG(@"[JSON-PATCH] Detected version check failure, modifying...");
            }
        }
    } @catch (NSException *e) {
        DLOG(@"[JSON-PARSE] Exception: %@", e);
    }
    
    return ret;
}

static void installJSONSerializationHook(void) {
    Class jsonCls = [NSJSONSerialization class];
    if (!jsonCls) {
        DLOG(@"[JSON-HOOK] NSJSONSerialization class not found");
        return;
    }
    
    Method jsonObjMethod = class_getClassMethod(jsonCls, @selector(JSONObjectWithData:options:error:));
    if (!jsonObjMethod) {
        DLOG(@"[JSON-HOOK] JSONObjectWithData:options:error: not found");
        return;
    }
    
    orig_JSONObjectWithData = (id(*)(Class, SEL, NSData*, NSJSONReadingOptions, NSError**))method_getImplementation(jsonObjMethod);
    method_setImplementation(jsonObjMethod, (IMP)hook_JSONObjectWithData);
    DLOG(@"[JSON-HOOK] Installed NSJSONSerialization hook");
}

// ============================================================
#pragma mark - NSURLSessionDataDelegate hooks
// ============================================================

static void (*orig_urlSessionDataTaskDidReceiveData)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*) = NULL;

static void hook_urlSessionDataTaskDidReceiveData(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {
    DLOG(@"[HTTP-DATA] urlSession:dataTask:didReceiveData: len=%zu", (unsigned long)[data length]);
    
    NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (dataStr) {
        if ([dataStr containsString:@"版本"] || [dataStr containsString:@"server"] || 
            [dataStr containsString:@"status"] || [dataStr containsString:@"maintenance"]) {
            DLOG(@"[HTTP-DATA] Response contains key info: %@", dataStr);
        }
    }
    
    if (orig_urlSessionDataTaskDidReceiveData) {
        orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, data);
    }
}

static void installNSURLSessionHooks(void) {
    Class sessionCls = [NSURLSession class];
    if (!sessionCls) {
        DLOG(@"[HTTP-HOOK] NSURLSession class not found");
        return;
    }
    
    Method dataTaskMethod = class_getInstanceMethod(sessionCls, @selector(dataTaskWithRequest:completionHandler:));
    if (!dataTaskMethod) {
        DLOG(@"[HTTP-HOOK] dataTaskWithRequest:completionHandler: not found");
    } else {
        DLOG(@"[HTTP-HOOK] NSURLSession dataTaskWithRequest:completionHandler: found");
    }
    
    Class dataTaskCls = NSClassFromString(@"__NSCFLocalDataTask");
    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"__NSCFLNetworkDataTask");
    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"NSURLSessionDataTask");
    
    if (dataTaskCls) {
        DLOG(@"[HTTP-HOOK] NSURLSessionDataTask class found: %@", NSStringFromClass(dataTaskCls));
    }
}

// ============================================================
#pragma mark - ServerInfoForClient hooks (trace server list parsing)
// ============================================================

static IMP orig_msi_init = NULL;
static IMP orig_msi_initWithDict = NULL;
static IMP orig_msi_status = NULL;

static id msi_init_hook(id self, SEL _cmd);
static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict);
static NSNumber *msi_status_hook(id self, SEL _cmd);
static NSString *msi_ip_hook(id self, SEL _cmd);
static NSString *msi_category_hook(id self, SEL _cmd);
static NSNumber *msi_serverType_hook(id self, SEL _cmd);
static NSString *msi_string_hook(id self, SEL _cmd);
static NSInteger msi_int_hook(id self, SEL _cmd);

// ============================================================
#pragma mark - UITableView DataSource hooks (force server list)
// ============================================================

static IMP orig_tableView_numberOfRows = NULL;
static IMP orig_tableView_cellForRow = NULL;
static IMP orig_tableView_numberOfSections = NULL;

static NSMutableArray *fakeServerList = nil;

static void initFakeServerList(void) {
    if (fakeServerList) return;
    fakeServerList = [NSMutableArray arrayWithArray:@[
        @{@"serverid": @1, @"name": @"测试服务器1", @"ip": @"47.100.222.229", @"port": @5678, @"status": @1},
        @{@"serverid": @2, @"name": @"测试服务器2", @"ip": @"47.100.222.229", @"port": @5679, @"status": @1},
        @{@"serverid": @3, @"name": @"测试服务器3", @"ip": @"47.100.222.229", @"port": @5680, @"status": @1},
    ]];
    DLOG(@"[FAKE-SERVER] Initialized fake server list: %@", fakeServerList);
}

static BOOL isServerListDataSource(id self) {
    @try {
        if ([self respondsToSelector:@selector(dataSource)]) {
            id ds = [self dataSource];
            if (ds) {
                NSString *dsName = NSStringFromClass([ds class]);
                if ([dsName containsString:@"Server"] || [dsName containsString:@"server"] || 
                    [dsName containsString:@"List"] || [dsName containsString:@"list"] ||
                    [dsName containsString:@"Login"] || [dsName containsString:@"login"]) {
                    return YES;
                }
            }
        }
        Class cls = [self class];
        NSString *clsName = NSStringFromClass(cls);
        return ([clsName containsString:@"Server"] || [clsName containsString:@"server"] || 
                [clsName containsString:@"List"] || [clsName containsString:@"list"] ||
                [clsName containsString:@"Login"] || [clsName containsString:@"login"]);
    } @catch (NSException *e) {
        return NO;
    }
}

static NSInteger hook_numberOfRowsInSection(id self, SEL _cmd, NSInteger section) {
    NSInteger (*origFunc)(id, SEL, NSInteger) = (NSInteger(*)(id, SEL, NSInteger))orig_tableView_numberOfRows;
    NSInteger ret = origFunc(self, _cmd, section);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        DLOG(@"[TV-CALL] -[%@ numberOfRowsInSection:%ld] -> %ld (original)", clsName, (long)section, (long)ret);
        
        if (ret == 0) {
            initFakeServerList();
            ret = fakeServerList.count;
            DLOG(@"[TV-PATCH] -[%@ numberOfRowsInSection:%ld] FORCE -> %ld (fake)", clsName, (long)section, (long)ret);
        }
    }
    return ret;
}

static UITableViewCell *hook_cellForRowAtIndexPath(id self, SEL _cmd, NSIndexPath *indexPath) {
    UITableViewCell *(*origFunc)(id, SEL, NSIndexPath*) = (UITableViewCell*(*)(id, SEL, NSIndexPath*))orig_tableView_cellForRow;
    UITableViewCell *ret = origFunc(self, _cmd, indexPath);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        NSString *text = @"";
        if (ret && ret.textLabel) text = ret.textLabel.text ?: @"";
        DLOG(@"[TV-CALL] -[%@ cellForRowAtIndexPath:{%ld,%ld}] -> text='%@'", clsName, 
             (long)indexPath.section, (long)indexPath.row, text);
        
        if (!ret || (ret && [text isEqualToString:@""])) {
            DLOG(@"[TV-PATCH] Creating fake cell for server list");
            UITableViewCell *newCell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            if (newCell) {
                initFakeServerList();
                if (indexPath.row < fakeServerList.count) {
                    NSDictionary *server = fakeServerList[indexPath.row];
                    newCell.textLabel.text = server[@"name"] ?: @"测试服务器";
                    newCell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
                    DLOG(@"[TV-PATCH] Created fake cell: %@", server[@"name"]);
                }
                ret = newCell;
            }
        }
    }
    return ret;
}

static NSInteger hook_numberOfSections(id self, SEL _cmd) {
    NSInteger (*origFunc)(id, SEL) = (NSInteger(*)(id, SEL))orig_tableView_numberOfSections;
    NSInteger ret = origFunc(self, _cmd);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        DLOG(@"[TV-CALL] -[%@ numberOfSections] -> %ld", clsName, (long)ret);
        if (ret == 0) {
            ret = 1;
            DLOG(@"[TV-PATCH] -[%@ numberOfSections] FORCE -> 1", clsName);
        }
    }
    return ret;
}

// ============================================================
#pragma mark - ServerInfoForClient helper
// ============================================================

static void msi_log_properties(id self) {
    @try {
        unsigned int count = 0;
        objc_property_t *props = class_copyPropertyList([self class], &count);
        for (unsigned int i = 0; i < count; i++) {
            const char *propName = property_getName(props[i]);
            id value = [self valueForKey:[NSString stringWithUTF8String:propName]];
            if (value) {
                DLOG(@"[MSI-PROP] %s = %@", propName, value);
            }
        }
        if (props) free(props);
    } @catch (NSException *e) {
        DLOG(@"[MSI-PROP] Exception: %@", e);
    }
}

static id msi_init_hook(id self, SEL _cmd) {
    id (*origFunc)(id, SEL) = (id(*)(id, SEL))orig_msi_init;
    id ret = origFunc(self, _cmd);
    if (ret) {
        DLOG(@"[MSI-CALL] -[%@ init] -> %p", NSStringFromClass([self class]), ret);
        msi_log_properties(ret);
    }
    return ret;
}

static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict) {
    NSMutableDictionary *mutDict = nil;
    if (dict) {
        mutDict = [dict mutableCopy];
        
        if ([mutDict objectForKey:@"status"]) {
            NSNumber *status = mutDict[@"status"];
            if ([status isKindOfClass:[NSNumber class]] && [status intValue] != 1) {
                DLOG(@"[MSI-PATCH] status=%@ -> 1", status);
                mutDict[@"status"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"serverType"]) {
            NSNumber *serverType = mutDict[@"serverType"];
            if ([serverType isKindOfClass:[NSNumber class]] && [serverType intValue] != 1) {
                DLOG(@"[MSI-PATCH] serverType=%@ -> 1", serverType);
                mutDict[@"serverType"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"clientid"]) {
            NSNumber *clientid = mutDict[@"clientid"];
            if ([clientid isKindOfClass:[NSNumber class]] && [clientid intValue] != 1) {
                DLOG(@"[MSI-PATCH] clientid=%@ -> 1", clientid);
                mutDict[@"clientid"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"serverid"]) {
            NSNumber *serverid = mutDict[@"serverid"];
            if ([serverid isKindOfClass:[NSNumber class]] && [serverid intValue] != 1) {
                DLOG(@"[MSI-PATCH] serverid=%@ -> 1", serverid);
                mutDict[@"serverid"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"ip"]) {
            NSString *ip = mutDict[@"ip"];
            if ([ip isKindOfClass:[NSString class]] && ![ip isEqualToString:@"47.100.222.229"]) {
                DLOG(@"[MSI-PATCH] ip=%@ -> 47.100.222.229", ip);
                mutDict[@"ip"] = @"47.100.222.229";
            }
        }
        
        if ([mutDict objectForKey:@"category"]) {
            NSString *category = mutDict[@"category"];
            if ([category isKindOfClass:[NSString class]]) {
                BOOL isAllDots = YES;
                for (NSInteger i = 0; i < category.length; i++) {
                    if ([category characterAtIndex:i] != '.') { isAllDots = NO; break; }
                }
                if (isAllDots || [category length] == 0) {
                    DLOG(@"[MSI-PATCH] category=%@ -> 一区", category);
                    mutDict[@"category"] = @"一区";
                }
            }
        }
        
        if ([mutDict objectForKey:@"description"]) {
            NSString *desc = mutDict[@"description"];
            if ([desc isKindOfClass:[NSString class]] && [desc containsString:@"维护"]) {
                DLOG(@"[MSI-PATCH] description=%@ -> 运行", desc);
                mutDict[@"description"] = @"运行";
            }
        }
        
        DLOG(@"[MSI-CALL] -[%@ initWithDictionary:] (patched) -> %@", NSStringFromClass([self class]), [mutDict allKeys]);
        for (NSString *key in mutDict) {
            DLOG(@"[MSI-DICT]   %@ = %@", key, mutDict[key]);
        }
    }
    
    id (*origFunc)(id, SEL, NSDictionary*) = (id(*)(id, SEL, NSDictionary*))orig_msi_initWithDict;
    id ret = origFunc(self, _cmd, mutDict ?: dict);
    
    if (ret) {
        msi_log_properties(ret);
    }
    return ret;
}

static NSNumber *msi_status_hook(id self, SEL _cmd) {
    NSNumber *(*origFunc)(id, SEL) = (NSNumber*(*)(id, SEL))orig_msi_status;
    NSNumber *ret = origFunc(self, _cmd);
    if (ret && [ret intValue] != 1) {
        DLOG(@"[MSI-PATCH-STATUS] status=%@ -> 1 (property access)", ret);
        return @1;
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_ip_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    if (ret && ![ret isEqualToString:@"47.100.222.229"]) {
        DLOG(@"[MSI-PATCH-IP] ip=%@ -> 47.100.222.229 (property access)", ret);
        return @"47.100.222.229";
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_category_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    if (ret) {
        BOOL isAllDots = YES;
        for (NSInteger i = 0; i < ret.length; i++) {
            if ([ret characterAtIndex:i] != '.') { isAllDots = NO; break; }
        }
        if (isAllDots || [ret length] == 0) {
            DLOG(@"[MSI-PATCH-CAT] category=%@ -> 一区 (property access)", ret);
            return @"一区";
        }
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSNumber *msi_serverType_hook(id self, SEL _cmd) {
    NSNumber *ret = ((NSNumber*(*)(id, SEL))objc_msgSend)(self, _cmd);
    if (ret && [ret intValue] != 1) {
        DLOG(@"[MSI-PATCH-TYPE] serverType=%@ -> 1 (property access)", ret);
        return @1;
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_string_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSInteger msi_int_hook(id self, SEL _cmd) {
    NSInteger ret = ((NSInteger(*)(id, SEL))objc_msgSend)(self, _cmd);
    DLOG(@"[MSI-CALL] -[%@ %@] -> %ld", NSStringFromClass([self class]), NSStringFromSelector(_cmd), (long)ret);
    return ret;
}

static void createLogButton(UIWindow *w) {
    if (!w || g_btn) return;
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
    [w bringSubviewToFront:g_btn];
    _log(@"[UI] Button created on window");
}

static void __attribute__((noinline)) tryHookMieshiServerInfo(int attempt) {
    Class msiCls = NSClassFromString(@"ServerInfoForClient");
    if (msiCls) {
        DLOG(@"[MSI-RETRY] ServerInfoForClient class FOUND at attempt #%d!", attempt);
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(msiCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);
            DLOG(@"[MSI-RETRY] -[%@ %@]", NSStringFromClass(msiCls), selName);
        }
        if (methods) free(methods);
        
        if (!orig_msi_init) {
            Method m_init = class_getInstanceMethod(msiCls, @selector(init));
            if (m_init) {
                orig_msi_init = method_getImplementation(m_init);
                method_setImplementation(m_init, (IMP)msi_init_hook);
                DLOG(@"[MSI-HOOK] Hooked: init");
            }
        }
        
        if (!orig_msi_initWithDict) {
            Method m_initDict = class_getInstanceMethod(msiCls, @selector(initWithDictionary:));
            if (m_initDict) {
                orig_msi_initWithDict = method_getImplementation(m_initDict);
                method_setImplementation(m_initDict, (IMP)msi_initWithDict_hook);
                DLOG(@"[MSI-HOOK] Hooked: initWithDictionary:");
            }
        }
        
        if (!orig_msi_status) {
            Method m_status = class_getInstanceMethod(msiCls, @selector(status));
            if (m_status) {
                orig_msi_status = method_getImplementation(m_status);
                method_setImplementation(m_status, (IMP)msi_status_hook);
                DLOG(@"[MSI-HOOK] Hooked: status");
            }
        }
        
        Method m_statusValue = class_getInstanceMethod(msiCls, @selector(statusValue));
        if (m_statusValue) {
            method_setImplementation(m_statusValue, (IMP)msi_status_hook);
            DLOG(@"[MSI-HOOK] Hooked: statusValue");
        }
        
        Method m_ip = class_getInstanceMethod(msiCls, @selector(ip));
        if (m_ip) {
            method_setImplementation(m_ip, (IMP)msi_ip_hook);
            DLOG(@"[MSI-HOOK] Hooked: ip");
        }
        
        Method m_category = class_getInstanceMethod(msiCls, @selector(category));
        if (m_category) {
            method_setImplementation(m_category, (IMP)msi_category_hook);
            DLOG(@"[MSI-HOOK] Hooked: category");
        }
        
        Method m_serverType = class_getInstanceMethod(msiCls, @selector(serverType));
        if (m_serverType) {
            method_setImplementation(m_serverType, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverType");
        }
        
        Method m_serverId = class_getInstanceMethod(msiCls, @selector(serverid));
        if (m_serverId) {
            method_setImplementation(m_serverId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverid");
        }
        
        Method m_clientId = class_getInstanceMethod(msiCls, @selector(clientid));
        if (m_clientId) {
            method_setImplementation(m_clientId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: clientid");
        }
    } else {
        DLOG(@"[MSI-RETRY] ServerInfoForClient class not found at attempt #%d", attempt);
        if (attempt < 3) {
            double delays[] = {2.0, 5.0, 10.0};
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delays[attempt] * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                tryHookMieshiServerInfo(attempt + 1);
            });
        }
    }
}

#pragma mark - Deep Diagnostics (trace server list display)
// ============================================================

static NSArray *(*orig_arrayWithObjects)(Class, SEL, const id *, unsigned int);
static NSArray *hook_arrayWithObjects(Class self, SEL _cmd, const id *objects, unsigned int count) {
    NSArray *ret = orig_arrayWithObjects(self, _cmd, objects, count);
    DLOG(@"[DIAG-ARRAY] +[NSArray arrayWithObjects:] count=%u", count);
    for (unsigned int i = 0; i < count && i < 5; i++) {
        if (objects[i]) {
            DLOG(@"[DIAG-ARRAY]   obj[%u] = %@ (%@)", i, objects[i], NSStringFromClass([objects[i] class]));
        }
    }
    return ret;
}

static NSUInteger (*orig_tableViewNumberOfRows)(id, SEL, UITableView *, NSInteger);
static NSUInteger hook_tableViewNumberOfRows(id self, SEL _cmd, UITableView *tableView, NSInteger section) {
    NSUInteger ret = orig_tableViewNumberOfRows(self, _cmd, tableView, section);
    DLOG(@"[DIAG-TABLE] -[DataSource numberOfRowsInSection:%ld] -> %lu", (long)section, (unsigned long)ret);
    return ret;
}

static NSInteger (*orig_tableViewNumberOfSections)(id, SEL, UITableView *);
static NSInteger hook_tableViewNumberOfSections(id self, SEL _cmd, UITableView *tableView) {
    NSInteger ret = orig_tableViewNumberOfSections(self, _cmd, tableView);
    DLOG(@"[DIAG-TABLE] -[DataSource numberOfSections] -> %ld", (long)ret);
    return ret;
}

static void (*orig_alertViewShow)(id, SEL);
static void hook_alertViewShow(id self, SEL _cmd) {
    NSString *title = [self performSelector:@selector(title)];
    NSString *msg = [self performSelector:@selector(message)];
    DLOG(@"[DIAG-ALERT] UIAlertView show: title='%@' msg='%@'", title, msg);
    
    NSArray *stack = [NSThread callStackSymbols];
    for (NSUInteger i = 0; i < [stack count] && i < 20; i++) {
        DLOG(@"[DIAG-ALERT-STACK] %@", stack[i]);
    }
    
    NSString *lowerMsg = [msg lowercaseString];
    NSString *lowerTitle = [title lowercaseString];
    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 
        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
        [lowerMsg containsString:@"升级"]) {
        DLOG(@"[ALERT-BLOCK] Blocked version check alert: title='%@' msg='%@'", title, msg);
        return;
    }
    
    orig_alertViewShow(self, _cmd);
}

static void (*orig_alertControllerPresent)(id, SEL, BOOL, dispatch_block_t);
static void hook_alertControllerPresent(id self, SEL _cmd, BOOL animated, dispatch_block_t completion) {
    NSString *title = [self performSelector:@selector(title)];
    NSString *msg = [self performSelector:@selector(message)];
    DLOG(@"[DIAG-ALERT] UIAlertController present: title='%@' msg='%@'", title, msg);
    
    NSArray *stack = [NSThread callStackSymbols];
    for (NSUInteger i = 0; i < [stack count] && i < 20; i++) {
        DLOG(@"[DIAG-ALERT-STACK] %@", stack[i]);
    }
    
    NSString *lowerMsg = [msg lowercaseString];
    NSString *lowerTitle = [title lowercaseString];
    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 
        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
        [lowerMsg containsString:@"升级"]) {
        DLOG(@"[ALERT-BLOCK] Blocked version check UIAlertController: title='%@' msg='%@'", title, msg);
        return;
    }
    
    orig_alertControllerPresent(self, _cmd, animated, completion);
}

// ============================================================
#pragma mark - BSD socket hooks (detect game network traffic)
// ============================================================

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// === Socket hook functions ===
typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
typedef ssize_t (*ReadFunc)(int, void *, size_t);
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);

static ConnectFunc orig_connect = NULL;
static SendFunc orig_send = NULL;
static RecvFunc orig_recv = NULL;
static RecvfromFunc orig_recvfrom = NULL;
static RecvmsgFunc orig_recvmsg = NULL;
static WriteFunc orig_write = NULL;
static ReadFunc orig_read = NULL;

// Track connected fds for data capture
#define MAX_TRACKED_FDS 32
static int g_trackedFds[MAX_TRACKED_FDS];
static char g_trackedHosts[MAX_TRACKED_FDS][64];
static int g_trackedPorts[MAX_TRACKED_FDS];
static int g_trackedCount = 0;

static void trackFd(int fd, const char *host, int port) {
    if (g_trackedCount >= MAX_TRACKED_FDS) return;
    g_trackedFds[g_trackedCount] = fd;
    strncpy(g_trackedHosts[g_trackedCount], host, 63);
    g_trackedPorts[g_trackedCount] = port;
    g_trackedCount++;
}

static const char *getHostForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) return g_trackedHosts[i];
    }
    return NULL;
}

static int getPortForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) return g_trackedPorts[i];
    }
    return 0;
}

static void updateFdHostPort(int fd, const char *host, int port) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            DLOG(@"[FD-UPDATE] Updated fd=%d to %s:%d", fd, host, port);
            return;
        }
    }
    // Not found, add new entry
    trackFd(fd, host, port);
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    char host[64] = "unknown";
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        port = ntohs(in->sin_port);
        trackFd(sockfd, host, port);
        DLOG(@"[SOCK] connect fd=%d %s:%d", sockfd, host, port);
        
        // Game server port (12003) may be down, try anyway
        // If connection fails, we need special handling in recv
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
        trackFd(sockfd, host, port);
        DLOG(@"[SOCK] connect6 fd=%d [%s]:%d", sockfd, host, port);
    }
    
    int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
    
    // If game server connection fails, try connecting to auth server instead
    if (result != 0 && port == 12003) {
        DLOG(@"[SOCK] Game server %s:%d connection failed (%d), trying auth server", host, port, result);
        // Create auth server address
        struct sockaddr_in authAddr;
        memset(&authAddr, 0, sizeof(authAddr));
        authAddr.sin_family = AF_INET;
        authAddr.sin_port = htons(5678);  // Auth server port
        inet_pton(AF_INET, "47.100.222.229", &authAddr.sin_addr);
        result = orig_connect(sockfd, (struct sockaddr *)&authAddr, sizeof(authAddr));
        if (result == 0) {
            DLOG(@"[SOCK] Redirected game server to auth server successfully!");
            // Update fd tracking
            updateFdHostPort(sockfd, "47.100.222.229", 5678);
        }
    }
    
    return result;
}

static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    void *sendBuf = (void *)buf;
    size_t sendLen = len;
    
    if (port == 5678 && len >= 12) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu", fd, cmd, len);
        
        // UUID/MAC modification disabled - keeping original values for proper account distinction
        (void)cmd;  // suppress unused warning
    }
    
    if (host && sendLen > 0) {
        const unsigned char *p = (const unsigned char *)sendBuf;
        NSMutableString *hex = [NSMutableString stringWithCapacity:sendLen * 3];
        NSMutableString *ascii = [NSMutableString stringWithCapacity:sendLen];
        size_t showLen = sendLen > 256 ? 256 : sendLen;
        for (size_t i = 0; i < showLen; i++) {
            [hex appendFormat:@"%02X ", p[i]];
            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
        }
        DLOG(@"[SEND] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, sendLen, hex, ascii);
    }
    
    ssize_t ret = orig_send ? orig_send(fd, sendBuf, sendLen, flags) : -1;
    if (sendBuf != buf) free(sendBuf);
    return ret;
}

static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv || !buf) return -1;
    
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 1024 ? 1024 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECV] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    if (port == 5678 && ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        if (cmd == 0x07777777 || cmd == 0x87777777) {
            unsigned char *payload = (unsigned char *)buf + 8;
            ssize_t payloadLen = ret - 8;
            BOOL isGzip = (payloadLen >= 3 && payload[0] == 0x1F && payload[1] == 0x8B && payload[2] == 0x08);
            DLOG(@"[PROTO] Resource response 0x%08X isGzip=%d payloadLen=%zd", cmd, isGzip, payloadLen);
        }
        
        if (cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version check response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            if (ret >= 12) {
                uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                DLOG(@"[PROTO-R] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
                if (status4 != 0) {
                    DLOG(@"[PROTO-R-PATCH] Version check status %u -> 0 (bypass)", status4);
                    memset((unsigned char *)buf + 8, 0, 4);
                }
            }
            if (ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 1-byte status at offset 12: %u -> 0", p[12]);
                ((unsigned char *)buf)[12] = 0;
            }
        }
        
        if (cmd == 0x802EE100 || cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server info response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            unsigned char *payload = (unsigned char *)buf + 8;
            ssize_t payloadLen = ret - 8;
            DLOG(@"[PROTO-R] Server info payload len=%zd", payloadLen);
            
            if (payloadLen > 0) {
                // Direct byte-level patching - NO string conversion to avoid binary corruption
                DLOG(@"[PROTO-R] Server info payload (first 200 bytes): %@", 
                     [[NSString alloc] initWithBytes:payload length:MIN(payloadLen, 200) encoding:NSUTF8StringEncoding]);
                
                BOOL patched = NO;
                char *cpayload = (char *)payload;
                
                // Patch status=X to status=1 (only first occurrence in text)
                char *statusPos = strstr(cpayload, "status=");
                if (statusPos) {
                    char *valPos = statusPos + 7; // "status=" is 7 chars
                    if (*valPos != '1') {
                        DLOG(@"[PROTO-R-PATCH] status=%c -> 1", *valPos);
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch serverid=0 to serverid=1
                char *serveridPos = strstr(cpayload, "serverid=");
                if (serveridPos) {
                    char *valPos = serveridPos + 9; // "serverid=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] serverid=0 -> 1");
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch clientid=0 to clientid=1
                char *clientidPos = strstr(cpayload, "clientid=");
                if (clientidPos) {
                    char *valPos = clientidPos + 9; // "clientid=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] clientid=0 -> 1");
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch httpPort=0 to httpPort=8
                char *httpPortPos = strstr(cpayload, "httpPort=");
                if (httpPortPos) {
                    char *valPos = httpPortPos + 9; // "httpPort=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] httpPort=0 -> 8");
                        *valPos = '8';
                        patched = YES;
                    }
                }
                
                if (patched) {
                    DLOG(@"[PROTO-R-PATCH] Server info patched successfully (byte-level, no corruption)");
                } else {
                    DLOG(@"[PROTO-R-PATCH] Server info no changes needed");
                }
            } else {
                DLOG(@"[PROTO-R-PATCH] Server info payload empty");
            }
        }
        
        if (cmd == 0x8002A017) {
            DLOG(@"[PROTO-R] Login response 0x8002A017 pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            if (ret >= 16) {
                uint32_t status = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                  ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO-R] Login status at offset 12-15: %u (0x%08X)", status, status);
                if (status != 0) {
                    DLOG(@"[PROTO-R-PATCH] Login status %u -> 0 (force success)", status);
                    memset((unsigned char *)buf + 12, 0, 4);
                }
            }
        }
        
        if (cmd == 0x8002A016) {
            DLOG(@"[PROTO-R] Server list response 0x8002A016 pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            if (ret >= 16) {
                uint32_t status8 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                uint32_t status12 = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                    ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO-R] Server list status: offset 8-11=%u, offset 12-15=%u", status8, status12);
                if (status8 != 0 || status12 != 0) {
                    DLOG(@"[PROTO-R-PATCH] Server list status %u/%u -> 0", status8, status12);
                    memset((unsigned char *)buf + 8, 0, 8);
                }
            }
        }
    }
    
    return ret;
}

static ssize_t hook_write(int fd, const void *buf, size_t len) {
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    if (host && len > 0 && len < 4096) {
        const unsigned char *p = (const unsigned char *)buf;
        NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];
        NSMutableString *ascii = [NSMutableString stringWithCapacity:len];
        size_t showLen = len > 128 ? 128 : len;
        for (size_t i = 0; i < showLen; i++) {
            [hex appendFormat:@"%02X ", p[i]];
            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
        }
        DLOG(@"[WRITE] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, len, hex, ascii);
        
        // Version patch DISABLED in write too
        (void)port;
    }
    return orig_write ? orig_write(fd, buf, len) : -1;
}

static ssize_t hook_read(int fd, void *buf, size_t len) {
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_read || !buf) return -1;
    
    ssize_t ret = orig_read(fd, buf, len);
    if (ret <= 0 || ret >= 4096) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 128 ? 128 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[READ] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    // Version check response: ret >= 13
    if (port == 5678 && ret >= 13) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-R] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        if (cmd == 0x802EE118) {
            DLOG(@"[PROTO-R] Version check response 0x802EE118 pktLen=%u ret=%zd", pktLenBE, ret);
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            DLOG(@"[PROTO-R] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
            if (status4 != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 4-byte status %u -> 0", status4);
                memset((unsigned char *)buf + 8, 0, 4);
            }
            if (ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 1-byte status at offset 12: %u -> 0", p[12]);
                ((unsigned char *)buf)[12] = 0;
            }
        }

        if (cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version check response 0x802EE121 pktLen=%u ret=%zd", pktLenBE, ret);
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            DLOG(@"[PROTO-R] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
            if (status4 != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 4-byte status %u -> 0", status4);
                memset((unsigned char *)buf + 8, 0, 8);
            }
        }
        
        if (cmd == 0x802EE100 || cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server info response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            unsigned char *payload = (unsigned char *)buf + 8;
            ssize_t payloadLen = ret - 8;
            DLOG(@"[PROTO-R] Server info payload len=%zd", payloadLen);
            
            if (payloadLen > 0) {
                // Direct byte-level patching - NO string conversion to avoid binary corruption
                DLOG(@"[PROTO-R] Server info payload (first 200 bytes): %@", 
                     [[NSString alloc] initWithBytes:payload length:MIN(payloadLen, 200) encoding:NSUTF8StringEncoding]);
                
                BOOL patched = NO;
                char *cpayload = (char *)payload;
                
                // Patch status=X to status=1 (only first occurrence in text)
                char *statusPos = strstr(cpayload, "status=");
                if (statusPos) {
                    char *valPos = statusPos + 7; // "status=" is 7 chars
                    if (*valPos != '1') {
                        DLOG(@"[PROTO-R-PATCH] status=%c -> 1", *valPos);
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch serverid=0 to serverid=1
                char *serveridPos = strstr(cpayload, "serverid=");
                if (serveridPos) {
                    char *valPos = serveridPos + 9; // "serverid=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] serverid=0 -> 1");
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch clientid=0 to clientid=1
                char *clientidPos = strstr(cpayload, "clientid=");
                if (clientidPos) {
                    char *valPos = clientidPos + 9; // "clientid=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] clientid=0 -> 1");
                        *valPos = '1';
                        patched = YES;
                    }
                }
                
                // Patch httpPort=0 to httpPort=8
                char *httpPortPos = strstr(cpayload, "httpPort=");
                if (httpPortPos) {
                    char *valPos = httpPortPos + 9; // "httpPort=" is 9 chars
                    if (*valPos == '0') {
                        DLOG(@"[PROTO-R-PATCH] httpPort=0 -> 8");
                        *valPos = '8';
                        patched = YES;
                    }
                }
                
                if (patched) {
                    DLOG(@"[PROTO-R-PATCH] Server info patched successfully (byte-level, no corruption)");
                } else {
                    DLOG(@"[PROTO-R-PATCH] Server info no changes needed");
                }
            } else {
                DLOG(@"[PROTO-R-PATCH] Server info payload empty");
            }
        }
        
        if (ret >= 16) {
            if (cmd == 0x8002A017) {
                DLOG(@"[PROTO-R] Login response 0x8002A017 pktLen=%u ret=%zd", pktLenBE, ret);
                uint32_t status = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                  ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO-R] Login status at offset 12-15: %u (0x%08X)", status, status);
                if (status != 0) {
                    DLOG(@"[PROTO-R-PATCH] Login status %u -> 0 (force success)", status);
                    memset((unsigned char *)buf + 12, 0, 4);
                }
            }
            
            if (cmd == 0x8002A016) {
                DLOG(@"[PROTO-R] Server list response 0x8002A016 pktLen=%u ret=%zd", pktLenBE, ret);
                uint32_t status8 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                uint32_t status12 = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                    ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO-R] Server list status at offset 8-11: %u (0x%08X), offset 12-15: %u (0x%08X)", status8, status8, status12, status12);
                if (status8 != 0 || status12 != 0) {
                    DLOG(@"[PROTO-R-PATCH] Server list status %u/%u -> 0 (force success)", status8, status12);
                    memset((unsigned char *)buf + 8, 0, 8);
                }
            }
        }
    }
    
    if (port == 5678) {
        static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
            if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                DLOG(@"[PATCH-R] Detected '版本过低' in response at offset %zd", i);
                memset((unsigned char *)buf + i, ' ', sizeof(verLow));
            }
        }
        static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
            if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                DLOG(@"[PATCH-R] Detected '当前版本' in response at offset %zd", i);
                memset((unsigned char *)buf + i, ' ', sizeof(curVer));
            }
        }
    }
    
    return ret;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom || !buf) return -1;
    
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    // Apply same patches as hook_recv
    if (port == 5678 && ret >= 13) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[RECVFROM] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        if (cmd == 0x802EE121) {
            DLOG(@"[PROTO-RF] Version check response 0x802EE121 - clearing error messages");
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            if (status4 != 0) {
                DLOG(@"[PROTO-RF-PATCH] Status %u -> 0", status4);
                memset((unsigned char *)buf + 8, 0, 4);
            }
            if (ret > 12) {
                DLOG(@"[PROTO-RF-PATCH] Clearing message from offset 12");
                memset((unsigned char *)buf + 12, 0, ret - 12);
            }
        }
        
        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-RF] Server list response 0x802EE113 - pktLen=%u ret=%zd", pktLenBE, ret);
            
            // Track server list response count
            static int serverListCountRF = 0;
            serverListCountRF++;
            DLOG(@"[PROTO-RF] Server list response #%d", serverListCountRF);
            
            // 1. Patch protocol status at offset 8-11 to 0
            ((unsigned char *)buf)[8] = 0;
            ((unsigned char *)buf)[9] = 0;
            ((unsigned char *)buf)[10] = 0;
            ((unsigned char *)buf)[11] = 0;
            DLOG(@"[PROTO-RF-PATCH] Protocol status set to 0");
            
            unsigned char *data = (unsigned char *)buf;
            
            // 3. Patch JSON status=6 to status=1 (for ALL responses)
            for (size_t i = 0; i + 7 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 't' && data[i+2] == 'a' && data[i+3] == 't' && 
                    data[i+4] == 'u' && data[i+5] == 's' && data[i+6] == '=' && data[i+7] == '6') {
                    DLOG(@"[PROTO-RF-PATCH] Found 'status=6' at offset %zu, changing to 1", i);
                    data[i+7] = '1';
                }
            }
            
            // 4. Patch serverType=2 to serverType=1 (for ALL responses)
            for (size_t i = 0; i + 11 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 'e' && data[i+2] == 'r' && data[i+3] == 'v' && 
                    data[i+4] == 'e' && data[i+5] == 'r' && data[i+6] == 'T' && data[i+7] == 'y' &&
                    data[i+8] == 'p' && data[i+9] == 'e' && data[i+10] == '=' && data[i+11] == '2') {
                    DLOG(@"[PROTO-RF-PATCH] Found 'serverType=2' at %zu, changing to 1", i);
                    data[i+11] = '1';
                }
            }
            
            // 5. Patch clientid=0 to clientid=1 (for ALL responses)
            for (size_t i = 0; i + 9 < (size_t)ret; i++) {
                if (data[i] == 'c' && data[i+1] == 'l' && data[i+2] == 'i' && data[i+3] == 'e' && 
                    data[i+4] == 'n' && data[i+5] == 't' && data[i+6] == 'i' && data[i+7] == 'd' &&
                    data[i+8] == '=' && data[i+9] == '0') {
                    DLOG(@"[PROTO-RF-PATCH] Found 'clientid=0' at %zu, changing to 1", i);
                    data[i+9] = '1';
                }
            }
            
            // 6. Patch serverid=0 to serverid=1 (for ALL responses)
            for (size_t i = 0; i + 9 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 'e' && data[i+2] == 'r' && data[i+3] == 'v' && 
                    data[i+4] == 'e' && data[i+5] == 'r' && data[i+6] == 'i' && data[i+7] == 'd' &&
                    data[i+8] == '=' && data[i+9] == '0') {
                    DLOG(@"[PROTO-RF-PATCH] Found 'serverid=0' at %zu, changing to 1", i);
                    data[i+9] = '1';
                }
            }
            
            // 7. Replace old IP (with quotes)
            const char *oldIP = "'47.100.204.160'";
            const char *newIP = "'47.100.222.229'";
            for (size_t i = 0; i + 16 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldIP, 16) == 0) {
                    DLOG(@"[PROTO-RF-PATCH] Found old IP at %zu, replacing", i);
                    memcpy(data + i, newIP, 16);
                }
            }
            
            // 8. Patch category
            const unsigned char oldCat[] = {0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E};
            const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};
            for (size_t i = 0; i + 6 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldCat, 6) == 0) {
                    memcpy(data + i, newCat, 6);
                }
            }
            
            // 9. Patch description '服务器维护中...' to '运行'
            const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 
                                             0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 
                                             0x2E, 0x2E, 0x2E};
            const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};
            for (size_t i = 0; i + 21 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldDesc, 21) == 0) {
                    DLOG(@"[PROTO-RF-PATCH] Found '服务器维护中...' at %zu, replacing with '运行'", i);
                    memcpy(data + i, newDesc, 6);
                    for (size_t j = 6; j < 21; j++) data[i+j] = ' ';
                }
            }
            
            DLOG(@"[PROTO-RF] Server list patching complete (response #%d, %zd bytes)", serverListCountRF, ret);
        }
    }
    
    return ret;
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;
    
    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    
    // Apply same patches as hook_recv
    if (port == 5678 && ret >= 13) {
        struct iovec *iov = msg->msg_iov;
        if (iov->iov_base && iov->iov_len >= 13) {
            const unsigned char *p = (const unsigned char *)iov->iov_base;
            uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
            uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                                ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            DLOG(@"[RECVMSG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            if (cmd == 0x802EE121) {
                DLOG(@"[PROTO-RM] Version check response 0x802EE121 - clearing error messages");
                uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                if (status4 != 0) {
                    DLOG(@"[PROTO-RM-PATCH] Status %u -> 0", status4);
                    memset((unsigned char *)iov->iov_base + 8, 0, 4);
                }
                if (iov->iov_len > 12) {
                    DLOG(@"[PROTO-RM-PATCH] Clearing message from offset 12");
                    memset((unsigned char *)iov->iov_base + 12, 0, iov->iov_len - 12);
                }
            }
            
            if (cmd == 0x802EE113) {
                DLOG(@"[PROTO-RM] Server list response 0x802EE113 - applying full patch");
                uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                if (status4 != 0) {
                    DLOG(@"[PROTO-RM-PATCH] Protocol status %u -> 0", status4);
                    memset((unsigned char *)iov->iov_base + 8, 0, 4);
                }
                unsigned char *data = (unsigned char *)iov->iov_base;
                
                if (iov->iov_len >= 16 && data[12] == 0x01) {
                    DLOG(@"[PROTO-RM-PATCH] Server count 1 -> 5");
                    data[12] = 0x05;
                }
                
                for (size_t i = 0; i + 7 < iov->iov_len; i++) {
                    if (data[i] == 's' && data[i+1] == 't' && data[i+2] == 'a' && data[i+3] == 't' && 
                        data[i+4] == 'u' && data[i+5] == 's' && data[i+6] == '=') {
                        data[i+7] = '1';
                    }
                }
                
                const char *oldIP = "47.100.204.160";
                const char *newIP = "47.100.222.229";
                for (size_t i = 0; i + 15 <= iov->iov_len; i++) {
                    if (memcmp(data + i, oldIP, 15) == 0) {
                        memcpy(data + i, newIP, 15);
                    }
                }
                
                // Patch category='......' to '一区'
                const unsigned char oldCat[] = {0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E};
                const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};
                for (size_t i = 0; i + sizeof(oldCat) <= iov->iov_len; i++) {
                    if (memcmp(data + i, oldCat, sizeof(oldCat)) == 0) {
                        memcpy(data + i, newCat, sizeof(newCat));
                    }
                }
                
                // Patch description '服务器维护中...' to '运行'
                const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 
                                                 0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 
                                                 0x2E, 0x2E, 0x2E};
                const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};
                for (size_t i = 0; i + 21 <= iov->iov_len; i++) {
                    if (memcmp(data + i, oldDesc, 21) == 0) {
                        DLOG(@"[PROTO-RM-PATCH] Found '服务器维护中...' at %zu, replacing with '运行'", i);
                        memcpy(data + i, newDesc, 6);
                        for (size_t j = 6; j < 21; j++) data[i+j] = ' ';
                    }
                }
            }
        }
    }
    
    return ret;
}

// === Universal fishhook: patch symbol in ALL loaded images ===
static int rebindSymbol(const char *symbolName, void *replacement, void **original) {
    int totalPatched = 0;
    uint32_t imageCount = _dyld_image_count();
    size_t pageSize = 16384;
    
    for (uint32_t img = 0; img < imageCount; img++) {
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!header || header->magic != 0xFEEDFACF) continue;
        
        const struct load_command *cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
        const struct segment_command_64 *linkeditSeg = NULL;
        struct symtab_command *symtab = NULL;
        struct dysymtab_command *dysymtab = NULL;
        
        // Collect data segments
        const struct segment_command_64 *dataSegs[8];
        int dataSegCount = 0;
        
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) linkeditSeg = seg;
                else if (strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
                    if (dataSegCount < 8) dataSegs[dataSegCount++] = seg;
                }
            } else if (cmd->cmd == LC_SYMTAB) {
                symtab = (struct symtab_command *)cmd;
            } else if (cmd->cmd == LC_DYSYMTAB) {
                dysymtab = (struct dysymtab_command *)cmd;
            }
            cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        
        if (!linkeditSeg || !symtab || !dysymtab) continue;
        
        char *linkeditBase = (char *)slide + linkeditSeg->vmaddr - linkeditSeg->fileoff;
        const struct nlist_64 *syms = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
        char *strtab = (char *)(linkeditBase + symtab->stroff);
        uint32_t *indirectSyms = (uint32_t *)(linkeditBase + dysymtab->indirectsymoff);
        
        for (int d = 0; d < dataSegCount; d++) {
            const struct section_64 *sec = (const struct section_64 *)((char *)dataSegs[d] + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < dataSegs[d]->nsects; s++) {
                // Check both __la_symbol_ptr and __got
                if (strcmp(sec[s].sectname, "__la_symbol_ptr") != 0 &&
                    strcmp(sec[s].sectname, "__got") != 0) continue;
                
                void **pointers = (void **)((char *)slide + sec[s].addr);
                uint32_t count = (uint32_t)(sec[s].size / sizeof(void *));
                for (uint32_t j = 0; j < count; j++) {
                    uint32_t symIdx = indirectSyms[sec[s].reserved1 + j];
                    if (symIdx >= symtab->nsyms) continue;
                    const char *name = strtab + syms[symIdx].n_un.n_strx;
                    if (strcmp(name, symbolName) == 0) {
                        void *page = (void *)((uintptr_t)&pointers[j] & ~(pageSize - 1));
                        if (mprotect(page, pageSize, PROT_READ | PROT_WRITE) == 0) {
                            if (original && !*original) *original = pointers[j];
                            pointers[j] = replacement;
                            totalPatched++;
                        }
                    }
                }
            }
        }
    }
    return totalPatched;
}

static void installSocketHooks(void) {
    orig_connect = NULL;
    orig_send = NULL;
    orig_recv = NULL;
    orig_write = NULL;
    orig_read = NULL;
    
    int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);
    int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);
    int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
    int w = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);
    int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);
    
    DLOG(@"[SOCK] Hooks: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d write=%d read=%d", c, s, r, rf, rm, w, rd);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p", orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg);
}

// ============================================================
#pragma mark - DYLD API Hooking (hide injected dylibs from detection)
// ============================================================

static const char *g_hiddenDylibs[] = {
    "WangXianHook", "lnSignature", "libSupport", "liblnSignature", "substrate", "frida", NULL
};

static BOOL shouldHideDylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hiddenDylibs[i]; i++) {
        if (strstr(name, g_hiddenDylibs[i])) return YES;
    }
    return NO;
}

// Store original dyld functions
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;

// Count of hidden images (computed at init)
static uint32_t g_hiddenCount = 0;
static uint32_t g_hiddenIndices[32] = {0};

// Hooked dyld_image_count - return reduced count
static uint32_t hook_dyld_image_count(void) {
    uint32_t realCount = orig_dyld_image_count ? orig_dyld_image_count() : 0;
    uint32_t fakeCount = realCount - g_hiddenCount;
    DLOG(@"[DYLD-HOOK] image_count: real=%u fake=%u", realCount, fakeCount);
    return fakeCount;
}

// Hooked dyld_get_image_name - filter out hidden libraries
static const char *hook_dyld_get_image_name(uint32_t index) {
    if (!orig_dyld_get_image_name) return "";
    
    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;
    if (index >= fakeCount) {
        DLOG(@"[DYLD-HOOK] get_image_name(%u): index out of range (fakeCount=%u)", index, fakeCount);
        return "";
    }
    
    // Map fake index to real index (skip hidden ones)
    uint32_t realIndex = index;
    for (uint32_t i = 0; i < g_hiddenCount; i++) {
        if (g_hiddenIndices[i] <= realIndex) {
            realIndex++;
        }
    }
    
    const char *name = orig_dyld_get_image_name(realIndex);
    if (shouldHideDylib(name)) {
        DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): STILL hidden '%s', skipping", index, realIndex, name);
        // Find next non-hidden
        while (shouldHideDylib(name) && realIndex < orig_dyld_image_count()) {
            realIndex++;
            name = orig_dyld_get_image_name(realIndex);
        }
    }
    
    DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): '%s'", index, realIndex, name ?: "");
    return name ?: "";
}

// Hooked dyld_get_image_header - return header for mapped index
static const struct mach_header *hook_dyld_get_image_header(uint32_t index) {
    if (!orig_dyld_get_image_header) return NULL;
    
    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;
    if (index >= fakeCount) return NULL;
    
    // Map fake index to real index
    uint32_t realIndex = index;
    for (uint32_t i = 0; i < g_hiddenCount; i++) {
        if (g_hiddenIndices[i] <= realIndex) {
            realIndex++;
        }
    }
    
    return orig_dyld_get_image_header(realIndex);
}

// Compute hidden indices at initialization
static void computeHiddenIndices(void) {
    g_hiddenCount = 0;
    uint32_t realCount = _dyld_image_count();
    for (uint32_t i = 0; i < realCount && g_hiddenCount < 32; i++) {
        const char *name = _dyld_get_image_name(i);
        if (shouldHideDylib(name)) {
            g_hiddenIndices[g_hiddenCount++] = i;
            DLOG(@"[DYLD-HIDE] Index %u: '%s' will be hidden", i, name);
        }
    }
    DLOG(@"[DYLD-HIDE] Total hidden: %u / %u", g_hiddenCount, realCount);
}

static void installDyldHooks(void) {
    // Compute hidden indices first
    computeHiddenIndices();
    
    // Get original functions
    orig_dyld_image_count = _dyld_image_count;
    orig_dyld_get_image_name = _dyld_get_image_name;
    orig_dyld_get_image_header = _dyld_get_image_header;
    
    // Try to rebind via fishhook (works for calls through PLT)
    rebindSymbol("_dyld_image_count", (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count);
    rebindSymbol("_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    rebindSymbol("_dyld_get_image_header", (void *)hook_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    
    DLOG(@"[DYLD-HOOK] Installed hooks for image_count/get_image_name/get_image_header");
}

// ============================================================
#pragma mark - dladdr Hook (hide hook function origin)
// ============================================================

typedef int (*DladdrFunc)(const void *, Dl_info *);
static DladdrFunc orig_dladdr = NULL;

static int hook_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr || !info) return 0;
    
    int ret = orig_dladdr(addr, info);
    if (ret && info->dli_fname) {
        // If the address belongs to our hidden dylib, return fake info
        if (shouldHideDylib(info->dli_fname)) {
            DLOG(@"[DLADDR-HOOK] Hiding origin of addr %p (was '%s')", addr, info->dli_fname);
            // Return libSystem.B.dylib as the origin
            info->dli_fname = "/usr/lib/libSystem.B.dylib";
            info->dli_fbase = (void *)0x19d500000;  // Fake base
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
        }
    }
    return ret;
}

static void installDladdrHook(void) {
    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
    if (libdyld) {
        orig_dladdr = (DladdrFunc)dlsym(libdyld, "dladdr");
        rebindSymbol("_dladdr", (void *)hook_dladdr, (void **)&orig_dladdr);
        DLOG(@"[DLADDR-HOOK] Installed, orig=%p", orig_dladdr);
    }
}

// ============================================================
#pragma mark - /proc/self/maps filtering (Linux fallback)
// ============================================================

static BOOL shouldHideLine(const char *line) {
    return shouldHideDylib(line);
}

// Hook fopen to detect /proc/self/maps access
typedef FILE *(*FopenFunc)(const char *, const char *);
static FopenFunc orig_fopen = NULL;
static FILE *hook_fopen(const char *path, const char *mode) {
    FILE *f = orig_fopen ? orig_fopen(path, mode) : NULL;
    if (f && path && strstr(path, "/proc/self/maps")) {
        DLOG(@"[PROC] /proc/self/maps opened");
    }
    return f;
}

// Hook fgets to filter out our dylibs from /proc/self/maps
typedef char *(*FgetsFunc)(char *, int, FILE *);
static FgetsFunc orig_fgets = NULL;
static char *hook_fgets(char *buf, int size, FILE *stream) {
    char *result = orig_fgets ? orig_fgets(buf, size, stream) : NULL;
    if (result && shouldHideLine(result)) {
        buf[0] = '\n';
        buf[1] = '\0';
    }
    return result;
}

static void installSecurityHooks(void) {
    // Log all loaded dylibs for diagnosis (use original functions before hook)
    uint32_t count = _dyld_image_count();
    DLOG(@"[DYLD] Total loaded images: %u", count);
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            NSString *nsname = [NSString stringWithUTF8String:name];
            if ([nsname containsString:@".dylib"]) {
                DLOG(@"[DYLD] %u: %@", i, nsname.lastPathComponent);
            }
        }
    }
    
    // Install DYLD hooks to hide injected libraries
    installDyldHooks();
    installDladdrHook();
    
    // Hook fopen/fgets for /proc/self/maps (Linux fallback)
    void *syslib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);
    if (syslib) {
        void *fp = dlsym(syslib, "fopen");
        void *fg = dlsym(syslib, "fgets");
        DLOG(@"[SEC] libSystem: fopen=%p fgets=%p", fp, fg);
    }
    
    DLOG(@"[SEC] Security hooks ready (with DYLD hiding)");
}

// ============================================================
#pragma mark - NSUserDefaults observation (log reads, set verify flags)
// ============================================================

typedef id (*ObjForKeyIMP)(id, SEL, NSString *);
static ObjForKeyIMP orig_objectForKey = NULL;
static int g_nsudCount = 0;
static id hook_objectForKey(id self, SEL _cmd, NSString *key) {
    id val = orig_objectForKey ? orig_objectForKey(self, _cmd, key) : nil;
    // Log first 50 NSUserDefaults reads to avoid spam
    if (g_nsudCount < 50) {
        DLOG(@"[NSUD] objectForKey: %@ = %@", key, val);
    }
    g_nsudCount++;
    return val;
}

typedef BOOL (*BoolForKeyIMP)(id, SEL, NSString *);
static BoolForKeyIMP orig_boolForKey = NULL;
static BOOL hook_boolForKey(id self, SEL _cmd, NSString *key) {
    BOOL val = orig_boolForKey ? orig_boolForKey(self, _cmd, key) : NO;
    if (g_nsudCount < 50) {
        DLOG(@"[NSUD] boolForKey: %@ = %d", key, val);
    }
    g_nsudCount++;
    return val;
}

// ============================================================
#pragma mark - Observation-only hooks (log, don't modify)
// ============================================================

// UITableView data source hooks - trace server list display
static NSInteger (*orig_numberOfRows)(id, SEL, NSInteger) = NULL;
static NSInteger (*orig_numberOfSections)(id, SEL) = NULL;
static NSInteger hook_numberOfRows(id self, SEL _cmd, NSInteger section) {
    NSInteger ret = orig_numberOfRows ? orig_numberOfRows(self, _cmd, section) : 0;
    NSString *cls = NSStringFromClass([self class]);
    if ([cls containsString:@"Server"] || [cls containsString:@"server"] || 
        [cls containsString:@"List"] || [cls containsString:@"list"] ||
        [cls containsString:@"Table"] || [cls containsString:@"table"]) {
        DLOG(@"[TABLE] numberOfRowsInSection:%ld -> %ld class=%@", (long)section, (long)ret, cls);
    }
    return ret;
}

// NSDictionary objectForKey: - trace server list parsing
static id (*orig_dictObjectForKey)(id, SEL, id) = NULL;
static id hook_dictObjectForKey(id self, SEL _cmd, id key) {
    id ret = orig_dictObjectForKey ? orig_dictObjectForKey(self, _cmd, key) : nil;
    NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
    // Log server-related keys
    if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
        [keyStr containsString:@"status"] || [keyStr containsString:@"Status"] ||
        [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
        NSString *retCls = ret ? NSStringFromClass([ret class]) : @"nil";
        DLOG(@"[DICT] objectForKey:'%@' -> %@ (%@)", keyStr, ret ?: @"nil", retCls);
    }
    return ret;
}

// NSArray arrayForKey: - for JSON parsing
static id (*orig_arrayForKey)(id, SEL, id) = NULL;
static id hook_arrayForKey(id self, SEL _cmd, id key) {
    id ret = orig_arrayForKey ? orig_arrayForKey(self, _cmd, key) : nil;
    NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
    if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
        [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
        NSUInteger cnt = 0;
        if ([ret isKindOfClass:[NSArray class]]) cnt = [ret count];
        DLOG(@"[DICT] arrayForKey:'%@' -> count=%lu", keyStr, (unsigned long)cnt);
    }
    return ret;
}

// NSURLSession.dataTaskWithRequest:completionHandler: - observe only
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static DTReqCompIMP orig_dtwrc = NULL;
static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = req.URL.absoluteString;
    DLOG(@"[NET] URL: %@", url);
    
    // Wrap completion handler to observe response (don't modify)
    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;
    if (comp) {
        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSHTTPURLResponse *httpResp = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;
            DLOG(@"[NET] Response: status=%ld url=%@ err=%@ bodyLen=%lu",
                 httpResp ? (long)httpResp.statusCode : -1, url, err, (unsigned long)data.length);
            if (data && data.length > 0 && data.length < 2000) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (body) DLOG(@"[NET] Body: %@", body);
            }
            comp(data, resp, err);
        } copy];
    }
    
    if (orig_dtwrc) return orig_dtwrc(self, _cmd, req, wrappedComp);
    return nil;
}

// NSURLSession.dataTaskWithRequest: (delegate mode, no completion handler)
// OBSERVE ONLY - no interception (delegate injection causes crashes)
typedef NSURLSessionDataTask *(*DTReqIMP)(id, SEL, NSURLRequest *);
static DTReqIMP orig_dtr = NULL;
static NSURLSessionDataTask *hook_dtr(id self, SEL _cmd, NSURLRequest *req) {
    DLOG(@"[NET-D] delegate URL: %@", req.URL.absoluteString);
    if (orig_dtr) return orig_dtr(self, _cmd, req);
    return nil;
}

// NSURLConnection.sendAsynchronousRequest:queue:completionHandler:
typedef void (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, void (^)(NSURLResponse *, NSData *, NSError *));
static AsyncReqIMP orig_asyncReq = NULL;
static void hook_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *q, void (^comp)(NSURLResponse *, NSData *, NSError *)) {
    DLOG(@"[NET-C] async URL: %@", req.URL.absoluteString);
    if (orig_asyncReq) orig_asyncReq(self, _cmd, req, q, comp);
}

// NSURLConnection.sendSynchronousRequest:returningResponse:error:
typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);
static SyncReqIMP orig_syncReq = NULL;
static NSData *hook_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **err) {
    DLOG(@"[NET-C] sync URL: %@", req.URL.absoluteString);
    if (orig_syncReq) return orig_syncReq(self, _cmd, req, resp, err);
    return nil;
}

// UIViewController.presentViewController - observe only
typedef void (*PresentVC_IMP)(id, SEL, UIViewController *, BOOL, void (^)(void));
static PresentVC_IMP orig_presentVC = NULL;
static void hook_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    NSString *vcClass = NSStringFromClass([vc class]);
    NSString *title = @"";
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        title = [NSString stringWithFormat:@" title='%@' msg='%@'", alert.title ?: @"", alert.message ?: @""];
    }
    DLOG(@"[UI] presentVC: %@%@", vcClass, title);
    if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark - Constructor - MINIMAL + observer hooks
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    // === IMMEDIATE: Anti-cheat bypass (diagnostic) ===
    installSecurityHooks();
    
    // Save original connect() via RTLD_NEXT as fallback
    orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    DLOG(@"[SOCK] Fallback originals: connect=%p send=%p recv=%p", orig_connect, orig_send, orig_recv);
    
    // Install socket hooks via universal fishhook (all images)
    installSocketHooks();
    
    // === IMMEDIATE: NSUserDefaults hooks ===
    Class udCls = [NSUserDefaults class];
    if (udCls) {
        Method m1 = class_getInstanceMethod(udCls, @selector(objectForKey:));
        if (m1) { orig_objectForKey = (ObjForKeyIMP)method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_objectForKey); }
        Method m2 = class_getInstanceMethod(udCls, @selector(boolForKey:));
        if (m2) { orig_boolForKey = (BoolForKeyIMP)method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_boolForKey); }
        _log(@"[INIT] NSUserDefaults hooked (objectForKey + boolForKey)");
    }
    
    // === IMMEDIATE: Observation-only hooks ===
    // NSURLSession completion handler mode
    Class sessCls = [NSURLSession class];
    if (sessCls) {
        Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
        if (m) { orig_dtwrc = (DTReqCompIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_dtwrc); _log(@"[INIT] NSURLSession.dataTask+comp observe"); }
        // Delegate mode (no completion handler)
        m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:));
        if (m) { orig_dtr = (DTReqIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_dtr); _log(@"[INIT] NSURLSession.dataTask delegate observe"); }
    }
    // NSURLConnection
    Class connCls = [NSURLConnection class];
    if (connCls) {
        Method am = class_getClassMethod(connCls, @selector(sendAsynchronousRequest:queue:completionHandler:));
        if (am) { orig_asyncReq = (AsyncReqIMP)method_getImplementation(am); method_setImplementation(am, (IMP)hook_async); }
        Method sm = class_getClassMethod(connCls, @selector(sendSynchronousRequest:returningResponse:error:));
        if (sm) { orig_syncReq = (SyncReqIMP)method_getImplementation(sm); method_setImplementation(sm, (IMP)hook_sync); }
        _log(@"[INIT] NSURLConnection observe");
    }
    // UIViewController present
    Class vcCls = [UIViewController class];
    if (vcCls) {
        Method m = class_getInstanceMethod(vcCls, @selector(presentViewController:animated:completion:));
        if (m) { orig_presentVC = (PresentVC_IMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_presentVC); _log(@"[INIT] presentVC observe"); }
    }
    
    // === DIAGNOSTIC: UITableView data source hooks ===
    Class tvCls = [UITableView class];
    if (tvCls) {
        Method m = class_getInstanceMethod(tvCls, @selector(numberOfRowsInSection:));
        if (m) { orig_numberOfRows = (NSInteger (*)(id, SEL, NSInteger))method_getImplementation(m); method_setImplementation(m, (IMP)hook_numberOfRows); _log(@"[INIT] UITableView.numberOfRowsInSection: observe"); }
        m = class_getInstanceMethod(tvCls, @selector(numberOfSections));
        if (m) { orig_numberOfSections = (NSInteger (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_numberOfSections); _log(@"[INIT] UITableView.numberOfSections: observe"); }
    }
    
    // === DIAGNOSTIC: UIAlertView show hook ===
    Class alertCls = [UIAlertView class];
    if (alertCls) {
        Method m = class_getInstanceMethod(alertCls, @selector(show));
        if (m) { orig_alertViewShow = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertViewShow); _log(@"[INIT] UIAlertView.show: hook"); }
    }
    
    // === DIAGNOSTIC: UIAlertController hook ===
    Class alertCtrlCls = [UIAlertController class];
    if (alertCtrlCls) {
        Method m = class_getInstanceMethod(alertCtrlCls, @selector(presentViewController:animated:completion:));
        if (m) { orig_alertControllerPresent = (void (*)(id, SEL, BOOL, dispatch_block_t))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertControllerPresent); _log(@"[INIT] UIAlertController.present: hook"); }
    }
    
    // === DIAGNOSTIC: NSDictionary hooks ===
    Class dictCls = [NSDictionary class];
    if (dictCls) {
        Method m = class_getInstanceMethod(dictCls, @selector(objectForKey:));
        if (m) { orig_dictObjectForKey = (id (*)(id, SEL, id))method_getImplementation(m); method_setImplementation(m, (IMP)hook_dictObjectForKey); _log(@"[INIT] NSDictionary.objectForKey: observe"); }
        m = class_getInstanceMethod(dictCls, @selector(arrayForKey:));
        if (m) { orig_arrayForKey = (id (*)(id, SEL, id))method_getImplementation(m); method_setImplementation(m, (IMP)hook_arrayForKey); _log(@"[INIT] NSDictionary.arrayForKey: observe"); }
    }
    
    // === IMMEDIATE: Hook SignatureKit (must run before original +load) ===
    Class skCls = NSClassFromString(@"SignatureKit");
    if (skCls) {
        Class metaCls = object_getClass(skCls);
        
        Method m = class_getClassMethod(skCls, @selector(showAlert:));
        if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); _log(@"[INIT] SK.showAlert: SUPPRESS"); }
        
        m = class_getClassMethod(skCls, @selector(exitApplication));
        if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); _log(@"[INIT] SK.exitApplication: BLOCK"); }
        
        m = class_getClassMethod(skCls, @selector(judgeAppInfoWithBaseUrl:));
        if (m) { orig_judgeBase = (JudgeBaseIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeBase); _log(@"[INIT] SK.judgeAppInfoWithBaseUrl: BYPASS"); }
        
        m = class_getClassMethod(skCls, @selector(handleAppInfoResult:));
        if (m) { orig_handleResult = (HandleResultIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_handleResult); _log(@"[INIT] SK.handleAppInfoResult: LOG"); }
        
        m = class_getClassMethod(skCls, @selector(judgeNet));
        if (m) { orig_judgeNet = (JudgeNetIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeNet); _log(@"[INIT] SK.judgeNet: BLOCK"); }
        
        m = class_getClassMethod(skCls, @selector(verifySignatureFromParameters:));
        if (m) { orig_verifySig = (VerifySigIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_verifySig); _log(@"[INIT] SK.verifySignatureFromParameters: BLOCK"); }
        
        m = class_getClassMethod(skCls, @selector(generateRequestParams));
        if (m) { orig_genParams = (GenParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_genParams); _log(@"[INIT] SK.generateRequestParams: LOG"); }
        
        m = class_getClassMethod(skCls, @selector(createSignatureParams:));
        if (m) { orig_createSigParams = (CreateSigParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_createSigParams); _log(@"[INIT] SK.createSignatureParams: LOG"); }
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(metaCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            DLOG(@"[SK] +[%@]", NSStringFromSelector(method_getName(methods[i])));
        }
        if (methods) free(methods);
    } else {
        _log(@"[INIT] WARNING: SignatureKit NOT found!");
    }
    
    // === IMMEDIATE: Hook SignatureCheck ===
    Class scCls = NSClassFromString(@"SignatureCheck");
    if (scCls) {
        Class metaCls = object_getClass(scCls);
        
        Method m = class_getClassMethod(scCls, @selector(JudgeApp));
        if (m) { orig_judgeApp = (JudgeAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeApp); _log(@"[INIT] SC.JudgeApp: BLOCK"); }
        
        m = class_getClassMethod(scCls, @selector(showTipViewEND:));
        if (m) { orig_showTip = (ShowTipIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showTip); _log(@"[INIT] SC.showTipViewEND: SUPPRESS"); }
        
        m = class_getClassMethod(scCls, @selector(exitApplication));
        if (m) { orig_scExit = (SCExitIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_scExit); _log(@"[INIT] SC.exitApplication: BLOCK"); }
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(metaCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            DLOG(@"[SC] +[%@]", NSStringFromSelector(method_getName(methods[i])));
        }
        if (methods) free(methods);
    } else {
        _log(@"[INIT] WARNING: SignatureCheck NOT found!");
    }
    
    // === IMMEDIATE: Version check bypass hooks ===
    // Based on observed version status codes: 58, 64, 73
    NSArray *versionCheckClasses = @[
        @"VersionManager", @"AppVersion", @"GameVersion", @"UpdateManager",
        @"VersionChecker", @"VersionVerify", @"ClientVersion", @"GameClient"
    ];
    
    for (NSString *clsName in versionCheckClasses) {
        Class cls = NSClassFromString(clsName);
        if (cls) {
            DLOG(@"[VER-CHK] Found version check class: %@", clsName);
            
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(cls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                SEL sel = method_getName(methods[i]);
                NSString *selName = NSStringFromSelector(sel);
                
                if ([selName containsString:@"version"] || [selName containsString:@"Version"] ||
                    [selName containsString:@"check"] || [selName containsString:@"Check"] ||
                    [selName containsString:@"verify"] || [selName containsString:@"Verify"] ||
                    [selName containsString:@"update"] || [selName containsString:@"Update"] ||
                    [selName containsString:@"status"] || [selName containsString:@"Status"]) {
                    DLOG(@"[VER-CHK] Instance method to monitor: -[%@ %@]", clsName, selName);
                }
            }
            if (methods) free(methods);
            
            Class metaCls = object_getClass(cls);
            Method *classMethods = class_copyMethodList(metaCls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                SEL sel = method_getName(classMethods[i]);
                NSString *selName = NSStringFromSelector(sel);
                
                if ([selName containsString:@"version"] || [selName containsString:@"Version"] ||
                    [selName containsString:@"check"] || [selName containsString:@"Check"] ||
                    [selName containsString:@"verify"] || [selName containsString:@"Verify"] ||
                    [selName containsString:@"update"] || [selName containsString:@"Update"] ||
                    [selName containsString:@"status"] || [selName containsString:@"Status"]) {
                    DLOG(@"[VER-CHK] Class method to monitor: +[%@ %@]", clsName, selName);
                }
            }
            if (classMethods) free(classMethods);
        }
    }
    
    // === IMMEDIATE: Hook ServerInfoForClient class to trace server list parsing ===
    Class msiCls = NSClassFromString(@"ServerInfoForClient");
    if (msiCls) {
        DLOG(@"[MSI] ServerInfoForClient class FOUND!");
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(msiCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);
            DLOG(@"[MSI] -[%@ %@]", NSStringFromClass(msiCls), selName);
        }
        if (methods) free(methods);
        
        Method m_init = class_getInstanceMethod(msiCls, @selector(init));
        if (m_init) {
            orig_msi_init = method_getImplementation(m_init);
            method_setImplementation(m_init, (IMP)msi_init_hook);
            DLOG(@"[MSI-HOOK] Hooked: init");
        }
        
        Method m_initDict = class_getInstanceMethod(msiCls, @selector(initWithDictionary:));
        if (m_initDict) {
            orig_msi_initWithDict = method_getImplementation(m_initDict);
            method_setImplementation(m_initDict, (IMP)msi_initWithDict_hook);
            DLOG(@"[MSI-HOOK] Hooked: initWithDictionary:");
        }
        
        Method m_status = class_getInstanceMethod(msiCls, @selector(status));
        if (m_status) {
            orig_msi_status = method_getImplementation(m_status);
            method_setImplementation(m_status, (IMP)msi_status_hook);
            DLOG(@"[MSI-HOOK] Hooked: status");
        }
        
        Method m_statusValue = class_getInstanceMethod(msiCls, @selector(statusValue));
        if (m_statusValue) {
            method_setImplementation(m_statusValue, (IMP)msi_status_hook);
            DLOG(@"[MSI-HOOK] Hooked: statusValue");
        }
        
        Method m_ip = class_getInstanceMethod(msiCls, @selector(ip));
        if (m_ip) {
            method_setImplementation(m_ip, (IMP)msi_ip_hook);
            DLOG(@"[MSI-HOOK] Hooked: ip");
        }
        
        Method m_category = class_getInstanceMethod(msiCls, @selector(category));
        if (m_category) {
            method_setImplementation(m_category, (IMP)msi_category_hook);
            DLOG(@"[MSI-HOOK] Hooked: category");
        }
        
        Method m_serverType = class_getInstanceMethod(msiCls, @selector(serverType));
        if (m_serverType) {
            method_setImplementation(m_serverType, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverType");
        }
        
        Method m_serverId = class_getInstanceMethod(msiCls, @selector(serverid));
        if (m_serverId) {
            method_setImplementation(m_serverId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverid");
        }
        
        Method m_clientId = class_getInstanceMethod(msiCls, @selector(clientid));
        if (m_clientId) {
            method_setImplementation(m_clientId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: clientid");
        }
    } else {
        DLOG(@"[MSI] ServerInfoForClient class NOT found!");
    }
    
    // Dump NSUserDefaults
    @try {
        NSDictionary *allDefaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        DLOG(@"[NSUD-DUMP] Total keys: %lu", (unsigned long)allDefaults.count);
        for (NSString *key in allDefaults) {
            NSString *lk = [key lowercaseString];
            if ([lk containsString:@"pass"] || [lk containsString:@"verify"] || 
                [lk containsString:@"sign"] || [lk containsString:@"ispass"] ||
                [lk containsString:@"cert"] || [lk containsString:@"check"]) {
                DLOG(@"[NSUD-DUMP] %@ = %@", key, allDefaults[key]);
            }
        }
    } @catch (NSException *e) {
        DLOG(@"[NSUD-DUMP] Exception: %@", e);
    }
    DLOG(@"[NSUD] Total reads so far: %d", g_nsudCount);
    
    // === ANTI-CHEAT MONITOR: Dynamic method logging ===
    // Monitor common anti-cheat related classes and methods
    NSArray *antiCheatClasses = @[
        @"SecurityCheck", @"AntiCheat", @"SafeGuard", @"CheatDetection",
        @"ProtectManager", @"GameGuard", @"AntiHack", @"SignatureVerify",
        @"DeviceCheck", @"EnvironmentCheck", @"DebugDetector", @"BanManager"
    ];
    
    for (NSString *clsName in antiCheatClasses) {
        Class cls = NSClassFromString(clsName);
        if (cls) {
            DLOG(@"[AC-MONITOR] Found anti-cheat class: %@", clsName);
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(cls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                SEL sel = method_getName(methods[i]);
                NSString *selName = NSStringFromSelector(sel);
                DLOG(@"[AC-MONITOR] Instance method: -[%@ %@]", clsName, selName);
            }
            if (methods) free(methods);
            
            Class metaCls = object_getClass(cls);
            Method *classMethods = class_copyMethodList(metaCls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                SEL sel = method_getName(classMethods[i]);
                NSString *selName = NSStringFromSelector(sel);
                DLOG(@"[AC-MONITOR] Class method: +[%@ %@]", clsName, selName);
            }
            if (classMethods) free(classMethods);
        }
    }
    
    // Monitor common anti-cheat method names
    NSArray *antiCheatSelectors = @[
        @"isJailbroken", @"isDebugged", @"isSimulator", @"isDebuggerAttached",
        @"detectCheat", @"detectHack", @"checkEnvironment", @"antiDebug",
        @"checkDebugger", @"securityCheck", @"verifySecurity", @"checkSecurityStatus",
        @"checkBanStatus", @"isBanned", @"punish:", @"verifySignature:",
        @"judgeApp:", @"JudgeApp", @"showAlert:", @"exitApplication"
    ];
    
    Class nsobjCls = [NSObject class];
    for (NSString *selName in antiCheatSelectors) {
        SEL sel = NSSelectorFromString(selName);
        if (sel) {
            if ([nsobjCls instancesRespondToSelector:sel]) {
                DLOG(@"[AC-MONITOR] NSObject responds to: %@", selName);
            }
            if ([nsobjCls respondsToSelector:sel]) {
                DLOG(@"[AC-MONITOR] NSObject class responds to: %@", selName);
            }
        }
    }
    
    // === DECODE-SEARCH: Search for decode/decrypt/parse methods ===
    // This helps find where protocol data is decoded after receiving
    DLOG(@"[DECODE-SEARCH] Starting scan for decode/decrypt/parse methods...");
    
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    if (allClasses) {
        NSArray *decodeKeywords = @[
            @"decrypt", @"Decrypt", @"DECRYPT",
            @"decode", @"Decode", @"DECODE",
            @"parse", @"Parse", @"PARSE",
            @"unpack", @"Unpack", @"UNPACK",
            @"decompress", @"Decompress", @"DECOMPRESS",
            @"decipher", @"Decipher", @"DECIPHER",
            @"decodePacket", @"decodeData", @"parsePacket",
            @"processPacket", @"handlePacket", @"readPacket",
            @"decodeServer", @"parseServer", @"serverList"
        ];
        
        for (unsigned int i = 0; i < classCount; i++) {
            Class cls = allClasses[i];
            NSString *clsName = NSStringFromClass(cls);
            
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(cls, &mcount);
            if (methods) {
                for (unsigned int j = 0; j < mcount; j++) {
                    SEL sel = method_getName(methods[j]);
                    NSString *selName = NSStringFromSelector(sel);
                    
                    for (NSString *keyword in decodeKeywords) {
                        if ([selName containsString:keyword]) {
                            DLOG(@"[DECODE-FOUND] Class: %@, Method: -[%@ %@]", 
                                 clsName, clsName, selName);
                            break;
                        }
                    }
                }
                free(methods);
            }
            
            Class metaCls = object_getClass(cls);
            Method *classMethods = class_copyMethodList(metaCls, &mcount);
            if (classMethods) {
                for (unsigned int j = 0; j < mcount; j++) {
                    SEL sel = method_getName(classMethods[j]);
                    NSString *selName = NSStringFromSelector(sel);
                    
                    for (NSString *keyword in decodeKeywords) {
                        if ([selName containsString:keyword]) {
                            DLOG(@"[DECODE-FOUND] Class: %@, Method: +[%@ %@]", 
                                 clsName, clsName, selName);
                            break;
                        }
                    }
                }
                free(classMethods);
            }
        }
        free(allClasses);
    }
    DLOG(@"[DECODE-SEARCH] Scan completed.");
    
    // === DEFERRED: Create UI button with retry ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *w = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
                if (s.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in s.windows) { 
                        if (win.isKeyWindow) { w = win; break; } 
                        if (!w && win.rootViewController) w = win;
                    }
                }
            }
        }
        if (!w) w = [UIApplication sharedApplication].keyWindow;
        if (!w) w = [UIApplication sharedApplication].windows.firstObject;
        
        if (w) {
            createLogButton(w);
        } else {
            DLOG(@"[UI] No window at 0.5s, retry at 2s");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UIWindow *w2 = [UIApplication sharedApplication].windows.firstObject;
                if (w2) {
                    createLogButton(w2);
                } else {
                    DLOG(@"[UI] No window at 2s, retry at 5s");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        UIWindow *w3 = [UIApplication sharedApplication].windows.firstObject;
                        if (w3) {
                            createLogButton(w3);
                        } else {
                            DLOG(@"[UI] No window found after 5s, giving up");
                        }
                    });
                }
            });
        }
    });
    
    tryHookMieshiServerInfo(0);
    
    // === DEFERRED: UITableView DataSource Hook for server list debugging ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class tableViewCls = [UITableView class];
        
        Method numberOfRows = class_getInstanceMethod(tableViewCls, @selector(numberOfRowsInSection:));
        if (numberOfRows) {
            IMP orig_impl = method_getImplementation(numberOfRows);
            method_setImplementation(numberOfRows, (IMP)hook_numberOfRowsInSection);
            orig_tableView_numberOfRows = orig_impl;
            DLOG(@"[TV-HOOK] Hooked UITableView numberOfRowsInSection:");
        }
        
        Method cellForRow = class_getInstanceMethod(tableViewCls, @selector(cellForRowAtIndexPath:));
        if (cellForRow) {
            IMP orig_impl = method_getImplementation(cellForRow);
            method_setImplementation(cellForRow, (IMP)hook_cellForRowAtIndexPath);
            orig_tableView_cellForRow = orig_impl;
            DLOG(@"[TV-HOOK] Hooked UITableView cellForRowAtIndexPath:");
        }
        
        Method numberOfSections = class_getInstanceMethod(tableViewCls, @selector(numberOfSections));
        if (numberOfSections) {
            IMP orig_impl = method_getImplementation(numberOfSections);
            method_setImplementation(numberOfSections, (IMP)hook_numberOfSections);
            orig_tableView_numberOfSections = orig_impl;
            DLOG(@"[TV-HOOK] Hooked UITableView numberOfSections");
        }
    });
    
    // === DEFERRED: NSURLSession Hook for HTTP-based version check/server list ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        installNSURLSessionHooks();
    });
    
    // === DEFERRED: Hook NSJSONSerialization for decrypted data modification ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        installJSONSerializationHook();
    });
    
    // === DEFERRED: Hook NSArray count to force non-empty server list ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        installNSArrayCountHook();
    });
    
    // === DEFERRED: Force inject mock server list if real list is empty ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
            NSArray *serverList = [defaults objectForKey:@"serverList"];
            if (!serverList || serverList.count == 0) {
                DLOG(@"[FORCE-INJECT] Server list empty, injecting mock data");
                NSArray *mockServers = @[
                    @{@"serverid": @1, @"name": @"测试服务器", @"ip": @"47.100.222.229", 
                      @"port": @5678, @"status": @1, @"serverType": @1, @"clientid": @1,
                      @"category": @"一区", @"description": @"运行中"}
                ];
                [defaults setObject:mockServers forKey:@"serverList"];
                [defaults synchronize];
                DLOG(@"[FORCE-INJECT] Mock server list injected: %@", mockServers);
            }
        } @catch (NSException *e) {
            DLOG(@"[FORCE-INJECT] Exception: %@", e);
        }
    });
    
    // === DEFERRED: Scan all server-related classes and hook their init methods ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);
            NSMutableArray *serverClasses = [NSMutableArray array];
            
            for (unsigned int i = 0; i < classCount; i++) {
                Class cls = classes[i];
                NSString *clsName = NSStringFromClass(cls);
                if (!clsName) continue;
                
                NSString *lower = [clsName lowercaseString];
                if (([lower containsString:@"server"] || [lower containsString:@"serverlist"] ||
                     [lower containsString:@"serverinfo"] || [lower containsString:@"servers"]) &&
                    ![lower containsString:@"mieshi"] && ![clsName isEqualToString:@"UIApplication"]) {
                    [serverClasses addObject:clsName];
                }
            }
            
            DLOG(@"[SERVER-CLASS] Found %d server-related classes:", serverClasses.count);
            for (NSString *clsName in serverClasses) {
                DLOG(@"[SERVER-CLASS]   %@", clsName);
            }
            
            if (classes) free(classes);
        } @catch (NSException *e) {
            DLOG(@"[SERVER-CLASS] Exception: %@", e);
        }
    });
    
    // === DEFERRED: Hook UITableViewDelegate didSelectRow for server selection ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class tableViewCls = [UITableView class];
        Method didSelect = class_getInstanceMethod(tableViewCls, @selector(didSelectRowAtIndexPath:));
        if (didSelect) {
            IMP orig_impl = method_getImplementation(didSelect);
            DLOG(@"[TV-HOOK] Found didSelectRowAtIndexPath in UITableView");
        }
        
        // Also hook reloadData to detect when server list table is reloaded
        Method reloadData = class_getInstanceMethod(tableViewCls, @selector(reloadData));
        if (reloadData) {
            DLOG(@"[TV-HOOK] Found reloadData in UITableView");
        }
    });
    
    // === DEFERRED: Hook LoginModuleMessageHandlerImpl for server list response ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            Class lmhiCls = NSClassFromString(@"LoginModuleMessageHandlerImpl");
            if (lmhiCls) {
                DLOG(@"[LMHI] LoginModuleMessageHandlerImpl class FOUND!");
                
                unsigned int mcount = 0;
                Method *methods = class_copyMethodList(lmhiCls, &mcount);
                for (unsigned int i = 0; i < mcount; i++) {
                    SEL sel = method_getName(methods[i]);
                    NSString *selName = NSStringFromSelector(sel);
                    if ([selName containsString:@"SERVER_LIST"] || 
                        [selName containsString:@"server"] || 
                        [selName containsString:@"Server"]) {
                        DLOG(@"[LMHI-METHOD] -[%@ %@]", NSStringFromClass(lmhiCls), selName);
                        
                        IMP orig = method_getImplementation(methods[i]);
                        IMP new_impl = imp_implementationWithBlock(^(id self, SEL _cmd, ...) {
                            DLOG(@"[LMHI-CALL] -[%@ %@] called", NSStringFromClass([self class]), selName);
                            va_list args;
                            va_start(args, _cmd);
                            id result = ((id(*)(id, SEL, va_list))orig)(self, _cmd, args);
                            va_end(args);
                            DLOG(@"[LMHI-CALL] -[%@ %@] returned: %@", NSStringFromClass([self class]), selName, result ?: @"nil");
                            return result;
                        });
                        method_setImplementation(methods[i], new_impl);
                        DLOG(@"[LMHI-HOOK] Hooked: %@", selName);
                    }
                }
                if (methods) free(methods);
            } else {
                DLOG(@"[LMHI] LoginModuleMessageHandlerImpl class NOT found!");
            }
        } @catch (NSException *e) {
            DLOG(@"[LMHI] Exception: %@", e);
        }
    });
    
    // === DEFERRED: Hook CLogin for server list UI ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            Class cLoginCls = NSClassFromString(@"CLogin");
            if (cLoginCls) {
                DLOG(@"[CLOGIN] CLogin class FOUND!");
                
                unsigned int mcount = 0;
                Method *methods = class_copyMethodList(cLoginCls, &mcount);
                for (unsigned int i = 0; i < mcount; i++) {
                    SEL sel = method_getName(methods[i]);
                    NSString *selName = NSStringFromSelector(sel);
                    if ([selName containsString:@"server"] || 
                        [selName containsString:@"Server"] ||
                        [selName containsString:@"ServerList"] ||
                        [selName containsString:@"updateServer"]) {
                        DLOG(@"[CLOGIN-METHOD] -[%@ %@]", NSStringFromClass(cLoginCls), selName);
                    }
                }
                if (methods) free(methods);
            } else {
                DLOG(@"[CLOGIN] CLogin class NOT found!");
            }
        } @catch (NSException *e) {
            DLOG(@"[CLOGIN] Exception: %@", e);
        }
    });
}


