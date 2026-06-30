/**
 * WangXianHook v34.73 - Anti-Cheat Bypass + DYLD Hiding + Protocol Login Patch
 * Strategy: Fill UUID/MACADDRESS in send data for server list request
 * Key: Use sizeof() instead of strlen() for strings with embedded nulls
 * NEW: Log app behavior after receiving server list to diagnose empty list issue
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

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES; // logging toggle

static void _log(NSString *msg) {
    if (!g_logPath || !g_logEnabled) return;
    
    @try {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        if (size > 500 * 1024) {
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            _log(@"[LOG] File too large (>500KB), truncated");
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
        _log(@"=== WXHook v34.73 Full Protocol Patch ===");
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

// 3. handleAppInfoResult: - LOG + pass through
typedef void (*HandleResultIMP)(id, SEL, id);
static HandleResultIMP orig_handleResult = NULL;
static void hook_handleResult(id self, SEL _cmd, id result) {
    DLOG(@"[SK] handleAppInfoResult: BLOCKED: %@", result);
    // Don't call original - prevent anti-cheat result processing
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
            lbl.text = @"WXHook v34.73 诊断面板";
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
    NSURL *fileURL = [NSURL fileURLWithPath:g_logPath];
    UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL] applicationActivities:nil];
    UIViewController *topVC = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (topVC.presentedViewController) topVC = topVC.presentedViewController;
    [topVC presentViewController:avc animated:YES completion:nil];
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
#pragma mark - MieshiServerInfo hooks (trace server list parsing)
// ============================================================

static id hook_msi_generic(id self, SEL _cmd, ...) {
    NSString *selName = NSStringFromSelector(_cmd);
    DLOG(@"[MSI-CALL] -[%@ %@]", NSStringFromClass([self class]), selName);
    
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
    
    va_list args;
    va_start(args, _cmd);
    id ret = ((id (*)(id, SEL, va_list))objc_msgSend)(self, _cmd, args);
    va_end(args);
    
    if (ret) {
        DLOG(@"[MSI-RET] %@ -> %@", selName, ret);
    }
    return ret;
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
    
    // Version check response: ret >= 13 (0x802EE118 = 13 bytes)
    if (port == 5678 && ret >= 13) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // When receiving heartbeat from auth server (instead of game server response),
        // DISABLED: fake login response causes app to hang/crash
        // if (cmd == 0x00FFFF01 || cmd == 0x00FFFF02) {
        //     DLOG(@"[PROTO-PATCH] Got heartbeat from auth server, IGNORING");
        // }
        
        // DISABLED: login failure patch causes app to hang/crash
        // if (cmd == 0x76666669 || cmd == 0x7666669A) {
        //     DLOG(@"[PROTO-PATCH] Got login failure from auth server, IGNORING");
        // }
        
        if (cmd == 0x802EE118) {
            DLOG(@"[PROTO] Version check response 0x802EE118 pktLen=%u ret=%zd", pktLenBE, ret);
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            DLOG(@"[PROTO] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
            if (status4 != 0) {
                DLOG(@"[PROTO-PATCH] Version check 4-byte status %u -> 0", status4);
                memset((unsigned char *)buf + 8, 0, 4);
            }
            if (ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-PATCH] Version check 1-byte status at offset 12: %u -> 0", p[12]);
                ((unsigned char *)buf)[12] = 0;
            }
        }

        if (cmd == 0x0000E011) {
            DLOG(@"[PROTO] Server info response 0x0000E011 pktLen=%u ret=%zd", pktLenBE, ret);
        }

        if (cmd == 0x802EE121) {
            DLOG(@"[PROTO] Version check response 0x802EE121 pktLen=%u ret=%zd", pktLenBE, ret);
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            DLOG(@"[PROTO] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
            if (status4 != 0) {
                DLOG(@"[PROTO-PATCH] Version check 4-byte status %u -> 0", status4);
                ((unsigned char *)buf)[8] = 0;
                ((unsigned char *)buf)[9] = 0;
                ((unsigned char *)buf)[10] = 0;
                ((unsigned char *)buf)[11] = 0;
            }
            // Also clear offset 12-15 (another status field) and message string
            if (ret > 16) {
                DLOG(@"[PROTO-PATCH] Clearing version check message (offset 12 onwards)");
                memset((unsigned char *)buf + 12, 0, ret - 12);
            }
        }

        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO] Server list response 0x802EE113 - pktLen=%u ret=%zd", pktLenBE, ret);
            
            // Track server list response count
            static int serverListCount = 0;
            serverListCount++;
            DLOG(@"[PROTO] Server list response #%d", serverListCount);
            
            // 1. Patch protocol status at offset 8-11 to 0
            ((unsigned char *)buf)[8] = 0;
            ((unsigned char *)buf)[9] = 0;
            ((unsigned char *)buf)[10] = 0;
            ((unsigned char *)buf)[11] = 0;
            DLOG(@"[PROTO-PATCH] Protocol status set to 0");
            
            unsigned char *data = (unsigned char *)buf;
            
            // 3. Patch JSON status=6 to status=1 (for ALL responses)
            int statusPatchCount = 0;
            for (size_t i = 0; i + 7 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 't' && data[i+2] == 'a' && data[i+3] == 't' && 
                    data[i+4] == 'u' && data[i+5] == 's' && data[i+6] == '=' && data[i+7] == '6') {
                    DLOG(@"[PROTO-PATCH] Found 'status=6' at offset %zu, changing to 1", i);
                    data[i+7] = '1';
                    statusPatchCount++;
                }
            }
            if (statusPatchCount > 0) DLOG(@"[PROTO-PATCH] Patched %d JSON status values", statusPatchCount);
            
            // 4. Patch serverType=2 to serverType=1 (for ALL responses)
            int serverTypePatchCount = 0;
            for (size_t i = 0; i + 11 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 'e' && data[i+2] == 'r' && data[i+3] == 'v' && 
                    data[i+4] == 'e' && data[i+5] == 'r' && data[i+6] == 'T' && data[i+7] == 'y' &&
                    data[i+8] == 'p' && data[i+9] == 'e' && data[i+10] == '=' && data[i+11] == '2') {
                    DLOG(@"[PROTO-PATCH] Found 'serverType=2' at offset %zu, changing to 1", i);
                    data[i+11] = '1';
                    serverTypePatchCount++;
                }
            }
            if (serverTypePatchCount > 0) DLOG(@"[PROTO-PATCH] Patched %d serverType values", serverTypePatchCount);
            
            // 5. Patch clientid=0 to clientid=1 (for ALL responses)
            int clientidPatchCount = 0;
            for (size_t i = 0; i + 9 < (size_t)ret; i++) {
                if (data[i] == 'c' && data[i+1] == 'l' && data[i+2] == 'i' && data[i+3] == 'e' && 
                    data[i+4] == 'n' && data[i+5] == 't' && data[i+6] == 'i' && data[i+7] == 'd' &&
                    data[i+8] == '=' && data[i+9] == '0') {
                    DLOG(@"[PROTO-PATCH] Found 'clientid=0' at offset %zu, changing to 1", i);
                    data[i+9] = '1';
                    clientidPatchCount++;
                }
            }
            if (clientidPatchCount > 0) DLOG(@"[PROTO-PATCH] Patched %d clientid values", clientidPatchCount);
            
            // 6. Patch serverid=0 to serverid=1 (for ALL responses)
            int serveridPatchCount = 0;
            for (size_t i = 0; i + 9 < (size_t)ret; i++) {
                if (data[i] == 's' && data[i+1] == 'e' && data[i+2] == 'r' && data[i+3] == 'v' && 
                    data[i+4] == 'e' && data[i+5] == 'r' && data[i+6] == 'i' && data[i+7] == 'd' &&
                    data[i+8] == '=' && data[i+9] == '0') {
                    DLOG(@"[PROTO-PATCH] Found 'serverid=0' at offset %zu, changing to 1", i);
                    data[i+9] = '1';
                    serveridPatchCount++;
                }
            }
            if (serveridPatchCount > 0) DLOG(@"[PROTO-PATCH] Patched %d serverid values", serveridPatchCount);
            
            // 7. Replace old test server IP (with quotes)
            const char *oldIP = "'47.100.204.160'";
            const char *newIP = "'47.100.222.229'";
            for (size_t i = 0; i + 16 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldIP, 16) == 0) {
                    DLOG(@"[PROTO-PATCH] Found old IP at offset %zu, replacing", i);
                    memcpy(data + i, newIP, 16);
                }
            }
            
            // 8. Patch category '......' to '一区'
            const unsigned char oldCat[] = {0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E};
            const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};
            for (size_t i = 0; i + 6 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldCat, 6) == 0) {
                    memcpy(data + i, newCat, 6);
                }
            }
            
            // 9. Patch description '服务器维护中...' to '运行'
            // UTF-8: 服务器维护中... = E6 9C 8D E5 8A A1 E5 99 A8 E7 BB B4 E6 8A A4 E4 B8 AD 2E 2E 2E
            // UTF-8: 运行 = E8 BF 90 E8 A1 8C
            const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 
                                             0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 
                                             0x2E, 0x2E, 0x2E};
            const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};
            for (size_t i = 0; i + 21 <= (size_t)ret; i++) {
                if (memcmp(data + i, oldDesc, 21) == 0) {
                    DLOG(@"[PROTO-PATCH] Found '服务器维护中...' at offset %zu, replacing with '运行'", i);
                    memcpy(data + i, newDesc, 6);
                    // Fill remaining space with spaces
                    for (size_t j = 6; j < 21; j++) data[i+j] = ' ';
                }
            }
            
            DLOG(@"[PROTO] Server list patching complete (response #%d, %zd bytes)", serverListCount, ret);
        }
        
        if (ret >= 16) {
            if (cmd == 0x8002A017) {
                DLOG(@"[PROTO] Login response 0x8002A017 pktLen=%u ret=%zd", pktLenBE, ret);
                uint32_t status = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                  ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO] Login status at offset 12-15: %u (0x%08X)", status, status);
                if (status != 0) {
                    DLOG(@"[PROTO-PATCH] Login status %u -> 0 (force success)", status);
                    memset((unsigned char *)buf + 12, 0, 4);
                }
            }
            
            if (cmd == 0x8002A016) {
                DLOG(@"[PROTO] Version/server list response 0x8002A016 pktLen=%u ret=%zd", pktLenBE, ret);
                uint32_t status8 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                uint32_t status12 = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                    ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO] Status at offset 8-11: %u (0x%08X), offset 12-15: %u (0x%08X)", status8, status8, status12, status12);
                
                // Patch ALL status fields to 0 for version response
                // Status 3 indicates version mismatch or verification failure
                // We need to force success so the app continues to send server list request
                if (status8 != 0 || status12 != 0) {
                    DLOG(@"[PROTO-PATCH] Version response status %u/%u -> 0 (force success)", status8, status12);
                    memset((unsigned char *)buf + 8, 0, 8);
                }
                
                // Also check for any other non-zero 4-byte status fields after version string
                // Response format: [len][cmd][status1][status2][version][...][status3][extra]
                for (size_t i = 24; i + 4 <= (size_t)ret; i += 4) {
                    uint32_t st = ((uint32_t)p[i] << 24) | ((uint32_t)p[i+1] << 16) |
                                   ((uint32_t)p[i+2] << 8) | (uint32_t)p[i+3];
                    if (st != 0 && st != 974) {
                        DLOG(@"[PROTO-PATCH] Found additional status %u at offset %zu -> 0", st, i);
                        memset((unsigned char *)buf + i, 0, 4);
                    }
                }
            }
        }
    }
    
    if (port == 5678) {
        static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
            if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                DLOG(@"[PATCH] Detected '版本过低' in server response at offset %zd, neutralizing", i);
                memset((unsigned char *)buf + i, ' ', sizeof(verLow));
            }
        }
        static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
            if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                DLOG(@"[PATCH] Detected '当前版本' in server response at offset %zd, neutralizing", i);
                memset((unsigned char *)buf + i, ' ', sizeof(curVer));
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

static NSInteger (*orig_numberOfSections)(id, SEL) = NULL;
static NSInteger hook_numberOfSections(id self, SEL _cmd) {
    NSInteger ret = orig_numberOfSections ? orig_numberOfSections(self, _cmd) : 0;
    NSString *cls = NSStringFromClass([self class]);
    if ([cls containsString:@"Server"] || [cls containsString:@"server"] || 
        [cls containsString:@"List"] || [cls containsString:@"list"]) {
        DLOG(@"[TABLE] numberOfSections -> %ld class=%@", (long)ret, cls);
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
    
    // === IMMEDIATE: Hook MieshiServerInfo class to trace server list parsing ===
    Class msiCls = NSClassFromString(@"MieshiServerInfo");
    if (msiCls) {
        DLOG(@"[MSI] MieshiServerInfo class FOUND!");
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(msiCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);
            DLOG(@"[MSI] -[%@ %@]", NSStringFromClass(msiCls), selName);
            
            if ([selName containsString:@"init"] || [selName containsString:@"Status"] || 
                [selName containsString:@"status"] || [selName containsString:@"server"] ||
                [selName containsString:@"Server"] || [selName containsString:@"ip"] ||
                [selName containsString:@"IP"] || [selName containsString:@"category"]) {
                DLOG(@"[MSI-HOOK] Attempting to hook: %@", selName);
                IMP origImp = method_getImplementation(methods[i]);
                if (origImp) {
                    method_setImplementation(methods[i], (IMP)hook_msi_generic);
                    DLOG(@"[MSI-HOOK] Hooked: %@", selName);
                }
            }
        }
        if (methods) free(methods);
    } else {
        DLOG(@"[MSI] MieshiServerInfo class NOT found!");
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
    
    // === DEFERRED: Create UI button only ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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

// __DATA,__interpose REMOVED - causes white screen crash (intercepts ALL system connect/send/recv too early)
// Using patched IPA with stub dylibs instead - prevents original +load from running
