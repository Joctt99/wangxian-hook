/**
 * WangXianHook v34.42 - Anti-Cheat Bypass + DYLD Hiding + Protocol Login Patch
 * Strategy: Fill UUID/MACADDRESS in send data for server list request
 * Key: Use sizeof() instead of strlen() for strings with embedded nulls
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
        _log(@"=== WXHook v34.42 Full Protocol Patch ===");
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
            lbl.text = @"WXHook v34.42 诊断面板";
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

static ConnectFunc orig_connect = NULL;
static SendFunc orig_send = NULL;
static RecvFunc orig_recv = NULL;
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
        
        if (cmd == 0x0002A018) {
            for (size_t i = 0; i + 32 < len; i++) {
                if (memcmp(p + i, "UUID=", 5) == 0) {
                    size_t uuidValueStart = i + 5;
                    size_t uuidValueEnd = uuidValueStart;
                    
                    while (uuidValueEnd < len && p[uuidValueEnd] != 0) {
                        uuidValueEnd++;
                    }
                    
                    size_t macStart = uuidValueEnd + 1;
                    if (macStart + 11 <= len && memcmp(p + macStart, "MACADDRESS=", 11) == 0) {
                        size_t macValueStart = macStart + 11;
                        size_t macValueEnd = macValueStart;
                        
                        while (macValueEnd < len && p[macValueEnd] != 0) {
                            macValueEnd++;
                        }
                        
                        size_t oldDataLen = macValueEnd - i;
                        const char replacement[] = "UUID=12345678-1234-1234-1234-123456789012\x00MACADDRESS=00:11:22:33:44:55\x00";
                        size_t replaceLen = sizeof(replacement) - 1;
                        size_t diff = replaceLen - oldDataLen;
                        
                        DLOG(@"[SEND-PATCH] UUID at %zu-%zu, MAC at %zu-%zu, old=%zu new=%zu diff=%zd", 
                             i, uuidValueEnd, macStart, macValueEnd, oldDataLen, replaceLen, diff);
                        
                        void *newBuf = malloc(len + diff);
                        if (newBuf) {
                            memcpy(newBuf, buf, i);
                            memcpy(((char *)newBuf) + i, replacement, replaceLen);
                            memcpy(((char *)newBuf) + i + replaceLen, 
                                   ((char *)buf) + macValueEnd,
                                   len - macValueEnd);
                            
                            uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                               ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
                            uint32_t newPktLen = pktLenBE + (uint32_t)diff;
                            ((unsigned char *)newBuf)[0] = (newPktLen >> 24) & 0xFF;
                            ((unsigned char *)newBuf)[1] = (newPktLen >> 16) & 0xFF;
                            ((unsigned char *)newBuf)[2] = (newPktLen >> 8) & 0xFF;
                            ((unsigned char *)newBuf)[3] = newPktLen & 0xFF;
                            
                            sendBuf = newBuf;
                            sendLen = len + diff;
                            DLOG(@"[SEND-PATCH] Done: len=%zu -> %zu", len, sendLen);
                        }
                        break;
                    }
                }
            }
        }
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
        // fake a login success response so app continues to game
        if (cmd == 0x00FFFF01 || cmd == 0x00FFFF02) {
            DLOG(@"[PROTO-PATCH] Got heartbeat from auth server, faking login success response");
            
            // Fake login response: 0x8002A017 with status=0 (total 40 bytes)
            const char fakeLoginResp[] = 
                "\x00\x00\x00\x28"  // length = 40 (0x28)
                "\x80\x02\xA0\x17"  // cmd = 0x8002A017 (login response)
                "\x00\x00\x00\x00"  // status = 0 (success)
                "\x00\x00\x00\x01"  // sub-status = 1
                "\x00\x00\x00\x00"  // padding
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00";
            
            if (sizeof(fakeLoginResp) - 1 <= len) {
                memcpy(buf, fakeLoginResp, sizeof(fakeLoginResp) - 1);
                ret = sizeof(fakeLoginResp) - 1;
                DLOG(@"[PROTO-PATCH] Faked login response injected (len=%zd)", ret);
            }
        }
        
        // When receiving login failure (vffi = 'login fail'), fake success to continue
        if (cmd == 0x76666669 || cmd == 0x7666669A) {  // 'vffi' or 'vfii'
            DLOG(@"[PROTO-PATCH] Got login failure from auth server, faking login success response");
            
            // Fake login success: 0x8002A017 with status=0 (total 40 bytes)
            const char fakeLoginResp[] = 
                "\x00\x00\x00\x28"  // length = 40 (0x28)
                "\x80\x02\xA0\x17"  // cmd = 0x8002A017 (login response)
                "\x00\x00\x00\x00"  // status = 0 (success)
                "\x00\x00\x00\x01"  // sub-status = 1
                "\x00\x00\x00\x00"  // padding
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00";
            
            if (sizeof(fakeLoginResp) - 1 <= len) {
                memcpy(buf, fakeLoginResp, sizeof(fakeLoginResp) - 1);
                ret = sizeof(fakeLoginResp) - 1;
                DLOG(@"[PROTO-PATCH] Faked login success response injected (len=%zd)", ret);
            }
        }
        
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
            DLOG(@"[PROTO] Server list response 0x802EE113 pktLen=%u ret=%zd", pktLenBE, ret);
            uint32_t status4 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
            DLOG(@"[PROTO] Server list status at offset 8-11: %u (0x%08X)", status4, status4);
            
            // Always inject fake server list since real response only contains test/maintenance servers
            DLOG(@"[PROTO-PATCH] Injecting fake server list with multiple servers");
            
            const char fakeServerList[] = "\x00\x00\x03\xF0\x80\x2E\xE1\x13\x00\x00\x00\x00\x00\x10\xE4\xB8"
                "\x80\xE5\x8C\xBA\x2F\xE5\xBF\x98\xE5\xB7\x9D\xE6\xB8\xA1\x00\x00\x00\x06"
                "\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x06\xE4\xBA\x8C\xE5\x8C\xBA\x00\x06"
                "\xE4\xB8\x89\xE5\x8C\xBA\x00\x06\xE5\x9B\x9B\xE5\x8C\xBA\x00\x06\xE4\xBA"
                "\x94\xE5\x8C\xBA\x00\x06\xE6\x96\xB0\xE5\x8C\xBA\x00\x00\x00\x03\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0E"
                "\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE5\xBF\x98\xE5\xB7\x9D\xE6\xB8"
                "\xA1\x00\x0E\x34\x37\x2E\x31\x30\x30\x2E\x32\x30\x34\x2E\x31\x36\x30\x00"
                "\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB\xE7\x88\x86\x00"
                "\x22\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6\x84\x89\xE5\xBF"
                "\xAB\x21\x20\x2D\x20\xE6\x9C\x80\xE8\xBF\x91\xE7\x99\xBB\xE9\x99\x86\x00"
                "\x00\x01\x51\x01\x00\x00\x00\x01\x00\x00\x00\x03\x00\x0C\xE6\x99\xAE\xE9"
                "\x80\x9A\xE6\x9C\x8B\xE5\x8F\x8B\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09"
                "\xE7\x81\xB5\xE9\x9B\xBE\xE6\xB3\xBD\x00\x0D\x34\x37\x2E\x31\x30\x30\x2E"
                "\x31\x38\x34\x2E\x37\x37\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06"
                "\xE7\x81\xAB\xE7\x88\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9"
                "\x80\x94\xE6\x84\x89\xE5\xBF\xAB\x21\x00\x00\x01\x49\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE6\x98"
                "\x9F\xE9\x99\xA8\xE8\xB0\xB7\x00\x0D\x34\x37\x2E\x31\x30\x30\x2E\x33\x33"
                "\x2E\x31\x33\x39\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81"
                "\xAB\xE7\x88\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94"
                "\xE6\x84\x89\xE5\xBF\xAB\x21\x00\x00\x00\x57\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE6\x9C\x88\xE8"
                "\x90\xBD\xE6\xB6\xA7\x00\x0E\x31\x33\x39\x2E\x32\x32\x34\x2E\x31\x33\x2E"
                "\x31\x36\x32\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB"
                "\xE7\x88\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6"
                "\xE6\x84\x89\xE5\xBF\xAB\x21\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE4\xBA\x91\xE6"
                "\xA0\x96\xE5\xB3\xB0\x00\x0E\x31\x33\x39\x2E\x31\x39\x36\x2E\x31\x35\x2E"
                "\x31\x31\x38\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB"
                "\xE7\x88\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6"
                "\xE6\x84\x89\xE5\xBF\xAB\x21\x00\x00\x00\x6E\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE9\x86\x89\xE4"
                "\xBB\x99\xE8\xB0\xA3\x00\x0F\x31\x30\x31\x2E\x31\x33\x32\x2E\x31\x30\x32"
                "\x2E\x32\x30\x39\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81"
                "\xAB\xE7\x88\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94"
                "\xE6\x84\x89\xE5\xBF\xAB\x21\x00\x00\x00\x71\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE7\x8E\x84\xE5"
                "\xA4\xA9\xE5\x9F\x9F\x00\x0C\x34\x37\x2E\x31\x30\x33\x2E\x32\x36\x2E\x31"
                "\x33\x00\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB\xE7\x88"
                "\x86\x00\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6\x84\x89"
                "\xE5\xBF\xAB\x21\x00\x00\x00\x5A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE9\x80\x8D\xE9\x81\xA5\xE6"
                "\xB4\xA5\x00\x0D\x34\x37\x2E\x31\x30\x31\x2E\x31\x38\x38\x2E\x38\x36\x00"
                "\x00\x2E\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB\xE7\x88\x86\x00"
                "\x13\xE7\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6\x84\x89\xE5\xBF"
                "\xAB\x21\x00\x00\x00\x38\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x06\xE4\xB8\x80\xE5\x8C\xBA\x00\x09\xE8\x8B\x8D\xE6\xBE\x9C\xE5\x9F\x9F"
                "\x00\x0D\x34\x37\x2E\x31\x30\x32\x2E\x31\x34\x36\x2E\x33\x39\x00\x00\x2E"
                "\xE3\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB\xE7\x88\x86\x00\x13\xE7"
                "\xA5\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6\x84\x89\xE5\xBF\xAB\x21"
                "\x00\x00\x00\x1F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\xE4"
                "\xB8\x80\xE5\x8C\xBA\x00\x09\xE5\xB7\xA8\xE7\xA5\x9E\xE5\xB3\xB0\x00\x0E"
                "\x34\x37\x2E\x31\x30\x31\x2E\x32\x30\x33\x2E\x32\x30\x32\x00\x00\x2E\xE3"
                "\x00\x00\x00\x00\x00\x04\x00\x06\xE7\x81\xAB\xE7\x88\x86\x00\x13\xE7\xA5"
                "\x9D\xE6\x82\xA8\xE4\xBB\x99\xE9\x80\x94\xE6\x84\x89\xE5\xBF\xAB\x21\x00"
                "\x00\x00\x26";
            
            size_t fakeLen = sizeof(fakeServerList) - 1;
            if (fakeLen <= len) {
                memcpy(buf, fakeServerList, fakeLen);
                ((unsigned char *)buf)[0] = (fakeLen >> 24) & 0xFF;
                ((unsigned char *)buf)[1] = (fakeLen >> 16) & 0xFF;
                ((unsigned char *)buf)[2] = (fakeLen >> 8) & 0xFF;
                ((unsigned char *)buf)[3] = fakeLen & 0xFF;
                ret = (ssize_t)fakeLen;
                DLOG(@"[PROTO-PATCH] Fake server list injected (len=%zu)", fakeLen);
            } else {
                DLOG(@"[PROTO-PATCH] Buffer too small (%zu < %zu)", len, fakeLen);
            }
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
                DLOG(@"[PROTO] Server list response 0x8002A016 pktLen=%u ret=%zd", pktLenBE, ret);
                uint32_t status8 = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                uint32_t status12 = ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                    ((uint32_t)p[14] << 8)  | (uint32_t)p[15];
                DLOG(@"[PROTO] Server list status at offset 8-11: %u (0x%08X), offset 12-15: %u (0x%08X)", status8, status8, status12, status12);
                if (status8 != 0 || status12 != 0 || ret <= 64) {
                    DLOG(@"[PROTO-PATCH] Server list empty or failed, constructing fake response");
                    
                    const char fakeServer[] = "\x00\x00\x00\x70\x80\x02\xA0\x16\x00\x00\x00\x00\x00\x00\x00\x01"
                        "\x00\x03\x49\x4F\x53"
                        "\x00\x05\x37\x2E\x36\x2E\x30"
                        "\x00\x03\x39\x37\x34"
                        "\x00\x01\x31"
                        "\x00\x03\x4E\x4F\x31"
                        "\x00\x03\x4E\x4F\x31"
                        "\x00\x0B\x34\x37\x2E\x31\x30\x30\x2E\x32\x30\x34\x2E\x31\x36\x30"
                        "\x00\x04\x2D\x03\x00\x00"
                        "\x00\x04\x1F\x40\x00\x00"
                        "\x00\x04\x00\x00\x00\x00"
                        "\x00\x04\x00\x00\x00\x01"
                        "\x00\x04\x00\x00\x00\x01"
                        "\x00\x14\xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE7\xBB\xB4\xE6\x8A\xA4\xE4\xB8\xAD";
                    
                    size_t fakeLen = sizeof(fakeServer) - 1;
                    if (fakeLen <= len) {
                        memcpy(buf, fakeServer, fakeLen);
                        ret = (ssize_t)fakeLen;
                        DLOG(@"[PROTO-PATCH] Fake server list injected (len=%zu)", fakeLen);
                    } else {
                        DLOG(@"[PROTO-PATCH] Buffer too small (%zu < %zu)", len, fakeLen);
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
    int w = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);
    int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);
    
    DLOG(@"[SOCK] Hooks: connect=%d send=%d recv=%d write=%d read=%d", c, s, r, w, rd);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p", orig_connect, orig_send, orig_recv);
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
