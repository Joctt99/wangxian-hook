#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <sys/mman.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:@"[%@] " fmt, _timestamp(), ##__VA_ARGS__])
#define DLOG_HEX(buf, len) _log_hex(buf, len)

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES;
static BOOL g_logHexEnabled = YES;
static BOOL g_logProtoEnabled = YES;
static NSUInteger g_logMaxSize = 10 * 1024 * 1024;

static UIButton *g_logBtn = nil;
static UIView *g_logPanel = nil;
static UITextView *g_logTextView = nil;
static UILabel *g_logStatusLbl = nil;

static NSString *_timestamp(void) {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";
    return [fmt stringFromDate:[NSDate date]];
}

static void _log_rotate(void) {
    if (!g_logPath) return;
    @try {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        if (size > g_logMaxSize) {
            NSString *oldPath = [g_logPath stringByAppendingString:@".old"];
            [[NSFileManager defaultManager] removeItemAtPath:oldPath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:g_logPath toPath:oldPath error:nil];
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[WX2Hook] Log rotated (>%llu bytes)", size);
        }
    } @catch (NSException *e) {}
}

static void _log(NSString *msg) {
    if (!g_logPath || !g_logEnabled) return;
    
    _log_rotate();
    
    @try {
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
        if (data) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { 
                [fh seekToEndOfFile]; 
                [fh writeData:data]; 
                [fh closeFile]; 
            }
        }
        NSLog(@"[WX2Hook] %@", msg);
        
        if (g_logTextView && !g_logPanel.hidden) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
                if (content.length > g_logTextView.text.length + 5000) {
                    content = [content substringFromIndex:content.length - 50000];
                }
                g_logTextView.text = content;
                [g_logTextView scrollRangeToVisible:NSMakeRange(g_logTextView.text.length, 0)];
            });
        }
    } @catch (NSException *e) {}
}

static void _log_hex(const void *buf, ssize_t len) {
    if (!g_logHexEnabled || !buf || len <= 0) return;
    
    const unsigned char *p = (const unsigned char *)buf;
    NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:len];
    
    size_t showLen = len > 256 ? 256 : (size_t)len;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    
    if (len > 256) {
        [hex appendFormat:@"... (%zd more bytes)", len - 256];
        [ascii appendFormat:@"..."];
    }
    
    _log([NSString stringWithFormat:@"HEX: %@\nTXT: %@", hex, ascii]);
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wx2hook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        _log(@"=== WangXian2Hook v2.9 ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
        _log([NSString stringWithFormat:@"Log max size: %lu bytes", (unsigned long)g_logMaxSize]);
    }
}

#pragma mark - Log Panel UI

@interface WX2Handler : NSObject
@property (nonatomic) BOOL panelVisible;
- (void)togglePanel;
- (void)clearLog;
- (void)toggleLogging;
- (void)copyLog;
- (void)exportLog;
- (void)refreshLog;
- (void)handlePan:(UIPanGestureRecognizer *)gesture;
- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture;
@end

@implementation WX2Handler

- (void)togglePanel {
    if (!g_logPanel) {
        [self createLogPanel];
    }
    self.panelVisible = !self.panelVisible;
    g_logPanel.hidden = !self.panelVisible;
    
    if (self.panelVisible) {
        [self refreshLog];
        DLOG(@"[UI] Log panel shown");
    } else {
        DLOG(@"[UI] Log panel hidden");
    }
}

- (void)createLogPanel {
    UIWindow *w = g_logBtn.window;
    if (!w) return;
    
    CGFloat pw = w.bounds.size.width - 32;
    CGFloat ph = w.bounds.size.height - 150;
    
    g_logPanel = [[UIView alloc] initWithFrame:CGRectMake(16, 100, pw, ph)];
    g_logPanel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    g_logPanel.layer.cornerRadius = 12;
    g_logPanel.hidden = YES;
    
    UILabel *titleLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, pw - 200, 24)];
    titleLbl.text = @"WangXian2Hook v2.9 诊断面板";
    titleLbl.textColor = [UIColor greenColor];
    titleLbl.font = [UIFont boldSystemFontOfSize:14];
    [g_logPanel addSubview:titleLbl];
    
    g_logStatusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];
    g_logStatusLbl.text = @"日志: 开";
    g_logStatusLbl.textColor = [UIColor greenColor];
    g_logStatusLbl.font = [UIFont boldSystemFontOfSize:12];
    [g_logPanel addSubview:g_logStatusLbl];
    
    CGFloat bx = pw - 270;
    
    UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    onOffBtn.frame = CGRectMake(bx, 8, 50, 28);
    [onOffBtn setTitle:@"开关" forState:UIControlStateNormal];
    [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];
    [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:onOffBtn];
    
    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clearBtn.frame = CGRectMake(bx + 55, 8, 50, 28);
    [clearBtn setTitle:@"清除" forState:UIControlStateNormal];
    [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
    [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:clearBtn];
    
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(bx + 110, 8, 50, 28);
    [copyBtn setTitle:@"复制" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
    [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:copyBtn];
    
    UIButton *shareBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    shareBtn.frame = CGRectMake(bx + 165, 8, 50, 28);
    [shareBtn setTitle:@"导出" forState:UIControlStateNormal];
    [shareBtn setTitleColor:[UIColor magentaColor] forState:UIControlStateNormal];
    [shareBtn addTarget:self action:@selector(exportLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:shareBtn];
    
    UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshBtn.frame = CGRectMake(bx + 220, 8, 50, 28);
    [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];
    [refreshBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
    [refreshBtn addTarget:self action:@selector(refreshLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:refreshBtn];
    
    g_logTextView = [[UITextView alloc] initWithFrame:CGRectMake(8, 62, pw - 16, ph - 72)];
    g_logTextView.backgroundColor = [UIColor blackColor];
    g_logTextView.textColor = [UIColor greenColor];
    g_logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    g_logTextView.editable = NO;
    [g_logPanel addSubview:g_logTextView];
    
    [w addSubview:g_logPanel];
}

- (void)clearLog {
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_logTextView.text = @"(cleared)";
    g_logEnabled = YES;
    g_logStatusLbl.text = @"日志: 开";
    g_logStatusLbl.textColor = [UIColor greenColor];
    DLOG(@"=== Log cleared ===");
}

- (void)toggleLogging {
    g_logEnabled = !g_logEnabled;
    g_logStatusLbl.text = g_logEnabled ? @"日志: 开" : @"日志: 关";
    g_logStatusLbl.textColor = g_logEnabled ? [UIColor greenColor] : [UIColor redColor];
    if (g_logEnabled) {
        DLOG(@"=== Logging resumed ===");
    }
}

- (void)copyLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [UIPasteboard generalPasteboard].string = content;
    DLOG(@">>> COPIED %lu chars >>>", (unsigned long)content.length);
    g_logTextView.text = [NSString stringWithFormat:@">>> COPIED %lu chars to clipboard <<<", (unsigned long)content.length];
}

- (void)exportLog {
    if (!g_logPath) {
        DLOG(@"[EXPORT] Error: log path is nil");
        return;
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:g_logPath]) {
        DLOG(@"[EXPORT] Error: log file does not exist");
        return;
    }
    
    NSData *fullData = [NSData dataWithContentsOfFile:g_logPath];
    NSData *exportData = fullData;
    if (fullData.length > 200 * 1024) {
        exportData = [fullData subdataWithRange:NSMakeRange(fullData.length - 200 * 1024, 200 * 1024)];
    }
    
    NSString *exportPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wx2hook_export.log"];
    [exportData writeToFile:exportPath atomically:YES];
    DLOG(@"[EXPORT] Log exported to: %@", exportPath);
    g_logTextView.text = [NSString stringWithFormat:@">>> EXPORTED to Documents/wx2hook_export.log <<<"];
}

- (void)refreshLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_logTextView.text = content;
    [g_logTextView scrollRangeToVisible:NSMakeRange(g_logTextView.text.length, 0)];
}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    if (!g_logBtn || g_logBtn.hidden) return;
    UIView *v = gesture.view;
    CGPoint translation = [gesture translationInView:v.superview];
    CGPoint newCenter = CGPointMake(v.center.x + translation.x, v.center.y + translation.y);
    CGRect bounds = v.superview.bounds;
    newCenter.x = MAX(25, MIN(bounds.size.width - 25, newCenter.x));
    newCenter.y = MAX(25, MIN(bounds.size.height - 25, newCenter.y));
    v.center = newCenter;
    [gesture setTranslation:CGPointZero inView:v.superview];
}

- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture {
    if (g_logBtn) {
        g_logBtn.hidden = !g_logBtn.hidden;
        if (!g_logBtn.hidden) {
            DLOG(@"[UI] Log button shown via double-tap");
        } else {
            DLOG(@"[UI] Log button hidden via double-tap");
            g_logPanel.hidden = YES;
            self.panelVisible = NO;
        }
    }
}

@end

static void createLogButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *w = [[[UIApplication sharedApplication] delegate] window];
        if (!w || g_logBtn) return;
        
        WX2Handler *handler = [[WX2Handler alloc] init];
        
        g_logBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        g_logBtn.frame = CGRectMake(w.bounds.size.width - 60, 200, 50, 50);
        g_logBtn.layer.cornerRadius = 25;
        g_logBtn.clipsToBounds = YES;
        
        [g_logBtn setTitle:@"LOG" forState:UIControlStateNormal];
        [g_logBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_logBtn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
        g_logBtn.titleLabel.font = [UIFont systemFontOfSize:10];
        g_logBtn.hidden = YES;
        g_logBtn.userInteractionEnabled = YES;
        
        [g_logBtn addTarget:handler action:@selector(togglePanel) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:g_logBtn];
        [w bringSubviewToFront:g_logBtn];
        
        UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:handler action:@selector(handlePan:)];
        panGesture.cancelsTouchesInView = NO;
        panGesture.requiresExclusiveTouchType = NO;
        [g_logBtn addGestureRecognizer:panGesture];
        
        UITapGestureRecognizer *doubleTap = [[UITapGestureRecognizer alloc] initWithTarget:handler action:@selector(handleDoubleTap:)];
        doubleTap.numberOfTapsRequired = 2;
        [w addGestureRecognizer:doubleTap];
        
        DLOG(@"[UI] Log button created (double-tap to show)");
    });
}

#pragma mark - Socket Tracking

#define MAX_FDS 64
static struct {
    char host[64];
    int port;
    int active;
} g_fdInfo[MAX_FDS] = {0};

static void trackFd(int fd, const char *host, int port) {
    if (fd >= 0 && fd < MAX_FDS) {
        strncpy(g_fdInfo[fd].host, host ?: "", sizeof(g_fdInfo[fd].host) - 1);
        g_fdInfo[fd].port = port;
        g_fdInfo[fd].active = 1;
    }
}

static const char *getHostForFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_fdInfo[fd].active) {
        return g_fdInfo[fd].host[0] ? g_fdInfo[fd].host : NULL;
    }
    return NULL;
}

static int getPortForFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_fdInfo[fd].active) {
        return g_fdInfo[fd].port;
    }
    return 0;
}

static void releaseFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS) {
        memset(&g_fdInfo[fd], 0, sizeof(g_fdInfo[fd]));
    }
}

#pragma mark - Socket Hooks

typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
typedef int (*CloseFunc)(int);

static RecvFunc orig_recv = NULL;
static RecvfromFunc orig_recvfrom = NULL;
static RecvmsgFunc orig_recvmsg = NULL;
static SendFunc orig_send = NULL;
static WriteFunc orig_write = NULL;
static ConnectFunc orig_connect = NULL;
static CloseFunc orig_close = NULL;

static void patchVersionCheckResponse(unsigned char *buf, ssize_t len) {
    if (!buf || len <= 0) return;
    
    BOOL patched = NO;
    
    if (len >= 8) {
        uint32_t pktLenBE = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                            ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
        uint32_t cmd = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                       ((uint32_t)buf[6] << 8)  | (uint32_t)buf[7];
        
        if (g_logProtoEnabled) {
            DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, len);
        }
        
        if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] VERSION CHECK RESPONSE cmd=0x%08X pktLen=%u actualLen=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len);
            
            ssize_t maxPatch = (ssize_t)pktLenBE;
            if (maxPatch > len) maxPatch = len;
            
            if (maxPatch >= 12) {
                uint32_t status4 = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                   ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
                DLOG(@"[PROTO-R] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
                if (status4 != 0) {
                    DLOG(@"[PROTO-R-PATCH] Version check 4-byte status %u -> 0", status4);
                    memset(buf + 8, 0, 4);
                    patched = YES;
                }
            }
            
            if (maxPatch >= 13 && buf[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 1-byte status at offset 12: %u -> 0", buf[12]);
                buf[12] = 0;
                patched = YES;
            }
            
            if (maxPatch > 13) {
                DLOG(@"[PROTO-R-PATCH] Clearing error messages from offset 13 onwards (%zd bytes, within pktLen)", maxPatch - 13);
                memset(buf + 13, 0, maxPatch - 13);
                patched = YES;
            }
        } else if (cmd == 0x76666669) {
            DLOG(@"[PROTO-R] DEBUG ECHO RESPONSE cmd=0x%08X", cmd);
        } else if (cmd == 0x80000015) {
            DLOG(@"[PROTO-R] PING RESPONSE cmd=0x%08X", cmd);
        } else if (cmd == 0x800FF012) {
            DLOG(@"[PROTO-R] SERVER LIST RESPONSE cmd=0x%08X pktLen=%u actualLen=%zd", cmd, pktLenBE, len);
            
            if (len >= 12) {
                uint32_t status4 = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                   ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
                if (status4 != 1) {
                    DLOG(@"[PROTO-R-PATCH] Server list status %u -> 1", status4);
                    buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x01;
                    patched = YES;
                }
            }
            
            if (len >= 30 && len < 100) {
                DLOG_HEX(buf, len);
            }
        } else if (cmd == 0x81EFBC8C) {
            DLOG(@"[PROTO-R] LARGE DATA RESPONSE cmd=0x%08X len=%zd", cmd, len);
        }
    }
    
    ssize_t searchLimit = len;
    if (len >= 4) {
        uint32_t firstPktLenBE = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                                 ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
        searchLimit = (ssize_t)firstPktLenBE;
        if (searchLimit > len) searchLimit = len;
    }
    
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(buf + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-R] Detected '版本过低' at offset %zd", i);
            memset(buf + i, ' ', sizeof(verLow));
            patched = YES;
        }
    }
    
    static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(curVer); i++) {
        if (memcmp(buf + i, curVer, sizeof(curVer)) == 0) {
            DLOG(@"[PATCH-R] Detected '当前版本' at offset %zd", i);
            memset(buf + i, ' ', sizeof(curVer));
            patched = YES;
        }
    }
    
    static const unsigned char needUpdate[] = {0xE8,0xAF,0xB7,0xE6,0x9B,0xB4,0xE6,0x96,0xB0};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(needUpdate); i++) {
        if (memcmp(buf + i, needUpdate, sizeof(needUpdate)) == 0) {
            DLOG(@"[PATCH-R] Detected '请更新' at offset %zd", i);
            memset(buf + i, ' ', sizeof(needUpdate));
            patched = YES;
        }
    }
    
    static const unsigned char forceUpdate[] = {0xE5,0xBC,0xBA,0x5F,0xE6,0x9B,0xB4,0xE6,0x96,0xB0};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(forceUpdate); i++) {
        if (memcmp(buf + i, forceUpdate, sizeof(forceUpdate)) == 0) {
            DLOG(@"[PATCH-R] Detected '强制更新' at offset %zd", i);
            memset(buf + i, ' ', sizeof(forceUpdate));
            patched = YES;
        }
    }
    
    if (patched) {
        DLOG(@"[PATCH] Version check response patched successfully!");
        DLOG_HEX(buf, len);
    }
}

static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv || !buf) return -1;
    
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    DLOG(@"[RECV] fd=%d %s:%d len=%zd", fd, host ?: "unknown", port, ret);
    
    patchVersionCheckResponse((unsigned char *)buf, ret);
    
    return ret;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom || !buf) return -1;
    
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) return ret;
    
    char host[64] = "unknown";
    int port = 0;
    
    if (src_addr && addrlen && *addrlen > 0) {
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[RECVFROM] fd=%d %s:%d len=%zd", fd, host, port, ret);
    
    patchVersionCheckResponse((unsigned char *)buf, ret);
    
    return ret;
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;
    
    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0) return ret;
    
    char host[64] = "unknown";
    int port = 0;
    
    if (msg->msg_name && msg->msg_namelen > 0) {
        struct sockaddr *src_addr = (struct sockaddr *)msg->msg_name;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[RECVMSG] fd=%d %s:%d len=%zd", fd, host, port, ret);
    
    struct iovec *iov = msg->msg_iov;
    if (iov->iov_base && iov->iov_len > 0) {
        patchVersionCheckResponse((unsigned char *)iov->iov_base, ret);
    }
    
    return ret;
}

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    
    char host[64] = "unknown";
    int port = 0;
    
    if (addr && addrlen > 0) {
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[CONNECT] fd=%d %s:%d", fd, host, port);
    
    int ret = orig_connect ? orig_connect(fd, addr, addrlen) : -1;
    if (ret == 0) {
        trackFd(fd, host, port);
        DLOG(@"[CONNECT] SUCCESS fd=%d", fd);
    } else {
        DLOG(@"[CONNECT] FAILED fd=%d err=%d", fd, errno);
    }
    
    return ret;
}

static int hook_close(int fd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    releaseFd(fd);
    
    return orig_close ? orig_close(fd) : -1;
}

static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_send || !buf) return -1;
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    DLOG(@"[SEND] fd=%d %s:%d len=%zu", fd, host ?: "unknown", port, len);
    
    void *sendBuf = (void *)buf;
    BOOL modified = NO;
    
    const char *oldVer = "7.5.0";
    const char *newVer = "9.9.9";
    size_t oldVerLen = strlen(oldVer);
    size_t newVerLen = strlen(newVer);
    
    for (size_t i = 0; i <= len - oldVerLen; i++) {
        if (memcmp(buf + i, oldVer, oldVerLen) == 0) {
            if (!modified) {
                sendBuf = malloc(len);
                memcpy(sendBuf, buf, len);
                modified = YES;
            }
            unsigned char *mp = (unsigned char *)sendBuf;
            memcpy(mp + i, newVer, newVerLen);
            DLOG(@"[SEND-PATCH] Version '%s' -> '%s' at offset %zu", oldVer, newVer, i);
        }
    }
    
    if (len >= 8) {
        const unsigned char *p = (const unsigned char *)sendBuf;
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        
        DLOG(@"[SEND-CMD] cmd=0x%08X pktLen=%u", cmd, pktLenBE);
        
        if (cmd == 0x002EE118 || cmd == 0x002EE119 || cmd == 0x002EE120) {
            DLOG(@"[SEND-CMD] VERSION CHECK REQUEST");
        } else if (cmd == 0x0234AB89) {
            DLOG(@"[SEND-CMD] LOGIN REQUEST");
        } else if (cmd == 0x000FF012) {
            DLOG(@"[SEND-CMD] SERVER LIST REQUEST");
        } else if (cmd == 0x000EE006) {
            DLOG(@"[SEND-CMD] UUID/HANDSHAKE REQUEST");
        }
        
        if (len >= 30 && len < 150) {
            DLOG_HEX(sendBuf, len);
        } else if (len >= 150) {
            DLOG_HEX(sendBuf, 100);
        }
    } else {
        DLOG_HEX(sendBuf, len);
    }
    
    ssize_t ret = orig_send(fd, sendBuf, len, flags);
    
    if (modified && sendBuf != buf) {
        free(sendBuf);
    }
    
    return ret;
}

#pragma mark - URLSession Hooks

static NSURLSessionDataTask *(*orig_dtwrc)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {
    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;
    if (comp) {
        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (data && data.length > 0) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (body) {
                    if ([body containsString:@"版本"] || [body containsString:@"更新"] || 
                        [body containsString:@"升级"] || [body containsString:@"status"]) {
                        DLOG(@"[NET] Version-related HTTP response detected (len=%lu)", (unsigned long)data.length);
                        DLOG(@"[NET] Original response: %@", body.length > 1000 ? [body substringToIndex:1000] : body);
                        
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":5" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":6" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"result\":\"fail\"" withString:@"\"result\":\"success\""];
                        body = [body stringByReplacingOccurrencesOfString:@"版本过低" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"请更新" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"强制更新" withString:@""];
                        
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Modified response, new len=%lu", (unsigned long)data.length);
                        DLOG(@"[NET-PATCH] Modified response: %@", body.length > 1000 ? [body substringToIndex:1000] : body);
                    }
                }
            }
            comp(data, resp, err);
        } copy];
    }
    
    if (orig_dtwrc) return orig_dtwrc(self, _cmd, req, wrappedComp);
    return nil;
}

#pragma mark - Alert Hooks

static void (*orig_alertShow)(id, SEL) = NULL;
static void hook_alertShow(id self, SEL _cmd) {
    NSString *title = @"";
    NSString *msg = @"";
    @try {
        if ([self respondsToSelector:@selector(title)]) title = [self performSelector:@selector(title)] ?: @"";
        if ([self respondsToSelector:@selector(message)]) msg = [self performSelector:@selector(message)] ?: @"";
    } @catch (NSException *e) {}
    
    NSString *lowerMsg = [msg lowercaseString];
    NSString *lowerTitle = [title lowercaseString];
    
    if ([lowerMsg containsString:@"版本"] || [lowerMsg containsString:@"更新"] || 
        [lowerMsg containsString:@"升级"] || [lowerTitle containsString:@"版本"]) {
        DLOG(@"[ALERT-BLOCK] Blocked version alert: title='%@' msg='%@'", title, msg);
        return;
    }
    
    if (orig_alertShow) orig_alertShow(self, _cmd);
}

#pragma mark - SignatureKit/SignatureCheck Hooks

typedef void (*ShowAlertIMP)(id, SEL, id);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, id msg) {
    DLOG(@"[SK] showAlert: SUPPRESSED: %@", msg);
}

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

#pragma mark - Symbol Rebinding

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

__attribute__((constructor))
static void entry(void) {
    log_init();
    DLOG(@"[INIT] WangXian2Hook initialized");
    
    int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);
    int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);
    int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
    int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);
    
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    DLOG(@"[SOCK] Patched: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d close=%d", c, s, r, rf, rm, cl);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p close=%p", orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg, orig_close);
    
    if (!orig_connect) DLOG(@"[SOCK-WARN] connect hook failed");
    if (!orig_recv) DLOG(@"[SOCK-WARN] recv hook failed");
    
    Class sessCls = [NSURLSession class];
    if (sessCls) {
        Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
        if (m) { 
            orig_dtwrc = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))method_getImplementation(m); 
            method_setImplementation(m, (IMP)hook_dtwrc); 
            DLOG(@"[INIT] NSURLSession hooked");
        }
    }
    
    Class alertCls = [UIAlertView class];
    if (alertCls) {
        Method m = class_getInstanceMethod(alertCls, @selector(show));
        if (m) { 
            orig_alertShow = (void (*)(id, SEL))method_getImplementation(m); 
            method_setImplementation(m, (IMP)hook_alertShow); 
            DLOG(@"[INIT] UIAlertView hooked");
        }
    }
    
    Class alertCtrlCls = [UIAlertController class];
    if (alertCtrlCls) {
        Method m = class_getInstanceMethod(alertCtrlCls, @selector(presentViewController:animated:completion:));
        if (m) { 
            method_setImplementation(m, (IMP)hook_alertShow); 
            DLOG(@"[INIT] UIAlertController hooked");
        }
    }
    
    Class skCls = NSClassFromString(@"SignatureKit");
    if (skCls) {
        Method m = class_getClassMethod(skCls, @selector(showAlert:));
        if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SK.showAlert hooked"); }
        
        m = class_getClassMethod(skCls, @selector(exitApplication));
        if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SK.exitApplication hooked"); }
    }
    
    Class scCls = NSClassFromString(@"SignatureCheck");
    if (scCls) {
        Method m = class_getClassMethod(scCls, @selector(exitApplication));
        if (m) { method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SC.exitApplication hooked"); }
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        createLogButton();
    });
    
    DLOG(@"[INIT] All hooks installed successfully!");
}