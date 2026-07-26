#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import "fishhook.h"

#pragma mark - File Logger

static NSFileHandle *logFileHandle = nil;

static void initLogger() {
    if (logFileHandle) return;
    
    @try {
        NSString *docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (!docPath) docPath = [NSTemporaryDirectory() copy];
        NSString *logPath = [docPath stringByAppendingPathComponent:@"wxhook.log"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:logPath]) {
            [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
        }
        
        logFileHandle = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (logFileHandle) [logFileHandle seekToEndOfFile];
        
        NSLog(@"[WX] Logger initialized: %@", logPath);
    } @catch (NSException *e) {
        NSLog(@"[WX] Logger init failed: %@", e.reason);
    }
}

#define DLOG(fmt, ...) do { \
    NSString *_s = [NSString stringWithFormat:fmt @"\n", ##__VA_ARGS__]; \
    NSLog(@"[WX] " fmt, ##__VA_ARGS__); \
    if (logFileHandle) { \
        @synchronized(logFileHandle) { \
            [logFileHandle writeData:[_s dataUsingEncoding:NSUTF8StringEncoding]]; \
            [logFileHandle synchronizeFile]; \
        } \
    } \
} while (0)

static NSString *fakeVersion = @"7.7.0";

#pragma mark - Socket Hooks

typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
static ConnectFunc orig_connect = NULL;
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
static SendFunc orig_send = NULL;
typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
static RecvFunc orig_recv = NULL;
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static RecvfromFunc orig_recvfrom = NULL;
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);
static RecvmsgFunc orig_recvmsg = NULL;
typedef int (*CloseFunc)(int);
static CloseFunc orig_close = NULL;
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
static WriteFunc orig_write = NULL;
typedef ssize_t (*ReadFunc)(int, void *, size_t);
static ReadFunc orig_read = NULL;

#define MAX_FDS 256
static struct { char host[64]; int port; } fdMap[MAX_FDS];

static void trackFd(int fd, const char *host, int port) {
    if (fd < 0 || fd >= MAX_FDS) return;
    strncpy(fdMap[fd].host, host, 63);
    fdMap[fd].port = port;
}
static const char *getHostForFd(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return "unknown";
    return fdMap[fd].host[0] ? fdMap[fd].host : "unknown";
}
static int getPortForFd(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return 0;
    return fdMap[fd].port;
}

#pragma mark - Protocol Patching

static void patchProtocolResponse(unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    
    if (cmd == 0x802EE121 && len >= 94) {
        unsigned char status = buf[12];
        if (status != 0) {
            DLOG(@"[PROTO-R-PATCH] 0x802EE121 status byte 12: 0x%02X -> 0x00", status);
            buf[12] = 0x00;
            if (len > 15) { memset(buf + 15, 0, 60); DLOG(@"[PROTO-R-PATCH] Cleared error msg1 at offset 15"); }
            if (len > 76) { memset(buf + 76, 0, 18); DLOG(@"[PROTO-R-PATCH] Cleared error msg2 at offset 76"); }
            DLOG(@"[PROTO-R-PATCH] Response length preserved: %zd bytes", len);
        }
    }
    
    if (cmd == 0x802EE118 && len >= 13) {
        unsigned char status = buf[12];
        if (status != 0) {
            buf[12] = 0x00;
            DLOG(@"[PROTO-R-PATCH] 0x802EE118 status byte 12: 0x%02X -> 0x00", status);
        }
    }
}

#pragma mark - Challenge Response

static void handleChallenge(int sockfd, unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    
    if (cmd == 0x00FFFF02) {
        unsigned char response[64];
        memset(response, 0, sizeof(response));
        
        uint32_t respLen = (uint32_t)len;
        response[0] = (respLen >> 24) & 0xFF;
        response[1] = (respLen >> 16) & 0xFF;
        response[2] = (respLen >> 8) & 0xFF;
        response[3] = respLen & 0xFF;
        
        response[4] = 0x80; response[5] = 0xFF; response[6] = 0xFF; response[7] = 0x02;
        
        memcpy(response + 8, buf + 8, len - 8);
        
        ssize_t sendRet = orig_send(sockfd, response, len, 0);
        DLOG(@"[CHALLENGE-RESP] Auto-responded to 0x00FFFF02 with 0x80FFFF02 (len=%zd, sent=%zd)", len, sendRet);
        
        NSMutableString *hexStr = [NSMutableString string];
        for (ssize_t i = 0; i < len && i < 64; i++) {
            [hexStr appendFormat:@"%02X ", response[i]];
        }
        DLOG(@"[CHALLENGE-RESP] Response hex: %@", hexStr);
    }
}

#pragma mark - Socket Hook Implementations

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_connect) return -1;
    
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    int port = ntohs(sin->sin_port);
    char host[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
    
    trackFd(sockfd, host, port);
    DLOG(@"[SOCK] connect fd=%d %s:%d", sockfd, host, port);
    
    return orig_connect(sockfd, addr, addrlen);
}

static ssize_t hook_send(int sockfd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_send) return -1;
    
    const unsigned char *cbuf = (const unsigned char *)buf;
    
    if (len >= 8) {
        uint32_t cmd = (cbuf[4] << 24) | (cbuf[5] << 16) | (cbuf[6] << 8) | cbuf[7];
        DLOG(@"[SEND-CMD] fd=%d %s:%d cmd=0x%08X len=%zu", sockfd, getHostForFd(sockfd), getPortForFd(sockfd), cmd, len);
    }
    
    // 版本替换 7.6.x -> 7.7.0
    if (len >= 8) {
        const char *patterns[] = {"7.6.2", "7.6.3", NULL};
        const char *newVer = "7.7.0";
        for (int p = 0; patterns[p]; p++) {
            const char *oldVer = patterns[p];
            size_t oldVerLen = strlen(oldVer);
            for (size_t i = 0; i <= len - oldVerLen; i++) {
                if (memcmp(cbuf + i, oldVer, oldVerLen) == 0) {
                    void *sendBuf = malloc(len);
                    memcpy(sendBuf, buf, len);
                    memcpy((unsigned char *)sendBuf + i, newVer, strlen(newVer));
                    ssize_t ret = orig_send(sockfd, sendBuf, len, flags);
                    free(sendBuf);
                    DLOG(@"[SEND] Version replaced %s->7.7.0 at offset %zu", oldVer, i);
                    return ret;
                }
            }
        }
    }
    
    return orig_send(sockfd, buf, len, flags);
}

static ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv) return -1;
    
    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    
    if (ret > 0) {
        unsigned char *p = (unsigned char *)buf;
        if (ret >= 8) {
            uint32_t cmd = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
            DLOG(@"[RECV] fd=%d %s:%d ret=%zd cmd=0x%08X", sockfd, getHostForFd(sockfd), getPortForFd(sockfd), ret, cmd);
        }
        
        patchProtocolResponse(p, ret);
        handleChallenge(sockfd, p, ret);
    } else if (ret == 0) {
        DLOG(@"[RECV-CLOSE] fd=%d %s:%d ret=0 (server closed)", sockfd, getHostForFd(sockfd), getPortForFd(sockfd));
    }
    
    return ret;
}

static ssize_t hook_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom) return -1;
    ssize_t ret = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (ret > 0) patchProtocolResponse((unsigned char *)buf, ret);
    return ret;
}

static ssize_t hook_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg) return -1;
    ssize_t ret = orig_recvmsg(sockfd, msg, flags);
    if (ret > 0 && msg->msg_iov && msg->msg_iovlen > 0) {
        patchProtocolResponse((unsigned char *)msg->msg_iov[0].iov_base, (ssize_t)msg->msg_iov[0].iov_len);
    }
    return ret;
}

static int hook_close(int fd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    if (!orig_close) return -1;
    if (fd >= 0 && fd < MAX_FDS && fdMap[fd].host[0]) {
        DLOG(@"[FD-CLOSE] fd=%d %s:%d removed", fd, fdMap[fd].host, fdMap[fd].port);
        fdMap[fd].host[0] = 0;
        fdMap[fd].port = 0;
    }
    return orig_close(fd);
}

static ssize_t hook_write(int fd, const void *buf, size_t count) {
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    if (!orig_write) return -1;
    return orig_write(fd, buf, count);
}

static ssize_t hook_read(int fd, void *buf, size_t count) {
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_read) return -1;
    ssize_t ret = orig_read(fd, buf, count);
    if (ret > 0) patchProtocolResponse((unsigned char *)buf, ret);
    return ret;
}

#pragma mark - UIDevice Hooks

static NSString *hook_currentVersion(id self, SEL _cmd) { return fakeVersion; }
static BOOL hook_isJailbroken(id self, SEL _cmd) { return NO; }

static NSUUID *fixedUUID = nil;
static NSUUID *hook_identifierForVendor(id self, SEL _cmd) {
    if (!fixedUUID) {
        fixedUUID = [[NSUUID alloc] initWithUUIDString:@"180C4F27-4414-4623-ACEB-0C12B30E48FD"];
    }
    return fixedUUID;
}

static NSString *hook_clientKey(id self, SEL _cmd) { return @"9776140989ac5e206bbf4ce03c0a47fd"; }
static NSString *hook_tid(id self, SEL _cmd) { return @"46304785137107367677"; }
static NSString *hook_udid(id self, SEL _cmd) { return @"86f8e1451fef27bb7bacf390f0a6355bdfbf9343"; }
static NSString *hook_virtualImei(id self, SEL _cmd) { return @"46304785137107367677"; }
static NSString *hook_virtualImsi(id self, SEL _cmd) { return @"46304785137107367677"; }

#pragma mark - NSBundle Hooks

static NSString *hook_objectForInfoDictionaryKey(id self, SEL _cmd, NSString *key) {
    if ([key isEqualToString:@"CFBundleShortVersionString"] || [key isEqualToString:@"CFBundleVersion"]) {
        return fakeVersion;
    }
    return [NSBundle.mainBundle objectForInfoDictionaryKey:key];
}

#pragma mark - NSUserDefaults Hooks

static id (*orig_objectForKey)(id, SEL, NSString *) = NULL;
static id hook_objectForKey(id self, SEL _cmd, NSString *key) {
    return orig_objectForKey(self, _cmd, key);
}

static BOOL (*orig_boolForKey)(id, SEL, NSString *) = NULL;
static BOOL hook_boolForKey(id self, SEL _cmd, NSString *key) {
    return orig_boolForKey(self, _cmd, key);
}

#pragma mark - NSURLSession Hooks

static NSURLSessionDataTask *(*orig_dtwrc)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;
static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    DLOG(@"[NSURL] %@", request.URL.absoluteString);
    return orig_dtwrc(self, _cmd, request, completionHandler);
}

#pragma mark - Alert Hooks

static void (*orig_alertShow)(id, SEL) = NULL;
static void hook_alertShow(id self, SEL _cmd) { DLOG(@"[ALERT] show BLOCKED"); }

#pragma mark - SignatureKit Hooks

typedef void (*ShowAlertIMP)(id, SEL, NSString *);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, NSString *msg) { DLOG(@"[SK] showAlert BLOCKED: %@", msg); }

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) { DLOG(@"[SK] exitApplication BLOCKED"); }

typedef void (*JudgeNetIMP)(id, SEL);
static JudgeNetIMP orig_judgeNet = NULL;
static void hook_judgeNet(id self, SEL _cmd) { DLOG(@"[SK] judgeNet BLOCKED"); }

#pragma mark - EncryptUtils Hooks

static NSData *(*orig_hmacSha256)(id, SEL, NSString *, NSString *) = NULL;
static NSData *hook_hmacSha256(id self, SEL _cmd, NSString *key, NSString *str) {
    str = [str stringByReplacingOccurrencesOfString:@"7.6.2" withString:@"7.7.0"];
    str = [str stringByReplacingOccurrencesOfString:@"7.6.3" withString:@"7.7.0"];
    return orig_hmacSha256(self, _cmd, key, str);
}

static BOOL hook_rsaVerifyData(id self, SEL _cmd, NSData *data, NSData *signature, NSString *publicKey) {
    return YES;
}

#pragma mark - Entry

__attribute__((constructor))
static void entry() {
    @autoreleasepool {
        initLogger();
        
        DLOG(@"=== WangXianHook v36.10 loaded @ %s ===", __DATE__);
        DLOG(@"App: %s", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
        DLOG(@"[ACT] Installing all hooks...");
        
        // Socket hooks
        struct rebinding rebindings[] = {
            {"connect", (void *)hook_connect, (void **)&orig_connect},
            {"send", (void *)hook_send, (void **)&orig_send},
            {"recv", (void *)hook_recv, (void **)&orig_recv},
            {"recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom},
            {"recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg},
            {"close", (void *)hook_close, (void **)&orig_close},
            {"write", (void *)hook_write, (void **)&orig_write},
            {"read", (void *)hook_read, (void **)&orig_read},
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        
        if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
        if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
        if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
        if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
        if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
        if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
        if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
        if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
        
        DLOG(@"[SOCK] Hooks: connect=%p send=%p recv=%p", orig_connect, orig_send, orig_recv);
        
        // NSUserDefaults
        Class udCls = [NSUserDefaults class];
        if (udCls) {
            Method m = class_getInstanceMethod(udCls, @selector(objectForKey:));
            if (m) { orig_objectForKey = (id (*)(id, SEL, NSString *))method_getImplementation(m); method_setImplementation(m, (IMP)hook_objectForKey); }
            m = class_getInstanceMethod(udCls, @selector(boolForKey:));
            if (m) { orig_boolForKey = (BOOL (*)(id, SEL, NSString *))method_getImplementation(m); method_setImplementation(m, (IMP)hook_boolForKey); }
            DLOG(@"[INIT] NSUserDefaults hooked (objectForKey + boolForKey)");
        }
        
        // NSBundle
        Class bundleCls = [NSBundle class];
        if (bundleCls) {
            Method m = class_getInstanceMethod(bundleCls, @selector(objectForInfoDictionaryKey:));
            if (m) { method_setImplementation(m, (IMP)hook_objectForInfoDictionaryKey); DLOG(@"[INIT] NSBundle.objectForInfoDictionaryKey: HOOKED (version fake 7.6.x->7.7.0)"); }
        }
        
        // UIDevice
        Class deviceCls = [UIDevice class];
        if (deviceCls) {
            Method m = class_getInstanceMethod(deviceCls, @selector(currentVersion));
            if (m) { method_setImplementation(m, (IMP)hook_currentVersion); DLOG(@"[INIT] UIDevice.currentVersion: HOOKED (fake 7.7.0)"); }
            else { class_addMethod(deviceCls, @selector(currentVersion), (IMP)hook_currentVersion, "@@:"); DLOG(@"[INIT] UIDevice.currentVersion: ADDED"); }
            
            m = class_getInstanceMethod(deviceCls, @selector(isJailbroken));
            if (m) { method_setImplementation(m, (IMP)hook_isJailbroken); DLOG(@"[INIT] UIDevice.isJailbroken: HOOKED (return NO)"); }
            else { class_addMethod(deviceCls, @selector(isJailbroken), (IMP)hook_isJailbroken, "B@:"); DLOG(@"[INIT] UIDevice.isJailbroken: ADDED"); }
            
            m = class_getInstanceMethod(deviceCls, @selector(identifierForVendor));
            if (m) { method_setImplementation(m, (IMP)hook_identifierForVendor); DLOG(@"[INIT] UIDevice.identifierForVendor: HOOKED (UUID fix)"); }
            
            m = class_getInstanceMethod(deviceCls, @selector(clientKey));
            if (m) { method_setImplementation(m, (IMP)hook_clientKey); DLOG(@"[INIT] UIDevice.clientKey: HOOKED"); }
            m = class_getInstanceMethod(deviceCls, @selector(tid));
            if (m) { method_setImplementation(m, (IMP)hook_tid); DLOG(@"[INIT] UIDevice.tid: HOOKED"); }
            m = class_getInstanceMethod(deviceCls, @selector(udid));
            if (m) { method_setImplementation(m, (IMP)hook_udid); DLOG(@"[INIT] UIDevice.udid: HOOKED"); }
            m = class_getInstanceMethod(deviceCls, @selector(virtualImei));
            if (m) { method_setImplementation(m, (IMP)hook_virtualImei); DLOG(@"[INIT] UIDevice.virtualImei: HOOKED"); }
            m = class_getInstanceMethod(deviceCls, @selector(virtualImsi));
            if (m) { method_setImplementation(m, (IMP)hook_virtualImsi); DLOG(@"[INIT] UIDevice.virtualImsi: HOOKED"); }
        }
        
        // NSURLSession
        Class sessCls = [NSURLSession class];
        if (sessCls) {
            Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
            if (m) { orig_dtwrc = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))method_getImplementation(m); method_setImplementation(m, (IMP)hook_dtwrc); DLOG(@"[INIT] NSURLSession.dataTask+comp observe"); }
        }
        
        // UIAlertView
        Class alertCls = [UIAlertView class];
        if (alertCls) {
            Method m = class_getInstanceMethod(alertCls, @selector(show));
            if (m) { orig_alertShow = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertShow); DLOG(@"[INIT] UIAlertView.show: hook"); }
        }
        
        // UIAlertController
        Class alertCtrlCls = [UIAlertController class];
        if (alertCtrlCls) {
            Method m = class_getInstanceMethod(alertCtrlCls, @selector(presentViewController:animated:completion:));
            if (m) { method_setImplementation(m, (IMP)hook_alertShow); DLOG(@"[INIT] UIAlertController.present: hook"); }
        }
        
        // SignatureKit
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            Method m = class_getClassMethod(skCls, @selector(showAlert:));
            if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SK.showAlert: SUPPRESS"); }
            m = class_getClassMethod(skCls, @selector(exitApplication));
            if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SK.exitApplication: BLOCK"); }
            m = class_getClassMethod(skCls, @selector(judgeNet));
            if (m) { orig_judgeNet = (JudgeNetIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeNet); DLOG(@"[INIT] SK.judgeNet: BLOCK"); }
        }
        
        // SignatureCheck
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            Method m = class_getClassMethod(scCls, @selector(exitApplication));
            if (m) { method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SC.exitApplication: BLOCK"); }
            m = class_getClassMethod(scCls, @selector(JudgeApp));
            if (m) { method_setImplementation(m, (IMP)hook_judgeNet); DLOG(@"[INIT] SC.JudgeApp: BLOCK"); }
            m = class_getClassMethod(scCls, @selector(showTipViewEND:));
            if (m) { method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SC.showTipViewEND: SUPPRESS"); }
        }
        
        // EncryptUtils
        Class euCls = NSClassFromString(@"EncryptUtils");
        if (euCls) {
            Method m = class_getClassMethod(euCls, @selector(hmacSha256WithKey:string:));
            if (m) { orig_hmacSha256 = (NSData *(*)(id, SEL, NSString *, NSString *))method_getImplementation(m); method_setImplementation(m, (IMP)hook_hmacSha256); DLOG(@"[INIT] EncryptUtils.hmacSha256WithKey:string: HOOKED (version fix)"); }
            
            m = class_getClassMethod(euCls, @selector(rsaVerifyData:signature:withPublicKey:));
            if (m) { method_setImplementation(m, (IMP)hook_rsaVerifyData); DLOG(@"[INIT] EncryptUtils.rsaVerifyData: HOOKED (force YES)"); }
        }
        
        // APSecurity (7.6.3新增)
        Class apsCls = NSClassFromString(@"APSecurity");
        if (apsCls) {
            DLOG(@"[INIT] APSecurity class FOUND - hooking");
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(apsCls, &mc);
            if (methods) {
                for (unsigned int i = 0; i < mc; i++) {
                    SEL sel = method_getName(methods[i]);
                    NSString *selStr = NSStringFromSelector(sel);
                    if ([selStr containsString:@"showAlert"] || [selStr containsString:@"alert"] ||
                        [selStr containsString:@"exit"] || [selStr containsString:@"crash"]) {
                        method_setImplementation(methods[i], (IMP)hook_showAlert);
                        DLOG(@"[INIT] APSecurity.%@: HOOKED", selStr);
                    }
                }
                free(methods);
            }
            Method m = class_getInstanceMethod(apsCls, @selector(isJailbroken));
            if (m) { method_setImplementation(m, (IMP)hook_isJailbroken); DLOG(@"[INIT] APSecurity.isJailbroken: HOOKED"); }
            m = class_getInstanceMethod(apsCls, @selector(checkSecurity));
            if (m) { class_replaceMethod(apsCls, @selector(checkSecurity), (IMP)hook_isJailbroken, "B@:"); DLOG(@"[INIT] APSecurity.checkSecurity: HOOKED"); }
        }
        
        DLOG(@"[ACT] All hooks installed - v36.10");
    }
}