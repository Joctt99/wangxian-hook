#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import "fishhook.h"

#define DLOG(fmt, ...) do { \
    NSLog(@"[WX] " fmt, ##__VA_ARGS__); \
} while (0)

static NSString *fakeVersion = @"7.7.0";

#pragma mark - UIDevice Hooks

static NSString *hook_currentVersion(id self, SEL _cmd) {
    DLOG(@"[VER-FAKE] currentVersion -> '%@'", fakeVersion);
    return fakeVersion;
}

static BOOL hook_isJailbroken(id self, SEL _cmd) {
    DLOG(@"[JAIL-FAKE] isJailbroken -> NO");
    return NO;
}

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

#pragma mark - Protocol Patching

static void patchLoginResponse(unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    
    if (cmd == 0x802EE121) {
        uint32_t status = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
        if (status != 0) {
            buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00;
            DLOG(@"[PROTO-PATCH] Login response patched: status %u -> 0", status);
        }
    }
}

static void patchVersionCheckResponse(unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    
    if (cmd == 0x802EE118) {
        uint32_t status = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
        if (status != 0) {
            buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00;
            DLOG(@"[PROTO-PATCH] Version check response patched: status %u -> 0", status);
        }
    }
}

#pragma mark - Connect Hook

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_connect) return -1;
    
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    int port = ntohs(sin->sin_port);
    char host[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
    
    DLOG(@"[CONNECT] fd=%d %s:%d", sockfd, host, port);
    
    return orig_connect(sockfd, addr, addrlen);
}

#pragma mark - Send Hook

static ssize_t hook_send(int sockfd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_send) return -1;
    
    const unsigned char *cbuf = (const unsigned char *)buf;
    
    if (len >= 12) {
        uint32_t cmd = (cbuf[4] << 24) | (cbuf[5] << 16) | (cbuf[6] << 8) | cbuf[7];
        
        const char *oldVer = "7.6.3";
        const char *newVer = "7.7.0";
        size_t oldVerLen = strlen(oldVer);
        for (size_t i = 0; i <= len - oldVerLen; i++) {
            if (memcmp(cbuf + i, oldVer, oldVerLen) == 0) {
                void *sendBuf = malloc(len);
                memcpy(sendBuf, buf, len);
                unsigned char *mp = (unsigned char *)sendBuf;
                memcpy(mp + i, newVer, strlen(newVer));
                ssize_t ret = orig_send(sockfd, sendBuf, len, flags);
                free(sendBuf);
                DLOG(@"[SEND] Version replaced 7.6.3->7.7.0");
                return ret;
            }
        }
    }
    
    return orig_send(sockfd, buf, len, flags);
}

#pragma mark - Recv Hook

static ssize_t hook_recv(int sockfd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv) return -1;
    
    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    
    if (ret > 0) {
        patchLoginResponse((unsigned char *)buf, ret);
        patchVersionCheckResponse((unsigned char *)buf, ret);
    }
    
    return ret;
}

#pragma mark - Recvfrom Hook

static ssize_t hook_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom) return -1;
    
    ssize_t ret = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    
    if (ret > 0) {
        patchLoginResponse((unsigned char *)buf, ret);
        patchVersionCheckResponse((unsigned char *)buf, ret);
    }
    
    return ret;
}

#pragma mark - Recvmsg Hook

static ssize_t hook_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg) return -1;
    
    ssize_t ret = orig_recvmsg(sockfd, msg, flags);
    
    if (ret > 0 && msg->msg_iov && msg->msg_iovlen > 0) {
        patchLoginResponse((unsigned char *)msg->msg_iov[0].iov_base, (ssize_t)msg->msg_iov[0].iov_len);
        patchVersionCheckResponse((unsigned char *)msg->msg_iov[0].iov_base, (ssize_t)msg->msg_iov[0].iov_len);
    }
    
    return ret;
}

#pragma mark - Close Hook

static int hook_close(int sockfd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    if (!orig_close) return -1;
    
    return orig_close(sockfd);
}

#pragma mark - Write Hook

static ssize_t hook_write(int fd, const void *buf, size_t count) {
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    if (!orig_write) return -1;
    
    return orig_write(fd, buf, count);
}

#pragma mark - Read Hook

static ssize_t hook_read(int fd, void *buf, size_t count) {
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_read) return -1;
    
    ssize_t ret = orig_read(fd, buf, count);
    
    if (ret > 0) {
        patchLoginResponse((unsigned char *)buf, ret);
        patchVersionCheckResponse((unsigned char *)buf, ret);
    }
    
    return ret;
}

#pragma mark - NSURLSession Hook

static NSURLSessionDataTask *(*orig_dtwrc)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    DLOG(@"[NSURL] Request: %@", request.URL.absoluteString);
    return orig_dtwrc(self, _cmd, request, completionHandler);
}

#pragma mark - NSUserDefaults Hook

static id (*orig_objectForKey)(id, SEL, NSString *) = NULL;

static id hook_objectForKey(id self, SEL _cmd, NSString *key) {
    id result = orig_objectForKey(self, _cmd, key);
    return result;
}

static void (*orig_setObjectForKey)(id, SEL, id, NSString *) = NULL;

static void hook_setObjectForKey(id self, SEL _cmd, id obj, NSString *key) {
    orig_setObjectForKey(self, _cmd, obj, key);
}

#pragma mark - EncryptUtils Hook

static BOOL hook_rsaVerifyData(id self, SEL _cmd, NSData *data, NSData *signature, NSString *publicKey) {
    DLOG(@"[ENC] rsaVerifyData: FORCED YES");
    return YES;
}

#pragma mark - UIAlertView Hook

static void (*orig_alertShow)(id, SEL) = NULL;

static void hook_alertShow(id self, SEL _cmd) {
    DLOG(@"[ALERT] show BLOCKED");
}

#pragma mark - SignatureKit Hooks

typedef void (*ShowAlertIMP)(id, SEL, NSString *);
static ShowAlertIMP orig_showAlert = NULL;

static void hook_showAlert(id self, SEL _cmd, NSString *msg) {
    DLOG(@"[SK] showAlert BLOCKED: '%@'", msg);
}

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;

static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

#pragma mark - Entry

__attribute__((constructor))
static void entry() {
    DLOG(@"=== WangXianHook v36.18 FULL (v36.10 restored) ===");
    
    @autoreleasepool {
        DLOG(@"[ACT] Installing FULL hooks...");
        
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
        
        DLOG(@"[INIT] Socket hooks installed: connect=%p send=%p recv=%p", orig_connect, orig_send, orig_recv);
        
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
        
        Class deviceCls = [UIDevice class];
        if (deviceCls) {
            Method m = class_getInstanceMethod(deviceCls, @selector(currentVersion));
            if (m) {
                method_setImplementation(m, (IMP)hook_currentVersion);
                DLOG(@"[INIT] UIDevice.currentVersion: HOOKED (fake 7.7.0)");
            } else {
                class_addMethod(deviceCls, @selector(currentVersion), (IMP)hook_currentVersion, "@@:");
                DLOG(@"[INIT] UIDevice.currentVersion: ADDED (fake 7.7.0)");
            }
            
            m = class_getInstanceMethod(deviceCls, @selector(isJailbroken));
            if (m) {
                method_setImplementation(m, (IMP)hook_isJailbroken);
                DLOG(@"[INIT] UIDevice.isJailbroken: HOOKED (return NO)");
            } else {
                class_addMethod(deviceCls, @selector(isJailbroken), (IMP)hook_isJailbroken, "B@:");
                DLOG(@"[INIT] UIDevice.isJailbroken: ADDED (return NO)");
            }
        }
        
        Class udCls = [NSUserDefaults class];
        if (udCls) {
            Method m = class_getInstanceMethod(udCls, @selector(objectForKey:));
            if (m) { orig_objectForKey = (id (*)(id, SEL, NSString *))method_getImplementation(m); method_setImplementation(m, (IMP)hook_objectForKey); DLOG(@"[INIT] NSUserDefaults.objectForKey hooked"); }
            
            m = class_getInstanceMethod(udCls, @selector(setObject:forKey:));
            if (m) { orig_setObjectForKey = (void (*)(id, SEL, id, NSString *))method_getImplementation(m); method_setImplementation(m, (IMP)hook_setObjectForKey); DLOG(@"[INIT] NSUserDefaults.setObject:forKey: hooked"); }
        }
        
        Class euCls = NSClassFromString(@"EncryptUtils");
        if (euCls) {
            Method m = class_getInstanceMethod(euCls, @selector(rsaVerifyData:signature:withPublicKey:));
            if (m) { method_setImplementation(m, (IMP)hook_rsaVerifyData); DLOG(@"[INIT] EncryptUtils.rsaVerifyData hooked"); }
        }
        
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            Method m = class_getClassMethod(skCls, @selector(showAlert:));
            if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SK.showAlert: HOOKED"); }
            m = class_getClassMethod(skCls, @selector(exitApplication));
            if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SK.exitApplication: HOOKED"); }
        }
        
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            Method m = class_getClassMethod(scCls, @selector(exitApplication));
            if (m) { method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SC.exitApplication: HOOKED"); }
        }
        
        Class apsCls = NSClassFromString(@"APSecurity");
        if (apsCls) {
            DLOG(@"[INIT] APSecurity class FOUND - hooking security methods");
            
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(apsCls, &methodCount);
            if (methods) {
                for (unsigned int i = 0; i < methodCount; i++) {
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
        
        DLOG(@"[ACT] FULL hooks installed - v36.18");
    }
}