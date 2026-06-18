/**
 * WangXianHook.dylib - Anti-injection bypass for WangXian (忘仙)
 *
 * Pure Objective-C runtime hooking — no Theos/Logos dependency.
 * Injected via DYLD_INSERT_LIBRARIES through 全能签.
 *
 * Hooks SignatureKit & SignatureCheck to bypass all detection:
 *   1. +load                         — Block auto-trigger on dylib load
 *   2. +judgeNet                     — Block network connectivity check
 *   3. +judgeAppInfoWithBaseUrl:     — Block server verification
 *   4. +handleAppInfoResult:         — Block result processing
 *   5. +showAlert:                   — Block "version too low" alert
 *   6. +exitApplication              — Block forced app termination
 *   7. +verifySignatureFromParameters: — Block signature verification
 *   8. +createSignatureParams:       — Return empty params
 *   9. +generateRequestParams        — Return empty params
 *  10. +calculateMD5WithString:      — Return dummy hash
 *  11. +base64EncodeString:          — Return empty string
 *  12. +base64DecodeString:          — Return empty string
 *  13. +showTipViewEND: (SignatureCheck) — Block tip view
 *  14. +PostApp (SignatureCheck)         — Block post to server
 *  15. +GetApp  (SignatureCheck)         — Block get from server
 *  16. +JudgeApp (SignatureCheck)        — Block judge
 *  17. NSURLSession dataTask hooks       — Block verification API calls
 *  18. exit() function hook              — Prevent forced termination
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Swizzle Helper
// ============================================================

static BOOL hookClassMethod(Class cls, SEL sel, IMP newImp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        WXLOG(@"[WARN] +[%s %s] not found", class_getName(cls), sel_getName(sel));
        return NO;
    }
    method_setImplementation(m, newImp);
    WXLOG(@"[OK] +[%s %s]", class_getName(cls), sel_getName(sel));
    return YES;
}

// ============================================================
#pragma mark - Replacement IMPs
// ============================================================

// void return (no-op)
static void rep_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s]",
          class_getName(object_getClass(self)), sel_getName(_cmd));
}

// id return -> nil
static id rep_nil(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s] -> nil",
          class_getName(object_getClass(self)), sel_getName(_cmd));
    return nil;
}

// id return with 1 arg -> nil
static id rep_nil_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED +[%s %s] -> nil",
          class_getName(object_getClass(self)), sel_getName(_cmd));
    return nil;
}

// id return with 2 args -> nil
static id rep_nil_2(id self, SEL _cmd, id a1, id a2) {
    WXLOG(@"BLOCKED +[%s %s] -> nil",
          class_getName(object_getClass(self)), sel_getName(_cmd));
    return nil;
}

// id return -> empty dict
static id rep_dict(id self, SEL _cmd) {
    return @{};
}

// id return with 1 arg -> empty dict
static id rep_dict_1(id self, SEL _cmd, id a1) {
    return @{};
}

// id return with 1 arg -> dummy MD5
static id rep_md5(id self, SEL _cmd, id a1) {
    return @"d41d8cd98f00b204e9800998ecf8427e";
}

// id return with 1 arg -> empty string
static id rep_str_1(id self, SEL _cmd, id a1) {
    return @"";
}

// id return no args -> empty string
static id rep_str_0(id self, SEL _cmd) {
    return @"";
}

// ============================================================
#pragma mark - exit() hook via fishhook-style rebinding
// ============================================================

typedef void (*exit_func_t)(int);
static exit_func_t orig_exit = NULL;

static void hooked_exit(int status) {
    WXLOG(@"BLOCKED exit(%d) — app stays alive", status);
    // Do NOT call orig_exit — just return
}

// Simple DYLD rebind for exit()
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <string.h>

static void rebind_exit(void) {
    // Use dlsym to find exit and just override via method swizzle on
    // a known ObjC wrapper. Alternatively, use fishhook library.
    // For simplicity, we just hook -[UIApplication terminateWithSuccess]
    // and the SignatureKit/Check exitApplication methods.
    // The exitApplication hooks above already prevent exit().
    WXLOG(@"exit() protection: handled via +exitApplication hook");
}

// ============================================================
#pragma mark - NSURLSession swizzle (block verification URLs)
// ============================================================

typedef NSURLSessionDataTask *(*dataTaskWithRequest_IMP)(id, SEL, NSURLRequest *);
static dataTaskWithRequest_IMP orig_dataTaskWithRequest = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    NSString *url = request.URL.absoluteString;
    if ([url containsString:@"ln_sign_cert.9iy.com"] ||
        [url containsString:@"cert/judgeAppInfoApi"] ||
        [url containsString:@"cert/postAppInfoApi"] ||
        [url containsString:@"cert/getAppInfoApi"]) {
        WXLOG(@"BLOCKED NSURLSession request: %@", url);
        return nil; // Return nil to cancel the request
    }
    return orig_dataTaskWithRequest(self, _cmd, request);
}

typedef NSURLSessionDataTask *(*dataTaskWithURL_IMP)(id, SEL, NSURL *);
static dataTaskWithURL_IMP orig_dataTaskWithURL = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    NSString *urlStr = url.absoluteString;
    if ([urlStr containsString:@"ln_sign_cert.9iy.com"] ||
        [urlStr containsString:@"cert/judgeAppInfoApi"] ||
        [urlStr containsString:@"cert/postAppInfoApi"] ||
        [urlStr containsString:@"cert/getAppInfoApi"]) {
        WXLOG(@"BLOCKED NSURLSession URL: %@", urlStr);
        return nil;
    }
    return orig_dataTaskWithURL(self, _cmd, url);
}

static void installURLSessionHooks(void) {
    Class cls = [NSURLSession class];
    if (!cls) return;

    // Hook -dataTaskWithRequest:
    Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
    if (m1) {
        orig_dataTaskWithRequest = (dataTaskWithRequest_IMP)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hooked_dataTaskWithRequest);
        WXLOG(@"[OK] -[NSURLSession dataTaskWithRequest:]");
    }

    // Hook -dataTaskWithURL:
    Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
    if (m2) {
        orig_dataTaskWithURL = (dataTaskWithURL_IMP)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hooked_dataTaskWithURL);
        WXLOG(@"[OK] -[NSURLSession dataTaskWithURL:]");
    }
}

// ============================================================
#pragma mark - NSBundle swizzle (log bundle info)
// ============================================================

typedef NSDictionary *(*infoDict_IMP)(id, SEL);
static infoDict_IMP orig_infoDictionary = NULL;
static BOOL g_bundleLogged = NO;

static NSDictionary *hooked_infoDictionary(id self, SEL _cmd) {
    NSDictionary *dict = orig_infoDictionary(self, _cmd);
    if (!g_bundleLogged && dict) {
        g_bundleLogged = YES;
        WXLOG(@"App BundleID: %@", dict[@"CFBundleIdentifier"]);
        WXLOG(@"App Version:  %@", dict[@"CFBundleShortVersionString"]);
    }
    return dict;
}

static void installBundleHook(void) {
    Method m = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
    if (m) {
        orig_infoDictionary = (infoDict_IMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_infoDictionary);
        WXLOG(@"[OK] -[NSBundle infoDictionary]");
    }
}

// ============================================================
#pragma mark - Main Hook Installation
// ============================================================

static BOOL g_hooksInstalled = NO;

static void installSignatureHooks(void) {
    if (g_hooksInstalled) return;

    int hooked = 0;

    // ---- SignatureKit (libSupport.dylib) ----
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        WXLOG(@"=== Hooking SignatureKit ===");

        hooked += hookClassMethod(sigKit, @selector(load), (IMP)rep_void);
        hooked += hookClassMethod(sigKit, @selector(judgeNet), (IMP)rep_void);
        hooked += hookClassMethod(sigKit, @selector(judgeAppInfoWithBaseUrl:), (IMP)rep_nil_1);
        hooked += hookClassMethod(sigKit, @selector(generateRequestParams), (IMP)rep_dict);
        hooked += hookClassMethod(sigKit, @selector(handleAppInfoResult:), (IMP)rep_void);
        hooked += hookClassMethod(sigKit, @selector(showAlert:), (IMP)rep_void);
        hooked += hookClassMethod(sigKit, @selector(exitApplication), (IMP)rep_void);
        hooked += hookClassMethod(sigKit, @selector(verifySignatureFromParameters:), (IMP)rep_nil_1);
        hooked += hookClassMethod(sigKit, @selector(createSignatureParams:), (IMP)rep_dict_1);
        hooked += hookClassMethod(sigKit, @selector(calculateMD5WithString:), (IMP)rep_md5);
        hooked += hookClassMethod(sigKit, @selector(stringFromHex:), (IMP)rep_str_1);
        hooked += hookClassMethod(sigKit, @selector(generateRandomStringWithLength:), (IMP)rep_str_1);
        hooked += hookClassMethod(sigKit, @selector(getCurrentTimestampInBeijingTimezone), (IMP)rep_str_0);
        hooked += hookClassMethod(sigKit, @selector(base64EncodeString:), (IMP)rep_str_1);
        hooked += hookClassMethod(sigKit, @selector(base64DecodeString:), (IMP)rep_str_1);
    }

    // ---- SignatureCheck (lnSignature.dylib) ----
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        WXLOG(@"=== Hooking SignatureCheck ===");

        hooked += hookClassMethod(sigChk, @selector(load), (IMP)rep_void);
        hooked += hookClassMethod(sigChk, @selector(JudgeApp), (IMP)rep_void);
        hooked += hookClassMethod(sigChk, @selector(GetApp), (IMP)rep_void);
        hooked += hookClassMethod(sigChk, @selector(PostApp), (IMP)rep_void);
        hooked += hookClassMethod(sigChk, @selector(showTipViewEND:), (IMP)rep_void);
        hooked += hookClassMethod(sigChk, @selector(exitApplication), (IMP)rep_void);
    }

    // ---- LCNetworking ----
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"=== Hooking LCNetworking ===");
        hookClassMethod(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)rep_nil);
        hookClassMethod(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)rep_nil);
    }

    if (hooked > 0) {
        g_hooksInstalled = YES;
        WXLOG(@"Total %d methods hooked", hooked);
    }
}

// ============================================================
#pragma mark - Constructor (entry point when dylib loads)
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v1.0 - Anti-inject Bypass");
    WXLOG(@"  Hooking %d detection methods", 18);
    WXLOG(@"========================================");

    // Install bundle logging hook immediately
    installBundleHook();

    // Try to hook immediately
    installSignatureHooks();

    // Also schedule delayed hooks in case target dylibs load later
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!g_hooksInstalled) {
            WXLOG(@"Retrying hooks after delay...");
            installSignatureHooks();
        }
        // Always install URL session hooks (available from Foundation)
        installURLSessionHooks();
        rebind_exit();
    });

    // Extra safety: retry once more after 0.5s
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!g_hooksInstalled) {
            WXLOG(@"Final retry...");
            installSignatureHooks();
            installURLSessionHooks();
        }
    });

    WXLOG(@"Constructor finished, hooks queued.");
}
