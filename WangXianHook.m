/**
 * WangXianHook.dylib v5.0 - Minimal signature bypass (same as v1.0)
 * ONLY hooks SignatureKit/SignatureCheck class methods.
 * No NSURLSession, no UIKit hooks, no PLT rebinding, no observers.
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

static void rep_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static void rep_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static id rep_nil(id self, SEL _cmd) { return nil; }
static id rep_nil_1(id self, SEL _cmd, id a1) { return nil; }
static id rep_dict(id self, SEL _cmd) { return @{}; }
static id rep_dict_1(id self, SEL _cmd, id a1) { return @{}; }
static id rep_md5(id self, SEL _cmd, id a1) { return @"d41d8cd98f00b204e9800998ecf8427e"; }
static id rep_str_1(id self, SEL _cmd, id a1) { return @""; }
static id rep_str_0(id self, SEL _cmd) { return @""; }

static BOOL safeHookClassMethod(Class cls, SEL sel, IMP newImp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    method_setImplementation(m, newImp);
    return YES;
}

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v5.0 - Minimal");
    WXLOG(@"========================================");
    
    int count = 0;
    
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        WXLOG(@"Hooking SignatureKit...");
        count += safeHookClassMethod(sigKit, @selector(load), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(judgeNet), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(judgeAppInfoWithBaseUrl:), (IMP)rep_nil_1);
        count += safeHookClassMethod(sigKit, @selector(generateRequestParams), (IMP)rep_dict);
        count += safeHookClassMethod(sigKit, @selector(handleAppInfoResult:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigKit, @selector(showAlert:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigKit, @selector(exitApplication), (IMP)rep_void);
        count += safeHookClassMethod(sigKit, @selector(verifySignatureFromParameters:), (IMP)rep_nil_1);
        count += safeHookClassMethod(sigKit, @selector(createSignatureParams:), (IMP)rep_dict_1);
        count += safeHookClassMethod(sigKit, @selector(calculateMD5WithString:), (IMP)rep_md5);
        count += safeHookClassMethod(sigKit, @selector(stringFromHex:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(generateRandomStringWithLength:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(getCurrentTimestampInBeijingTimezone), (IMP)rep_str_0);
        count += safeHookClassMethod(sigKit, @selector(base64EncodeString:), (IMP)rep_str_1);
        count += safeHookClassMethod(sigKit, @selector(base64DecodeString:), (IMP)rep_str_1);
    }
    
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        WXLOG(@"Hooking SignatureCheck...");
        count += safeHookClassMethod(sigChk, @selector(load), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(JudgeApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(GetApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(PostApp), (IMP)rep_void);
        count += safeHookClassMethod(sigChk, @selector(showTipViewEND:), (IMP)rep_void_1);
        count += safeHookClassMethod(sigChk, @selector(exitApplication), (IMP)rep_void);
    }
    
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"Hooking LCNetworking...");
        count += safeHookClassMethod(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)rep_nil);
        count += safeHookClassMethod(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)rep_nil);
    }
    
    WXLOG(@"Done. Hooked %d methods.", count);
}
