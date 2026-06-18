/**
 * WangXianHook.dylib v2.0 - Anti-injection bypass for WangXian (忘仙)
 *
 * KEY FIX: The original detection runs in +load of SignatureKit/SignatureCheck,
 * which executes BEFORE our constructor. The entire chain (network call → server
 * response → UIAlertController → exit) completes before we can hook class methods.
 *
 * v2.0 Strategy:
 *   1. IMMEDIATELY hook NSURLSession in constructor (no dispatch_after delay)
 *   2. Hook UIAlertController to intercept/block the "版本过低" alert
 *   3. Hook UIViewController presentViewController: to block alert presentation
 *   4. Hook C exit()/_exit() via fishhook-style PLT rebinding
 *   5. Still hook SignatureKit/SignatureCheck methods as backup
 *   6. Hook UIApplication delegate methods to intercept app lifecycle
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>

#define WXLOG(fmt, ...) NSLog(@"[WXHook] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark - Forward declarations
// ============================================================

static BOOL hookClassMethod(Class cls, SEL sel, IMP newImp);
static void installAllHooks(void);

// ============================================================
#pragma mark - Replacement IMPs (void / nil / safe values)
// ============================================================

static void rep_void(id self, SEL _cmd) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static void rep_void_1(id self, SEL _cmd, id a1) {
    WXLOG(@"BLOCKED +[%s %s]", class_getName(object_getClass(self)), sel_getName(_cmd));
}

static id rep_nil(id self, SEL _cmd) {
    return nil;
}

static id rep_nil_1(id self, SEL _cmd, id a1) {
    return nil;
}

static id rep_nil_2(id self, SEL _cmd, id a1, id a2) {
    return nil;
}

static id rep_dict(id self, SEL _cmd) { return @{}; }
static id rep_dict_1(id self, SEL _cmd, id a1) { return @{}; }
static id rep_md5(id self, SEL _cmd, id a1) { return @"d41d8cd98f00b204e9800998ecf8427e"; }
static id rep_str_1(id self, SEL _cmd, id a1) { return @""; }
static id rep_str_0(id self, SEL _cmd) { return @""; }

// ============================================================
#pragma mark - NSURLSession Hook (CRITICAL - blocks server request)
// ============================================================

typedef NSURLSessionDataTask *(*DataTaskReqIMP)(id, SEL, NSURLRequest *);
typedef NSURLSessionDataTask *(*DataTaskURLIMP)(id, SEL, NSURL *);
static DataTaskReqIMP orig_dataTaskWithRequest = NULL;
static DataTaskURLIMP orig_dataTaskWithURL = NULL;

static BOOL isBlockedURL(NSString *url) {
    return [url containsString:@"ln_sign_cert"] ||
           [url containsString:@"9iy.com"] ||
           [url containsString:@"cert/judgeApp"] ||
           [url containsString:@"cert/postApp"] ||
           [url containsString:@"cert/getApp"] ||
           [url containsString:@"sign_cert"] ||
           [url containsString:@"SignatureCheck"] ||
           [url containsString:@"SignatureKit"];
}

static NSURLSessionDataTask *hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    NSString *url = request.URL.absoluteString;
    if (isBlockedURL(url)) {
        WXLOG(@"BLOCKED NSURLSession request: %@", url);
        return nil;
    }
    if (orig_dataTaskWithRequest)
        return orig_dataTaskWithRequest(self, _cmd, request);
    return nil;
}

static NSURLSessionDataTask *hooked_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    NSString *urlStr = url.absoluteString;
    if (isBlockedURL(urlStr)) {
        WXLOG(@"BLOCKED NSURLSession URL: %@", urlStr);
        return nil;
    }
    if (orig_dataTaskWithURL)
        return orig_dataTaskWithURL(self, _cmd, url);
    return nil;
}

// Also hook dataTaskWithRequest:completionHandler:
typedef void (^DataTaskCompletionHandler)(NSData *, NSURLResponse *, NSError *);
typedef NSURLSessionDataTask *(*DataTaskReqCompIMP)(id, SEL, NSURLRequest *, DataTaskCompletionHandler);
static DataTaskReqCompIMP orig_dataTaskWithRequestComp = NULL;

static NSURLSessionDataTask *hooked_dataTaskWithRequestComp(id self, SEL _cmd, NSURLRequest *request, DataTaskCompletionHandler handler) {
    NSString *url = request.URL.absoluteString;
    if (isBlockedURL(url)) {
        WXLOG(@"BLOCKED NSURLSession+completion request: %@", url);
        // Call handler with success (empty response) to prevent failure handling
        if (handler) {
            NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL
                                                                      statusCode:200
                                                                     HTTPVersion:@"HTTP/1.1"
                                                                    headerFields:@{@"Content-Type": @"application/json"}];
            NSData *fakeData = [@"{\"code\":0,\"msg\":\"ok\"}" dataUsingEncoding:NSUTF8StringEncoding];
            handler(fakeData, fakeResp, nil);
        }
        return nil;
    }
    if (orig_dataTaskWithRequestComp)
        return orig_dataTaskWithRequestComp(self, _cmd, request, handler);
    return nil;
}

// ============================================================
#pragma mark - UIAlertController Hook (CRITICAL - blocks alert)
// ============================================================

typedef UIAlertController *(*AlertCreateIMP)(id, SEL, NSString *, NSString *, NSInteger);
static AlertCreateIMP orig_alertControllerWithTitle = NULL;

static UIAlertController *hooked_alertControllerWithTitle(id self, SEL _cmd, NSString *title, NSString *message, NSInteger style) {
    // Check if this is the anti-injection alert
    if ([message containsString:@"版本过低"] ||
        [message containsString:@"下载最新版本"] ||
        [message containsString:@"联系客服"] ||
        [title containsString:@"版本过低"] ||
        [title containsString:@"提示"] ||
        [message containsString:@"下载最新的版本"]) {
        WXLOG(@"BLOCKED anti-inject alert: title=%@ msg=%@", title, message);
        // Return a dummy alert that won't be presented
        UIAlertController *dummy = [UIAlertController alertControllerWithTitle:@"" message:@"" preferredStyle:UIAlertControllerStyleAlert];
        return dummy;
    }
    if (orig_alertControllerWithTitle)
        return orig_alertControllerWithTitle(self, _cmd, title, message, style);
    return nil;
}

// ============================================================
#pragma mark - UIViewController Hook (blocks alert presentation)
// ============================================================

typedef void (*PresentVCIMP)(id, SEL, UIViewController *, BOOL, void (^)(void));
static PresentVCIMP orig_presentViewController = NULL;

static void hooked_presentViewController(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    // Block UIAlertController presentation
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *msg = alert.message ?: @"";
        NSString *title = alert.title ?: @"";
        if ([msg containsString:@"版本过低"] ||
            [msg containsString:@"下载最新版本"] ||
            [msg containsString:@"联系客服"] ||
            [msg containsString:@"下载最新的版本"] ||
            [title containsString:@"版本过低"]) {
            WXLOG(@"BLOCKED alert presentation: title=%@ msg=%@", title, msg);
            if (completion) completion();
            return;
        }
    }
    if (orig_presentViewController)
        orig_presentViewController(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark - exit() / _exit() Hook via PLT rebinding
// ============================================================

typedef void (*exit_fn)(int);
static exit_fn real_exit = NULL;
static exit_fn real__exit = NULL;

static void hooked_exit(int status) {
    WXLOG(@"BLOCKED exit(%d)", status);
    // Don't actually exit - just return
}

// Rebind symbol in a single image
static void rebind_symbol_in_image(const char *symbol_name, void *replacement, void **original) {
    // Walk through loaded images and rebind lazy/non-lazy pointers
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = (const struct mach_header *)_dyld_get_image_header(i);
        if (!header) continue;
        
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        
        const struct load_command *cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
        const struct symtab_command *symtab = NULL;
        const struct dysymtab_command *dysymtab = NULL;
        const char *linkedit_base = NULL;
        
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (cmd->cmd == LC_SYMTAB) {
                symtab = (const struct symtab_command *)cmd;
            } else if (cmd->cmd == LC_DYSYMTAB) {
                dysymtab = (const struct dysymtab_command *)cmd;
            } else if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit_base = (char *)(seg->vmaddr + slide - seg->fileoff);
                }
            }
            cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        
        if (!symtab || !dysymtab || !linkedit_base) continue;
        
        const struct nlist_64 *symtab_entries = (const struct nlist_64 *)(linkedit_base + symtab->symoff);
        const char *strtab = linkedit_base + symtab->stroff;
        const uint32_t *indirect_syms = (const uint32_t *)(linkedit_base + dysymtab->indirectsymoff);
        
        // Find __DATA segment's __la_symbol_ptr and __got sections
        cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
                    const struct section_64 *section = (const struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
                    for (uint32_t k = 0; k < seg->nsects; k++) {
                        uint32_t type = section[k].flags & SECTION_TYPE;
                        if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS || type == S_SYMBOL_STUBS) {
                            uint32_t stride = (type == S_SYMBOL_STUBS) ? section[k].reserved2 : sizeof(void *);
                            uint32_t count_syms = (uint32_t)(section[k].size / stride);
                            uint32_t indirect_idx = section[k].reserved1;
                            
                            void **ptrs = (void **)(section[k].addr + slide);
                            for (uint32_t l = 0; l < count_syms; l++) {
                                uint32_t sym_idx = indirect_syms[indirect_idx + l];
                                if (sym_idx == INDIRECT_SYMBOL_ABS || sym_idx == INDIRECT_SYMBOL_LOCAL) continue;
                                if (sym_idx >= symtab->nsyms) continue;
                                
                                const char *name = strtab + symtab_entries[sym_idx].n_un.n_strx;
                                if (strcmp(name, symbol_name) == 0) {
                                    if (original && !*original) {
                                        *original = ptrs[l];
                                    }
                                    ptrs[l] = replacement;
                                    WXLOG("Rebound %s in %s", symbol_name, _dyld_get_image_name(i));
                                }
                            }
                        }
                    }
                }
            }
            cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
        }
    }
}

// ============================================================
#pragma mark - Helper Functions
// ============================================================

static BOOL hookClassMethod(Class cls, SEL sel, IMP newImp) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    method_setImplementation(m, newImp);
    WXLOG(@"[OK] +[%s %s]", class_getName(cls), sel_getName(sel));
    return YES;
}

static IMP safeGetInstanceMethod(Class cls, SEL sel) {
    if (!cls) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    return m ? method_getImplementation(m) : NULL;
}

static BOOL safeHookInstanceMethod(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    if (outOrig) *outOrig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    WXLOG(@"[OK] -[%s %s]", class_getName(cls), sel_getName(sel));
    return YES;
}

static BOOL safeHookClassMethod(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls) return NO;
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    if (outOrig) *outOrig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    WXLOG(@"[OK] +[%s %s]", class_getName(cls), sel_getName(sel));
    return YES;
}

// ============================================================
#pragma mark - Main Hook Installation
// ============================================================

static void installAllHooks(void) {
    int total = 0;
    
    // --- NSURLSession hooks (MOST CRITICAL) ---
    WXLOG(@"=== Hooking NSURLSession ===");
    Class urlSession = [NSURLSession class];
    if (urlSession) {
        total += safeHookInstanceMethod(urlSession, @selector(dataTaskWithRequest:),
            (IMP)hooked_dataTaskWithRequest, (IMP *)&orig_dataTaskWithRequest);
        total += safeHookInstanceMethod(urlSession, @selector(dataTaskWithURL:),
            (IMP)hooked_dataTaskWithURL, (IMP *)&orig_dataTaskWithURL);
        total += safeHookInstanceMethod(urlSession,
            @selector(dataTaskWithRequest:completionHandler:),
            (IMP)hooked_dataTaskWithRequestComp, (IMP *)&orig_dataTaskWithRequestComp);
    }
    
    // --- UIAlertController hooks ---
    WXLOG(@"=== Hooking UIAlertController ===");
    total += safeHookClassMethod([UIAlertController class],
        @selector(alertControllerWithTitle:message:preferredStyle:),
        (IMP)hooked_alertControllerWithTitle, (IMP *)&orig_alertControllerWithTitle);
    
    // --- UIViewController presentViewController: hook ---
    WXLOG(@"=== Hooking UIViewController ===");
    total += safeHookInstanceMethod([UIViewController class],
        @selector(presentViewController:animated:completion:),
        (IMP)hooked_presentViewController, (IMP *)&orig_presentViewController);
    
    // --- exit() rebinding ---
    WXLOG(@"=== Rebinding exit() ===");
    rebind_symbol_in_image("_exit", (void *)hooked_exit, (void **)&real_exit);
    
    // --- SignatureKit hooks ---
    Class sigKit = objc_getClass("SignatureKit");
    if (sigKit) {
        WXLOG(@"=== Hooking SignatureKit ===");
        total += hookClassMethod(sigKit, @selector(load), (IMP)rep_void);
        total += hookClassMethod(sigKit, @selector(judgeNet), (IMP)rep_void);
        total += hookClassMethod(sigKit, @selector(judgeAppInfoWithBaseUrl:), (IMP)rep_nil_1);
        total += hookClassMethod(sigKit, @selector(generateRequestParams), (IMP)rep_dict);
        total += hookClassMethod(sigKit, @selector(handleAppInfoResult:), (IMP)rep_void_1);
        total += hookClassMethod(sigKit, @selector(showAlert:), (IMP)rep_void_1);
        total += hookClassMethod(sigKit, @selector(exitApplication), (IMP)rep_void);
        total += hookClassMethod(sigKit, @selector(verifySignatureFromParameters:), (IMP)rep_nil_1);
        total += hookClassMethod(sigKit, @selector(createSignatureParams:), (IMP)rep_dict_1);
        total += hookClassMethod(sigKit, @selector(calculateMD5WithString:), (IMP)rep_md5);
        total += hookClassMethod(sigKit, @selector(stringFromHex:), (IMP)rep_str_1);
        total += hookClassMethod(sigKit, @selector(generateRandomStringWithLength:), (IMP)rep_str_1);
        total += hookClassMethod(sigKit, @selector(getCurrentTimestampInBeijingTimezone), (IMP)rep_str_0);
        total += hookClassMethod(sigKit, @selector(base64EncodeString:), (IMP)rep_str_1);
        total += hookClassMethod(sigKit, @selector(base64DecodeString:), (IMP)rep_str_1);
    }
    
    // --- SignatureCheck hooks ---
    Class sigChk = objc_getClass("SignatureCheck");
    if (sigChk) {
        WXLOG(@"=== Hooking SignatureCheck ===");
        total += hookClassMethod(sigChk, @selector(load), (IMP)rep_void);
        total += hookClassMethod(sigChk, @selector(JudgeApp), (IMP)rep_void);
        total += hookClassMethod(sigChk, @selector(GetApp), (IMP)rep_void);
        total += hookClassMethod(sigChk, @selector(PostApp), (IMP)rep_void);
        total += hookClassMethod(sigChk, @selector(showTipViewEND:), (IMP)rep_void_1);
        total += hookClassMethod(sigChk, @selector(exitApplication), (IMP)rep_void);
    }
    
    // --- LCNetworking hooks ---
    Class lcNet = objc_getClass("LCNetworking");
    if (lcNet) {
        WXLOG(@"=== Hooking LCNetworking ===");
        total += hookClassMethod(lcNet, @selector(getWithURL:Params:success:failure:), (IMP)rep_nil);
        total += hookClassMethod(lcNet, @selector(PostWithURL:Params:success:failure:), (IMP)rep_nil);
    }
    
    WXLOG(@"Total %d hooks installed", total);
}

// ============================================================
#pragma mark - Constructor (entry point)
// ============================================================

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    WXLOG(@"========================================");
    WXLOG(@"  WangXianHook v2.0 - Anti-inject Bypass");
    WXLOG(@"  Strategy: Early NSURLSession + Alert block");
    WXLOG(@"========================================");
    
    // Install ALL hooks immediately - no delays!
    installAllHooks();
    
    // Schedule retries for late-loading classes
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WXLOG(@"Retry pass for late-loading classes...");
        installAllHooks();
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WXLOG(@"Final retry pass...");
        installAllHooks();
    });
    
    WXLOG(@"Constructor finished.");
}
