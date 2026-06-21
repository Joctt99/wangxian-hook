/**
 * WangXianHook v33.0 - Anti-Cheat Bypass: Hide injected dylibs
 * Strategy: Hook _dyld functions to hide our dylibs from the game's anti-cheat
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
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
        _log(@"=== WXHook v33.0 Anti-Cheat Bypass ===");
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
    DLOG(@"[SK] handleAppInfoResult: %@", result);
    if (orig_handleResult) orig_handleResult(self, _cmd, result);
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

// 5. judgeNet - LOG only (observe which method triggers HTTP)
typedef void (*JudgeNetIMP)(id, SEL);
static JudgeNetIMP orig_judgeNet = NULL;
static void hook_judgeNet(id self, SEL _cmd) {
    DLOG(@"[SK] judgeNet called (passing through)");
    if (orig_judgeNet) orig_judgeNet(self, _cmd);
}

// 6. verifySignatureFromParameters: - LOG only
typedef id (*VerifySigIMP)(id, SEL, id);
static VerifySigIMP orig_verifySig = NULL;
static id hook_verifySig(id self, SEL _cmd, id params) {
    DLOG(@"[SK] verifySignatureFromParameters: %@", params);
    if (orig_verifySig) return orig_verifySig(self, _cmd, params);
    return nil;
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

// Hook SignatureCheck.JudgeApp to skip the real HTTP verification
typedef void (*JudgeAppIMP)(id, SEL);
static JudgeAppIMP orig_judgeApp = NULL;
static void hook_judgeApp(id self, SEL _cmd) {
    DLOG(@"[SC] SignatureCheck.JudgeApp called (BLOCKED - no HTTP request)");
    // Don't call original - skip the real HTTP verification
    // The original makes a synchronous HTTP request that might hang/fail
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
            lbl.text = @"WXHook v33.0";
            lbl.textColor = [UIColor greenColor];
            lbl.font = [UIFont boldSystemFontOfSize:14];
            [g_panel addSubview:lbl];
            
            // Status label (shows ON/OFF)
            g_statusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];
            g_statusLbl.text = @"LOG: ON";
            g_statusLbl.textColor = [UIColor greenColor];
            g_statusLbl.font = [UIFont boldSystemFontOfSize:12];
            [g_panel addSubview:g_statusLbl];
            
            // Button row
            CGFloat bx = pw - 200;
            UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            onOffBtn.frame = CGRectMake(bx, 8, 60, 28);
            [onOffBtn setTitle:@"On/Off" forState:UIControlStateNormal];
            [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];
            [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:onOffBtn];
            
            UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            clearBtn.frame = CGRectMake(bx + 65, 8, 60, 28);
            [clearBtn setTitle:@"Clear" forState:UIControlStateNormal];
            [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
            [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:clearBtn];
            
            UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            copyBtn.frame = CGRectMake(bx + 130, 8, 60, 28);
            [copyBtn setTitle:@"Copy" forState:UIControlStateNormal];
            [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
            [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:copyBtn];
            
            // Second row: Dump button
            UIButton *dumpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            dumpBtn.frame = CGRectMake(bx, 34, 80, 24);
            [dumpBtn setTitle:@"Dump View" forState:UIControlStateNormal];
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
    g_statusLbl.text = @"LOG: ON";
    g_statusLbl.textColor = [UIColor greenColor];
    DLOG(@"=== Log cleared ===");
}
- (void)toggleLogging {
    g_logEnabled = !g_logEnabled;
    g_statusLbl.text = g_logEnabled ? @"LOG: ON" : @"LOG: OFF";
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
    [UIPasteboard generalPasteboard].string = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_tv.text = @">>> COPIED <<<";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    });
}
@end

// ============================================================
#pragma mark - Dylib hiding (anti-cheat bypass)
// ============================================================

// Dylib names to hide from the game's anti-cheat
static const char *g_hiddenDylibs[] = {
    "WangXianHook", "lnSignature", "libSupport", "liblnSignature", NULL
};

static BOOL shouldHideImage(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hiddenDylibs[i]; i++) {
        if (strstr(name, g_hiddenDylibs[i])) return YES;
    }
    return NO;
}

// Build a mapping of visible images
static uint32_t *g_visibleMap = NULL;  // visibleMap[realIndex] = visibleIndex
static uint32_t g_realCount = 0;
static uint32_t g_visibleCount = 0;

static void buildVisibleMap(void) {
    static BOOL built = NO;
    if (built) return;
    built = YES;
    
    g_realCount = _dyld_image_count();
    g_visibleMap = (uint32_t *)calloc(g_realCount, sizeof(uint32_t));
    g_visibleCount = 0;
    
    for (uint32_t i = 0; i < g_realCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!shouldHideImage(name)) {
            g_visibleMap[i] = g_visibleCount;
            g_visibleCount++;
        } else {
            g_visibleMap[i] = 0xFFFFFFFF; // hidden
        }
    }
    DLOG(@"[DYLD] Real images: %u, Visible: %u (hidden: %u)", g_realCount, g_visibleCount, g_realCount - g_visibleCount);
}

// Replacement for _dyld_image_count
typedef uint32_t (*DyldCountFunc)(void);
static DyldCountFunc orig_dyldCount = NULL;
static uint32_t hook_dyldCount(void) {
    buildVisibleMap();
    if (g_visibleCount > 0) return g_visibleCount;
    return orig_dyldCount ? orig_dyldCount() : 0;
}

// Replacement for _dyld_get_image_name
typedef const char *(*DyldNameFunc)(uint32_t);
static DyldNameFunc orig_dyldName = NULL;
static const char *hook_dyldName(uint32_t idx) {
    buildVisibleMap();
    // Map visible index back to real index
    uint32_t realIdx = 0;
    uint32_t visIdx = 0;
    for (realIdx = 0; realIdx < g_realCount; realIdx++) {
        if (g_visibleMap[realIdx] != 0xFFFFFFFF) {
            if (visIdx == idx) {
                return orig_dyldName ? orig_dyldName(realIdx) : NULL;
            }
            visIdx++;
        }
    }
    return orig_dyldName ? orig_dyldName(idx) : NULL;
}

// Replacement for _dyld_get_image_header
typedef const struct mach_header *(*DyldHeaderFunc)(uint32_t);
static DyldHeaderFunc orig_dyldHeader = NULL;
static const struct mach_header *hook_dyldHeader(uint32_t idx) {
    buildVisibleMap();
    uint32_t realIdx = 0;
    uint32_t visIdx = 0;
    for (realIdx = 0; realIdx < g_realCount; realIdx++) {
        if (g_visibleMap[realIdx] != 0xFFFFFFFF) {
            if (visIdx == idx) {
                return orig_dyldHeader ? orig_dyldHeader(realIdx) : NULL;
            }
            visIdx++;
        }
    }
    return orig_dyldHeader ? orig_dyldHeader(idx) : NULL;
}

// Replacement for _dyld_get_image_vmaddr_slide
typedef intptr_t (*DyldSlideFunc)(uint32_t);
static DyldSlideFunc orig_dyldSlide = NULL;
static intptr_t hook_dyldSlide(uint32_t idx) {
    buildVisibleMap();
    uint32_t realIdx = 0;
    uint32_t visIdx = 0;
    for (realIdx = 0; realIdx < g_realCount; realIdx++) {
        if (g_visibleMap[realIdx] != 0xFFFFFFFF) {
            if (visIdx == idx) {
                return orig_dyldSlide ? orig_dyldSlide(realIdx) : 0;
            }
            visIdx++;
        }
    }
    return orig_dyldSlide ? orig_dyldSlide(idx) : 0;
}

// Minimal fishhook: rebind symbol in a single image
static int rebindSymbolInImage(const struct mach_header_64 *header, intptr_t slide,
                               const char *symbolName, void *replacement, void **original) {
    // Find __DATA (or __DATA_CONST) segment
    const struct segment_command_64 *dataSeg = NULL;
    const struct segment_command_64 *linkeditSeg = NULL;
    const struct load_command *cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
                dataSeg = seg;
            } else if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                linkeditSeg = seg;
            }
        }
        cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (!linkeditSeg) return -1;
    
    // Find LC_DYLD_INFO_ONLY
    struct linkedit_data_command *dyldInfo = NULL;
    cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_DYLD_INFO_ONLY) {
            dyldInfo = (struct linkedit_data_command *)cmd;
            break;
        }
        cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    // Find LC_SYMTAB
    struct symtab_command *symtab = NULL;
    cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)cmd;
            break;
        }
        cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (!dyldInfo || !symtab) return -1;
    
    char *linkeditBase = (char *)slide + linkeditSeg->vmaddr - linkeditSeg->fileoff;
    const struct nlist_64 *symtab_entries = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
    char *strtab = (char *)(linkeditBase + symtab->stroff);
    
    // Process lazy and non-lazy bind opcodes
    uint32_t *bindOffsets[] = { &dyldInfo->lazy_bind_off, &dyldInfo->bind_off };
    uint32_t bindSizes[] = { dyldInfo->lazy_bind_size, dyldInfo->bind_size };
    
    int rebindCount = 0;
    
    // Also check __DATA.__la_symbol_ptr and __DATA.__got sections
    if (dataSeg) {
        const struct section_64 *sec = (const struct section_64 *)((char *)dataSeg + sizeof(struct segment_command_64));
        for (uint32_t s = 0; s < dataSeg->nsects; s++) {
            if (strcmp(sec[s].sectname, "__la_symbol_ptr") == 0 ||
                strcmp(sec[s].sectname, "__got") == 0) {
                void **pointers = (void **)((char *)slide + sec[s].addr);
                uint32_t count = (uint32_t)(sec[s].size / sizeof(void *));
                // Get indirect symbol table entries
                uint32_t *indirectSyms = (uint32_t *)(linkeditBase + symtab->indirectsymoff + sec[s].reserved1 * sizeof(uint32_t));
                
                for (uint32_t j = 0; j < count; j++) {
                    uint32_t symIdx = indirectSyms[j];
                    if (symIdx == INDIRECT_SYMBOL_ABS || symIdx == INDIRECT_SYMBOL_LOCAL ||
                        symIdx == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
                    
                    const char *symName = strtab + symtab_entries[symIdx].n_un.n_strx;
                    if (strcmp(symName, symbolName) == 0) {
                        if (original && *original == NULL) {
                            *original = pointers[j];
                        }
                        // Make page writable
                        size_t pageSize = getpagesize();
                        void *page = (void *)((uintptr_t)&pointers[j] & ~(pageSize - 1));
                        if (mprotect(page, pageSize, PROT_READ | PROT_WRITE) == 0) {
                            pointers[j] = replacement;
                            rebindCount++;
                        }
                    }
                }
            }
        }
    }
    return rebindCount;
}

static void rebindAllImages(const char *symbolName, void *replacement, void **original) {
    uint32_t count = _dyld_image_count();
    int totalRebinds = 0;
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (header) {
            int r = rebindSymbolInImage(header, slide, symbolName, replacement, original);
            if (r > 0) {
                const char *name = _dyld_get_image_name(i);
                DLOG(@"[HOOK] Rebound '%s' in %s (%d pointers)", symbolName, name ? strrchr(name, '/') + 1 : "?", r);
                totalRebinds += r;
            }
        }
    }
    DLOG(@"[HOOK] Total rebinds for '%s': %d", symbolName, totalRebinds);
}

static void installDyldHooks(void) {
    // Log current dylibs
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
    
    // Save originals
    orig_dyldCount = _dyld_image_count;
    orig_dyldName = _dyld_get_image_name;
    orig_dyldHeader = _dyld_get_image_header;
    orig_dyldSlide = _dyld_get_image_vmaddr_slide;
    
    // Rebind in all loaded images
    rebindAllImages("_dyld_image_count", (void *)hook_dyldCount, (void **)&orig_dyldCount);
    rebindAllImages("_dyld_get_image_name", (void *)hook_dyldName, (void **)&orig_dyldName);
    rebindAllImages("_dyld_get_image_header", (void *)hook_dyldHeader, (void **)&orig_dyldHeader);
    rebindAllImages("_dyld_get_image_vmaddr_slide", (void *)hook_dyldSlide, (void **)&orig_dyldSlide);
    
    DLOG(@"[HOOK] dyld hooks installed - hiding %d dylibs", (int)(sizeof(g_hiddenDylibs)/sizeof(g_hiddenDylibs[0]) - 1));
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
    
    // === IMMEDIATE: Anti-cheat bypass - hide dylibs ===
    installDyldHooks();
    
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
    
    // === DEFERRED: Wait for all dylibs to load, then hook SignatureKit + SignatureCheck ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // --- Hook SignatureKit (全能签 verification) ---
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            Class metaCls = object_getClass(skCls);
            
            // showAlert: - SUPPRESS
            Method m = class_getClassMethod(skCls, @selector(showAlert:));
            if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); _log(@"[INIT] SK.showAlert: hooked (SUPPRESS)"); }
            
            // exitApplication - BLOCK
            m = class_getClassMethod(skCls, @selector(exitApplication));
            if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); _log(@"[INIT] SK.exitApplication hooked (BLOCK)"); }
            
            // judgeAppInfoWithBaseUrl: - BYPASS
            m = class_getClassMethod(skCls, @selector(judgeAppInfoWithBaseUrl:));
            if (m) { orig_judgeBase = (JudgeBaseIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeBase); _log(@"[INIT] SK.judgeAppInfoWithBaseUrl: hooked (BYPASS)"); }
            
            // handleAppInfoResult: - LOG
            m = class_getClassMethod(skCls, @selector(handleAppInfoResult:));
            if (m) { orig_handleResult = (HandleResultIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_handleResult); _log(@"[INIT] SK.handleAppInfoResult: hooked"); }
            
            // judgeNet - LOG
            m = class_getClassMethod(skCls, @selector(judgeNet));
            if (m) { orig_judgeNet = (JudgeNetIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeNet); _log(@"[INIT] SK.judgeNet hooked (LOG)"); }
            
            // verifySignatureFromParameters: - LOG
            m = class_getClassMethod(skCls, @selector(verifySignatureFromParameters:));
            if (m) { orig_verifySig = (VerifySigIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_verifySig); _log(@"[INIT] SK.verifySignatureFromParameters: hooked (LOG)"); }
            
            // generateRequestParams - LOG
            m = class_getClassMethod(skCls, @selector(generateRequestParams));
            if (m) { orig_genParams = (GenParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_genParams); _log(@"[INIT] SK.generateRequestParams hooked (LOG)"); }
            
            // createSignatureParams: - LOG
            m = class_getClassMethod(skCls, @selector(createSignatureParams:));
            if (m) { orig_createSigParams = (CreateSigParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_createSigParams); _log(@"[INIT] SK.createSignatureParams: hooked (LOG)"); }
            
            // Enumerate all methods for diagnostics
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(metaCls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                DLOG(@"[SK] +[%@]", NSStringFromSelector(method_getName(methods[i])));
            }
            if (methods) free(methods);
        } else {
            _log(@"[INIT] WARNING: SignatureKit NOT found!");
        }
        
        // --- Hook SignatureCheck (original verification - from stub) ---
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            Class metaCls = object_getClass(scCls);
            
            // JudgeApp - BLOCK (prevents real HTTP request)
            Method m = class_getClassMethod(scCls, @selector(JudgeApp));
            if (m) { orig_judgeApp = (JudgeAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeApp); _log(@"[INIT] SC.JudgeApp hooked (BLOCK)"); }
            
            // showTipViewEND: - SUPPRESS
            m = class_getClassMethod(scCls, @selector(showTipViewEND:));
            if (m) { orig_showTip = (ShowTipIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showTip); _log(@"[INIT] SC.showTipViewEND: hooked (SUPPRESS)"); }
            
            // exitApplication - BLOCK
            m = class_getClassMethod(scCls, @selector(exitApplication));
            if (m) { orig_scExit = (SCExitIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_scExit); _log(@"[INIT] SC.exitApplication hooked (BLOCK)"); }
            
            // Enumerate all methods
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(metaCls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                DLOG(@"[SC] +[%@]", NSStringFromSelector(method_getName(methods[i])));
            }
            if (methods) free(methods);
        } else {
            _log(@"[INIT] WARNING: SignatureCheck NOT found!");
        }
        
        // Dump NSUserDefaults to find verification keys
        @try {
            NSDictionary *allDefaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
            DLOG(@"[NSUD-DUMP] Total keys: %lu", (unsigned long)allDefaults.count);
            for (NSString *key in allDefaults) {
                // Only log keys that look like they might be related to verification
                NSString *lk = [key lowercaseString];
                if ([lk containsString:@"pass"] || [lk containsString:@"verify"] || 
                    [lk containsString:@"sign"] || [lk containsString:@"license"] ||
                    [lk containsString:@"ispass"] || [lk containsString:@"cert"] ||
                    [lk containsString:@"check"] || [lk containsString:@"auth"] ||
                    [lk containsString:@"valid"]) {
                    DLOG(@"[NSUD-DUMP] %@ = %@", key, allDefaults[key]);
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[NSUD-DUMP] Exception: %@", e);
        }
        DLOG(@"[NSUD] Total reads so far: %d", g_nsudCount);
        
        // --- Create LOG button ---
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
