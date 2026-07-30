#import "ProtocolPatcher.h"
/**
 * WangXianHook v36.109: Fix SIGSEGV crash - all responses minimal 16-byte header only
 * MODE: PROACTIVE - Inject fake responses when server closes, block quitFromServer
 *
 * v36.109 FIXES:
 *   1. Fix SIGSEGV crash: 0x80FFF495 maps to handle_CHOOSE_WOOD_BOX_RES(string)
 *   2. ALL fake responses now use 16-byte header only (no payload) to prevent parsing crashes
 *   3. Remove all fabricated payload data that caused string parsing crashes
 *
 * v36.107 FIXES:
 *   1. Filter heartbeat (0x00000015) and challenge cmds from command queue
 *   2. Prioritize critical login/character data commands in response generation
 *   3. Fix queue overflow caused by heartbeat flooding
 *   4. Add enhanced debug logging for command tracking
 *
 * v36.105 FIXES:
 *   1. Reset g_fakeRespDelivered in FAKE-SEND path - every send gets a response
 *   2. Add g_lastRespCmd tracking to prevent infinite loop on same cmd
 *   3. Add g_respCount cap (200) to prevent any infinite loop
 *   4. Fix stuck at "正在进入..." - now client can proceed with responses
 *
 * v36.104 FIXES:
 *   1. Disable dangerous inline patch (caused crash on iOS)
 *   2. Hook poll() to clear POLLHUP/POLLERR for fake response fd
 *   3. Hook select() to clear exception for fake response fd
 *   4. This prevents heartbeat from detecting dead connection
 *
 * v36.103 FIXES:
 *   1. Use mach_vm_remap to bypass iOS code page write protection (kr=2 fix)
 *   2. Fallback to mprotect on jailbroken devices
 *   3. Properly allocate+copy+modify+remap code pages
 *
 * v36.103 FIXES:
 *   1. Inline patch C++ functions (quitFromServer/heartbeat) to ret instruction
 *   2. Use dladdr+backtrace to find function addresses when close() is called
 *   3. Proactively search for functions via dlsym at hook installation
 *   4. Fix double-response bug: set g_fakeRespDelivered in injection code
 *
 * v36.101 FIXES:
 *   1. Fix infinite loop: fake response delivered only ONCE per client request
 *   2. After delivery, return EAGAIN until client sends a new command
 *   3. g_fakeRespDelivered flag cleared in send hook when new cmd is sent
 *
 * v36.100 FIXES:
 *   1. Smart fake response system - track client requests and generate responses
 *   2. Active fake response mode - continuously generate responses instead of EAGAIN
 *   3. Dynamic response generation based on last game server command
 *   4. Updated version numbers throughout the codebase
 *
 * v36.99 FIXES:
 *   1. ALWAYS return EAGAIN for game server fd when orig_recv returns 0
 *   2. This prevents SocketClient/NetImpl from detecting "connection closed"
 *   3. Prevents internal disconnected state being set, avoiding "网络中断" error
 *
 * v36.98 FIXES:
 *   1. Reset g_fakeRespInjected on server rotation (tryNextServer)
 *   2. Reset g_fakeRespInjected on new game server connection (hook_connect)
 *   3. This ensures FAKE-RESP can be injected on each new connection attempt
 *
 * v36.97 FIXES:
 *   1. Hook send() for fake resp fd - simulate send success
 *   2. Hook getsockopt() for fake resp fd - return SO_ERROR=0
 *   3. Fix dlsym search logic - use dlopen instead of raw image header
 *   4. Use rebindSymbol (fishhook) to hook C++ heartbeat/disconnect functions
 *
 * v36.93 DISCOVERY (TRUE ROOT CAUSE):
 *   The SERVER is closing the connection, not the client!
 *   Sequence: client sends 0x000EE007 + 0x00FFF493 → server closes connection
 *   recv() returns 0 BEFORE the client calls quitFromServer
 *   Close block is useless - server already terminated the connection
 *
 * v36.94 SOLUTION:
 *   1. [FAKE-RESP] When recv() returns 0 (server closed) for game server fd,
 *      inject fake 0x80FFF493 success response packet (status=0)
 *      This tells client "login successful" and prevents disconnection
 *   2. [NETIMPL-HOOK] Hook NetImpl::quitFromServer as no-op
 *      Prevents client state machine from entering disconnected state
 *      Uses dlsym + Objective-C runtime to find and hook the method
 *
 * REMAINS from v36.91-v36.93:
 *   DELETE: FORCE-HS mechanism (no fake 0x80FFF495 injection)
 *   DELETE: 0x00FFFF02 auto-respond (let client send native 0x00FFF495 703B)
 *   DELETE: FORCE-SEND logic (let client send native encrypted 0x000EE007)
 */
/*
 * HISTORY:
 * v36.55 CRITICAL FIXES:
 * - Just pass through to original connect with logging
 * - All port rewrite attempts (12003->58158) failed - 58158 unreachable
 * 
 * v36.54 CRITICAL FIXES:
 * - Non-blocking connect + select wait 30s (restore blocking after)
 * - Game expects connect() to complete, not EINPROGRESS
 * - 30s timeout instead of 5s to allow slower connections
 * 
 * v36.53 CRITICAL FIXES:
 * - Non-blocking connect with port rewrite (12003->58158), NO select wait
 * - Let game handle async connection itself (no timeout, no close)
 * - Previous select() was causing 5-second timeout, blocking caused hang
 * 
 * v36.52 CRITICAL FIXES:
 * - SIMPLE port rewrite: 12003 -> 58158 with DIRECT blocking connect (no O_NONBLOCK, no select)
 * - Use setsockopt(SO_SNDTIMEO, 10s) as safety net instead of non-blocking mode
 * 
 * v36.51 CRITICAL FIXES:
 * - RE-ENABLE port rewrite: 12003 -> 58158 (normal client uses 58158!)
 * - Add non-blocking mode and select() timeout for game server connections
 * 
 * v36.50 CRITICAL FIXES:
 * - FIX: Remove ret=13 truncation in hook_read() - it was destroying 0x802EE121 responses!
 * - FIX: Limit '版本过低' clearing to ONLY port=5678 (login server), NOT port=12003 (game server)
 * 
 * PREVIOUS (v36.46):
 * MINIMAL MODE - Only 0x802EE121 patch
 * 
 * PREVIOUS (v36.45):
 * DISABLE port rewrite, test direct 12003 connection
 * 
 * PREVIOUS (v36.44):
 * Non-blocking connect with select wait
 * 
 * PREVIOUS (v36.39):
 * FIX: Revert login server redirect, keep game server fix with 5s timeout
 * 
 * PREVIOUS (v36.38):
 * FIX: Added login server IP rewriting: 47.100.222.229 -> 47.100.14.198
 * FIX: Added game server IP rewriting logic
 * FIX: Added global variables g_loginServerIP and g_loginServerPort
 * WHY: Game hardcodes wrong login server IP (47.100.222.229), need to redirect to correct IP
 * 
 * PREVIOUS (v36.27):
 * FIX: Changed default game server port from 12003 to 58158 (matching normal client)
 * FIX: Added parseServerListResponse() to dynamically extract IP and port from server list response
 * FIX: Updated close hook to use dynamic game server port instead of hardcoded 12003
 * FIX: Updated recv/read hooks to call parseServerListResponse() for server list parsing
 * WHY: Normal client uses port 58158 for game server, not 12003
 * 
 * PREVIOUS (v36.26):
 * FIX: Simplified device info packet analysis to avoid Objective-C exceptions in threads
 * FIX: Added @try/@catch protection around all packet analysis code
 * FIX: Added signal handlers (SIGABRT/SIGSEGV/SIGILL/SIGBUS/SIGFPE/SIGTRAP) to capture crash info
 * FIX: Removed challenge packet (0x00FFFF01/0x00FFFF02) auto-response
 * WHY: Normal client does NOT respond to these packets, auto-response causes server disconnect
 * NOTE: Multiple hook libraries detected (libWJHook.dylib + WangXianHook.dylib)
 * 
 * PREVIOUS (v36.23):
 * - REMOVED mock data injection, OBSERVE ONLY
 * - ProtocolPatcher only patches errorCode, never modifies payload data
 * 
 * RESTORED (needed for injection detection bypass):
 * - 0x802EE121 response patching (status→0, clear '版本过低' message)
 * - '版本过低'/'当前版本' message clearing in responses
 * 
 * KEPT REMOVED (breaks normal protocol):
 * - Challenge packet auto-response (causes disconnect)
 * - Server list IP replacement
 * - Version number modification (7.6.3→7.7.0)
 * - Server list status/serverType/clientid/serverid patching
 * - UUID injection into 0x000EE007
 * 
 * RETAINED:
 * - Socket hooks (connect/send/recv) for logging
 * - Encryption hooks (CCCrypt/SecKey) for logging
 * - UIAlertView/UIAlertController hooks
 * - dlsym hook to hide injection detection
 * - SignatureKit hooks for monitoring
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <libkern/OSCacheControl.h>

// v36.103: Declare private Mach API for code page patching
extern "C" kern_return_t mach_vm_remap(
    vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance
);
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <poll.h>
#include <sys/select.h>
#include <zlib.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

// v36.57: FULL MODE - Enable all hooks including game server analysis, crypto hooks
// v36.47: EXTREME MINIMAL MODE - Only 0x802EE121 patch, NO crypto hooks, NO socket modifications
// v36.47: Critical fix - Disable all crypto function hooks that corrupt encryption data
// v36.47: Critical fix - Fix hook_alertControllerPresent SIGSEGV crash
#define MINIMAL_MODE 0
#define DISABLE_CRYPTO_HOOKS 0
#define DISABLE_SOCKET_MODS 0
#define DISABLE_UI_HOOKS 0

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES; // logging toggle
static BOOL g_isActivated = NO; // activation status
static void installAllHooks(void);

#include <signal.h>
#include <execinfo.h>

static void signalHandler(int sig) {
    NSString *sigName = nil;
    switch(sig) {
        case SIGABRT: sigName = @"SIGABRT"; break;
        case SIGSEGV: sigName = @"SIGSEGV"; break;
        case SIGILL: sigName = @"SIGILL"; break;
        case SIGBUS: sigName = @"SIGBUS"; break;
        case SIGFPE: sigName = @"SIGFPE"; break;
        case SIGTRAP: sigName = @"SIGTRAP"; break;
        case SIGEMT: sigName = @"SIGEMT"; break;
        default: sigName = [NSString stringWithFormat:@"SIG%d", sig];
    }
    
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **strs = backtrace_symbols(callstack, frames);
    
    NSMutableString *crashInfo = [NSMutableString string];
    [crashInfo appendFormat:@"\n=== CRASH (%@) ===\n", sigName];
    [crashInfo appendFormat:@"Signal: %d (%@)\n", sig, sigName];
    [crashInfo appendFormat:@"Backtrace (%d frames):\n", frames];
    for (int i = 0; i < frames && i < 30; i++) {
        if (strs[i]) {
            [crashInfo appendFormat:@"  #%d: %s\n", i, strs[i]];
        }
    }
    [crashInfo appendFormat:@"====================\n"];
    
    if (g_logPath) {
        @try {
            NSData *data = [crashInfo dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        } @catch (NSException *e) {}
    }
    
    if (strs) free(strs);
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static void setupSignalHandlers(void) {
    signal(SIGABRT, signalHandler);
    signal(SIGSEGV, signalHandler);
    signal(SIGILL, signalHandler);
    signal(SIGBUS, signalHandler);
    signal(SIGFPE, signalHandler);
    signal(SIGTRAP, signalHandler);
}

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
        setupSignalHandlers();
        _log(@"=== WangXianHook v36.107 loaded ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
        _log(@"[CRASH-HANDLER] Signal handlers registered");
        g_isActivated = YES;
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

// 4. judgeAppInfoWithBaseUrl: - Call original to allow normal auth flow
// IMPORTANT: Do NOT bypass this - it breaks device authorization
// Let the game make real requests to md5xor.com
typedef void (*JudgeBaseIMP)(id, SEL, id);
static JudgeBaseIMP orig_judgeBase = NULL;
static void hook_judgeBase(id self, SEL _cmd, id baseUrl) {
    DLOG(@"[SK] judgeAppInfoWithBaseUrl: %@ (calling original)", baseUrl);
    if (orig_judgeBase) orig_judgeBase(self, _cmd, baseUrl);
}

// 5. judgeNet - Call original to let it complete
typedef void (*JudgeNetIMP)(id, SEL);
static JudgeNetIMP orig_judgeNet = NULL;
static void hook_judgeNet(id self, SEL _cmd) {
    DLOG(@"[SK] judgeNet called, calling original");
    if (orig_judgeNet) orig_judgeNet(self, _cmd);
}

// 6. verifySignatureFromParameters: - Call original (returns real signature result)
// IMPORTANT: Must call original to get valid signature result, returning fake data breaks game server auth
typedef id (*VerifySigIMP)(id, SEL, id);
static VerifySigIMP orig_verifySig = NULL;
static id hook_verifySig(id self, SEL _cmd, id params) {
    DLOG(@"[SK] verifySignatureFromParameters: calling original: %@", params);
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
- (void)handleTripleTap:(UITapGestureRecognizer *)gesture;
- (void)handlePan:(UIPanGestureRecognizer *)gesture;
@end

static UIButton *g_btn = nil;
static UIView *g_panel = nil;
static UITextView *g_tv = nil;
static WXHandler *g_handler = nil;
static UILabel *g_statusLbl = nil;

static BOOL g_isKeyboardActive = NO;

static void keyboardWillShow(NSNotification *notification) {
    g_isKeyboardActive = YES;
    DLOG(@"[KB] Keyboard will show");
}

static void keyboardWillHide(NSNotification *notification) {
    g_isKeyboardActive = NO;
    DLOG(@"[KB] Keyboard will hide");
}

static void keyboardDidShow(NSNotification *notification) {
    DLOG(@"[KB] Keyboard did show");
}

static void keyboardDidHide(NSNotification *notification) {
    DLOG(@"[KB] Keyboard did hide");
}

static void installKeyboardProtection(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillShowNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardWillShow(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillHideNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardWillHide(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidShowNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardDidShow(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidHideNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardDidHide(note); }];
    DLOG(@"[KB] Keyboard protection installed");
}

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
            lbl.text = @"WXHook v36.109 诊断面板";
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
- (void)handleTripleTap:(UITapGestureRecognizer *)gesture {
    if (g_btn) {
        g_btn.hidden = !g_btn.hidden;
        if (!g_btn.hidden) {
            DLOG(@"[UI] Log button shown via triple-tap");
        } else {
            DLOG(@"[UI] Log button hidden via triple-tap");
        }
    }
}
- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    if (!g_btn || g_btn.hidden) return;
    UIView *v = gesture.view;
    CGPoint translation = [gesture translationInView:v.superview];
    CGPoint newCenter = CGPointMake(v.center.x + translation.x, v.center.y + translation.y);
    CGRect bounds = v.superview.bounds;
    newCenter.x = MAX(25, MIN(bounds.size.width - 25, newCenter.x));
    newCenter.y = MAX(25, MIN(bounds.size.height - 25, newCenter.y));
    v.center = newCenter;
    [gesture setTranslation:CGPointZero inView:v.superview];
}
@end

// ============================================================
// NOTE: NSArray count hook REMOVED - causes crashes during keyboard input
// Server list handling is now done at the protocol level (hook_recv/recvfrom/recvmsg)
// ============================================================

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
            
            BOOL hasFail = NO;
            if ([result isKindOfClass:[NSString class]]) {
                hasFail = [(NSString *)result containsString:@"fail"];
            }
            BOOL hasVersionMsg = NO;
            if ([msg isKindOfClass:[NSString class]]) {
                hasVersionMsg = [(NSString *)msg containsString:@"版本"] || 
                               [(NSString *)msg containsString:@"更新"] || 
                               [(NSString *)msg containsString:@"升级"];
            }
            if (hasVersionMsg || hasFail) {
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
    NSString *url = dataTask.currentRequest.URL.absoluteString;
    DLOG(@"[HTTP-DATA] urlSession:dataTask:didReceiveData: len=%zu url=%@", (unsigned long)[data length], url);
    
    NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (dataStr) {
        if ([dataStr containsString:@"版本"] || [dataStr containsString:@"server"] || 
            [dataStr containsString:@"status"] || [dataStr containsString:@"maintenance"] ||
            [dataStr containsString:@"ispass"] || [dataStr containsString:@"md5xor"] ||
            [dataStr containsString:@"code"] || [dataStr containsString:@"sign"] ||
            [dataStr containsString:@"ENDTIME"]) {
            DLOG(@"[HTTP-DATA] Response contains key info: %@", dataStr);
            [ProtocolPatcher patchServerResponse:[dataStr dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }
    
    // Patch delegate-mode responses for sign/cert APIs
    if (dataStr && url && ([url containsString:@"judgeAppInfoSignApi"] || [url containsString:@"judgeAppInfoApi"] || [dataStr containsString:@"ENDTIME"])) {
        DLOG(@"[HTTP-DATA-PATCH] Patching delegate-mode cert/sign API response");
        NSString *newBody = dataStr;
        // Extend ENDTIME to future
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];
        newBody = [regex stringByReplacingMatchesInString:newBody options:0 range:NSMakeRange(0, newBody.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
        NSData *newData = [newBody dataUsingEncoding:NSUTF8StringEncoding];
        DLOG(@"[HTTP-DATA-PATCH] Patched delegate response: %@", newBody);
        if (orig_urlSessionDataTaskDidReceiveData) {
            orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, newData);
            return;
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
    
    // Hook URLSession:dataTask:didReceiveData: on classes that implement it
    // This intercepts delegate-mode responses (used by judgeAppInfoSignApi)
    unsigned int classCount = 0;
    Class *classes = (Class *)malloc(sizeof(Class) * 0x10000);
    if (classes) {
        int numClasses = objc_getClassList(classes, 0x10000);
        int hookedCount = 0;
        for (int i = 0; i < numClasses; i++) {
            Class cls = classes[i];
            Method m = class_getInstanceMethod(cls, @selector(URLSession:dataTask:didReceiveData:));
            if (m) {
                IMP currentImp = method_getImplementation(m);
                if (currentImp != (IMP)hook_urlSessionDataTaskDidReceiveData) {
                    orig_urlSessionDataTaskDidReceiveData = (void(*)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*))currentImp;
                    method_setImplementation(m, (IMP)hook_urlSessionDataTaskDidReceiveData);
                    DLOG(@"[HTTP-HOOK] Hooked URLSession:dataTask:didReceiveData: on class: %@", NSStringFromClass(cls));
                    hookedCount++;
                    if (hookedCount >= 5) break;
                }
            }
        }
        free(classes);
        if (hookedCount > 0) {
            DLOG(@"[INIT] URLSession:dataTask:didReceiveData: hooked on %d classes", hookedCount);
        }
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
#pragma mark - UITableView DataSource hooks (OBSERVE ONLY, NO MODIFICATION)
// ============================================================

static IMP orig_tableView_numberOfRows = NULL;
static IMP orig_tableView_cellForRow = NULL;
static IMP orig_tableView_numberOfSections = NULL;

static BOOL isServerListDataSource(id self) {
    @try {
        if ([self respondsToSelector:@selector(dataSource)]) {
            id ds = [self dataSource];
            if (ds) {
                NSString *dsName = NSStringFromClass([ds class]);
                return ([dsName containsString:@"Server"] || [dsName containsString:@"server"] || 
                        [dsName containsString:@"List"] || [dsName containsString:@"list"] ||
                        [dsName containsString:@"Login"] || [dsName containsString:@"login"]);
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
        DLOG(@"[TV-OBSERVE] -[%@ numberOfRowsInSection:%ld] -> %ld", clsName, (long)section, (long)ret);
        
        @try {
            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;
            if (dataSource) {
                NSString *dsCls = NSStringFromClass([dataSource class]);
                DLOG(@"[TV-OBSERVE] dataSource=%@ (%@)", dataSource, dsCls);
                
                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {
                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];
                    if ([serverList isKindOfClass:[NSArray class]]) {
                        DLOG(@"[TV-OBSERVE] serverList count=%lu", (unsigned long)[serverList count]);
                        for (NSUInteger i = 0; i < [serverList count] && i < 5; i++) {
                            id item = serverList[i];
                            DLOG(@"[TV-OBSERVE]   [%lu] = %@ (%@)", i, item, NSStringFromClass([item class]));
                            if ([item isKindOfClass:[NSDictionary class]]) {
                                NSDictionary *dict = (NSDictionary *)item;
                                DLOG(@"[TV-OBSERVE]     keys=%@", [dict allKeys]);
                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@ status=%@", dict[@"name"], dict[@"ip"], dict[@"port"], dict[@"status"]);
                            } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)] && [item respondsToSelector:@selector(port)]) {
                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@", 
                                     [item performSelector:@selector(name)], 
                                     [item performSelector:@selector(ip)], 
                                     [item performSelector:@selector(port)]);
                            }
                        }
                    } else {
                        DLOG(@"[TV-OBSERVE] serverList is NOT NSArray: %@", serverList ? NSStringFromClass([serverList class]) : @"nil");
                    }
                }
                
                if ([dataSource respondsToSelector:@selector(dataArray)] || [dataSource respondsToSelector:@selector(items)]) {
                    id data = [dataSource performSelector:[dataSource respondsToSelector:@selector(dataArray)] ? @selector(dataArray) : @selector(items)];
                    if ([data isKindOfClass:[NSArray class]]) {
                        DLOG(@"[TV-OBSERVE] dataArray/items count=%lu", (unsigned long)[data count]);
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[TV-OBSERVE] Exception: %@", e);
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
        NSString *detailText = @"";
        if (ret && [ret respondsToSelector:@selector(detailTextLabel)] && [(UITableViewCell*)ret detailTextLabel]) {
            detailText = [(UITableViewCell*)ret detailTextLabel].text ?: @"";
        }
        
        DLOG(@"[TV-OBSERVE] -[%@ cellForRowAtIndexPath:{%ld,%ld}] -> text='%@' detail='%@'", clsName, 
             (long)indexPath.section, (long)indexPath.row, text, detailText);
        
        @try {
            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;
            if (dataSource) {
                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {
                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];
                    if ([serverList isKindOfClass:[NSArray class]] && indexPath.row < [serverList count]) {
                        id item = serverList[indexPath.row];
                        DLOG(@"[TV-OBSERVE] Row %ld data: %@ (%@)", (long)indexPath.row, item, NSStringFromClass([item class]));
                        if ([item isKindOfClass:[NSDictionary class]]) {
                            NSDictionary *dict = (NSDictionary *)item;
                            DLOG(@"[TV-OBSERVE]   name=%@ status=%@ ip=%@ port=%@", 
                                 dict[@"name"], dict[@"status"], dict[@"ip"], dict[@"port"]);
                        } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)]) {
                            DLOG(@"[TV-OBSERVE]   name=%@ ip=%@", 
                                 [item performSelector:@selector(name)], 
                                 [item performSelector:@selector(ip)]);
                        }
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[TV-OBSERVE] Exception: %@", e);
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
        DLOG(@"[TV-OBSERVE] -[%@ numberOfSections] -> %ld", clsName, (long)ret);
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

// ============================================================
// ServerInfoForClient Stub Class Implementation
// ============================================================

// Game server config variables (defined early for stub class access)
static int g_gameServerPort = 0;  // v36.61: Default to 0 (not set yet), will be parsed from server list
static char g_gameServerIP[64] = "47.100.14.198";
static BOOL g_gameServerInfoUpdated = YES;

// v36.61: Track game server connection state
static BOOL g_gameServerConnected = NO;  // Whether game server handshake completed
static int g_gameServerFd = -1;  // Track which fd is connected to game server
static NSTimeInterval g_gameConnectTime = 0;  // Time of game server connection

// v36.66: Store 0x000EE007 device info packet for forced send to game server
#define MAX_DEVICE_INFO_SIZE 512
static uint8_t g_deviceInfoPacket[MAX_DEVICE_INFO_SIZE];
static ssize_t g_deviceInfoPacketLen = 0;
static BOOL g_deviceInfoCaptured = NO;
static BOOL g_deviceInfoSentToGame = NO;

// v36.87: Enhanced device info packet (with UUID injected) for game server
// Login server (5678) sends 143-byte version (no UUID)
// Game server expects 179-byte version (with UUID field)
static uint8_t g_deviceInfoEnhanced[MAX_DEVICE_INFO_SIZE];
static ssize_t g_deviceInfoEnhancedLen = 0;
static BOOL g_deviceInfoEnhancedReady = NO;

// v36.68: Sticky packet leftover buffer - for splitting sticky packets
// When 0x80FFF494 and heartbeat ACK arrive in same TCP buffer,
// we split them so the game client only sees the handshake response
#define MAX_STICKY_LEFTOVER 4096
static uint8_t g_stickyLeftoverBuf[MAX_STICKY_LEFTOVER];
static ssize_t g_stickyLeftoverLen = 0;
static int g_stickyLeftoverFd = -1;

// v36.68: Local heartbeat ACK buffer - for faking heartbeat responses
// When game sends heartbeat to game server during handshake, we intercept
// and return a local ACK to prevent server from including it in handshake response
#define MAX_LOCAL_HEARTBEAT_ACK 256
static uint8_t g_localHeartbeatAckBuf[MAX_LOCAL_HEARTBEAT_ACK];
static ssize_t g_localHeartbeatAckLen = 0;
static int g_localHeartbeatAckFd = -1;

// v36.68: Global handshake state tracking (moved from hook_recv for cross-function access)
static BOOL g_handshakeComplete = NO;
static int g_heartbeatCount = 0;

// v36.79: Store game server public key for RSA encrypt
// Extracted from 0x80FFF494 response (Base64-encoded DER public key)
#define MAX_PUBKEY_BASE64 1024
static char g_pubKeyBase64[MAX_PUBKEY_BASE64];
static size_t g_pubKeyBase64Len = 0;
static BOOL g_pubKeyCaptured = NO;

// v36.79: Track if we already auto-responded to 0x00FFFF02
static BOOL g_challengeResponded = NO;
static int g_challengeFd = -1;

// v36.83: Force handshake complete packet buffer
// When client sends heartbeat after challenge response (server didn't send 0x80FFF495),
// we prepare a fake 0x80FFF495 handshake complete response
#define MAX_FORCE_HS_BUF 256
static BOOL g_forceHandshakeComplete = NO;
static int g_forceHandshakeFd = -1;
static uint8_t g_forceHandshakeBuf[MAX_FORCE_HS_BUF];
static uint32_t g_forceHandshakeLen = 0;

// v36.107: Smart fake response system - track ALL client requests in a queue with sequence numbers
// Command queue - track ALL game server commands for ordered response
#define MAX_CMD_QUEUE 64
typedef struct {
    uint32_t cmd;
    int fd;
    uint32_t sendLen;
    uint32_t seqNum;  // v36.107: Sequence number from original request for correct response matching
} GameCmdEntry;

static GameCmdEntry g_cmdQueue[MAX_CMD_QUEUE];
static int g_cmdQueueHead = 0;   // Next command to dequeue
static int g_cmdQueueTail = 0;   // Next slot to enqueue
static int g_cmdQueueCount = 0;  // Number of commands in queue

// Track last game server command for generating appropriate fake responses
static uint32_t g_lastGameCmd = 0;
static int g_lastGameCmdFd = -1;
static uint32_t g_lastSeqNum = 0;  // v36.107: Last sequence number for fallback responses
static BOOL g_fakeRespActive = NO;
static BOOL g_fakeRespDelivered = NO;
static uint32_t g_lastRespCmd = 0;
static int g_respCount = 0;

// v36.107: Command queue functions - filter heartbeat and challenge cmds, track sequence numbers
static BOOL isFilteredCmd(uint32_t cmd) {
    if (cmd == 0x00000015) return YES;  // Heartbeat
    if (cmd == 0x00FFFF01) return YES;  // Challenge response 1
    if (cmd == 0x00FFFF02) return YES;  // Challenge response 2
    if (cmd == 0x80000015) return YES;  // Heartbeat (response direction)
    return NO;
}

static void enqueueGameCmd(uint32_t cmd, int fd, uint32_t sendLen, uint32_t seqNum) {
    // v36.107: Filter heartbeat and challenge commands to prevent queue flooding
    if (isFilteredCmd(cmd)) {
        DLOG(@"[CMD-QUEUE] v36.107: Filtered cmd=0x%08X seq=0x%08X (heartbeat/challenge)", cmd, seqNum);
        return;
    }
    
    if (g_cmdQueueCount >= MAX_CMD_QUEUE) {
        // Queue full - discard oldest
        g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;
        g_cmdQueueCount--;
        DLOG(@"[CMD-QUEUE] v36.107: Queue full, discarding oldest");
    }
    g_cmdQueue[g_cmdQueueTail].cmd = cmd;
    g_cmdQueue[g_cmdQueueTail].fd = fd;
    g_cmdQueue[g_cmdQueueTail].sendLen = sendLen;
    g_cmdQueue[g_cmdQueueTail].seqNum = seqNum;
    g_cmdQueueTail = (g_cmdQueueTail + 1) % MAX_CMD_QUEUE;
    g_cmdQueueCount++;
    DLOG(@"[CMD-QUEUE] v36.107: Enqueued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (queue=%d)", 
         cmd, seqNum, fd, sendLen, g_cmdQueueCount);
}

static BOOL dequeueGameCmd(GameCmdEntry *entry) {
    if (g_cmdQueueCount <= 0) return NO;
    *entry = g_cmdQueue[g_cmdQueueHead];
    g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;
    g_cmdQueueCount--;
    return YES;
}

static void resetCmdQueue(void) {
    g_cmdQueueHead = 0;
    g_cmdQueueTail = 0;
    g_cmdQueueCount = 0;
}

// v36.106: Generate response based on queued command
static BOOL g_quitFromServerPatched = NO;
static BOOL g_heartbeatPatched = NO;

// v36.104: Disabled inline patch (caused crash) - using poll/select hook instead
static BOOL patchFunctionToReturn(void *funcAddr, const char *funcName) {
    // v36.104: Inline patching causes crash on iOS - disabled
    // Instead, we hook poll()/select() to prevent heartbeat from detecting dead connection
    DLOG(@"[INLINE-PATCH] v36.104: Inline patch disabled (caused crash), using poll/select hook instead");
    (void)funcAddr; (void)funcName;
    return NO;
}

// v36.103: Find and patch C++ functions using backtrace from close() call
static void findAndPatchDisconnectFunctions(void) {
    if (g_quitFromServerPatched && g_heartbeatPatched) return;
    
    void *callstack[32];
    int frames = backtrace(callstack, 32);
    
    DLOG(@"[INLINE-PATCH] v36.103: Scanning %d backtrace frames for C++ functions...", frames);
    
    for (int i = 0; i < frames; i++) {
        Dl_info info;
        if (dladdr(callstack[i], &info) && info.dli_sname) {
            const char *name = info.dli_sname;
            
            // Check for quitFromServer
            if (!g_quitFromServerPatched && strstr(name, "quitFromServer")) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 
                     name, info.dli_saddr, i, callstack[i]);
                if (patchFunctionToReturn(info.dli_saddr, name)) {
                    g_quitFromServerPatched = YES;
                }
            }
            
            // Check for heartbeat
            if (!g_heartbeatPatched && strstr(name, "heartbeat") && strstr(name, "NetImpl")) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 
                     name, info.dli_saddr, i, callstack[i]);
                if (patchFunctionToReturn(info.dli_saddr, name)) {
                    g_heartbeatPatched = YES;
                }
            }
        }
    }
    
    if (!g_quitFromServerPatched && !g_heartbeatPatched) {
        DLOG(@"[INLINE-PATCH] v36.103: No C++ functions found in backtrace");
    }
}

// v36.103: Proactively search for C++ functions in main binary and patch them
static void proactivePatchCppFunctions(void) {
    if (g_quitFromServerPatched && g_heartbeatPatched) return;
    
    DLOG(@"[INLINE-PATCH] v36.103: Proactively searching for C++ functions in main binary...");
    
    const char *targetNames[] = {
        "_ZN7NetImpl14quitFromServerEv",
        "_ZN7NetImpl9heartbeatEv",
        NULL
    };
    
    int imageCount = _dyld_image_count();
    for (int idx = 0; idx < imageCount; idx++) {
        const char *imageName = _dyld_get_image_name(idx);
        if (!imageName) continue;
        
        // Skip non-main binaries
        if (!strstr(imageName, "wangxian") && !strstr(imageName, "WangXian")) continue;
        
        DLOG(@"[INLINE-PATCH] v36.103: Searching in main binary: %s (slide=0x%lx)", 
             imageName, (unsigned long)_dyld_get_image_vmaddr_slide(idx));
        
        void *handle = dlopen(imageName, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) continue;
        
        for (int n = 0; targetNames[n] != NULL; n++) {
            void *sym = dlsym(handle, targetNames[n]);
            if (sym) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at %p via dlsym", targetNames[n], sym);
                
                if (strstr(targetNames[n], "quitFromServer") && !g_quitFromServerPatched) {
                    if (patchFunctionToReturn(sym, targetNames[n])) {
                        g_quitFromServerPatched = YES;
                    }
                }
                if (strstr(targetNames[n], "heartbeat") && !g_heartbeatPatched) {
                    if (patchFunctionToReturn(sym, targetNames[n])) {
                        g_heartbeatPatched = YES;
                    }
                }
            }
        }
        
        dlclose(handle);
        
        if (g_quitFromServerPatched && g_heartbeatPatched) break;
    }
    
    // Also try RTLD_DEFAULT
    if (!g_quitFromServerPatched) {
        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl14quitFromServerEv");
        if (sym) {
            DLOG(@"[INLINE-PATCH] v36.103: Found quitFromServer via RTLD_DEFAULT at %p", sym);
            if (patchFunctionToReturn(sym, "quitFromServer")) {
                g_quitFromServerPatched = YES;
            }
        }
    }
    if (!g_heartbeatPatched) {
        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl9heartbeatEv");
        if (sym) {
            DLOG(@"[INLINE-PATCH] v36.103: Found heartbeat via RTLD_DEFAULT at %p", sym);
            if (patchFunctionToReturn(sym, "heartbeat")) {
                g_heartbeatPatched = YES;
            }
        }
    }
    
    DLOG(@"[INLINE-PATCH] v36.103: Proactive search complete: quitFromServer=%d heartbeat=%d", 
         g_quitFromServerPatched, g_heartbeatPatched);
}

// v36.107: Generate fake response based on request command with correct sequence number
// Returns response length, 0 if no response needed
static uint32_t generateFakeResponse(uint32_t requestCmd, uint8_t *respBuf, uint32_t bufSize, uint32_t seqNum) {
    if (!respBuf || bufSize < 16) return 0;
    
    uint32_t respCmd = requestCmd | 0x80000000;  // Response cmd = request cmd | 0x80000000
    uint32_t respLen = 0;
    
    // v36.107: Extract sequence number bytes for reuse
    uint8_t seqBytes[4];
    seqBytes[0] = (seqNum >> 24) & 0xFF;
    seqBytes[1] = (seqNum >> 16) & 0xFF;
    seqBytes[2] = (seqNum >> 8) & 0xFF;
    seqBytes[3] = seqNum & 0xFF;
    
    switch (requestCmd) {
        case 0x00FFF494: {  // v36.107: Protocol init/small request
            respLen = 16;
            memset(respBuf, 0, respLen);
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            // v36.107: Preserve sequence number from request
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;
            break;
        }
            
        case 0x00FFF495: {  // v36.109: CHOOSE_WOOD_BOX_RES - minimal header only to prevent crash
            // v36.108 CRASH FIX: 0x80FFF495 maps to handle_CHOOSE_WOOD_BOX_RES(string)
            // Any payload data causes string parsing crash. Use 16-byte header only.
            respLen = 16;
            memset(respBuf, 0, respLen);
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;
            break;
        }
            
        case 0x00FFF493:  // Login data request -> success response
        case 0x000EE007:  // Device info request -> success response
        case 0x000EE121: {  // Auth request -> success response
            // v36.109: Minimal 16-byte header only to prevent payload parsing crashes
            respLen = 16;
            memset(respBuf, 0, respLen);
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;  // Status = 0 (success)
            break;
        }
            
        case 0x00000015:  // Heartbeat request -> heartbeat response
        case 0x00FFFF01:  // Challenge response -> echo
        case 0x00FFFF02: {
            respLen = 16;  // Minimal response
            memset(respBuf, 0, respLen);
            
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            
            // v36.107: Preserve sequence number
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;
            break;
        }
            
        case 0x0000F013: {  // Server select request -> success response
            respLen = 32;
            memset(respBuf, 0, respLen);
            
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            
            // v36.107: Preserve sequence number
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;  // Success
            
            // Server list data (minimal)
            respBuf[16] = 0x00; respBuf[17] = 0x00;
            respBuf[18] = 0x00; respBuf[19] = 0x01;  // 1 server
            
            // IP: 127.0.0.1
            respBuf[20] = 127; respBuf[21] = 0;
            respBuf[22] = 0; respBuf[23] = 1;
            
            // Port: 12003
            respBuf[24] = 0x2EE9 >> 8; respBuf[25] = 0x2EE9 & 0xFF;
            respBuf[26] = 0x00; respBuf[27] = 0x00;
            
            for (uint32_t i = 28; i < respLen; i++) {
                respBuf[i] = 0x00;
            }
            break;
        }
            
        default: {
            // Unknown command: generate generic success response
            respLen = 16;
            memset(respBuf, 0, respLen);
            
            respBuf[0] = 0x00; respBuf[1] = 0x00;
            respBuf[2] = 0x00; respBuf[3] = respLen;
            
            respBuf[4] = (respCmd >> 24) & 0xFF;
            respBuf[5] = (respCmd >> 16) & 0xFF;
            respBuf[6] = (respCmd >> 8) & 0xFF;
            respBuf[7] = respCmd & 0xFF;
            
            // v36.107: Preserve sequence number
            respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
            respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
            
            respBuf[12] = 0x00; respBuf[13] = 0x00;
            respBuf[14] = 0x00; respBuf[15] = 0x00;  // Success
            break;
        }
    }
    
    return respLen;
}

// v36.95: Track when client sends login packets to game server
// This replaces g_challengeResponded for fake response injection trigger
static BOOL g_loginPacketsSent = NO;

// v36.94: Fake login success response injection
// When server closes connection (recv returns 0) after client sends login packets,
// inject fake 0x80FFF493 success response to prevent disconnection
#define MAX_FAKE_RESP_BUF 256
static BOOL g_fakeRespInjected = NO;
static int g_fakeRespFd = -1;
static uint8_t g_fakeRespBuf[MAX_FAKE_RESP_BUF];
static uint32_t g_fakeRespLen = 0;
static int g_fakeRespSentCount = 0;  // Track how many fake responses sent

// v36.94: Hook for NetImpl::quitFromServer
// This C++ method is called when heartbeat detects dead connection
// Making it a no-op prevents client state machine from entering disconnected state
typedef void (*NetImplQuitFunc)(void);
static NetImplQuitFunc orig_NetImpl_quitFromServer = NULL;
static BOOL g_quitFromServerHooked = NO;

// v36.97: MSHookFunction variables for heartbeat and disconnect
typedef void (*HeartbeatFunc)(void);
typedef void (*DisconnectFunc)(void);
static HeartbeatFunc orig_heartbeat_func = NULL;
static DisconnectFunc orig_disconnect_func = NULL;

// v36.97: No-op functions for MSHookFunction
static void noop_heartbeat(void) {
    DLOG(@"[NETIMPL-BLOCK] v36.97: HEARTBEAT BLOCKED (no-op)");
}

static void noop_disconnect(void) {
    DLOG(@"[NETIMPL-BLOCK] v36.97: DISCONNECT BLOCKED (no-op)");
}

// v36.57: Server list for rotation/retry
#define MAX_SERVERS 20
typedef struct {
    char ip[64];
    int port;
} ServerInfo;

static ServerInfo g_serverList[MAX_SERVERS];
static int g_serverCount = 0;
static int g_currentServerIndex = 0;
static int g_connectionFailCount = 0;

static NSMutableDictionary *g_msiStubData = nil;

static id msiStub_init(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient init] called");
    if (!g_msiStubData) {
        g_msiStubData = [[NSMutableDictionary alloc] init];
        [g_msiStubData setObject:@1 forKey:@"status"];
        [g_msiStubData setObject:@1 forKey:@"serverType"];
        [g_msiStubData setObject:@1 forKey:@"serverid"];
        [g_msiStubData setObject:@1 forKey:@"clientid"];
        [g_msiStubData setObject:@"一区" forKey:@"category"];
        [g_msiStubData setObject:@"运行" forKey:@"description"];
        // v36.59: Do NOT hardcode ip/port here - let initWithDictionary set them
        DLOG(@"[MSI-STUB] Initialized empty (ip/port to be filled by caller)");
    }
    return self;
}

static id msiStub_initWithDict(id self, SEL _cmd, NSDictionary *dict) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient initWithDictionary:] called");
    if (!g_msiStubData) {
        g_msiStubData = [[NSMutableDictionary alloc] init];
    }
    
    if (dict) {
        // v36.59: Use the provided dictionary - preserve ORIGINAL ip and port from game server list!
        [g_msiStubData setDictionary:dict];
        DLOG(@"[MSI-STUB] Using original dict values from server list response");
    }
    
    // Ensure critical fields are set (ONLY if missing from dict)
    if (![g_msiStubData objectForKey:@"status"])
        [g_msiStubData setObject:@1 forKey:@"status"];
    if (![g_msiStubData objectForKey:@"serverType"])
        [g_msiStubData setObject:@1 forKey:@"serverType"];
    if (![g_msiStubData objectForKey:@"category"])
        [g_msiStubData setObject:@"一区" forKey:@"category"];
    // v36.59: FIX description field - replace '维护' with '运行'
    NSString *desc = [g_msiStubData objectForKey:@"description"];
    if (!desc || [desc isEqualToString:@"维护"]) {
        [g_msiStubData setObject:@"运行" forKey:@"description"];
    }
    
    // v36.59: DO NOT override ip and port! Keep ORIGINAL values from dict!
    // Game knows which server it selected - don't interfere with its choice!
    
    // Log all properties
    @try {
        for (NSString *key in g_msiStubData) {
            DLOG(@"[MSI-STUB]   %@ = %@", key, g_msiStubData[key]);
        }
    } @catch (NSException *e) {
        DLOG(@"[MSI-STUB] Exception logging: %@", e.reason);
    }
    
    return self;
}

static NSNumber *msiStub_status(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient status] -> 1");
    return @1;
}

static NSString *msiStub_ip(id self, SEL _cmd) {
    // v36.59: Return ip from g_msiStubData (original value from dict), NOT hardcoded g_gameServerIP!
    NSString *ip = [g_msiStubData objectForKey:@"ip"];
    if (!ip) ip = [NSString stringWithUTF8String:g_gameServerIP];
    DLOG(@"[MSI-STUB] -[ServerInfoForClient ip] -> %@", ip);
    return ip;
}

static NSNumber *msiStub_port(id self, SEL _cmd) {
    // v36.59: Return port from g_msiStubData (original value from dict), NOT hardcoded g_gameServerPort!
    NSNumber *portNum = [g_msiStubData objectForKey:@"port"];
    int port = portNum ? [portNum intValue] : g_gameServerPort;
    DLOG(@"[MSI-STUB] -[ServerInfoForClient port] -> %d", port);
    return @(port);
}

static NSString *msiStub_category(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient category] -> 一区");
    return @"一区";
}

static NSNumber *msiStub_serverType(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient serverType] -> 1");
    return @1;
}

static NSInteger msiStub_integer(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] integer method called -> 1");
    return 1;
}

static NSString *msiStub_string(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] string method called -> stub");
    return @"stub";
}

static void createServerInfoForClientStub(void) {
    @try {
        // Check if class already exists
        Class existingClass = NSClassFromString(@"ServerInfoForClient");
        if (existingClass) {
            DLOG(@"[MSI-STUB] ServerInfoForClient class already exists");
            return;
        }
        
        // Create stub class
        Class stubClass = objc_allocateClassPair([NSObject class], "ServerInfoForClient", 0);
        if (stubClass) {
            // Add instance methods
            class_addMethod(stubClass, @selector(init), (IMP)msiStub_init, "@@:");
            class_addMethod(stubClass, @selector(initWithDictionary:), (IMP)msiStub_initWithDict, "@@:@");
            class_addMethod(stubClass, @selector(status), (IMP)msiStub_status, "@@:");
            class_addMethod(stubClass, @selector(statusValue), (IMP)msiStub_status, "@@:");
            class_addMethod(stubClass, @selector(ip), (IMP)msiStub_ip, "@@:");
            class_addMethod(stubClass, @selector(port), (IMP)msiStub_serverType, "@@:");
            class_addMethod(stubClass, @selector(category), (IMP)msiStub_category, "@@:");
            class_addMethod(stubClass, @selector(serverType), (IMP)msiStub_serverType, "@@:");
            class_addMethod(stubClass, @selector(serverid), (IMP)msiStub_integer, "l@:");
            class_addMethod(stubClass, @selector(clientid), (IMP)msiStub_integer, "l@:");
            class_addMethod(stubClass, @selector(description), (IMP)msiStub_string, "@@:");
            class_addMethod(stubClass, @selector(objectForKey:), (IMP)msiStub_string, "@@:@");
            
            // Register the class
            objc_registerClassPair(stubClass);
            DLOG(@"[MSI-STUB] Created ServerInfoForClient stub class successfully");
            
            // Verify class exists
            Class verifyClass = NSClassFromString(@"ServerInfoForClient");
            if (verifyClass) {
                DLOG(@"[MSI-STUB] Verified: ServerInfoForClient class is now available");
                
                // Log all methods
                unsigned int mcount = 0;
                Method *methods = class_copyMethodList(verifyClass, &mcount);
                for (unsigned int i = 0; i < mcount; i++) {
                    SEL sel = method_getName(methods[i]);
                    DLOG(@"[MSI-STUB]   Method: %@", NSStringFromSelector(sel));
                }
                if (methods) free(methods);
            }
        } else {
            DLOG(@"[MSI-STUB] Failed to create ServerInfoForClient stub class");
        }
    } @catch (NSException *e) {
        DLOG(@"[MSI-STUB] Exception creating stub class: %@", e.reason);
    }
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
        
        // NO IP REPLACEMENT - keep original server IP
        // Normal client connects to 47.100.14.198 for both login and game servers
        if ([mutDict objectForKey:@"ip"]) {
            NSString *ip = mutDict[@"ip"];
            if ([ip isKindOfClass:[NSString class]]) {
                DLOG(@"[MSI] Server IP: %@ (not modified)", ip);
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
    g_btn.layer.cornerRadius = 25;
    g_btn.clipsToBounds = YES;
    
    NSString *imagePath = [[NSBundle mainBundle] pathForResource:@"123" ofType:@"jpg"];
    if (imagePath && [[NSFileManager defaultManager] fileExistsAtPath:imagePath]) {
        UIImage *btnImage = [UIImage imageWithContentsOfFile:imagePath];
        if (btnImage) {
            btnImage = [btnImage imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
            [g_btn setImage:btnImage forState:UIControlStateNormal];
            g_btn.imageView.contentMode = UIViewContentModeScaleAspectFill;
            DLOG(@"[UI] Log button using custom image: %@", imagePath);
        } else {
            [g_btn setTitle:@"LOG" forState:UIControlStateNormal];
            [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
        }
    } else {
        [g_btn setTitle:@"LOG" forState:UIControlStateNormal];
        [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
    }
    
    g_btn.titleLabel.font = [UIFont systemFontOfSize:10];
    g_btn.hidden = YES;
    g_btn.userInteractionEnabled = YES;
    [g_btn addTarget:g_handler action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:g_btn];
    [w bringSubviewToFront:g_btn];
    
    // Pan gesture for moving the log button (drag to reposition)
    UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handlePan:)];
    panGesture.cancelsTouchesInView = NO;
    panGesture.requiresExclusiveTouchType = NO;
    [g_btn addGestureRecognizer:panGesture];
    
    UITapGestureRecognizer *tripleTap = [[UITapGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handleTripleTap:)];
    tripleTap.numberOfTapsRequired = 2;
    tripleTap.numberOfTouchesRequired = 3;
    tripleTap.cancelsTouchesInView = NO;
    tripleTap.delaysTouchesEnded = NO;
    tripleTap.delaysTouchesBegan = NO;
    tripleTap.requiresExclusiveTouchType = NO;
    [w addGestureRecognizer:tripleTap];
    
    _log(@"[UI] Button created on window (hidden, triple-tap to show)");
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
        
        if (attempt >= 2) {
            // v36.40: After 2 retries, create stub class so UI can display server list
            DLOG(@"[MSI-STUB] Attempt %d >= 2, creating ServerInfoForClient stub class...", attempt);
            createServerInfoForClientStub();
            
            // Verify and hook the newly created stub class
            Class stubCls = NSClassFromString(@"ServerInfoForClient");
            if (stubCls) {
                DLOG(@"[MSI-STUB] Stub class created and verified successfully");
                
                // Log all methods on stub
                unsigned int smcount = 0;
                Method *smethods = class_copyMethodList(stubCls, &smcount);
                for (unsigned int i = 0; i < smcount; i++) {
                    SEL sel = method_getName(smethods[i]);
                    DLOG(@"[MSI-STUB]   Method: %@", NSStringFromSelector(sel));
                }
                if (smethods) free(smethods);
            } else {
                DLOG(@"[MSI-STUB] Failed to verify stub class after creation!");
            }
            return;
        }
        
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

// v36.59: COMPLETE FIX - Correct method signature!
// -[UIViewController presentViewController:animated:completion:] has 3 params after self/_cmd:
//   arg1 = viewControllerToPresent (UIViewController*)
//   arg2 = animated (BOOL)
//   arg3 = completion (dispatch_block_t)
// Previous hook had WRONG parameter order causing SIGSEGV when calling the "completion"
// which was actually a BOOL value (0x0 or 0x1) interpreted as block pointer!
static void (*orig_alertControllerPresent)(id, SEL, id, BOOL, dispatch_block_t);
static void hook_alertControllerPresent(id self, SEL _cmd, id viewControllerToPresent, BOOL animated, dispatch_block_t completion) {
    @try {
        // Check orig function pointer
        if (!orig_alertControllerPresent) {
            DLOG(@"[DIAG-ALERT] orig_alertControllerPresent is NULL, passthrough");
            // Even if orig is NULL we can't proceed - but avoid crash
            return;
        }
        
        // v36.59: Check self (presenting VC)
        if (!self) {
            DLOG(@"[DIAG-ALERT] self (presenting VC) is nil/NULL");
            return;
        }
        
        // v36.59: Check viewControllerToPresent (the one being presented, could be UIAlertController)
        if (!viewControllerToPresent) {
            DLOG(@"[DIAG-ALERT] viewControllerToPresent is nil/NULL");
            return;
        }
        
        // Check if the presented VC is UIAlertController - that's what we want to intercept
        BOOL isAlert = NO;
        @try {
            if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
                isAlert = YES;
                UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
                NSString *title = [alert title];
                NSString *msg = [alert message];
                DLOG(@"[DIAG-ALERT] UIAlertController present: title='%@' msg='%@' presentingVC=%@", 
                     title ? title : @"<nil>", msg ? msg : @"<nil>", 
                     NSStringFromClass([self class]));
                
                // Block version-related alerts
                if (title || msg) {
                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";
                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";
                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 
                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||
                        [lowerMsg containsString:@"update"]) {
                        DLOG(@"[ALERT-BLOCK] Blocked version check UIAlertController: title='%@' msg='%@'", 
                             title ? title : @"", msg ? msg : @"");
                        return;  // Do not present!
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[DIAG-ALERT] Exception checking alert: %@", e.reason);
            isAlert = NO;  // On error, just passthrough
        }
        
        // v36.59: SAFE completion handling with Block_copy to avoid stack-block crash
        dispatch_block_t safeCompletion = NULL;
        if (completion != NULL) {
            // Copy the block to heap in case it's a stack-allocated block
            @try {
                safeCompletion = [completion copy];  // ARC-style or Block_copy equivalent
            } @catch (NSException *e) {
                DLOG(@"[DIAG-ALERT] Exception copying completion block: %@", e.reason);
                safeCompletion = NULL;
            }
        }
        if (!safeCompletion) {
            // Provide a static empty block (heap-allocated by compiler)
            safeCompletion = ^{};
        }
        
        // v36.59: Use __weak self to avoid dangling pointers on async dispatch
        __weak id weakPresentingVC = self;
        __weak id weakPresentedVC = viewControllerToPresent;
        dispatch_block_t copiedCompletion = [safeCompletion copy];
        
        void (*callOrig)(id, SEL, id, BOOL, dispatch_block_t) = orig_alertControllerPresent;
        
        if ([NSThread isMainThread]) {
            @try {
                callOrig(self, _cmd, viewControllerToPresent, animated, copiedCompletion);
            } @catch (NSException *e) {
                DLOG(@"[DIAG-ALERT] Exception calling orig present (main thread): %@", e.reason);
            } @catch (...) {
                DLOG(@"[DIAG-ALERT] Unknown C++/signal exception calling orig present (main thread)");
            }
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    id strongPresenting = weakPresentingVC;
                    id strongPresented = weakPresentedVC;
                    if (strongPresenting && strongPresented) {
                        callOrig(strongPresenting, _cmd, strongPresented, animated, copiedCompletion);
                    } else {
                        DLOG(@"[DIAG-ALERT] Async present aborted: presentingVC or presentedVC deallocated");
                    }
                } @catch (NSException *e) {
                    DLOG(@"[DIAG-ALERT] Exception calling orig present (async main thread): %@", e.reason);
                } @catch (...) {
                    DLOG(@"[DIAG-ALERT] Unknown exception calling orig present (async main thread)");
                }
            });
        }
    } @catch (NSException *e) {
        DLOG(@"[DIAG-ALERT] Exception in alert hook OUTER: %@", e.reason);
    } @catch (...) {
        DLOG(@"[DIAG-ALERT] Unknown C++/foreign exception in alert hook OUTER");
    }
}

// ============================================================
#pragma mark - Gzip utilities
// ============================================================

static BOOL isGzipData(const unsigned char *data, size_t len) {
    return (len >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08);
}

static unsigned char *gzipDecompress(const unsigned char *data, size_t len, size_t *outLen) {
    if (!data || len < 10 || !isGzipData(data, len)) return NULL;
    
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    
    if (inflateInit2(&strm, MAX_WBITS + 16) != Z_OK) return NULL;
    
    strm.next_in = (Bytef *)data;
    strm.avail_in = len;
    
    size_t bufSize = len * 4;
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (!buf) { inflateEnd(&strm); return NULL; }
    
    unsigned char *outBuf = buf;
    size_t totalOut = 0;
    
    do {
        strm.next_out = (Bytef *)buf;
        strm.avail_out = bufSize;
        
        int ret = inflate(&strm, Z_NO_FLUSH);
        
        size_t produced = bufSize - strm.avail_out;
        if (produced > 0) {
            totalOut += produced;
            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);
            if (!newBuf) { free(outBuf); inflateEnd(&strm); return NULL; }
            buf = newBuf + totalOut - produced;
            outBuf = newBuf;
        }
        
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { free(outBuf); inflateEnd(&strm); return NULL; }
        
    } while (strm.avail_in > 0);
    
    inflateEnd(&strm);
    
    unsigned char *finalBuf = (unsigned char *)realloc(outBuf, totalOut + 1);
    if (finalBuf) {
        finalBuf[totalOut] = '\0';
        *outLen = totalOut;
        return finalBuf;
    }
    
    free(outBuf);
    return NULL;
}

static unsigned char *gzipCompress(const unsigned char *data, size_t len, size_t *outLen) {
    if (!data || len == 0) return NULL;
    
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return NULL;
    
    strm.next_in = (Bytef *)data;
    strm.avail_in = len;
    
    size_t bufSize = len + (len / 10) + 12;
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (!buf) { deflateEnd(&strm); return NULL; }
    
    unsigned char *outBuf = buf;
    size_t totalOut = 0;
    
    do {
        strm.next_out = (Bytef *)buf;
        strm.avail_out = bufSize;
        
        int ret = deflate(&strm, Z_FINISH);
        
        size_t produced = bufSize - strm.avail_out;
        if (produced > 0) {
            totalOut += produced;
            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);
            if (!newBuf) { free(outBuf); deflateEnd(&strm); return NULL; }
            buf = newBuf + totalOut - produced;
            outBuf = newBuf;
        }
        
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { free(outBuf); deflateEnd(&strm); return NULL; }
        
    } while (strm.avail_in > 0);
    
    deflateEnd(&strm);
    
    *outLen = totalOut;
    return outBuf;
}

// ============================================================
#pragma mark - BSD socket hooks (detect game network traffic)
// ============================================================

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/time.h>
#include <fcntl.h>

// === Socket hook functions ===
typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
typedef ssize_t (*ReadFunc)(int, void *, size_t);
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);
typedef int (*CloseFunc)(int);
typedef int (*GetsockoptFunc)(int, int, int, void *, socklen_t *);
typedef int (*PollFunc)(struct pollfd *, nfds_t, int);
typedef int (*SelectFunc)(int, fd_set *, fd_set *, fd_set *, struct timeval *);

static ConnectFunc orig_connect = NULL;
static SendFunc orig_send = NULL;
static RecvFunc orig_recv = NULL;
static RecvfromFunc orig_recvfrom = NULL;
static RecvmsgFunc orig_recvmsg = NULL;
static WriteFunc orig_write = NULL;
static ReadFunc orig_read = NULL;
static CloseFunc orig_close = NULL;
static GetsockoptFunc orig_getsockopt = NULL;
static PollFunc orig_poll = NULL;
static SelectFunc orig_select = NULL;

#define MAX_TRACKED_FDS 64
static int g_trackedFds[MAX_TRACKED_FDS];
static char g_trackedHosts[MAX_TRACKED_FDS][64];
static int g_trackedPorts[MAX_TRACKED_FDS];
static int g_trackedCount = 0;
static BOOL g_trackedActive[MAX_TRACKED_FDS];

// Note: g_gameServerPort, g_gameServerIP, g_gameServerInfoUpdated defined earlier for stub class access

static void clearTrackedFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            DLOG(@"[FD-CLOSE] fd=%d %s:%d removed from tracking", fd, g_trackedHosts[i], g_trackedPorts[i]);
            g_trackedActive[i] = NO;
            g_trackedFds[i] = -1;
            g_trackedHosts[i][0] = '\0';
            g_trackedPorts[i] = 0;
            return;
        }
    }
}

static void trackFd(int fd, const char *host, int port) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            DLOG(@"[FD-UPDATE] fd=%d updated from %s:%d to %s:%d", fd, 
                 g_trackedHosts[i], g_trackedPorts[i], host, port);
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            g_trackedActive[i] = YES;
            return;
        }
    }
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == -1) {
            g_trackedFds[i] = fd;
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            g_trackedActive[i] = YES;
            DLOG(@"[FD-REUSE] fd=%d %s:%d reused slot %d", fd, host, port, i);
            return;
        }
    }
    if (g_trackedCount >= MAX_TRACKED_FDS) {
        DLOG(@"[FD-ERROR] Max tracked fds reached (%d)", MAX_TRACKED_FDS);
        return;
    }
    g_trackedFds[g_trackedCount] = fd;
    strncpy(g_trackedHosts[g_trackedCount], host, 63);
    g_trackedPorts[g_trackedCount] = port;
    g_trackedActive[g_trackedCount] = YES;
    g_trackedCount++;
}

static const char *getHostForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedHosts[i];
    }
    return NULL;
}

static int getPortForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedPorts[i];
    }
    return 0;
}

// v36.87: Inject UUID into 0x000EE007 device info packet for game server
// Login server (5678) sends 143-byte packet without UUID field
// Game server expects 179-byte packet with 36-byte UUID TLV (len=0x0024 + 36 char UUID)
// UUID field is inserted after first field (account/ticket: 0x0014 + 20 bytes) at offset 12+2+20 = 34
static ssize_t injectUUIDIntoDeviceInfo(const uint8_t *src, size_t srcLen,
                                         uint8_t *dst, size_t dstMaxLen) {
    if (!src || srcLen < 36 || !dst || dstMaxLen < srcLen + 40) {
        DLOG(@"[UUID-INJECT] Invalid params: srcLen=%zu dstMaxLen=%zu", srcLen, dstMaxLen);
        return -1;
    }
    
    // Generate a consistent fake UUID using NSUserDefaults or derive from UDID/IDFV
    // Use a hardcoded UUID for reproducibility across sessions (server may bind UUID)
    const char *fakeUUID = "00000000-0000-0000-0000-000000000001";
    // Prefer device's IDFV if available
    @try {
        UIDevice *device = [UIDevice currentDevice];
        if (device && [device respondsToSelector:@selector(identifierForVendor)]) {
            NSUUID *idfv = [device identifierForVendor];
            if (idfv) {
                NSString *uuidStr = [idfv UUIDString];
                if (uuidStr && uuidStr.length == 36) {
                    fakeUUID = uuidStr.UTF8String;
                }
            }
        }
    } @catch (NSException *e) {}
    
    size_t uuidStrLen = strlen(fakeUUID);
    
    // Find insertion point: header(12) + first TLV (2-byte len + N bytes)
    // First field starts at offset 12 with 2-byte length prefix
    if (srcLen < 14) return -1;
    uint16_t firstFieldLen = ((uint16_t)src[12] << 8) | (uint16_t)src[13];
    if (firstFieldLen > 200 || 14 + firstFieldLen > srcLen) {
        DLOG(@"[UUID-INJECT] First field invalid: len=%u srcLen=%zu", firstFieldLen, srcLen);
        return -1;
    }
    
    size_t insertOffset = 12 + 2 + firstFieldLen;  // after header + first TLV
    DLOG(@"[UUID-INJECT] Inserting UUID at offset %zu (firstFieldLen=%u, srcLen=%zu)",
         insertOffset, firstFieldLen, srcLen);
    
    // Build new packet
    size_t newPayloadSize = srcLen + 2 + uuidStrLen;  // +2 for TLV length prefix
    if (newPayloadSize > dstMaxLen) {
        DLOG(@"[UUID-INJECT] Output too large: need %zu max %zu", newPayloadSize, dstMaxLen);
        return -1;
    }
    
    // Copy bytes before insertion point
    memcpy(dst, src, insertOffset);
    
    // Insert UUID TLV: length (2 bytes, big-endian) + UUID string
    dst[insertOffset] = (uuidStrLen >> 8) & 0xFF;
    dst[insertOffset + 1] = uuidStrLen & 0xFF;
    memcpy(dst + insertOffset + 2, fakeUUID, uuidStrLen);
    
    // Copy remaining bytes after insertion point
    size_t remaining = srcLen - insertOffset;
    memcpy(dst + insertOffset + 2 + uuidStrLen, src + insertOffset, remaining);
    
    // Update total packet length in header (bytes 0-3, big-endian)
    uint32_t newTotalLen = (uint32_t)newPayloadSize;
    dst[0] = (newTotalLen >> 24) & 0xFF;
    dst[1] = (newTotalLen >> 16) & 0xFF;
    dst[2] = (newTotalLen >> 8) & 0xFF;
    dst[3] = newTotalLen & 0xFF;
    
    DLOG(@"[UUID-INJECT] SUCCESS: %zu -> %u bytes (added UUID=%.*s)",
         srcLen, newTotalLen, 8, fakeUUID);
    
    return (ssize_t)newTotalLen;
}

// v36.71: Check if a command is from game server protocol (not login server)
// Game server cmd ranges:
//   0x00FFxxxx / 0x80FFxxxx - Handshake/challenge/response
//   0x000Exxxx / 0x800Exxxx - Device info related
//   0x00EExxxx / 0x80EExxxx - Extended device info responses
// Login server uses 0x802Exxxx range
static BOOL isGameCmd(uint32_t cmd) {
    uint32_t prefix = cmd & 0xFFFF0000;
    // Game server: 0x00FFxxxx, 0x80FFxxxx, 0x000Exxxx, 0x800Exxxx, 0x00EExxxx, 0x80EExxxx
    if (prefix == 0x00FF0000 || prefix == 0x80FF0000 ||
        prefix == 0x000E0000 || prefix == 0x800E0000 ||
        prefix == 0x00EE0000 || prefix == 0x80EE0000) {
        return YES;
    }
    return NO;
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

static void parseServerListResponse(const unsigned char *data, ssize_t len) {
    if (!data || len < 12) return;
    
    @try {
        NSString *bodyStr = [[NSString alloc] initWithBytes:data+12 length:(NSUInteger)(len-12) encoding:NSUTF8StringEncoding];
        if (bodyStr && bodyStr.length > 0) {
            DLOG(@"[SERVERLIST-PARSE] Response body length: %lu", (unsigned long)bodyStr.length);
            
            NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:@"\"ip\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
            NSArray *ipMatches = [ipRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            NSMutableArray *ips = [NSMutableArray array];
            for (NSTextCheckingResult *match in ipMatches) {
                NSString *ipStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                [ips addObject:ipStr];
                DLOG(@"[SERVERLIST-PARSE] Found IP: %@", ipStr);
            }
            
            NSRegularExpression *portRegex = [NSRegularExpression regularExpressionWithPattern:@"\"port\"\\s*:\\s*(\\d+)" options:0 error:nil];
            NSArray *portMatches = [portRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            NSMutableArray *ports = [NSMutableArray array];
            for (NSTextCheckingResult *match in portMatches) {
                NSString *portStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                int portInt = [portStr intValue];
                [ports addObject:portStr];
                DLOG(@"[SERVERLIST-PARSE] Found port: %@ (int=%d)", portStr, portInt);
            }
            
            if (ips.count > 0 && ports.count > 0) {
                // v36.57: Store servers in list for rotation
                g_serverCount = 0;
                for (NSUInteger i = 0; i < MIN(ips.count, ports.count) && g_serverCount < MAX_SERVERS; i++) {
                    int portInt = [ports[i] intValue];
                    if (portInt > 0 && portInt < 65536) {
                        NSString *ipStr = ips[i];
                        DLOG(@"[SERVERLIST-PARSE] Server %d: %@:%d", g_serverCount, ipStr, portInt);
                        
                        // Store in server list for rotation
                        strncpy(g_serverList[g_serverCount].ip, [ipStr UTF8String], 63);
                        g_serverList[g_serverCount].port = portInt;
                        g_serverCount++;
                        
                        // Set first valid server as default
                        if (g_serverCount == 1) {
                            strncpy(g_gameServerIP, [ipStr UTF8String], 63);
                            g_gameServerPort = portInt;
                            g_currentServerIndex = 0;
                            DLOG(@"[SERVERLIST-PARSE] Set default game server: %s:%d", g_gameServerIP, g_gameServerPort);
                        }
                    }
                }
                DLOG(@"[SERVERLIST-PARSE] Stored %d servers for rotation", g_serverCount);
            }
        } else {
            DLOG(@"[SERVERLIST-PARSE] Binary/mixed response, parsing...");
            DLOG(@"[SERVERLIST-PARSE] First 64 bytes hex:");
            for (int i = 0; i < MIN(64, len-12); i++) {
                printf("%02x ", data[12+i]);
                if ((i+1) % 16 == 0) printf("\n");
            }
            printf("\n");
            
            const unsigned char *body = data + 12;
            ssize_t bodyLen = len - 12;
            
            // v36.60: CLEAN REWRITE of binary parsing
            // BUG in v36.59: Raw 4-byte IP scan produced 100% false positives!
            //   e.g. bytes of ASCII strings ("47.100.14.198" encoded) got treated as binary IP
            //   resulting in garbage servers like "16.228.184.128:58764" being stored FIRST,
            //   crowding out the 12 real ASCII IPs that were found but never stored (MAX_SERVERS=20).
            // FIX:
            //   1. DISABLE raw 4-byte IP scan entirely.
            //   2. ONLY use ASCII IP pattern scan (we know it finds real IPs from the log).
            //   3. If we can't find a port near an ASCII IP, DEFAULT TO PORT 12003!
            //      (from previous tests v36.55 we know at least 12003 accepts connections and completes handshake,
            //       whereas 58158 hangs completely)
            
            g_serverCount = 0;
            NSMutableArray *foundServers = [NSMutableArray array];
            const int DEFAULT_GAME_PORT = 58158;  // v36.62: Force default port to 58158
            
            DLOG(@"[SERVERLIST-PARSE] (v36.62) Scanning ONLY for ASCII IP patterns, port FORCED to 58158");
            DLOG(@"[SERVERLIST-PARSE] (v36.62) Binary port parsing DISABLED (was causing 11776 misparse)");
            
            for (ssize_t offset = 0; offset < bodyLen - 7 && g_serverCount < MAX_SERVERS; offset++) {
                if (body[offset] >= '1' && body[offset] <= '9') {
                    char candidate[128];
                    ssize_t i = 0;
                    ssize_t start = offset;
                    while (offset < bodyLen && i < 63 &&
                           ((body[offset] >= '0' && body[offset] <= '9') || body[offset] == '.')) {
                        candidate[i++] = (char)body[offset++];
                    }
                    candidate[i] = '\0';
                    
                    int dots = 0;
                    int octets[4] = {0, 0, 0, 0};
                    int octIdx = 0;
                    int curVal = 0;
                    BOOL validFormat = YES;
                    for (ssize_t j = 0; candidate[j]; j++) {
                        if (candidate[j] == '.') {
                            if (j == 0 || candidate[j+1] == '.' || candidate[j+1] == '\0') { validFormat = NO; break; }
                            dots++;
                            if (curVal > 255) { validFormat = NO; break; }
                            octets[octIdx++] = curVal;
                            curVal = 0;
                        } else if (candidate[j] >= '0' && candidate[j] <= '9') {
                            curVal = curVal * 10 + (candidate[j] - '0');
                            if (curVal > 255) { validFormat = NO; break; }
                        } else {
                            validFormat = NO;
                            break;
                        }
                    }
                    if (octIdx < 3) validFormat = NO;  // need at least 3 dots (i.e. 4 octets)
                    if (validFormat && dots == 3) {
                        octets[3] = curVal;
                        if (octets[3] > 255) validFormat = NO;
                    }
                    if (octets[0] == 0 || octets[0] == 127 || octets[0] >= 224) validFormat = NO;
                    if (octets[3] == 0) validFormat = NO;
                    
                    if (dots == 3 && validFormat && i > 6) {
                        DLOG(@"[SERVERLIST-PARSE] Valid ASCII IP at %zd: '%s' (octets=%d.%d.%d.%d)",
                             start, candidate, octets[0], octets[1], octets[2], octets[3]);
                        
                        int assignedPort = DEFAULT_GAME_PORT;
                        BOOL portFound = NO;
                        
                        // Try to find ASCII port first - pattern after IP: "port":12003 or :12003
                        // Search up to 60 bytes after IP for the first : followed by digits
                        ssize_t maxSearch = (offset + 100 < bodyLen) ? (offset + 100) : bodyLen;
                        for (ssize_t pOffset = offset; pOffset < maxSearch - 6 && !portFound; pOffset++) {
                            // Try ASCII: :<number>
                            if (body[pOffset] == ':' && (body[pOffset+1] >= '1' && body[pOffset+1] <= '9')) {
                                ssize_t k = pOffset + 1;
                                int p = 0;
                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {
                                    p = p * 10 + (body[k] - '0');
                                    k++;
                                }
                                if (p >= 1024 && p < 65536) {
                                    assignedPort = p;
                                    portFound = YES;
                                    DLOG(@"[SERVERLIST-PARSE]   -> Found ASCII port %d at offset %zd", assignedPort, pOffset);
                                }
                            }
                            
                            // Also check for "port":<digits> pattern
                            if (pOffset + 7 < maxSearch &&
                                body[pOffset]=='p' && body[pOffset+1]=='o' && body[pOffset+2]=='r' &&
                                body[pOffset+3]=='t' && body[pOffset+5]=='\"' &&
                                body[pOffset+6] >= '1' && body[pOffset+6] <= '9') {
                                ssize_t k = pOffset + 6;
                                int p = 0;
                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {
                                    p = p * 10 + (body[k] - '0');
                                    k++;
                                }
                                if (p >= 1024 && p < 65536) {
                                    assignedPort = p;
                                    portFound = YES;
                                    DLOG(@"[SERVERLIST-PARSE]   -> Found port via \"port\" keyword: %d at offset %zd",
                                         assignedPort, pOffset);
                                }
                            }
                            
                        // v36.62: DISABLE binary port parsing - it was causing 11776 misparse
                        // (0x2E00 is the low byte of 0xE32E = 58158, not a real port)
                        // Always use DEFAULT_GAME_PORT (58158) instead of trying to parse binary ports
                        assignedPort = DEFAULT_GAME_PORT;
                        portFound = YES;  // Mark as found (using default)
                        DLOG(@"[SERVERLIST-PARSE]   -> Port forced to %d (binary parsing disabled to prevent 11776 misparse)", assignedPort);
                        }
                        
                        if (!portFound) {
                            DLOG(@"[SERVERLIST-PARSE]   -> No port found, using DEFAULT port %d",
                                 DEFAULT_GAME_PORT);
                        }
                        
                        // De-dupe and store
                        NSString *key = [NSString stringWithFormat:@"%s:%d", candidate, assignedPort];
                        BOOL duplicate = NO;
                        for (NSString *s in foundServers) {
                            if ([s isEqualToString:key]) { duplicate = YES; break; }
                        }
                        if (!duplicate && g_serverCount < MAX_SERVERS) {
                            [foundServers addObject:key];
                            strncpy(g_serverList[g_serverCount].ip, candidate, 63);
                            g_serverList[g_serverCount].port = assignedPort;
                            DLOG(@"[SERVERLIST-PARSE] STORED server %d: %s:%d (portSource=%@)",
                                 g_serverCount,
                                 g_serverList[g_serverCount].ip,
                                 g_serverList[g_serverCount].port,
                                 portFound ? @"detected" : @"DEFAULT");
                            
                            if (g_serverCount == 0) {
                                strncpy(g_gameServerIP, candidate, 63);
                                g_gameServerPort = assignedPort;
                                g_currentServerIndex = 0;
                                DLOG(@"[SERVERLIST-PARSE] Set DEFAULT game server: %s:%d",
                                     g_gameServerIP, g_gameServerPort);
                            }
                            g_serverCount++;
                        }
                    }
                }
            }
            
            if (g_serverCount > 0) {
                DLOG(@"[SERVERLIST-PARSE] Final: Stored %d servers for rotation", g_serverCount);
                for (int i = 0; i < g_serverCount; i++) {
                    DLOG(@"[SERVERLIST-PARSE]   [%d] %s:%d",
                         i, g_serverList[i].ip, g_serverList[i].port);
                }
            } else {
                DLOG(@"[SERVERLIST-PARSE] No servers found! (Game may still use its own internal parsing)");
                // v36.60: If even ASCII scan fails, at least populate with known-working defaults
                // so that the rotation mechanism has something to try (in case we're called for fallback)
                const char *defaultIP = "47.100.14.198";
                if (strlen(g_gameServerIP) < 7) {
                    strncpy(g_gameServerIP, defaultIP, 63);
                }
                if (g_gameServerPort < 1024) {
                    g_gameServerPort = DEFAULT_GAME_PORT;
                }
                strncpy(g_serverList[0].ip, g_gameServerIP, 63);
                g_serverList[0].port = g_gameServerPort;
                g_serverCount = 1;
                g_currentServerIndex = 0;
                DLOG(@"[SERVERLIST-PARSE] Populated fallback server %s:%d as last resort",
                     g_gameServerIP, g_gameServerPort);
            }
        }
    } @catch (NSException *e) {
        DLOG(@"[SERVERLIST-PARSE] Exception: %@", e.reason);
    }
}

// v36.62: Function to try next server in rotation (IP rotation, port always 58158)
static BOOL tryNextServer(void) {
    if (g_serverCount <= 1) {
        DLOG(@"[SERVER-ROTATE] Only %d server(s) available, cannot rotate", g_serverCount);
        return NO;
    }
    
    g_connectionFailCount++;
    g_currentServerIndex = (g_currentServerIndex + 1) % g_serverCount;
    
    // v36.63: Override port to 12003 (the only confirmed working port)
    strncpy(g_gameServerIP, g_serverList[g_currentServerIndex].ip, 63);
    g_gameServerPort = 12003;  // Always use 12003, the only confirmed working port
    
    DLOG(@"[SERVER-ROTATE] Switching to server %d/%d: %s:12003 (forced port, parsed was %d, fail count=%d)", 
         g_currentServerIndex + 1, g_serverCount, g_gameServerIP, g_serverList[g_currentServerIndex].port, g_connectionFailCount);
    
    // v36.98: Reset fake response state for new connection
    // This ensures the new connection can trigger fake response injection again
    g_fakeRespInjected = NO;
    g_fakeRespActive = NO;
    g_fakeRespDelivered = NO;
    g_fakeRespFd = -1;
    g_fakeRespSentCount = 0;
    g_lastRespCmd = 0;
    g_respCount = 0;
    resetCmdQueue();  // v36.106: Reset command queue for new connection
    g_loginPacketsSent = NO;
    g_handshakeComplete = NO;
    g_heartbeatCount = 0;
    g_lastGameCmd = 0;  // v36.107: Reset last game command
    g_lastSeqNum = 0;  // v36.107: Reset last sequence number
    g_lastGameCmdFd = -1;
    DLOG(@"[SERVER-ROTATE] v36.101: Reset fake response state for new connection");
    
    // Update stub data
    if (g_msiStubData) {
        [g_msiStubData setObject:[NSString stringWithUTF8String:g_gameServerIP] forKey:@"ip"];
        [g_msiStubData setObject:@(12003) forKey:@"port"];  // Force 12003 in stub too
    }
    
    return YES;
}

// v36.97: Hook getsockopt to prevent heartbeat from detecting dead connection
// When fake response fd is used, SO_ERROR should return 0 (no error)
static int hook_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");
    
    // If this is the fake response fd and checking SO_ERROR, return 0
    if (g_fakeRespInjected && g_fakeRespFd == fd && level == SOL_SOCKET && optname == SO_ERROR) {
        if (optval && optlen && *optlen >= sizeof(int)) {
            *(int *)optval = 0;  // No error
            *optlen = sizeof(int);
            DLOG(@"[FAKE-SOCKOPT] v36.97: Returning SO_ERROR=0 for fake resp fd=%d", fd);
            return 0;
        }
    }
    
    return orig_getsockopt ? orig_getsockopt(fd, level, optname, optval, optlen) : -1;
}

// v36.104: Hook poll() to prevent heartbeat from detecting dead connection
// When server closes connection, poll() returns POLLHUP/POLLERR
// We clear these flags for the fake response fd to pretend connection is alive
static int hook_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");
    if (!orig_poll || !fds) return -1;
    
    int result = orig_poll(fds, nfds, timeout);
    
    // v36.104: If fake response fd is in the poll set, clear error flags
    if (g_fakeRespInjected && g_fakeRespFd >= 0 && result > 0) {
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].fd == g_fakeRespFd) {
                // Clear POLLHUP and POLLERR flags - pretend connection is alive
                if (fds[i].revents & (POLLHUP | POLLERR)) {
                    DLOG(@"[FAKE-POLL] v36.104: Clearing POLLHUP/POLLERR for fake resp fd=%d (was 0x%x)", 
                         fds[i].fd, fds[i].revents);
                    fds[i].revents &= ~(POLLHUP | POLLERR);
                    // If only error flags were set, set POLLIN instead so recv can return EAGAIN
                    if (fds[i].revents == 0) {
                        fds[i].revents = 0;  // No events - connection appears idle
                        result = 0;  // No events ready
                    }
                }
                // Clear POLLIN for fake response fd if response already delivered
                if (g_fakeRespDelivered) {
                    fds[i].revents &= ~POLLIN;
                }
            }
        }
        // Recalculate result
        result = 0;
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].revents != 0) result++;
        }
    }
    
    return result;
}

// v36.104: Hook select() to prevent heartbeat from detecting dead connection
static int hook_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");
    if (!orig_select) return -1;
    
    int result = orig_select(nfds, readfds, writefds, exceptfds, timeout);
    
    // v36.104: If fake response fd is in the except set, clear it
    if (g_fakeRespInjected && g_fakeRespFd >= 0 && result >= 0) {
        if (exceptfds && FD_ISSET(g_fakeRespFd, exceptfds)) {
            DLOG(@"[FAKE-SELECT] v36.104: Clearing exception for fake resp fd=%d", g_fakeRespFd);
            FD_CLR(g_fakeRespFd, exceptfds);
            // Recalculate result
            result = 0;
            if (readfds) {
                for (int i = 0; i < nfds; i++) {
                    if (FD_ISSET(i, readfds)) result++;
                }
            }
            if (writefds) {
                for (int i = 0; i < nfds; i++) {
                    if (FD_ISSET(i, writefds)) result++;
                }
            }
        }
        // Also clear readfds for fake response fd if response already delivered
        if (readfds && g_fakeRespDelivered && FD_ISSET(g_fakeRespFd, readfds)) {
            FD_CLR(g_fakeRespFd, readfds);
        }
    }
    
    return result;
}

static int hook_close(int fd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    // v36.97: Also block close for fake response fd
    if (g_fakeRespInjected && g_fakeRespFd == fd) {
        DLOG(@"[FAKE-CLOSE] v36.103: Blocking close(%d) for fake response fd", fd);
        // v36.103: Use this opportunity to find and patch C++ disconnect functions
        // The backtrace from close() should include quitFromServer and heartbeat
        findAndPatchDisconnectFunctions();
        return 0;
    }
    
    // v36.93: Track game server port closures and BLOCK them during login flow
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) {
            int port = g_trackedPorts[i];
            BOOL isGamePort = (port == 58158 || port == 12003 || 
                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            if (isGamePort) {
                DLOG(@"[CLOSE-BLOCK] v36.93 BLOCKING close(%d) for game server %s:%d (port=%d)", fd, g_trackedHosts[i], port, port);
                
                // v36.93: Log call stack for debugging
                void *callstack[8];
                int frames = backtrace(callstack, 8);
                char **strs = backtrace_symbols(callstack, frames);
                if (strs) {
                    for (int j = 1; j < frames && j < 8; j++) {
                        DLOG(@"[CLOSE-BT] %d: %s", j, strs[j] ? strs[j] : "?");
                    }
                    free(strs);
                }
                
                // v36.93: BLOCK close() for game server fd during login handshake
                // This prevents quitFromServer() from disconnecting the game server
                // while client is still sending login packets (0x000EE007, 0x00FFF493)
                // Return 0 (success) to trick the client into thinking close succeeded
                DLOG(@"[CLOSE-BLOCK] v36.93: Returning 0 (blocked) to prevent game server disconnect");
                return 0;  // Block the close, return success
            }
        }
    }
    
    clearTrackedFd(fd);
    return orig_close ? orig_close(fd) : -1;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    char host[64] = "unknown";
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        port = ntohs(in->sin_port);
        
        // v36.63: REVERT to port 12003 (the only port confirmed to connect and complete handshake)
        // Port 58158 is unreachable - ALL tests since v36.51 showed timeout/hang
        // If game uses non-standard port (like 11776), rewrite to 12003
        BOOL isGameServerPort = (port == 12003 || port == 58158 || 
                                 (port >= 10000 && port <= 65535 && port != 5678));
        BOOL needPortRewrite = (port != 5678 && port != 12003);  // Rewrite any non-login, non-12003 port to 12003
        
        int origPort = port;
        char origHost[64];
        strncpy(origHost, host, 63);
        origHost[63] = '\0';
        
        struct sockaddr_in newAddr = *in;
        
        if (needPortRewrite && isGameServerPort) {
            // v36.63: Force rewrite non-standard game ports (like 11776) to 12003
            newAddr.sin_port = htons(12003);
            port = 12003;
            DLOG(@"[REWRITE-PORT] FORCE game server %s:%d -> %s:12003 (only confirmed working port)", 
                 origHost, origPort, origHost);
        }
        
        // v36.63: Track fd BEFORE connect with target port
        trackFd(sockfd, host, port);
        
        DLOG(@"[SOCK] connect START fd=%d target=%s:%d origPort=%d rewrite=%d isGamePort=%d",
             sockfd, host, port, origPort, needPortRewrite ? 1 : 0, isGameServerPort ? 1 : 0);
        
        if (!orig_connect) {
            DLOG(@"[SOCK] FATAL: orig_connect is NULL! dlsym failed.");
            errno = EACCES;
            return -1;
        }
        
        // v36.63: Set SO_SNDTIMEO 10s timeout as safety net for blocking connect
        // Prevents hanging forever on unreachable ports
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        // v36.63: SIMPLE blocking connect with timeout protection
        const struct sockaddr *actualAddr = needPortRewrite ? (struct sockaddr *)&newAddr : addr;
        socklen_t actualAddrLen = needPortRewrite ? sizeof(newAddr) : addrlen;
        
        struct timeval startTV;
        gettimeofday(&startTV, NULL);
        
        int result = orig_connect(sockfd, actualAddr, actualAddrLen);
        int connectErrno = errno;
        
        // v36.63: Clear the timeout after connect
        struct timeval tvZero;
        tvZero.tv_sec = 0;
        tvZero.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tvZero, sizeof(tvZero));
        
        struct timeval endTV;
        gettimeofday(&endTV, NULL);
        double elapsed = (endTV.tv_sec - startTV.tv_sec) + (endTV.tv_usec - startTV.tv_usec) / 1000000.0;
        
        if (result == 0) {
            // v36.63: Track game server connection state
            if (isGameServerPort) {
                g_gameServerConnected = YES;
                g_gameServerFd = sockfd;
                g_gameConnectTime = [[NSDate date] timeIntervalSince1970];
                DLOG(@"[GAME-CONNECT] Game server connected fd=%d target=%s:%d (confirmed working port)", 
                     sockfd, host, port);
                
                // v36.98: Reset fake response state on new game server connection
                // This ensures the new connection can trigger fake response injection
                if (g_fakeRespInjected || g_fakeRespActive) {
                    DLOG(@"[GAME-CONNECT] v36.101: Resetting fake response state on new connection (old fd=%d, new fd=%d)", g_fakeRespFd, sockfd);
                    g_fakeRespInjected = NO;
                    g_fakeRespActive = NO;
                    g_fakeRespDelivered = NO;  // v36.101: Reset delivered flag
                    g_fakeRespFd = -1;
                    g_fakeRespSentCount = 0;
                    g_loginPacketsSent = NO;
                    g_handshakeComplete = NO;
                    g_heartbeatCount = 0;
                    g_lastGameCmd = 0;
                    g_lastSeqNum = 0;  // v36.107: Reset sequence number on new connect
                    g_lastGameCmdFd = -1;
                }
            }
            DLOG(@"[SOCK] connect END fd=%d SUCCESS target=%s:%d origPort=%d elapsed=%.3fs",
                 sockfd, host, port, origPort, elapsed);
        } else {
            DLOG(@"[SOCK] connect END fd=%d FAILED target=%s:%d origPort=%d errno=%d(%s) elapsed=%.3fs",
                 sockfd, host, port, origPort, connectErrno, strerror(connectErrno), elapsed);
            
            // v36.63: Game server failed: try IP rotation (port stays 12003)
            if (isGameServerPort) {
                DLOG(@"[SOCK] Game server %s:%d FAILED -> attempting IP rotation...", host, port);
                @try {
                    BOOL rotated = tryNextServer();
                    if (rotated) {
                        DLOG(@"[SOCK] Rotation succeeded: %s:12003 (index %d/%d)",
                             g_gameServerIP, g_currentServerIndex + 1, g_serverCount);
                    } else {
                        DLOG(@"[SOCK] Rotation unavailable (servers=%d)", g_serverCount);
                    }
                } @catch (NSException *e) {
                    DLOG(@"[SOCK] Exception during rotation: %@", e.reason);
                }
            }
        }
        
        errno = connectErrno;
        return result;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
        trackFd(sockfd, host, port);
        DLOG(@"[SOCK] connect6 START fd=%d [%s]:%d", sockfd, host, port);
        
        int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
        DLOG(@"[SOCK] connect6 END fd=%d [%s]:%d result=%d errno=%d(%s)", sockfd, host, port, result, errno, strerror(errno));
        return result;
    }
    
    int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
    return result;
}

static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    
    // v36.108: If this is the fake response fd, pretend send succeeds
    // This prevents heartbeat from detecting the dead connection via send()
    // v36.108: Only reset delivered flag when client sends a NEW command (not heartbeat)
    if (g_fakeRespInjected && g_fakeRespFd == fd) {
        // Check if this is a new command (not heartbeat)
        BOOL isNewCmd = NO;
        if (len >= 12) {
            const unsigned char *p = (const unsigned char *)buf;
            uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            // Only reset for game commands, not heartbeat
            if (cmd != 0x00000015 && cmd < 0x80000000) {
                isNewCmd = YES;
                DLOG(@"[FAKE-SEND] v36.108: New cmd=0x%08X detected, resetting delivered flag", cmd);
            }
        }
        if (isNewCmd) {
            g_fakeRespDelivered = NO;
        } else {
            DLOG(@"[FAKE-SEND] v36.108: Simulating send success for fd=%d len=%zu (heartbeat/ack, keep delivered)", fd, len);
        }
        return (ssize_t)len;
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    void *sendBuf = (void *)buf;
    size_t sendLen = len;
    
    if (len >= 12) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        // v36.61: Use dynamic game port detection (12003, 58158, or parsed port)
        BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 
                                  (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
        if (isGameOrLoginPort) {
            const char *serverType;
            if (port == 5678) serverType = "LOGIN";
            else if (port == 58158) serverType = "GAME-58158";
            else if (port == 12003) serverType = "GAME-12003";
            else serverType = "GAME-DYNAMIC";
            DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu [%s port=%d]", fd, cmd, len, serverType, port);
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
        
        // v36.75: Log game server initial connection packets (before handshake)
        // These are packets sent right after connecting to game server
        BOOL isGamePort = (port == 12003 || port == 58158 ||
                          (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
        if (isGamePort && !g_handshakeComplete && len > 0 && len < 12) {
            DLOG(@"[GAME-INIT] Small packet to game server: len=%zu hex=%@ (may be handshake init)", len, hex);
        }
    }
    
    // Analyze device info packets (0x000EE007) - on login server (5678), game server (all ports)
    BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 
                              (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
    if (len >= 12 && isGameOrLoginPort) {
        const unsigned char *dp = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)dp[4] << 24) | ((uint32_t)dp[5] << 16) |
                       ((uint32_t)dp[6] << 8)  | (uint32_t)dp[7];
        if (cmd == 0x000EE007) {
            @try {
                // v36.61: Detailed device info packet logging
                DLOG(@"[DEVICE-INFO] ===== DEVICE INFO PACKET (0x000EE007) =====");
                DLOG(@"[DEVICE-INFO] len=%zu port=%d fd=%d gameConnected=%d", len, port, fd, g_gameServerConnected ? 1 : 0);
                
                // Hex dump - full packet
                NSMutableString *hex = [NSMutableString string];
                for (size_t i = 0; i < len && i < 128; i++) {
                    [hex appendFormat:@"%02X ", dp[i]];
                }
                if (len > 128) [hex appendFormat:@"...(truncated)"];
                DLOG(@"[DEVICE-INFO] HEX: %@", hex);
                
                // Parse header
                if (len >= 16) {
                    uint32_t pktLen = ((uint32_t)dp[0]<<24)|((uint32_t)dp[1]<<16)|((uint32_t)dp[2]<<8)|dp[3];
                    uint32_t pktCmd = ((uint32_t)dp[4]<<24)|((uint32_t)dp[5]<<16)|((uint32_t)dp[6]<<8)|dp[7];
                    uint8_t status = dp[12];
                    DLOG(@"[DEVICE-INFO] pktLen=%u cmd=0x%08X status=%u", pktLen, pktCmd, status);
                }
                
                // ASCII decode payload
                if (len > 12) {
                    NSString *payload = [[NSString alloc] initWithBytes:dp+12 length:MIN(len-12, 100) encoding:NSUTF8StringEncoding];
                    if (payload) {
                        DLOG(@"[DEVICE-INFO] payload (offset 12): '%@'", payload);
                    }
                }
                
                DLOG(@"[DEVICE-INFO] ===== END DEVICE INFO =====");
                
                // v36.66: Capture 0x000EE007 packet for forced send to game server
                if (len > 0 && len <= MAX_DEVICE_INFO_SIZE) {
                    memcpy(g_deviceInfoPacket, buf, len);
                    g_deviceInfoPacketLen = len;
                    g_deviceInfoCaptured = YES;
                    g_deviceInfoSentToGame = NO;  // Reset flag for new capture
                    g_deviceInfoEnhancedReady = NO;
                    DLOG(@"[DEVICE-INFO] CAPTURED %zd bytes for forced game server send", len);
                    
                    // v36.87: Immediately create enhanced version with UUID injected
                    // Login server (5678) sends 143-byte without UUID
                    // Game server (12003/58158) expects 179-byte with UUID
                    ssize_t enhancedLen = injectUUIDIntoDeviceInfo(
                        (const uint8_t *)buf, len,
                        g_deviceInfoEnhanced, MAX_DEVICE_INFO_SIZE
                    );
                    if (enhancedLen > 0) {
                        g_deviceInfoEnhancedLen = enhancedLen;
                        g_deviceInfoEnhancedReady = YES;
                        DLOG(@"[DEVICE-INFO] ENHANCED ready: %zd bytes (UUID injected)", enhancedLen);
                    } else {
                        // Fallback: use original if injection fails
                        DLOG(@"[DEVICE-INFO] ENHANCED FAILED, will use original %zd bytes", len);
                    }
                }
            } @catch (NSException *e) {
                // Silently ignore any errors in packet analysis
                DLOG(@"[DEVICE-INFO] Analysis skipped due to exception: %@", e.reason);
            }
        }
        
        // v36.85: Only block heartbeats during initial handshake (BEFORE challenge response)
        // After challenge response (g_challengeResponded=YES), let heartbeats go to server
        // so we can intercept the server's heartbeat ACK and replace it with 0x80FFF495
        if (isGameOrLoginPort && (cmd == 0x00000015 || cmd == 0x00000014)) {
            BOOL isGamePortOnly = (port == 12003 || port == 58158 ||
                                   (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            BOOL isGameCmdOnly = isGameCmd(cmd);
            
            // v36.85: Only block heartbeats BEFORE challenge response (NOT after)
            if ((isGamePortOnly || isGameCmdOnly) && !g_handshakeComplete && !g_challengeResponded) {
                @try {
                    uint8_t ackBuf[22];
                    memcpy(ackBuf, buf, 22);
                    ackBuf[4] = 0x80;  // Change command from 0x00000015 to 0x80000015
                    
                    if (g_localHeartbeatAckLen == 0 || g_localHeartbeatAckFd != fd) {
                        g_localHeartbeatAckLen = 22;
                        g_localHeartbeatAckFd = fd;
                        memcpy(g_localHeartbeatAckBuf, ackBuf, 22);
                        DLOG(@"[HEARTBEAT-BLOCK] Blocked heartbeat during handshake (cmd=0x%08X) to port=%d", cmd, port);
                    }
                } @catch (NSException *e) {
                    DLOG(@"[HEARTBEAT-BLOCK] Exception: %@", e.reason);
                }
                return len;
            }
        }
        
        // v36.74: Track client protocol behavior after handshake completion
        // Monitor what client sends in response to 0x00FFFF02 challenge
        if (g_handshakeComplete && isGameOrLoginPort && len >= 12) {
            @try {
                const unsigned char *tp = (const unsigned char *)buf;
                NSMutableString *protoTrace = [NSMutableString stringWithCapacity:256];
                uint32_t trackCmd = ((uint32_t)tp[4] << 24) | ((uint32_t)tp[5] << 16) |
                                   ((uint32_t)tp[6] << 8)  | (uint32_t)tp[7];
                uint32_t trackPktLen = ((uint32_t)tp[0] << 24) | ((uint32_t)tp[1] << 16) |
                                      ((uint32_t)tp[2] << 8)  | (uint32_t)tp[3];
                
                [protoTrace appendFormat:@"[PROTO-TRACE] Client send after handshake: cmd=0x%08X pktLen=%u port=%d\n", trackCmd, trackPktLen, port];
                
                // v36.95: Track login packets to game server for fake response injection
                // 0x000EE007 (device info) and 0x00FFF493 (encrypted login data) are the key login packets
                BOOL isGamePortOnly = (port == 12003 || port == 58158 ||
                                      (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
                if (isGamePortOnly && (trackCmd == 0x000EE007 || trackCmd == 0x00FFF493 || 
                                       trackCmd == 0x80EEE007 || trackCmd == 0x80F493)) {
                    if (!g_loginPacketsSent) {
                        g_loginPacketsSent = YES;
                        DLOG(@"[LOGIN-PACKETS] v36.95: Client sending login packets to game server (cmd=0x%08X port=%d) - FAKE-RESP armed", trackCmd, port);
                    }
                }
                
                // v36.107: Track game server commands in a QUEUE for ordered response with sequence numbers
                if (isGamePortOnly && trackCmd != 0 && trackCmd < 0x80000000) {
                    g_lastGameCmd = trackCmd;
                    g_lastGameCmdFd = fd;
                    // v36.107: Extract sequence number from packet (bytes 8-11)
                    uint32_t trackSeqNum = 0;
                    if (len >= 12) {
                        trackSeqNum = ((uint32_t)tp[8] << 24) | ((uint32_t)tp[9] << 16) |
                                      ((uint32_t)tp[10] << 8)  | (uint32_t)tp[11];
                    }
                    g_lastSeqNum = trackSeqNum;
                    // v36.107: Add to command queue with sequence number
                    enqueueGameCmd(trackCmd, fd, (uint32_t)len, trackSeqNum);
                    DLOG(@"[CMD-TRACK] v36.107: Queued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (queue=%d)", 
                         trackCmd, trackSeqNum, fd, (uint32_t)len, g_cmdQueueCount);
                    // v36.107: Clear delivered flag so next recv can return a response
                    g_fakeRespDelivered = NO;
                }
                
                // Categorize the command
                if (trackCmd == 0x80FFFF02) {
                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF02 - responding to 0x00FFFF02 challenge!\n"];
                } else if (trackCmd == 0x80FFFF01) {
                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF01 - responding to 0x00FFFF01 challenge\n"];
                } else if (trackCmd == 0x000EE007) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending 0x000EE007 device info (plaintext)!\n"];
                } else if (trackCmd == 0x80EEE007 || trackCmd == 0x80EE0007) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted device info!\n"];
                } else if (trackCmd == 0x00F493 || trackCmd == 0x80F493) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted game data\n"];
                } else if (trackCmd == 0x00000015) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending heartbeat (may be stuck)\n"];
                } else if (trackCmd >= 0x80000000) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending server response (cmd=0x%08X)\n", trackCmd];
                } else {
                    [protoTrace appendFormat:@"  [V36.74] Unknown command (cmd=0x%08X) - tracing...\n", trackCmd];
                }
                
                // Hex dump first 32 bytes
                [protoTrace appendFormat:@"  HEX(32): "];
                for (size_t i = 0; i < MIN((size_t)32, len); i++) {
                    [protoTrace appendFormat:@"%02X ", tp[i]];
                }
                [protoTrace appendFormat:@"\n"];
                
                DLOG(@"%@", protoTrace);
            } @catch (NSException *e) {
                DLOG(@"[PROTO-TRACE] Exception: %@", e.reason);
            }
        }
    }
    
    // Analyze 0x0000F013 packet - select server / enter game
    if (len >= 12 && port == 5678) {
        const unsigned char *fp = (const unsigned char *)buf;
        uint32_t fcmd = ((uint32_t)fp[4] << 24) | ((uint32_t)fp[5] << 16) |
                        ((uint32_t)fp[6] << 8)  | (uint32_t)fp[7];
        if (fcmd == 0x0000F013) {
            @try {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[SERVER-SELECT] cmd=0x%08X len=%zu\n", fcmd, len];
                [detail appendFormat:@"  Full hex: "];
                for (size_t i = 0; i < len && i < 128; i++) {
                    [detail appendFormat:@"%02X ", fp[i]];
                }
                if (len > 128) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                
                if (len >= 12) {
                    uint32_t pktLen = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |
                                      ((uint32_t)fp[2] << 8)  | (uint32_t)fp[3];
                    uint32_t field1 = ((uint32_t)fp[8] << 24) | ((uint32_t)fp[9] << 16) |
                                      ((uint32_t)fp[10] << 8) | (uint32_t)fp[11];
                    [detail appendFormat:@"  Header: pktLen=%u field1=0x%08X\n", pktLen, field1];
                }
                
                // Parse TLV-style fields after header
                size_t offset = 12;
                int fieldIdx = 0;
                while (offset + 2 < len && fieldIdx < 10) {
                    uint16_t fieldLen = (fp[offset] << 8) | fp[offset + 1];
                    offset += 2;
                    if (offset + fieldLen > len) break;
                    
                    NSMutableString *fieldHex = [NSMutableString string];
                    for (uint16_t i = 0; i < fieldLen && i < 32; i++) {
                        [fieldHex appendFormat:@"%02X ", fp[offset + i]];
                    }
                    
                    NSString *fieldStr = [[NSString alloc] initWithBytes:fp+offset length:fieldLen encoding:NSUTF8StringEncoding];
                    if (fieldStr && fieldStr.length > 0 && fieldLen < 64) {
                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@] str='%@'\n", fieldIdx, fieldLen, fieldHex, fieldStr];
                    } else {
                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@]\n", fieldIdx, fieldLen, fieldHex];
                    }
                    offset += fieldLen;
                    fieldIdx++;
                }
                
                DLOG(@"%@", detail);
            } @catch (NSException *e) {
                DLOG(@"[SERVER-SELECT] Analysis exception: %@", e.reason);
            }
        }
    }

    // Analyze game server packets (58158 port)
    if (len >= 12 && port == 58158) {
        const unsigned char *gp = (const unsigned char *)buf;
        uint32_t gcmd = ((uint32_t)gp[4] << 24) | ((uint32_t)gp[5] << 16) |
                        ((uint32_t)gp[6] << 8)  | (uint32_t)gp[7];
        
        @try {
            // Log game data packets (0x00FFF493)
            if (gcmd == 0x00FFF493) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[GAME-DATA] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                size_t showLen = len > 64 ? 64 : len;
                for (size_t i = 0; i < showLen; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                if (len > 64) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
            // Log heartbeat packets (0x00000015)
            else if (gcmd == 0x00000015) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:128];
                [detail appendFormat:@"[GAME-HEARTBEAT] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                for (size_t i = 0; i < len; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
            // Log server select packets (0x0000F013) on game server
            else if (gcmd == 0x0000F013) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[GAME-SERVER-SELECT] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                size_t showLen = len > 128 ? 128 : len;
                for (size_t i = 0; i < showLen; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                if (len > 128) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
        } @catch (NSException *e) {
            DLOG(@"[GAME-ANALYZE] Exception: %@", e.reason);
        }
    }

    ssize_t ret = orig_send ? orig_send(fd, sendBuf, sendLen, flags) : -1;
    if (sendBuf != buf) free(sendBuf);
    return ret;
}

// v36.81: Manual Base64 decode function for reliable RSA public key extraction
// Standard Base64 alphabet
static const uint8_t g_base64DecodeTable[256] = {
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,63, // + /
    52,53,54,55,56,57,58,59,60,61,62,62,62,65,62,62, // 0-9 =
    62, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // A-O
    15,16,17,18,19,20,21,22,23,24,25,62,62,62,62,62, // P-Z
    62,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // a-o
    41,42,43,44,45,46,47,48,49,50,51,62,62,62,62,62, // p-z
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62
};

// v36.81: Manual Base64 decode with robust error handling
static int manualBase64Decode(const uint8_t *input, size_t inputLen, 
                               uint8_t *output, size_t outputBufSize, size_t *outputLen) {
    if (!input || !output || !outputLen || inputLen == 0) return -1;
    
    size_t inPos = 0;
    size_t outPos = 0;
    uint8_t group[4];
    int groupIdx = 0;
    
    // Clear output
    memset(output, 0, outputBufSize);
    
    while (inPos < inputLen) {
        uint8_t c = input[inPos];
        inPos++;
        
        // Skip whitespace and newlines
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        
        // Check for padding
        if (c == '=') {
            // Padding should only appear at the end
            if (groupIdx < 2) return -1; // Invalid padding position
            break;
        }
        
        uint8_t val = g_base64DecodeTable[c];
        if (val >= 64) {
            // Invalid character - skip it (could be protocol overhead)
            DLOG(@"[RSA-MANUAL-B64] Skipping invalid char at input pos %zu: 0x%02X", inPos-1, c);
            continue;
        }
        
        group[groupIdx++] = val;
        
        if (groupIdx == 4) {
            // Decode 4 Base64 chars to 3 bytes
            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6) | group[3];
            
            if (outPos + 3 > outputBufSize) return -1; // Output buffer too small
            
            output[outPos++] = (triple >> 16) & 0xFF;
            output[outPos++] = (triple >> 8) & 0xFF;
            output[outPos++] = triple & 0xFF;
            groupIdx = 0;
        }
    }
    
    // Handle remaining group (if any)
    if (groupIdx > 0) {
        if (groupIdx < 2) return -1; // Invalid: need at least 2 chars
        
        if (groupIdx == 2) {
            uint32_t triple = (group[0] << 18) | (group[1] << 12);
            if (outPos + 1 > outputBufSize) return -1;
            output[outPos++] = (triple >> 16) & 0xFF;
        } else if (groupIdx == 3) {
            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6);
            if (outPos + 2 > outputBufSize) return -1;
            output[outPos++] = (triple >> 16) & 0xFF;
            output[outPos++] = (triple >> 8) & 0xFF;
        }
    }
    
    *outputLen = outPos;
    return 0;
}

// v36.82: RSA encrypt challenge data using server's public key certificate
// Returns encrypted data length, or -1 on failure
static ssize_t rsaEncryptChallenge(const uint8_t *plainData, size_t plainLen,
                                    uint8_t *cipherBuf, size_t cipherBufSize) {
    if (!g_pubKeyCaptured || g_pubKeyBase64Len == 0) {
        DLOG(@"[RSA-ENCRYPT] No public key captured, cannot encrypt (captured=%d, len=%lu)", 
             g_pubKeyCaptured, (unsigned long)g_pubKeyBase64Len);
        return -1;
    }
    
    DLOG(@"[RSA-ENCRYPT] Starting encryption: pubKeyLen=%lu, plainLen=%zu", 
          (unsigned long)g_pubKeyBase64Len, plainLen);
    
    // Step 1: Manual Base64 decode (most reliable)
    uint8_t *derData = (uint8_t *)malloc(1024);
    if (!derData) {
        DLOG(@"[RSA-ENCRYPT] Failed to allocate DER buffer");
        return -1;
    }
    
    size_t derLen = 0;
    int decodeResult = manualBase64Decode((const uint8_t *)g_pubKeyBase64, 
                                           g_pubKeyBase64Len, 
                                           derData, 1024, &derLen);
    
    if (decodeResult != 0 || derLen == 0) {
        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode failed (result=%d, derLen=%zu), trying NSData...", decodeResult, derLen);
        
        // Fallback: Try NSData Base64 decode
        @try {
            NSString *certStr = [[NSString alloc] initWithBytes:g_pubKeyBase64 
                                                        length:g_pubKeyBase64Len 
                                                      encoding:NSASCIIStringEncoding];
            if (certStr) {
                NSData *certDER = [[NSData alloc] initWithBase64EncodedString:certStr 
                                                                      options:NSDataBase64DecodingIgnoreUnknownCharacters];
                if (certDER && certDER.length > 0) {
                    derLen = certDER.length;
                    memcpy(derData, certDER.bytes, MIN(derLen, 1024));
                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode succeeded: %lu bytes", (unsigned long)derLen);
                } else {
                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode also failed");
                    free(derData);
                    return -1;
                }
            } else {
                DLOG(@"[RSA-ENCRYPT] Cannot create NSString from Base64 data");
                free(derData);
                return -1;
            }
        } @catch (NSException *e) {
            DLOG(@"[RSA-ENCRYPT] Exception in NSData decode: %@", e.reason);
            free(derData);
            return -1;
        }
    } else {
        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode succeeded: %zu bytes", derLen);
    }
    
    // Log DER header for debugging
    if (derLen >= 8) {
        DLOG(@"[RSA-ENCRYPT] DER header: %02X %02X %02X %02X %02X %02X %02X %02X",
             derData[0], derData[1], derData[2], derData[3],
             derData[4], derData[5], derData[6], derData[7]);
    }
    
    // Step 2: Create SecKey from DER data
    SecKeyRef pubKeyRef = NULL;
    
    // Try as X.509 certificate first
    @try {
        CFDataRef certData = CFDataCreate(NULL, derData, derLen);
        SecCertificateRef certRef = SecCertificateCreateWithData(NULL, certData);
        CFRelease(certData);
        
        if (certRef) {
            DLOG(@"[RSA-ENCRYPT] Created SecCertificate from DER data");
            pubKeyRef = SecCertificateCopyKey(certRef);
            CFRelease(certRef);
            
            if (!pubKeyRef) {
                DLOG(@"[RSA-ENCRYPT] SecCertificateCopyKey failed, trying direct SecKey...");
            }
        } else {
            DLOG(@"[RSA-ENCRYPT] SecCertificateCreateWithData failed, trying direct SecKey...");
        }
    } @catch (NSException *e) {
        DLOG(@"[RSA-ENCRYPT] Exception creating certificate: %@", e.reason);
    }
    
    // Try as direct public key (not a certificate)
    if (!pubKeyRef) {
        @try {
            NSDictionary *keyAttrs = @{
                (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                (__bridge id)kSecAttrKeySizeInBits: @2048
            };
            CFDataRef keyData = CFDataCreate(NULL, derData, derLen);
            pubKeyRef = SecKeyCreateWithData(keyData, (__bridge CFDictionaryRef)keyAttrs, NULL);
            CFRelease(keyData);
            
            if (pubKeyRef) {
                DLOG(@"[RSA-ENCRYPT] Created SecKey directly from DER data");
            } else {
                DLOG(@"[RSA-ENCRYPT] SecKeyCreateWithData also failed");
                free(derData);
                return -1;
            }
        } @catch (NSException *e) {
            DLOG(@"[RSA-ENCRYPT] Exception creating SecKey: %@", e.reason);
            free(derData);
            return -1;
        }
    }
    
    free(derData);
    DLOG(@"[RSA-ENCRYPT] Got public key reference, proceeding to encryption");
    
    // Step 3: Encrypt with RSA using SecKeyCreateEncryptedData
    // v36.86: Try PKCS1 first (most common for challenge-response), then OAEP, then Raw
    CFErrorRef encryptErr = NULL;
    SecKeyAlgorithm algo = kSecKeyAlgorithmRSAEncryptionPKCS1;
    
    // Check if the algorithm is supported
    if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
        DLOG(@"[RSA-ENCRYPT] PKCS1 not supported, trying SHA256...");
        algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
        if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
            DLOG(@"[RSA-ENCRYPT] SHA256 not supported, trying SHA1...");
            algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
            if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
                DLOG(@"[RSA-ENCRYPT] SHA1 not supported, trying Raw...");
                algo = kSecKeyAlgorithmRSAEncryptionRaw;
                if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
                    DLOG(@"[RSA-ENCRYPT] No RSA encryption algorithm supported");
                    CFRelease(pubKeyRef);
                    return -1;
                }
            }
        }
    }
    
    DLOG(@"[RSA-ENCRYPT] Using encryption algorithm: %s",
          algo == kSecKeyAlgorithmRSAEncryptionPKCS1 ? "PKCS1" :
          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA256 ? "SHA256" :
          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA1 ? "SHA1" : "Raw");
    
    CFDataRef plainCFData = CFDataCreate(NULL, plainData, plainLen);
    CFErrorRef *encryptErrPtr = NULL;
    CFDataRef cipherCFData = SecKeyCreateEncryptedData(pubKeyRef, algo,
                                                       plainCFData, encryptErrPtr);
    CFRelease(plainCFData);
    CFRelease(pubKeyRef);
    
    if (cipherCFData) {
        size_t cipherLen = CFDataGetLength(cipherCFData);
        if (cipherLen <= cipherBufSize) {
            CFDataGetBytes(cipherCFData, CFRangeMake(0, cipherLen), cipherBuf);
            CFRelease(cipherCFData);
            DLOG(@"[RSA-ENCRYPT] SUCCESS: encrypted %lu bytes -> %lu bytes RSA cipher",
                 (unsigned long)plainLen, (unsigned long)cipherLen);
            return (ssize_t)cipherLen;
        }
        CFRelease(cipherCFData);
        DLOG(@"[RSA-ENCRYPT] Cipher buffer too small: need %lu, have %lu",
             (unsigned long)cipherLen, (unsigned long)cipherBufSize);
        return -1;
    } else {
        CFStringRef errStr = encryptErrPtr && *encryptErrPtr ? CFErrorCopyDescription(*encryptErrPtr) : NULL;
        DLOG(@"[RSA-ENCRYPT] SecKeyCreateEncryptedData failed: %@",
             errStr ? CFBridgingRelease(errStr) : @"unknown");
        if (encryptErrPtr && *encryptErrPtr) CFRelease(*encryptErrPtr);
        return -1;
    }
}

// v36.81: Auto-respond to 0x00FFFF02 challenge with RSA-encrypted 0x80FFFF02
// Returns YES if response was sent
static BOOL autoRespondToChallenge(int fd, const unsigned char *pktBuf, size_t pktLen,
                                    uint32_t cmd) {
    if (cmd != 0x00FFFF02 || pktLen < 12) return NO;
    if (g_challengeResponded && g_challengeFd == fd) {
        DLOG(@"[CHALLENGE-AUTO] Already responded to 0x00FFFF02 for fd=%d, skipping", fd);
        return NO;
    }
    if (!g_pubKeyCaptured) {
        DLOG(@"[CHALLENGE-AUTO] No public key available, cannot auto-respond (captured=%d)", g_pubKeyCaptured);
        return NO;
    }
    
    // Extract challenge payload (bytes[12..end])
    size_t payloadLen = pktLen - 12;
    const uint8_t *payloadData = pktBuf + 12;
    
    DLOG(@"[CHALLENGE-AUTO] Auto-responding to 0x00FFFF02: payload=%zu bytes, fd=%d", payloadLen, fd);
    
    // Encrypt the challenge data with RSA public key
    uint8_t encryptedData[256]; // RSA 2048-bit = 256 bytes max
    ssize_t encryptedLen = rsaEncryptChallenge(payloadData, payloadLen, encryptedData, sizeof(encryptedData));
    if (encryptedLen <= 0) {
        DLOG(@"[CHALLENGE-AUTO] RSA encryption failed, cannot auto-respond (encryptedLen=%zd)", encryptedLen);
        return NO;
    }
    
    // Construct 0x80FFFF02 response packet (with STATUS byte):
    // 4 bytes: total packet length (4 + 4 + 4 + 1 + encryptedLen)
    // 4 bytes: cmd = 0x80FFFF02
    // 4 bytes: seq (same as challenge, bytes[8-11])
    // 1 byte:  status = 0 (success)
    // encryptedLen bytes: encrypted challenge data
    uint32_t totalLen = (uint32_t)(4 + 4 + 4 + 1 + encryptedLen);
    uint8_t responseBuf[300]; // Max 4+4+4+1+256 = 269
    if (totalLen > sizeof(responseBuf)) {
        DLOG(@"[CHALLENGE-AUTO] Response too large: %u bytes", totalLen);
        return NO;
    }
    
    // Build packet with STATUS byte at offset 12
    responseBuf[0] = (totalLen >> 24) & 0xFF;
    responseBuf[1] = (totalLen >> 16) & 0xFF;
    responseBuf[2] = (totalLen >> 8) & 0xFF;
    responseBuf[3] = totalLen & 0xFF;
    
    responseBuf[4] = 0x80; responseBuf[5] = 0xFF; responseBuf[6] = 0xFF; responseBuf[7] = 0x02;
    
    // Copy seq from challenge (bytes[8-11])
    memcpy(responseBuf + 8, pktBuf + 8, 4);
    
    // STATUS byte = 0 (success)
    responseBuf[12] = 0x00;
    
    // Copy encrypted data starting at offset 13 (after STATUS)
    memcpy(responseBuf + 13, encryptedData, encryptedLen);
    
    // Send the response
    DLOG(@"[CHALLENGE-AUTO] Sending 0x80FFFF02 response: %u bytes to fd=%d (encrypted %zd bytes, WITH status byte)", totalLen, fd, encryptedLen);
    ssize_t sent = orig_send ? orig_send(fd, responseBuf, totalLen, 0) : -1;
    if (sent > 0) {
        g_challengeResponded = YES;
        g_challengeFd = fd;
        DLOG(@"[CHALLENGE-AUTO] SUCCESS: Sent 0x80FFFF02 response: %zd bytes (encrypted %zu -> %zd)",
             sent, payloadLen, encryptedLen);
        
        // Log response hex
        NSMutableString *hexStr = [NSMutableString stringWithString:@"[CHALLENGE-AUTO] Response HEX: "];
        for (uint32_t i = 0; i < totalLen && i < 64; i++) {
            [hexStr appendFormat:@"%02X ", responseBuf[i]];
        }
        if (totalLen > 64) [hexStr appendFormat:@"..."];
        DLOG(@"%@", hexStr);
        
        // v36.88: Construct 0x80FFF495 handshake complete PACKET (not fake 22-byte ACK)
        // Challenge response was sent. Server may not send 0x80FFF495, so client state
        // machine is stuck on heartbeats. We inject a REAL-SIZED 0x80FFF495 packet into recv.
        // Key: must be LARGE enough to avoid SIGSEGV in handle_CHOOSE_WOOD_BOX_RES handler,
        // which reads significant payload. We build ~200 byte packet with proper header + padding.
        {
            uint32_t hsPktSize = 200;  // Large enough to avoid out-of-bounds read
            if (hsPktSize > MAX_FORCE_HS_BUF) hsPktSize = MAX_FORCE_HS_BUF;
            
            memset(g_forceHandshakeBuf, 0, hsPktSize);
            
            // Byte[0-3]: Total packet length (big-endian)
            g_forceHandshakeBuf[0] = (hsPktSize >> 24) & 0xFF;
            g_forceHandshakeBuf[1] = (hsPktSize >> 16) & 0xFF;
            g_forceHandshakeBuf[2] = (hsPktSize >> 8) & 0xFF;
            g_forceHandshakeBuf[3] = hsPktSize & 0xFF;
            
            // Byte[4-7]: cmd = 0x80FFF495 (handshake complete, response to challenge)
            g_forceHandshakeBuf[4] = 0x80;
            g_forceHandshakeBuf[5] = 0xFF;
            g_forceHandshakeBuf[6] = 0xF4;
            g_forceHandshakeBuf[7] = 0x95;
            
            // Byte[8-11]: seq number, use same base as challenge response
            g_forceHandshakeBuf[8]  = responseBuf[8];
            g_forceHandshakeBuf[9]  = responseBuf[9];
            g_forceHandshakeBuf[10] = responseBuf[10];
            g_forceHandshakeBuf[11] = responseBuf[11];
            
            // Byte[12]: STATUS = 0 (SUCCESS)
            g_forceHandshakeBuf[12] = 0x00;
            
            // Byte[13]: format flags (copy from 0x80FFF494 style = 0x88)
            g_forceHandshakeBuf[13] = 0x88;
            
            // Byte[14...]: SAFETY PADDING - fill with recognizable Base64-like content
            // This prevents SIGSEGV when handler parses the payload.
            const char *padding = 
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOJwUMBZ0a1FZkot1lJ"
                "+LB4rodylyGvUbq7sOO6nHgBqeqT2bp/mCShyDsVKdGGruFM8TY1cKlrHHhukEHV"
                "vr2+5zTL7Pg+ywmn+53vB4azfuaetHwVctLFmTyqrENWsTiL0uyl5w4k52TSvX7sC"
                "tuMx2grh6f1Hhb0/LqsFNjPobudwS00ypDtBG0Ung3T32DO2eFQ4JI0hXKkbCp0cyBT";
            size_t padLen = strlen(padding);
            size_t copyLen = padLen;
            if (copyLen > hsPktSize - 14) copyLen = hsPktSize - 14;
            memcpy(g_forceHandshakeBuf + 14, padding, copyLen);
            
            g_forceHandshakeLen = hsPktSize;
            g_forceHandshakeFd = fd;
            g_forceHandshakeComplete = YES;
            
            DLOG(@"[FORCE-HS-PREP] Prepared 0x80FFF495 packet size=%u bytes (fd=%d)",
                 hsPktSize, fd);
            DLOG(@"[FORCE-HS-PREP] Header: len=%u cmd=0x%02X%02X%02X%02X seq=0x%02X%02X%02X%02X status=%u",
                 hsPktSize,
                 g_forceHandshakeBuf[4], g_forceHandshakeBuf[5], g_forceHandshakeBuf[6], g_forceHandshakeBuf[7],
                 g_forceHandshakeBuf[8], g_forceHandshakeBuf[9], g_forceHandshakeBuf[10], g_forceHandshakeBuf[11],
                 g_forceHandshakeBuf[12]);
        }
        
        // v36.88: REMOVED immediate plaintext 0x000EE007 force-send.
        // Game server expects ENCRYPTED device info after handshake.
        // Force-sending plaintext (143/181/217 bytes) is silently discarded.
        // Instead, the injected 0x80FFF495 above will cause client state machine
        // to advance and send proper AES-encrypted 0x000EE007 (179 bytes) itself.
        DLOG(@"[GAME-FLOW] Waiting for FORCE-HS 0x80FFF495 injection -> client will send encrypted device info");
        
        return YES;
    } else {
        DLOG(@"[CHALLENGE-AUTO] Send failed: %zd", sent);
        return NO;
    }
}

static void applyServerListPatch(unsigned char *payload, size_t payloadLen) {
    if (!payload || payloadLen == 0) return;
    
    BOOL patched = NO;
    char *cpayload = (char *)payload;
    
    for (size_t i = 0; i + 7 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 't' && cpayload[i+2] == 'a' && 
            cpayload[i+3] == 't' && cpayload[i+4] == 'u' && cpayload[i+5] == 's' && 
            cpayload[i+6] == '=' && cpayload[i+7] != '1') {
            DLOG(@"[PROTO-PATCH] Found status=%c at offset %zu, changing to 1", cpayload[i+7], i);
            cpayload[i+7] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 9 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 
            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 
            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '0') {
            DLOG(@"[PROTO-PATCH] Found serverid=0 at offset %zu, changing to 1", i);
            cpayload[i+9] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 9 < payloadLen; i++) {
        if (cpayload[i] == 'c' && cpayload[i+1] == 'l' && cpayload[i+2] == 'i' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == 'n' && cpayload[i+5] == 't' && 
            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '0') {
            DLOG(@"[PROTO-PATCH] Found clientid=0 at offset %zu, changing to 1", i);
            cpayload[i+9] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 11 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 
            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 
            cpayload[i+6] == 'T' && cpayload[i+7] == 'y' && cpayload[i+8] == 'p' && 
            cpayload[i+9] == 'e' && cpayload[i+10] == '=' && cpayload[i+11] == '2') {
            DLOG(@"[PROTO-PATCH] Found serverType=2 at offset %zu, changing to 1", i);
            cpayload[i+11] = '1';
            patched = YES;
        }
    }
    
    const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};
    for (size_t i = 0; i + 11 <= payloadLen; i++) {
        if (cpayload[i] == 'c' && cpayload[i+1] == 'a' && cpayload[i+2] == 't' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == 'g' && cpayload[i+5] == 'o' && 
            cpayload[i+6] == 'r' && cpayload[i+7] == 'y' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '\'') {
            size_t endIdx = i + 10;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t catLen = endIdx - (i + 10);
                if (catLen >= 6) {
                    DLOG(@"[PROTO-PATCH] Found category field at offset %zu, replacing with '一区'", i);
                    memcpy(payload + i + 10, newCat, 6);
                    for (size_t j = 6; j < catLen; j++) payload[i+10+j] = ' ';
                    patched = YES;
                }
            }
        }
    }
    
    const unsigned char newName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};
    for (size_t i = 0; i + 6 <= payloadLen; i++) {
        if (cpayload[i] == 'n' && cpayload[i+1] == 'a' && cpayload[i+2] == 'm' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == '=' && cpayload[i+5] == '\'') {
            size_t endIdx = i + 6;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t nameLen = endIdx - (i + 6);
                if (nameLen >= 6) {
                    size_t validCharCount = 0;
                    size_t dotCount = 0;
                    for (size_t j = 0; j < nameLen && j < 30; j++) {
                        unsigned char ch = payload[i+6+j];
                        if (ch == '.') {
                            dotCount++;
                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 
                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
                            validCharCount++;
                        }
                    }
                    if (dotCount >= nameLen / 2 || validCharCount < 3) {
                        DLOG(@"[PROTO-PATCH] Found garbage name (dots=%zu, valid=%zu) at offset %zu, replacing", 
                             dotCount, validCharCount, i);
                        memcpy(payload + i + 6, newName, 13);
                        for (size_t j = 13; j < nameLen; j++) payload[i+6+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    const unsigned char newRealName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};
    for (size_t i = 0; i + 10 <= payloadLen; i++) {
        if (cpayload[i] == 'r' && cpayload[i+1] == 'e' && cpayload[i+2] == 'a' && 
            cpayload[i+3] == 'l' && cpayload[i+4] == 'n' && cpayload[i+5] == 'a' && 
            cpayload[i+6] == 'm' && cpayload[i+7] == 'e' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '\'') {
            size_t endIdx = i + 10;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t nameLen = endIdx - (i + 10);
                if (nameLen >= 6) {
                    size_t validCharCount = 0;
                    size_t dotCount = 0;
                    for (size_t j = 0; j < nameLen && j < 30; j++) {
                        unsigned char ch = payload[i+10+j];
                        if (ch == '.') {
                            dotCount++;
                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 
                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
                            validCharCount++;
                        }
                    }
                    if (dotCount >= nameLen / 2 || validCharCount < 3) {
                        DLOG(@"[PROTO-PATCH] Found garbage realname (dots=%zu, valid=%zu) at offset %zu, replacing", 
                             dotCount, validCharCount, i);
                        memcpy(payload + i + 10, newRealName, 13);
                        for (size_t j = 13; j < nameLen; j++) payload[i+10+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 
                                     0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 
                                     0x2E, 0x2E, 0x2E};
    const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};
    for (size_t i = 0; i + 21 <= payloadLen; i++) {
        if (memcmp(payload + i, oldDesc, 21) == 0) {
            DLOG(@"[PROTO-PATCH] Found '服务器维护中...' at offset %zu, replacing with '运行'", i);
            memcpy(payload + i, newDesc, 6);
            for (size_t j = 6; j < 21; j++) payload[i+j] = ' ';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 17 <= payloadLen; i++) {
        if (cpayload[i] == 'd' && cpayload[i+1] == 'e' && cpayload[i+2] == 's' && 
            cpayload[i+3] == 'c' && cpayload[i+4] == 'r' && cpayload[i+5] == 'i' && 
            cpayload[i+6] == 'p' && cpayload[i+7] == 't' && cpayload[i+8] == 'i' && 
            cpayload[i+9] == 'o' && cpayload[i+10] == 'n' && cpayload[i+11] == '=' && 
            cpayload[i+12] == '\'') {
            size_t endIdx = i + 13;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t descLen = endIdx - (i + 13);
                if (descLen >= 6) {
                    BOOL isGarbage = YES;
                    for (size_t j = 0; j < descLen && j < 20; j++) {
                        unsigned char ch = payload[i+13+j];
                        if ((ch >= 0x20 && ch < 0x7F) || (ch >= 0xE4 && ch <= 0xE9)) {
                            isGarbage = NO;
                            break;
                        }
                    }
                    if (isGarbage) {
                        DLOG(@"[PROTO-PATCH] Found garbage description at offset %zu, replacing with '运行'", i);
                        memcpy(payload + i + 13, newDesc, 6);
                        for (size_t j = 6; j < descLen; j++) payload[i+13+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    for (size_t i = 0; i + 16 <= payloadLen; i++) {
        if (cpayload[i] == 'o' && cpayload[i+1] == 'n' && cpayload[i+2] == 'l' && 
            cpayload[i+3] == 'i' && cpayload[i+4] == 'n' && cpayload[i+5] == 'e' && 
            cpayload[i+6] == 'P' && cpayload[i+7] == 'l' && cpayload[i+8] == 'a' && 
            cpayload[i+9] == 'y' && cpayload[i+10] == 'e' && cpayload[i+11] == 'r' && 
            cpayload[i+12] == 'N' && cpayload[i+13] == 'u' && cpayload[i+14] == 'm' && 
            cpayload[i+15] == '=' && cpayload[i+16] == '0') {
            DLOG(@"[PROTO-PATCH] Found onlinePlayerNum=0 at offset %zu, changing to 100", i);
            cpayload[i+16] = '1';
            if (i + 17 < payloadLen && cpayload[i+17] == ',') {
                cpayload[i+17] = '0';
                cpayload[i+18] = '0';
            } else {
                cpayload[i+17] = '0';
            }
            patched = YES;
        }
    }
    
    if (patched) {
        DLOG(@"[PROTO-PATCH] Server list patched successfully");
    }
}

static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv || !buf) return -1;
    
    // v36.108: Queue-based fake response system (PRIORITY PATH)
    // This handles ALL subsequent recv calls after initial injection
    if (g_fakeRespActive && g_fakeRespFd == fd) {
        // v36.108: Cap total responses to prevent infinite loop
        if (g_respCount >= 200) {
            DLOG(@"[FAKE-RESP] v36.108: Response cap reached (%d), returning EAGAIN", g_respCount);
            errno = EAGAIN;
            return -1;
        }
        
        // v36.108: Try to dequeue next command with sequence number
        GameCmdEntry entry;
        uint32_t responseCmd = 0;
        uint32_t respSeqNum = 0;
        BOOL dequeued = NO;
        
        if (dequeueGameCmd(&entry)) {
            responseCmd = entry.cmd;
            respSeqNum = entry.seqNum;
            dequeued = YES;
            DLOG(@"[FAKE-RESP] v36.108: Dequeued cmd=0x%08X seq=0x%08X from queue (remaining=%d)", 
                 responseCmd, respSeqNum, g_cmdQueueCount);
        } else if (g_lastGameCmd != 0) {
            // v36.108: Queue empty but we have a last command
            responseCmd = g_lastGameCmd;
            respSeqNum = g_lastSeqNum;
            
            // Only respond if:
            // 1. Different from last response, OR
            // 2. Client sent new data (delivered flag was reset)
            if (responseCmd == g_lastRespCmd && g_fakeRespDelivered) {
                // Same command already responded to, wait for new data
                errno = EAGAIN;
                return -1;
            }
            DLOG(@"[FAKE-RESP] v36.108: Queue empty, using last cmd=0x%08X seq=0x%08X (delivered=%d)", 
                 responseCmd, respSeqNum, g_fakeRespDelivered);
        } else {
            // No commands at all
            DLOG(@"[FAKE-RESP] v36.108: No commands to respond to, returning EAGAIN");
            errno = EAGAIN;
            return -1;
        }
        
        // v36.108: Generate response for the command with correct sequence number
        uint8_t tempBuf[MAX_FAKE_RESP_BUF];
        uint32_t respLen = generateFakeResponse(responseCmd, tempBuf, sizeof(tempBuf), respSeqNum);
        
        if (respLen > 0 && respLen <= len) {
            memcpy(buf, tempBuf, respLen);
            g_fakeRespSentCount++;
            g_fakeRespDelivered = YES;
            g_lastRespCmd = responseCmd;
            g_respCount++;
            
            // v36.108: Log full response details for debugging
            NSMutableString *respHex = [NSMutableString stringWithCapacity:48];
            for (uint32_t i = 0; i < MIN(respLen, 16); i++) {
                [respHex appendFormat:@"%02X ", tempBuf[i]];
            }
            DLOG(@"[FAKE-RESP] v36.108: Delivered response for cmd=0x%08X seq=0x%08X len=%u (queue=%d, respCount=%d, hex=%@)", 
                 responseCmd, respSeqNum, respLen, g_cmdQueueCount, g_respCount, respHex);
            return (ssize_t)respLen;
        }
        
        DLOG(@"[FAKE-RESP] v36.108: generateFakeResponse returned invalid len=%u (max=%zu), returning EAGAIN", respLen, len);
        errno = EAGAIN;
        return -1;
    }
    
    // v36.96: Check for fake response state FIRST - before any real recv call
    if (g_fakeRespInjected && g_fakeRespFd == fd) {
        if (g_fakeRespSentCount >= 1) {
            // v36.101: Switch to active mode but respect delivered flag
            if (!g_fakeRespActive) {
                g_fakeRespActive = YES;
                DLOG(@"[FAKE-RESP] v36.105: Switching to ACTIVE fake response mode for fd=%d", fd);
            }
            // v36.105: If already delivered AND same cmd, return EAGAIN
            if (g_fakeRespDelivered && g_lastGameCmd == g_lastRespCmd) {
                errno = EAGAIN;
                return -1;
            }
            if (g_respCount >= 200) {
                errno = EAGAIN;
                return -1;
            }
            
            // v36.107: Generate fake response based on last tracked game server command with correct seq
            uint8_t tempBuf[MAX_FAKE_RESP_BUF];
            uint32_t respLen = generateFakeResponse(g_lastGameCmd, tempBuf, sizeof(tempBuf), g_lastSeqNum);
            
            if (respLen > 0 && respLen <= len) {
                memcpy(buf, tempBuf, respLen);
                g_fakeRespSentCount++;
                g_fakeRespDelivered = YES;  // v36.101: Mark as delivered
                g_lastRespCmd = g_lastGameCmd;  // v36.107: Track which cmd we responded to
                g_respCount++;  // v36.107: Increment response counter
                DLOG(@"[FAKE-RESP] v36.107: Delivered response for cmd=0x%08X seq=0x%08X len=%u (total #%d, respCount=%d)", 
                     g_lastGameCmd, g_lastSeqNum, respLen, g_fakeRespSentCount, g_respCount);
                return (ssize_t)respLen;
            }
            
            // No response needed, return EAGAIN
            errno = EAGAIN;
            return -1;
        }
        // First call after injection: return fake response data
        g_fakeRespSentCount++;
        if (g_fakeRespLen > 0 && buf) {
            ssize_t retLen = (ssize_t)g_fakeRespLen;
            if (retLen > (ssize_t)len) retLen = (ssize_t)len;
            memcpy(buf, g_fakeRespBuf, retLen);
            DLOG(@"[FAKE-RESP] v36.96: Returning stored fake response (%zd bytes) for fd=%d", retLen, fd);
            return retLen;
        }
        // No fake response data available, return EAGAIN
        DLOG(@"[FAKE-RESP] v36.96: No fake response data, returning EAGAIN for fd=%d", fd);
        errno = EAGAIN;
        return -1;
    }
    
    // v36.91: Debug log to track recv calls (FORCE-HS removed - no more fake packet injection!)
    DLOG(@"[RECV-ENTRY] fd=%d len=%zu hbAck=%zd hbFd=%d",
         fd, len, g_localHeartbeatAckLen, g_localHeartbeatAckFd);
    
    // v36.91: FORCE-HS MECHANISM COMPLETELY REMOVED!
    // v36.90 proved: injecting fake 0x80FFF495 BEFORE real server packet = state machine corruption.
    // Client receives TWO 0x80FFF495 (fake first, then real) with mismatched seq = handshake fails.
    // Only patch the REAL server 0x80FFF495 status byte = minimum intervention approach.
    
    // v36.68: Check for local heartbeat ACK first (blocked heartbeat responses)
    if (g_localHeartbeatAckLen > 0 && g_localHeartbeatAckFd == fd) {
        ssize_t ackLen = g_localHeartbeatAckLen;
        if (ackLen > (ssize_t)len) ackLen = (ssize_t)len;
        memcpy(buf, g_localHeartbeatAckBuf, ackLen);
        DLOG(@"[LOCAL-HB-ACK] Returning %zd bytes local heartbeat ACK (fd=%d)", ackLen, fd);
        g_localHeartbeatAckLen = 0;
        g_localHeartbeatAckFd = -1;
        return ackLen;
    }
    
    // v36.68: Check for leftover bytes from sticky packet split
    // When 0x80FFF494 + heartbeat ACK arrive in same TCP buffer, we split them
    if (g_stickyLeftoverLen > 0 && g_stickyLeftoverFd == fd) {
        ssize_t leftoverLen = g_stickyLeftoverLen;
        if (leftoverLen > (ssize_t)len) leftoverLen = (ssize_t)len;
        memcpy(buf, g_stickyLeftoverBuf, leftoverLen);
        DLOG(@"[STICKY-LEFTOVER] Returning %zd leftover bytes from sticky packet split (fd=%d)", leftoverLen, fd);
        
        // v36.74: DISABLED auto-response to 0x00FFFF02 in leftover path
        // Let client handle challenge naturally - it needs to construct proper RSA-encrypted response
        // Previously: auto-responded with fake 0x80FFFF02 by copying bytes and flipping cmd,
        // which server rejected because it expects RSA-encrypted data using certificate from 0x80FFF494
        
        // Shift remaining leftover bytes
        if (leftoverLen < g_stickyLeftoverLen) {
            memmove(g_stickyLeftoverBuf, g_stickyLeftoverBuf + leftoverLen, g_stickyLeftoverLen - leftoverLen);
        }
        g_stickyLeftoverLen -= leftoverLen;
        if (g_stickyLeftoverLen == 0) g_stickyLeftoverFd = -1;
        return leftoverLen;
    }
    
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret <= 0) {
        // Log connection close/error with context
        const char *host = ""; int port = 0;
        for (int i = 0; i < g_trackedCount; i++) {
            if (g_trackedFds[i] == fd && g_trackedActive[i]) { host = g_trackedHosts[i]; port = g_trackedPorts[i]; break; }
        }
        if (ret == 0) {
            DLOG(@"[RECV-CLOSE] fd=%d %s:%d ret=0 (server closed connection gracefully)", fd, host, port);
            // v36.61: Game server disconnected, try next server (dynamic port detection)
            BOOL isGamePort = (port == 12003 || port == 58158 || 
                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            if (isGamePort) {
                // v36.99: KEY FIX - For game server fd, NEVER return 0 to client!
                // Returning 0 causes SocketClient/NetImpl to detect "connection closed"
                // and set internal disconnected state, leading to "网络中断" error.
                // Instead: inject fake response or return EAGAIN to keep connection alive.
                
                // v36.108: Fix initial injection - use command queue instead of hardcoding
                if (g_handshakeComplete && g_loginPacketsSent && !g_fakeRespInjected) {
                    // v36.108: Get first command from queue for proper response matching
                    GameCmdEntry firstEntry;
                    uint32_t responseCmd = 0;
                    uint32_t respSeqNum = 0;
                    BOOL hasEntry = NO;
                    
                    // Try to dequeue the first command
                    if (dequeueGameCmd(&firstEntry)) {
                        responseCmd = firstEntry.cmd;
                        respSeqNum = firstEntry.seqNum;
                        hasEntry = YES;
                        DLOG(@"[FAKE-RESP] v36.108: Using queued cmd=0x%08X seq=0x%08X for initial injection", responseCmd, respSeqNum);
                    } else if (g_lastGameCmd != 0) {
                        // Fallback: use last tracked command
                        responseCmd = g_lastGameCmd;
                        respSeqNum = g_lastSeqNum;
                        DLOG(@"[FAKE-RESP] v36.108: No queued cmd, using last cmd=0x%08X seq=0x%08X", responseCmd, respSeqNum);
                    } else {
                        DLOG(@"[FAKE-RESP] v36.108: No commands tracked, using default response");
                        responseCmd = 0x000EE007;  // Default to device info response
                        respSeqNum = 0;
                    }
                    
                    // v36.108: Generate response using proper function with correct sequence number
                    uint8_t *tempBuf = g_fakeRespBuf;
                    uint32_t respLen = generateFakeResponse(responseCmd, tempBuf, MAX_FAKE_RESP_BUF, respSeqNum);
                    
                    if (respLen == 0) {
                        respLen = 16;
                        memset(tempBuf, 0, respLen);
                        tempBuf[3] = respLen;
                        tempBuf[4] = (responseCmd >> 24) | 0x80;
                        tempBuf[5] = (responseCmd >> 16) & 0xFF;
                        tempBuf[6] = (responseCmd >> 8) & 0xFF;
                        tempBuf[7] = responseCmd & 0xFF;
                        tempBuf[8] = (respSeqNum >> 24) & 0xFF;
                        tempBuf[9] = (respSeqNum >> 16) & 0xFF;
                        tempBuf[10] = (respSeqNum >> 8) & 0xFF;
                        tempBuf[11] = respSeqNum & 0xFF;
                    }
                    
                    g_fakeRespInjected = YES;
                    g_fakeRespFd = fd;
                    g_fakeRespLen = respLen;
                    g_fakeRespSentCount = 1;
                    g_fakeRespActive = YES;
                    g_fakeRespDelivered = YES;
                    g_lastRespCmd = responseCmd;
                    g_respCount = 1;
                    
                    if (buf) {
                        ssize_t retLen = (ssize_t)respLen;
                        if (retLen > (ssize_t)len) retLen = (ssize_t)len;
                        memcpy(buf, tempBuf, retLen);
                        DLOG(@"[FAKE-RESP] v36.108: Injected response for cmd=0x%08X seq=0x%08X len=%u (queue=%d)", 
                             responseCmd, respSeqNum, respLen, g_cmdQueueCount);
                        
                        NSMutableString *fakeHex = [NSMutableString stringWithCapacity:64];
                        for (uint32_t i = 0; i < MIN(respLen, 32); i++) {
                            [fakeHex appendFormat:@"%02X ", tempBuf[i]];
                        }
                        DLOG(@"[FAKE-RESP] v36.108: Response hex: %@", fakeHex);
                        
                        return retLen;
                    }
                }
                
                // v36.96: This check is now a safety net only
                // Primary fake response handling is at the BEGINNING of hook_recv (line 3377)
                // which returns EAGAIN immediately for ALL subsequent recv calls
                if (g_fakeRespInjected && g_fakeRespFd == fd && g_fakeRespSentCount > 2) {
                    DLOG(@"[FAKE-RESP] v36.96: Safety net triggered - returning EAGAIN for fd=%d", fd);
                    errno = EAGAIN;
                    return -1;
                }
                
                // v36.61: Original rotation logic
                DLOG(@"[SERVER-ROTATE] Game server %s:%d disconnected, attempting rotation...", host, port);
                @try {
                    BOOL rotated = tryNextServer();
                    if (rotated) {
                        DLOG(@"[SERVER-ROTATE] Rotated to %s:%d, game should retry connection", g_gameServerIP, g_gameServerPort);
                    }
                } @catch (NSException *e) {
                    DLOG(@"[SERVER-ROTATE] Exception during rotation: %@", e.reason);
                }
                
                // v36.99: KEY FIX - For game server fd, NEVER return 0 to client!
                // Always return EAGAIN for game server fd when server closes
                // This prevents SocketClient/NetImpl from detecting "connection closed"
                // and setting internal disconnected state, leading to "网络中断" error
                DLOG(@"[RECV-EAGAIN] v36.99: Game server fd=%d ret=0 -> returning EAGAIN (prevent disconnect detection)", fd);
                errno = EAGAIN;
                return -1;
            }
        } else {
            DLOG(@"[RECV-ERR] fd=%d %s:%d ret=%zd errno=%d (%s)", fd, host, port, ret, errno, strerror(errno));
        }
        return ret;
    }
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECV] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // Challenge packets (0x00FFFF01/0x00FFFF02) - LOG AND RESPOND
        // v36.67: Server requires response to 0x00FFFF02 to continue handshake
        if (cmd == 0x00FFFF01 || cmd == 0x00FFFF02) {
            NSMutableString *challengeDetail = [NSMutableString string];
            [challengeDetail appendFormat:@"[CHALLENGE-LOG] cmd=0x%08X len=%zd port=%d\n", cmd, (size_t)ret, port];
            [challengeDetail appendFormat:@"  Full hex: "];
            for (ssize_t i = 0; i < ret && i < 64; i++) {
                [challengeDetail appendFormat:@"%02X ", p[i]];
            }
            if (ret > 64) [challengeDetail appendFormat:@"...\n"];
            else [challengeDetail appendFormat:@"\n"];
            
            // Parse packet structure for analysis
            if (ret >= 12) {
                uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                  ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
                uint32_t seq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                [challengeDetail appendFormat:@"  Parsed: pktLen=%u seq=0x%08X\n", pktLen, seq];
                
                // Check for payload data after header
                if (ret > 12) {
                    [challengeDetail appendFormat:@"  Payload (%zd bytes): ", ret - 12];
                    for (ssize_t i = 12; i < ret && i < 32; i++) {
                        [challengeDetail appendFormat:@"%02X ", p[i]];
                    }
                    if (ret > 32) [challengeDetail appendFormat:@"..."];
                    [challengeDetail appendFormat:@"\n"];
                }
                
                // Try to decode payload as ASCII
                NSString *payloadStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
                if (payloadStr && payloadStr.length > 0) {
                    [challengeDetail appendFormat:@"  Payload text: %@\n", payloadStr];
                }
            }
            
            // v36.93: DISABLED auto-respond to 0x00FFFF02! (same as v36.91-v36.92)
            // v36.90 analysis: Hook's auto-response (0x80FFFF02) + Client's native response (0x00FFF495)
            // cause DOUBLE response to single challenge, activating FORCE-HS and corrupting state machine.
            // v36.89 observation PROVED client can handle 0x00FFFF02 challenge natively.
            // Let client send 0x00FFF495 (703B RSA response) - this is the PROPER response format!
            if (cmd == 0x00FFFF02 && ret >= 28) {
                [challengeDetail appendFormat:@"  [V36.93] SKIP AUTO-RESPOND: Let client handle 0x00FFFF02 challenge natively\n"];
                [challengeDetail appendFormat:@"  [V36.93] Client will parse RSA cert from 0x80FFF494 and send 0x00FFF495 response\n"];
                DLOG(@"[CHALLENGE] v36.93: Skipping auto-respond - let client send native 0x00FFF495 (703B RSA response)");
            } else if (cmd == 0x00FFFF01) {
                [challengeDetail appendFormat:@"  [NOTE] 0x00FFFF01 (first challenge) - game handles this normally\n"];
            }
            
            DLOG(@"%@", challengeDetail);
        }
        
        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // DETAILED HEX DUMP of server list response
            DLOG(@"[SERVERLIST-HEX] Full response hex (%zd bytes):", ret);
            for (ssize_t i = 0; i < ret; i += 32) {
                NSMutableString *line = [NSMutableString string];
                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {
                    [line appendFormat:@"%02X ", p[j]];
                }
                DLOG(@"[SERVERLIST-HEX]   %zd: %@", i, line);
            }
            
            // v36.45: DISABLE port patch - use original port directly
            // Just log the ports found, don't modify them
            int portCount = 0;
            for (ssize_t i = 12; i + 1 < ret; i++) {
                if (p[i] == 0x2E && p[i+1] == 0xE3) {
                    portCount++;
                }
            }
            DLOG(@"[SERVERLIST-PATCH] DISABLED: found %d occurrences of port 12003, NOT modifying", portCount);
            
            // Update global game server info from response
            parseServerListResponse((const unsigned char *)buf, ret);
            
            // Also try to decode as JSON
            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {
                DLOG(@"[SERVERLIST-JSON] JSON response: %@", jsonStr);
            }
        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // v36.49: ALWAYS patch status byte for 0x802EE121 - KEEP original ret (don't truncate!)
            if (cmd == 0x802EE121 && ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] Status %u -> 0 (critical login patch, keeping %zd bytes)", p[12], ret);
                ((unsigned char *)buf)[12] = 0;
                // v36.49: Do NOT truncate ret! Game needs full response including sessionId etc.
            }
        }
    }
    
    // v36.50: ONLY clear '版本过低'/'当前版本' on login server (port 5678) - NOT on game server!
    // Running on port 12003 binary data could corrupt protocol data
    if (port == 5678) {
        static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
            if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                DLOG(@"[PATCH-R] Cleared '版本过低' at offset %zd (port=5678 only)", i);
                memset((unsigned char *)buf + i, ' ', sizeof(verLow));
            }
        }
        static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
            if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                DLOG(@"[PATCH-R] Cleared '当前版本' at offset %zd (port=5678 only)", i);
                memset((unsigned char *)buf + i, ' ', sizeof(curVer));
            }
        }
    }
    
#if !MINIMAL_MODE
    // v36.70: Enhanced game server response analysis with CMD-BASED detection
    // Analyze responses on game ports OR by command range detection
    // This ensures analysis works even when getPortForFd returns 0
    BOOL isGamePort = (port == 12003 || port == 58158 || 
                       (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
    // v36.70: Parse cmd FIRST to enable cmd-based detection when port fails
    uint32_t rcmd_precheck = 0;
    if (ret >= 8) {
        rcmd_precheck = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                        ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
    }
    BOOL gameCmdDetected = isGameCmd(rcmd_precheck);
    // v36.70: Use BOTH port-based AND cmd-based detection
    BOOL isGameAnalysis = isGamePort || gameCmdDetected;
    
    if (isGameAnalysis && ret >= 4) {
        @try {
            uint32_t rcmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                             ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
            
            // v36.86: REMOVED ACK-REPLACE logic - it causes SIGSEGV crash!
            // 0x80FFF495 maps to handle_CHOOSE_WOOD_BOX_RES in the game client.
            // Faking this packet causes the client to call the wrong handler -> crash.
            // Instead: force-send 0x000EE007 device info directly after challenge response.
            
            const char *gamePort;
            if (port == 58158) gamePort = "58158";
            else if (port == 12003) gamePort = "12003";
            else if (port > 0) gamePort = "DYNAMIC";
            else gamePort = "CMD-DETECT";
            
            // v36.70: Log detection method for debugging
            if (gameCmdDetected && !isGamePort) {
                DLOG(@"[CMD-DETECT] Game server detected via cmd range (cmd=0x%08X, port=%d, host=%s) - port-based FAILED", 
                     rcmd_precheck, port, host);
            } else if (isGamePort) {
                DLOG(@"[CMD-DETECT] Game server detected via port (port=%d, host=%s) - cmd check=%d", 
                     port, host, gameCmdDetected ? 1 : 0);
            }
            
            // v36.57: Build comprehensive log with hex dump
            NSMutableString *detail = [NSMutableString stringWithCapacity:1024];
            [detail appendFormat:@"[GAME-RECV] cmd=0x%08X pktLen=%u recvLen=%zd port=%s fd=%d host=%s\n", 
                 rcmd, pktLen, ret, gamePort, fd, host];
            
            // Hex dump - show up to 256 bytes for thorough analysis
            [detail appendFormat:@"  HEX(%zd bytes): ", ret];
            size_t showLen = ret > 256 ? 256 : (size_t)ret;
            for (ssize_t i = 0; i < showLen; i++) {
                [detail appendFormat:@"%02X ", p[i]];
                if ((i+1) % 32 == 0 && (ssize_t)i+1 < showLen) {
                    [detail appendFormat:@"\n  CONT: "];
                }
            }
            if ((size_t)ret > 256) [detail appendFormat:@"...TRUNCATED\n"];
            else [detail appendFormat:@"\n"];
            
            // ASCII interpretation of payload (offset 12 onwards)
            if (ret > 12) {
                NSString *asciiPayload = [[NSString alloc] initWithBytes:p+12 length:MIN((NSUInteger)(ret-12), 200) encoding:NSUTF8StringEncoding];
                if (asciiPayload && asciiPayload.length > 0) {
                    // Check if it's printable text or binary
                    BOOL hasPrintable = NO;
                    for (NSUInteger i = 0; i < MIN(asciiPayload.length, 50); i++) {
                        unichar c = [asciiPayload characterAtIndex:i];
                        if ((c >= 0x20 && c < 0x7F) || c == 0x0A || c == 0x0D) { hasPrintable = YES; break; }
                    }
                    if (hasPrintable) {
                        [detail appendFormat:@"  ASCII payload: %@\n", asciiPayload];
                    }
                }
            }
            
            // v36.61: Special detailed logging for 0x80FFF494 (login response from game server)
            if (rcmd == 0x80FFF494) {
                DLOG(@"[GAME-80FFF494] ===== DETAILED ANALYSIS OF 0x80FFF494 RESPONSE =====");
                DLOG(@"[GAME-80FFF494] Total length: %zd bytes", ret);
                DLOG(@"[GAME-80FFF494] FULL HEX DUMP:");
                for (ssize_t i = 0; i < ret; i += 16) {
                    NSMutableString *line = [NSMutableString string];
                    for (ssize_t j = i; j < MIN(i + 16, ret); j++) {
                        [line appendFormat:@"%02X ", p[j]];
                    }
                    DLOG(@"[GAME-80FFF494]   %04zd: %@", i, line);
                }
                // Parse known fields
                if (ret >= 16) {
                    uint32_t pLen = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
                    uint32_t pCmd = ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7];
                    uint8_t pStatus = p[12];
                    DLOG(@"[GAME-80FFF494] pktLen=%u cmd=0x%08X status=%u(0x%02X)", pLen, pCmd, pStatus, pStatus);
                    // Check bytes 12-20 for status/error fields
                    DLOG(@"[GAME-80FFF494] Header fields (offset 8-20):");
                    for (int i = 8; i < MIN(20, (int)ret); i++) {
                        DLOG(@"[GAME-80FFF494]   byte[%d] = %u (0x%02X)", i, p[i], p[i]);
                    }
                    // Try to decode payload
                    if (ret > 13) {
                        NSString *payload = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];
                        if (payload && payload.length > 0) {
                            DLOG(@"[GAME-80FFF494] ASCII payload (offset 13+): '%@'", payload);
                        }
                    }
                }
                DLOG(@"[GAME-80FFF494] ===== END DETAILED ANALYSIS =====");
            }
            
            // v36.61: Also log all GAME-RECV packets in detail (first 128 bytes)
            [detail appendFormat:@"  [DETAIL] Full packet hex (all %zd bytes):\n", ret];
            for (ssize_t i = 0; i < ret; i += 16) {
                [detail appendFormat:@"    %04zd: ", i];
                for (ssize_t j = i; j < MIN(i + 16, ret); j++) {
                    [detail appendFormat:@"%02X ", p[j]];
                }
                [detail appendFormat:@"\n"];
            }
            if (ret >= 13) {
                uint8_t status = p[12];
                [detail appendFormat:@"  [STATUS] byte@12 = %u (0x%02X)\n", status, status];
                if (status != 0) {
                    [detail appendFormat:@"  *** WARNING: Non-zero status! Server returned error ***\n"];
                    // v36.90: SELECTIVE status patching based on 80+ version learnings:
                    //   0x80FFF494 (handshake init, status=1) -> DO NOT PATCH!
                    //       status=1 means "challenge required". Patching to 0
                    //       makes client skip challenge -> never sends 0x00FFF495 -> hangs.
                    //   0x80FFF495 (handshake complete, status=1) -> PATCH TO 0!
                    //       This is the REAL handshake completion ACK from server.
                    //       v36.89 observation confirmed server returns status=1 here,
                    //       causing client to call quitFromServer() -> "network interrupted".
                    //       Patching 1->0 allows client to proceed to send 0x000EE007 + 0x00FFF493.
                    if (rcmd == 0x80FFF494) {
                        DLOG(@"[GAME-PATCH] v36.93: NOT patching status %u for 0x80FFF494 (means 'challenge required')", status);
                        [detail appendFormat:@"  [OBSERVE] v36.93: 0x80FFF494 status NOT patched (preserve challenge signal)\n"];
                        
                        // v36.79: Extract RSA public key certificate from 0x80FFF494 response
                        // Cert starts at byte[14] (4 bytes length + 4 bytes cmd + 4 bytes field + 1 byte status + 1 byte type)
                        // byte[13] = cert format type (0x88 = X.509 cert)
                        // bytes[14..end] = Base64-encoded DER certificate data
                        if (ret > 14 && !g_pubKeyCaptured) {
                            // Debug: Log full packet structure
                            DLOG(@"[PUBKEY-DEBUG] Full 0x80FFF494 packet: ret=%zd bytes", ret);
                            DLOG(@"[PUBKEY-DEBUG] Bytes 0-15 hex: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                                 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
                            DLOG(@"[PUBKEY-DEBUG] Packet header analysis:");
                            DLOG(@"[PUBKEY-DEBUG]   pktLen=%u (bytes 0-3)", ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
                            DLOG(@"[PUBKEY-DEBUG]   cmd=0x%08X (bytes 4-7)", ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7]);
                            DLOG(@"[PUBKEY-DEBUG]   seq=0x%08X (bytes 8-11)", ((uint32_t)p[8]<<24)|((uint32_t)p[9]<<16)|((uint32_t)p[10]<<8)|p[11]);
                            DLOG(@"[PUBKEY-DEBUG]   status=%u (byte 12)", p[12]);
                            DLOG(@"[PUBKEY-DEBUG]   format=%u (byte 13)", p[13]);
                            
                            // Try multiple offset values
                            NSArray *offsetAttempts = @[@14, @13, @12, @15, @16];
                            for (NSNumber *offsetNum in offsetAttempts) {
                                ssize_t certOffset = offsetNum.integerValue;
                                if (certOffset >= ret) continue;
                                ssize_t certLen = ret - certOffset;
                                if (certLen > 0 && certLen < MAX_PUBKEY_BASE64) {
                                    NSString *certStrTest = [[NSString alloc] initWithBytes:p+certOffset length:(NSUInteger)certLen encoding:NSASCIIStringEncoding];
                                    if (certStrTest) {
                                        // Count valid Base64 chars
                                        int validB64 = 0;
                                        int invalidB64 = 0;
                                        for (ssize_t i = 0; i < certLen; i++) {
                                            unsigned char c = p[certOffset + i];
                                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '\n') {
                                                validB64++;
                                            } else {
                                                invalidB64++;
                                            }
                                        }
                                        
                                        DLOG(@"[PUBKEY-DEBUG] Offset %zd: len=%zd, validB64=%d, invalidB64=%d, starts: %@",
                                             certOffset, certLen, validB64, invalidB64,
                                             [certStrTest substringToIndex:MIN(60, certStrTest.length)]);
                                        
                                        // If most chars are valid Base64, this is likely the correct offset
                                        if (validB64 > invalidB64 * 2 && certLen > 100) {
                                            DLOG(@"[PUBKEY-DEBUG] Offset %zd looks promising (valid/invalid ratio)", certOffset);
                                        }
                                    }
                                }
                            }
                            
                            // v36.81: Improved public key extraction
                            // Find Base64 public key data starting from offset 14
                            ssize_t certOffset = 14;
                            ssize_t maxCertLen = ret - certOffset;
                            
                            if (maxCertLen > 0 && maxCertLen < MAX_PUBKEY_BASE64) {
                                // v36.81: Find the actual end of Base64 data (look for padding or non-Base64 chars)
                                ssize_t certLen = 0;
                                BOOL foundPadding = NO;
                                
                                // First pass: find the Base64 data boundaries
                                for (ssize_t i = 0; i < maxCertLen; i++) {
                                    unsigned char c = p[certOffset + i];
                                    
                                    // Valid Base64: A-Z, a-z, 0-9, +, /, =
                                    BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 
                                                       (c >= 'a' && c <= 'z') || 
                                                       (c >= '0' && c <= '9') || 
                                                       c == '+' || c == '/' || c == '=';
                                    
                                    // Skip newlines (valid in Base64 but not part of key data)
                                    BOOL isWhitespace = c == '\n' || c == '\r';
                                    
                                    if (isBase64Char) {
                                        certLen = i + 1;
                                        if (c == '=') {
                                            foundPadding = YES;
                                            // Padding at end of Base64, stop here
                                            // But allow max 2 padding chars
                                            ssize_t nextI = i + 1;
                                            if (nextI >= maxCertLen || p[certOffset + nextI] != '=') {
                                                // Found single or double padding, stop
                                                break;
                                            }
                                        }
                                    } else if (!isWhitespace && i > 20) {
                                        // Found non-Base64 char after some data, stop extraction
                                        // But only if we have enough data (at least 20 chars)
                                        break;
                                    } else if (isWhitespace && i > 20) {
                                        // Whitespace after some data - could be line ending
                                        // Skip it but continue
                                        continue;
                                    }
                                }
                                
                                // Ensure we have a reasonable length (RSA 2048-bit key = ~392 chars Base64)
                                if (certLen > 100 && certLen < MAX_PUBKEY_BASE64) {
                                    // Extract only the Base64 data (skip non-Base64 chars in between)
                                    size_t cleanLen = 0;
                                    for (ssize_t i = 0; i < certLen && cleanLen < MAX_PUBKEY_BASE64; i++) {
                                        unsigned char c = p[certOffset + i];
                                        BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 
                                                           (c >= 'a' && c <= 'z') || 
                                                           (c >= '0' && c <= '9') || 
                                                           c == '+' || c == '/' || c == '=';
                                        if (isBase64Char) {
                                            g_pubKeyBase64[cleanLen++] = c;
                                        }
                                    }
                                    g_pubKeyBase64Len = cleanLen;
                                    g_pubKeyCaptured = YES;
                                    g_challengeResponded = NO; // Reset challenge response flag
                                    
                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Extracted RSA cert: %lu bytes Base64 (cleaned from %zd raw bytes, offset=%zd)",
                                         (unsigned long)cleanLen, certLen, certOffset);
                                    DLOG(@"[PUBKEY-EXTRACT] Padding found: %d, Base64 length mod 4: %lu",
                                         foundPadding, (unsigned long)(cleanLen % 4));
                                    
                                    // Log first 80 chars of cert
                                    NSString *certPreview = [[NSString alloc] initWithBytes:(const void *)g_pubKeyBase64 length:MIN((NSUInteger)cleanLen, 80) encoding:NSASCIIStringEncoding];
                                    if (certPreview) {
                                        DLOG(@"[PUBKEY-EXTRACT] Cert starts: %@...", certPreview);
                                    }
                                    // Log last 30 chars
                                    if (cleanLen > 30) {
                                        NSString *certEnd = [[NSString alloc] initWithBytes:(const void *)(g_pubKeyBase64 + cleanLen - 30) length:30 encoding:NSASCIIStringEncoding];
                                        if (certEnd) {
                                            DLOG(@"[PUBKEY-EXTRACT] Cert ends: ...%@", certEnd);
                                        }
                                    }
                                } else {
                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Invalid cert length: %zd (must be 100-%d)", certLen, MAX_PUBKEY_BASE64);
                                }
                            }
                        }
                    } else if (rcmd == 0x80FFF495) {
                        // v36.93: OBSERVATION MODE - Do NOT patch status
                        // Let client handle status=1 naturally:
                        //   status=1 triggers client to send 0x000EE007 + 0x00FFF493 (encrypted)
                        //   Then client calls quitFromServer() → close() is BLOCKED by hook_close
                        // This allows native encrypted login packets to reach the server
                        DLOG(@"[GAME-PATCH] v36.93 OBSERVATION MODE: NOT patching status %u for 0x80FFF495 (let client handle naturally)", status);
                        [detail appendFormat:@"  [OBSERVE] v36.93: 0x80FFF495 status=%u NOT patched (observation mode - let client send native login packets)\n", status];
                        [detail appendFormat:@"  [OBSERVE] v36.93: close() hook will block disconnect if client calls quitFromServer\n"];
                    } else {
                        [detail appendFormat:@"  *** WARNING: Non-zero status on non-handshake packet (cmd=0x%08X) ***\n", rcmd];
                        DLOG(@"[GAME-PATCH] Non-handshake packet (cmd=0x%08X) status=%u left unchanged", rcmd, status);
                    }
                }
            }
            
            // Check for specific error keywords in payload
            if (ret > 12) {
                NSData *payloadData = [NSData dataWithBytes:p+12 length:(NSUInteger)(ret-12)];
                NSString *payloadStr = [[NSString alloc] initWithData:payloadData encoding:NSUTF8StringEncoding];
                if (payloadStr && payloadStr.length > 0) {
                    if ([payloadStr containsString:@"版本过低"] || [payloadStr containsString:@"当前版本"] || 
                        [payloadStr containsString:@"版本太旧"]) {
                        [detail appendFormat:@"  *** ERROR TEXT DETECTED: %@ ***\n", payloadStr];
                        DLOG(@"[GAME-PATCH] Error text found in game server response: %@ (port=%d)", payloadStr, port);
                        // v36.70: RE-ENABLE text clearing with cmd-based detection support
                        if (isGamePort || gameCmdDetected) {
                            static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
                            static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
                                if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                                    DLOG(@"[GAME-PATCH] Cleared '版本过低' at offset %zd (port=%d)", i, port);
                                    memset((unsigned char *)buf + i, ' ', sizeof(verLow));
                                }
                            }
                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
                                if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                                    DLOG(@"[GAME-PATCH] Cleared '当前版本' at offset %zd (port=%d)", i, port);
                                    memset((unsigned char *)buf + i, ' ', sizeof(curVer));
                                }
                            }
                        }
                    }
                }
            }
            
            // v36.57: Categorize known game protocol commands
            if (rcmd == 0x00FFFF01 || rcmd == 0x00FFFF02) {
                [detail appendFormat:@"  [CHALLENGE] Server challenge packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x80FFFF01 || rcmd == 0x80FFFF02) {
                [detail appendFormat:@"  [RESPONSE] Challenge response packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007) {
                [detail appendFormat:@"  [DEVICE-INFO] Device info response (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x00F493 || rcmd == 0x80F493) {
                [detail appendFormat:@"  [ENCRYPTED] Encrypted game data (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x80EE0007 || rcmd == 0x80EE0700) {
                [detail appendFormat:@"  [GAME-PROTO] Game protocol packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd >= 0x80000000) {
                [detail appendFormat:@"  [SERVER-RESP] Server response (cmd=0x%08X)\n", rcmd];
            } else {
                [detail appendFormat:@"  [UNKNOWN] Unknown command (cmd=0x%08X) - possible protocol data\n", rcmd];
            }
            
            // v36.68: Track game server protocol flow (now using global g_handshakeComplete/g_heartbeatCount)
            // After handshake (0x80FFF494), client should send 0x000EE007 (device info)
            // If only heartbeats are being sent, the device info packet may be missing
            
            if (rcmd == 0x80FFF494 || rcmd == 0x80FFF495) {
                if (!g_handshakeComplete) {
                    g_handshakeComplete = YES;
                    g_heartbeatCount = 0;
                    // v36.68: Clear local heartbeat ACK buffer when handshake completes
                    g_localHeartbeatAckLen = 0;
                    g_localHeartbeatAckFd = -1;
                    DLOG(@"[GAME-FLOW] Handshake complete (cmd=0x%08X). Waiting for 0x00FFFF02 challenge...", rcmd);
                    DLOG(@"[GAME-FLOW] v36.79: Auto-responding to 0x00FFFF02 with RSA-encrypted 0x80FFFF02");
                    DLOG(@"[GAME-FLOW] After challenge response, client should send encrypted 0x000EE007 (device info)");
                }
            } else if (g_handshakeComplete && rcmd >= 0x80000000 && rcmd != 0x000EE007) {
                // Count server responses after handshake - these are likely responses to client heartbeats
                g_heartbeatCount++;
                if (g_heartbeatCount == 3) {
                    // v36.93: OBSERVATION MODE - No FALLBACK FORCE-SEND needed
                    // In v36.93, we DON'T patch status, so client sends native encrypted login packets.
                    // close() hook blocks disconnect. If client enters heartbeat loop anyway,
                    // the close block prevents disconnection and server will eventually respond.
                    DLOG(@"[GAME-FLOW] v36.93 OBSERVATION: Received %d server responses after handshake (no FORCE-SEND needed)", g_heartbeatCount);
                    DLOG(@"[GAME-FLOW] v36.93: If client in heartbeat loop, close() hook prevents disconnect");
                }
                if (g_heartbeatCount == 10) {
                    DLOG(@"[GAME-FLOW] v36.93 CRITICAL: %d heartbeats after handshake! close() blocking disconnect.", g_heartbeatCount);
                    DLOG(@"[GAME-FLOW] v36.93: close() hook still active - connection should remain alive");
                }
            }
            
            // Log if 0x000EE007 related responses are received
            if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007 || rcmd == 0x00EE007) {
                DLOG(@"[GAME-FLOW] Device info response received (cmd=0x%08X). Game should be entering now.", rcmd);
                g_handshakeComplete = YES;
                g_heartbeatCount = 0;
            }
            
            // Reset handshake state on disconnect (heartbeat timeout)
            if (g_handshakeComplete && ret == 0) {
                g_handshakeComplete = NO;
                g_heartbeatCount = 0;
                // v36.95: Reset login packets sent flag
                g_loginPacketsSent = NO;
                g_fakeRespInjected = NO;
                // v36.68: Clear all leftover buffers on disconnect
                g_stickyLeftoverLen = 0;
                g_stickyLeftoverFd = -1;
                g_localHeartbeatAckLen = 0;
                g_localHeartbeatAckFd = -1;
                g_deviceInfoSentToGame = NO;
                // v36.84: Clear force handshake state
                g_forceHandshakeComplete = NO;
                g_forceHandshakeFd = -1;
                g_forceHandshakeLen = 0;
                DLOG(@"[GAME-FLOW] Connection closed, resetting handshake state");
            }
            
            DLOG(@"%@", detail);
            
            // v36.77: STICKY PACKET PATCHING (NO SPLITTING) - Return full buffer to client
            // v36.68-36.76 split sticky packets and saved extra bytes for next recv.
            // This BROKE the protocol because client needs to see 0x00FFFF02 
            // challenge IMMEDIATELY after 0x80FFF494 (same recv buffer).
            // Now: patch ALL sub-packets in buffer, return ENTIRE buffer to client.
            // Client's own parser will extract individual packets correctly.
            BOOL patchedExtra = NO;
            ssize_t scanOffset = pktLen;
            while (scanOffset < ret) {
                ssize_t scanRemaining = ret - scanOffset;
                if (scanRemaining < 8) break;
                
                uint32_t scanPktLen = ((uint32_t)p[scanOffset] << 24) | ((uint32_t)p[scanOffset+1] << 16) |
                                      ((uint32_t)p[scanOffset+2] << 8)  | (uint32_t)p[scanOffset+3];
                uint32_t scanCmd    = ((uint32_t)p[scanOffset+4] << 24) | ((uint32_t)p[scanOffset+5] << 16) |
                                      ((uint32_t)p[scanOffset+6] << 8)  | (uint32_t)p[scanOffset+7];
                
                if (scanPktLen < 8 || scanPktLen > 65535) break;
                if (scanPktLen > (uint32_t)scanRemaining) break;
                
                // v36.93: OBSERVATION MODE - No status patching for sticky sub-packets
                // Let client handle all status values naturally
                if (scanRemaining >= 13) {
                    uint8_t scanStatus = p[scanOffset + 12];
                    if (scanStatus != 0 && (scanCmd == 0x80FFF494 || scanCmd == 0x80FFF495)) {
                        DLOG(@"[STICKY-PATCH] v36.93 OBSERVATION: NOT patching status %u for %s sub-packet at offset %zd",
                             scanStatus,
                             scanCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",
                             scanOffset);
                    }
                }
                
                // Log the sub-packet
                DLOG(@"[STICKY-SCAN] Sub-packet at offset %zd: cmd=0x%08X len=%u status=%u",
                     scanOffset, scanCmd, scanPktLen, p[scanOffset + 12]);
                
                // v36.92: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)
                // Let the CLIENT handle the challenge itself. Our auto-response was
                // sending 0x80FFFF02 BEFORE the client could, and the server may have
                // rejected our format (extra status byte, wrong seq, etc.).
                // v36.89 observation confirmed client handles challenge perfectly.
                if (scanCmd == 0x00FFFF02 && scanRemaining >= 28) {
                    DLOG(@"[STICKY-SCAN] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");
                    DLOG(@"[STICKY-SCAN] Challenge data at offset %zd: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                         scanOffset,
                         p[scanOffset+12], p[scanOffset+13], p[scanOffset+14], p[scanOffset+15],
                         p[scanOffset+16], p[scanOffset+17], p[scanOffset+18], p[scanOffset+19],
                         p[scanOffset+20], p[scanOffset+21], p[scanOffset+22], p[scanOffset+23],
                         p[scanOffset+24], p[scanOffset+25], p[scanOffset+26], p[scanOffset+27]);
                }
                
                scanOffset += scanPktLen;
            }
            if (patchedExtra) {
                DLOG(@"[STICKY-PATCH] Patched extra sub-packets in buffer (no splitting, returning full %zd bytes)", ret);
            }
            
            // v36.66: TCP STICKY PACKET DETECTION - Check for multiple packets in one recv
            DLOG(@"[STICKY-DETECT] Starting sticky packet detection: ret=%zd firstPktLen=%u firstCmd=0x%08X", 
                 ret, pktLen, rcmd);
            
            ssize_t offset = 0;
            int subPacketCount = 0;
            BOOL foundSticky = NO;
            while (offset < ret) {
                ssize_t remaining = ret - offset;
                if (remaining < 8) break; // Need at least header
                
                uint32_t subPktLen = ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |
                                     ((uint32_t)p[offset+2] << 8)  | (uint32_t)p[offset+3];
                uint32_t subCmd    = ((uint32_t)p[offset+4] << 24) | ((uint32_t)p[offset+5] << 16) |
                                     ((uint32_t)p[offset+6] << 8)  | (uint32_t)p[offset+7];
                
                // Validate packet length
                if (subPktLen < 8 || subPktLen > 65535) break;
                
                subPacketCount++;
                if (subPacketCount > 1) {
                    foundSticky = YES;
                    DLOG(@"[STICKY-PACKET] Sub-packet #%d at offset %zd: cmd=0x%08X pktLen=%u remaining=%zd", 
                         subPacketCount, offset, subCmd, subPktLen, remaining);
                    
                    // v36.93: OBSERVATION MODE - No status patching for detected sticky sub-packets
                    if (remaining >= 13) {
                        uint8_t subStatus = p[offset + 12];
                        if (subStatus != 0 && (subCmd == 0x80FFF494 || subCmd == 0x80FFF495)) {
                            DLOG(@"[STICKY-PACKET] v36.93 OBSERVATION: NOT patching status %u for %s sub-packet at offset %zd",
                                 subStatus,
                                 subCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",
                                 offset);
                        }
                    }
                }
                
                // v36.93: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)
                if (subCmd == 0x00FFFF02 && remaining >= 28) {
                    DLOG(@"[STICKY-AUTO] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");
                }
                
                // Move to next packet
                if (subPktLen > (uint32_t)remaining) {
                    // Packet extends beyond available data - incomplete packet
                    DLOG(@"[STICKY-PACKET] Incomplete packet at offset %zd: pktLen=%u > remaining=%zd", 
                         offset, subPktLen, remaining);
                    break;
                }
                offset += subPktLen;
            }
            if (foundSticky) {
                DLOG(@"[STICKY-PACKET] Processed %d sub-packets in one recv (total %zd bytes)", subPacketCount, ret);
            } else {
                DLOG(@"[STICKY-DETECT] No sticky packets found (single packet: cmd=0x%08X len=%u)", rcmd, pktLen);
            }
        } @catch (NSException *e) {
            DLOG(@"[GAME-RECV] Exception during analysis: %@", e.reason);
        }
    }
#endif
    
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
        
        if (len >= 8) {
            uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            DLOG(@"[WRITE-CMD] cmd=0x%08X", cmd);
        }
    }
    // NO PACKET MODIFICATION IN WRITE HOOK
    // Version replacement removed - modifying packet data breaks integrity verification
    return orig_write ? orig_write(fd, buf, len) : -1;
}

static ssize_t hook_read(int fd, void *buf, size_t len) {
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_read || !buf) return -1;
    
    ssize_t ret = orig_read(fd, buf, len);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[READ] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-R] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // DETAILED HEX DUMP of server list response
            DLOG(@"[SERVERLIST-HEX2] Full response hex (%zd bytes):", ret);
            for (ssize_t i = 0; i < ret; i += 32) {
                NSMutableString *line = [NSMutableString string];
                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {
                    [line appendFormat:@"%02X ", p[j]];
                }
                DLOG(@"[SERVERLIST-HEX2]   %zd: %@", i, line);
            }
            
            // DISABLED parseServerListResponse for v36.35
            DLOG(@"[SERVERLIST-HEX2] NO PARSING - leaving data untouched");
            
            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {
                DLOG(@"[SERVERLIST-JSON2] JSON response: %@", jsonStr);
            }
        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

            // v36.50: ONLY patch on login server (port=5678), and NEVER truncate!
            if (cmd == 0x802EE121 && ret >= 13 && port == 5678) {
                if (p[12] != 0) {
                    DLOG(@"[PROTO-R-PATCH] Status %u -> 0 (read hook, keeping %zd bytes)", p[12], ret);
                    ((unsigned char *)buf)[12] = 0;
                    // v36.50: Do NOT truncate! Game needs full response with sessionId
                }
            }
        }
    }
    
    // v36.50: Remove '版本过低' clearing from read hook - it's handled in recv hook only
    // read hook should NOT modify any data to avoid double-patching issues
    
    return ret;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom || !buf) return -1;
    
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) return ret;
    
    if (src_addr && addrlen && *addrlen > 0) {
        char host[64] = "unknown";
        int port = 0;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
            port = ntohs(in->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            port = ntohs(in6->sin6_port);
        }
        if (port != 0) {
            updateFdHostPort(fd, host, port);
        }
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECVFROM] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-RF] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // RESTORED: Patch injection-detection error responses
        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {
            DLOG(@"[PROTO-RF] Version/auth response 0x%08X", cmd);
            if (ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-RF-PATCH] Status %u -> 0 (injection detection)", p[12]);
                ((unsigned char *)buf)[12] = 0;
            }
        }
    }
    
    // RESTORED: Clear '版本过低' messages
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-RF] Cleared '版本过低' at offset %zd", i);
            memset((unsigned char *)buf + i, ' ', sizeof(verLow));
        }
    }
    
    return ret;
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;
    
    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0) return ret;
    
    if (msg->msg_name && msg->msg_namelen > 0) {
        struct sockaddr *src_addr = (struct sockaddr *)msg->msg_name;
        char host[64] = "unknown";
        int port = 0;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
            port = ntohs(in->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            port = ntohs(in6->sin6_port);
        }
        if (port != 0) {
            updateFdHostPort(fd, host, port);
        }
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    struct iovec *iov = msg->msg_iov;
    if (!iov->iov_base || iov->iov_len == 0) return ret;
    
    const unsigned char *p = (const unsigned char *)iov->iov_base;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECVMSG] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);
    
    if (ret >= 8 && iov->iov_len >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-RM] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // RESTORED: Patch injection-detection error responses
        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {
            DLOG(@"[PROTO-RM] Version/auth response 0x%08X", cmd);
            if (iov->iov_len >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-RM-PATCH] Status %u -> 0 (injection detection)", p[12]);
                ((unsigned char *)iov->iov_base)[12] = 0;
            }
        }
    }
    
    // RESTORED: Clear '版本过低' messages
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow) && i <= (ssize_t)iov->iov_len - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-RM] Cleared '版本过低' at offset %zd", i);
            memset((unsigned char *)iov->iov_base + i, ' ', sizeof(verLow));
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
    orig_recvfrom = NULL;
    orig_recvmsg = NULL;
    orig_write = NULL;
    orig_read = NULL;
    orig_close = NULL;
    orig_getsockopt = NULL;
    
    int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);
    int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);
    int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
    int w = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);
    int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);
    int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);
    int gs = rebindSymbol("_getsockopt", (void *)hook_getsockopt, (void **)&orig_getsockopt);
    int p = rebindSymbol("_poll", (void *)hook_poll, (void **)&orig_poll);
    int sel = rebindSymbol("_select", (void *)hook_select, (void **)&orig_select);
    
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");
    if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");
    if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");
    
    DLOG(@"[SOCK] Hooks: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d write=%d read=%d close=%d getsockopt=%d poll=%d select=%d", c, s, r, rf, rm, w, rd, cl, gs, p, sel);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p write=%p read=%p close=%p getsockopt=%p poll=%p select=%p", 
         orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg, orig_write, orig_read, orig_close, orig_getsockopt, orig_poll, orig_select);
    
    if (!orig_connect) DLOG(@"[SOCK-ERROR] connect hook failed - network monitoring disabled!");
    if (!orig_send) DLOG(@"[SOCK-ERROR] send hook failed - outgoing data monitoring disabled!");
    if (!orig_recv) DLOG(@"[SOCK-ERROR] recv hook failed - incoming data monitoring disabled!");
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
#pragma mark - dlsym Hook (hide hook framework symbols)
// ============================================================

typedef void* (*DlsymFunc)(void *, const char *);
static DlsymFunc orig_dlsym = NULL;

static void* hook_dlsym(void *handle, const char *symbol) {
    if (!orig_dlsym) {
        void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
        if (libdyld) {
            orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");
        }
    }
    if (!orig_dlsym) return NULL;
    
    NSString *symStr = [NSString stringWithUTF8String:symbol];
    NSString *lowerSym = [symStr lowercaseString];
    
    const char *hiddenSymbols[] = {
        "substrate", "fishhook", "mshookfunction", "rebind_symbols",
        "mshookmsg", "mshookclass", "mshookselector",
        "cydia", "cydiasubstrate", "theos",
        NULL
    };
    
    for (int i = 0; hiddenSymbols[i]; i++) {
        if ([lowerSym containsString:[NSString stringWithUTF8String:hiddenSymbols[i]]]) {
            DLOG(@"[DLSYM-HIDE] Returning NULL for symbol: '%s'", symbol);
            return NULL;
        }
    }
    
    void *result = orig_dlsym(handle, symbol);
    if (result) {
        DLOG(@"[DLSYM-LOG] symbol='%s' -> %p", symbol, result);
    }
    return result;
}

static void installDlsymHook(void) {
    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
    if (libdyld) {
        orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");
        rebindSymbol("_dlsym", (void *)hook_dlsym, (void **)&orig_dlsym);
        DLOG(@"[DLSYM-HOOK] Installed, orig=%p", orig_dlsym);
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

#pragma mark - CCCrypt / SecKey Hooks

typedef int (*CCCryptFunc)(uint32_t op, uint32_t alg, uint32_t options,
                           const void *key, size_t keyLen,
                           const void *iv,
                           const void *dataIn, size_t dataInLen,
                           void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static CCCryptFunc orig_CCCrypt = NULL;

static int hook_CCCrypt(uint32_t op, uint32_t alg, uint32_t options,
                        const void *key, size_t keyLen,
                        const void *iv,
                        const void *dataIn, size_t dataInLen,
                        void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    if (!orig_CCCrypt) orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");
    if (!orig_CCCrypt) return -1;
    
    const char *opStr = (op == 0) ? "ENC" : "DEC";
    DLOG(@"[CC-AES] #%d %s inLen=%zu keyLen=%zu", op, opStr, dataInLen, keyLen);
    
    int ret = orig_CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved);
    
    if (dataOutMoved && *dataOutMoved > 0) {
        DLOG(@"[CC-AES-OUT] #%d %s len=%zu", op, opStr, *dataOutMoved);
    }
    return ret;
}

typedef OSStatus (*SecKeyEncryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen);
static SecKeyEncryptFunc orig_SecKeyEncrypt = NULL;

static OSStatus hook_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {
    if (!orig_SecKeyEncrypt) orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");
    if (!orig_SecKeyEncrypt) return errSecParam;
    DLOG(@"[SEC] SecKeyEncrypt plainLen=%zu cipherLen=%zu", plainTextLen, cipherTextLen ? *cipherTextLen : 0);
    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
}

typedef OSStatus (*SecKeyDecryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen);
static SecKeyDecryptFunc orig_SecKeyDecrypt = NULL;

static OSStatus hook_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {
    if (!orig_SecKeyDecrypt) orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");
    if (!orig_SecKeyDecrypt) return errSecParam;
    OSStatus ret = orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
    DLOG(@"[SEC] SecKeyDecrypt cipherLen=%zu plainLen=%zu ret=%d", cipherTextLen, plainTextLen ? *plainTextLen : 0, (int)ret);
    return ret;
}

// SecKeyCreateDecryptedData hook (iOS 10+)
// CORRECT signature: CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);
typedef CFDataRef (*SecKeyCreateDecryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);
static SecKeyCreateDecryptedDataFunc orig_SecKeyCreateDecryptedData = NULL;

static CFDataRef hook_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error) {
    if (!orig_SecKeyCreateDecryptedData) {
        orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");
    }
    if (!orig_SecKeyCreateDecryptedData) return NULL;
    CFErrorRef *errPtr = NULL;
    CFDataRef result = orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, errPtr);
    if (errPtr && *errPtr) {
        DLOG(@"[SEC] SecKeyCreateDecryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));
    } else if (result) {
        DLOG(@"[SEC] SecKeyCreateDecryptedData SUCCESS: cipherLen=%lu plainLen=%lu", 
             ciphertext ? CFDataGetLength(ciphertext) : 0, CFDataGetLength(result));
    } else {
        DLOG(@"[SEC] SecKeyCreateDecryptedData returned NULL");
    }
    return result;
}

// SecKeyCreateEncryptedData hook (iOS 10+)
// CORRECT signature: CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
typedef CFDataRef (*SecKeyCreateEncryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
static SecKeyCreateEncryptedDataFunc orig_SecKeyCreateEncryptedData = NULL;

static CFDataRef hook_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error) {
    if (!orig_SecKeyCreateEncryptedData) {
        orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");
    }
    if (!orig_SecKeyCreateEncryptedData) return NULL;
    CFErrorRef *errPtr = NULL;
    CFDataRef result = orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, errPtr);
    if (errPtr && *errPtr) {
        DLOG(@"[SEC] SecKeyCreateEncryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));
    } else if (result) {
        DLOG(@"[SEC] SecKeyCreateEncryptedData SUCCESS: plainLen=%lu cipherLen=%lu", 
             plaintext ? CFDataGetLength(plaintext) : 0, CFDataGetLength(result));
    } else {
        DLOG(@"[SEC] SecKeyCreateEncryptedData returned NULL");
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
    installDlsymHook();
    
    // Hook fopen/fgets for /proc/self/maps (Linux fallback)
    void *syslib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);
    if (syslib) {
        void *fp = dlsym(syslib, "fopen");
        void *fg = dlsym(syslib, "fgets");
        DLOG(@"[SEC] libSystem: fopen=%p fgets=%p", fp, fg);
    }
    
#if !DISABLE_CRYPTO_HOOKS
    // Hook CCCrypt for AES encryption logging
    orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");
    if (orig_CCCrypt) {
        int r1 = rebindSymbol("_CCCrypt", (void *)hook_CCCrypt, (void **)&orig_CCCrypt);
        DLOG(@"[SEC] CCCrypt hook: rebind=%d addr=%p", r1, orig_CCCrypt);
    } else {
        DLOG(@"[SEC] CCCrypt not found via dlsym");
    }
    
    // Hook SecKeyEncrypt / SecKeyDecrypt for RSA logging
    orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");
    if (orig_SecKeyEncrypt) {
        int r2 = rebindSymbol("_SecKeyEncrypt", (void *)hook_SecKeyEncrypt, (void **)&orig_SecKeyEncrypt);
        DLOG(@"[SEC] SecKeyEncrypt hook: rebind=%d addr=%p", r2, orig_SecKeyEncrypt);
    }
    
    orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");
    if (orig_SecKeyDecrypt) {
        int r3 = rebindSymbol("_SecKeyDecrypt", (void *)hook_SecKeyDecrypt, (void **)&orig_SecKeyDecrypt);
        DLOG(@"[SEC] SecKeyDecrypt hook: rebind=%d addr=%p", r3, orig_SecKeyDecrypt);
    }
    
    // Hook SecKeyCreateDecryptedData (iOS 10+ decrypt API)
    orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");
    if (orig_SecKeyCreateDecryptedData) {
        int r4 = rebindSymbol("_SecKeyCreateDecryptedData", (void *)hook_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData);
        DLOG(@"[SEC] SecKeyCreateDecryptedData hook: rebind=%d addr=%p", r4, orig_SecKeyCreateDecryptedData);
    }
    
    // Hook SecKeyCreateEncryptedData (iOS 10+ encrypt API)
    orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");
    if (orig_SecKeyCreateEncryptedData) {
        int r5 = rebindSymbol("_SecKeyCreateEncryptedData", (void *)hook_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData);
        DLOG(@"[SEC] SecKeyCreateEncryptedData hook: rebind=%d addr=%p", r5, orig_SecKeyCreateEncryptedData);
    }
#else
    DLOG(@"[SEC] Crypto hooks DISABLED (v36.47 fix - avoid corrupting encryption data)");
#endif
    
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

// NSDictionary objectForKey: - trace server list parsing (minimal logging)
static id (*orig_dictObjectForKey)(id, SEL, id) = NULL;
static int g_dictLogCount = 0;
static id hook_dictObjectForKey(id self, SEL _cmd, id key) {
    id ret = orig_dictObjectForKey ? orig_dictObjectForKey(self, _cmd, key) : nil;
    // Limit logging to first 30 calls to avoid performance issues during keyboard input
    if (g_dictLogCount < 30) {
        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
            [keyStr containsString:@"status"] || [keyStr containsString:@"Status"] ||
            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
            NSString *retCls = ret ? NSStringFromClass([ret class]) : @"nil";
            DLOG(@"[DICT] objectForKey:'%@' -> %@ (%@)", keyStr, ret ?: @"nil", retCls);
            g_dictLogCount++;
        }
    }
    return ret;
}

// NSArray arrayForKey: - for JSON parsing (minimal logging)
static id (*orig_arrayForKey)(id, SEL, id) = NULL;
static int g_arrayLogCount = 0;
static id hook_arrayForKey(id self, SEL _cmd, id key) {
    id ret = orig_arrayForKey ? orig_arrayForKey(self, _cmd, key) : nil;
    // Limit logging to first 20 calls to avoid performance issues during keyboard input
    if (g_arrayLogCount < 20) {
        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
            NSUInteger cnt = 0;
            if ([ret isKindOfClass:[NSArray class]]) cnt = [ret count];
            DLOG(@"[DICT] arrayForKey:'%@' -> count=%lu", keyStr, (unsigned long)cnt);
            g_arrayLogCount++;
        }
    }
    return ret;
}

// NSURLSession.dataTaskWithRequest:completionHandler: - intercept and modify responses
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static DTReqCompIMP orig_dtwrc = NULL;
static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = req.URL.absoluteString;
    DLOG(@"[NET] URL: %@", url);
    
    // Wrap completion handler to intercept and modify response
    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;
    if (comp) {
        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSHTTPURLResponse *httpResp = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;
            DLOG(@"[NET] Response: status=%ld url=%@ err=%@ bodyLen=%lu",
                 httpResp ? (long)httpResp.statusCode : -1, url, err, (unsigned long)data.length);
            
            if (data && data.length > 0) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                
                if (body) {
                    DLOG(@"[NET] Body: %@", body);
                    
                    // Check if this is a server list response
                    BOOL isServerList = ([body containsString:@"server"] || [body containsString:@"servers"] || 
                                        [body containsString:@"serverCount"] || [body containsString:@"serverid"]);
                    
                    // Check if response indicates empty/no servers
                    BOOL isEmptyList = ([body containsString:@"\"serverCount\":0"] || 
                                        [body containsString:@"\"servers\":[]"] ||
                                        [body containsString:@"\"status\":5"] ||
                                        [body containsString:@"\"result\":\"fail\""]);
                    
                    if (isServerList && isEmptyList) {
                        DLOG(@"[NET-PATCH] Server list is empty, replacing with fake data");
                        NSString *fakeServerList = @"{\"status\":0,\"serverCount\":1,\"servers\":[{\"serverid\":1,\"name\":\"测试一区\",\"realname\":\"测试一区\",\"category\":\"一区\",\"serverType\":1,\"ip\":\"127.0.0.1\",\"port\":5678,\"status\":1,\"clientid\":1,\"onlinePlayerNum\":100,\"description\":\"运行\"}]}";
                        data = [fakeServerList dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Replaced with fake server list, new len=%lu", (unsigned long)data.length);
                    }
                    
                    // Check for version error
                    if ([body containsString:@"版本"] || [body containsString:@"更新"] || 
                        [body containsString:@"升级"] || [body containsString:@"版本过低"]) {
                        DLOG(@"[NET-PATCH] Detected version error, modifying...");
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":5" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"result\":\"fail\"" withString:@"\"result\":\"success\""];
                        body = [body stringByReplacingOccurrencesOfString:@"版本过低" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"请更新" withString:@""];
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                    }
                    
                    // Patch judgeAppInfoApi response: extend ENDTIME to future date
                    if ([url containsString:@"judgeAppInfoApi"] || [body containsString:@"ENDTIME"]) {
                        DLOG(@"[NET-PATCH] Detected judgeAppInfoApi response, extending ENDTIME");
                        // Replace any ENDTIME value with a future date (2027-12-31)
                        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];
                        body = [regex stringByReplacingMatchesInString:body options:0 range:NSMakeRange(0, body.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];
                        // Ensure END=0 (not ended) and OPEN=1 (open)
                        body = [body stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];
                        // Ensure code=1 (success) instead of code=0
                        body = [body stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Patched judgeAppInfoApi: ENDTIME extended, END=0, OPEN=1, code=1");
                    }
                    
                    // Patch any sign/cert API response to success
                    if ([url containsString:@"judgeAppInfoSignApi"] || [url containsString:@"postAppInfoApi"] || [url containsString:@"getAppInfoApi"]) {
                        DLOG(@"[NET-PATCH] Detected cert/sign API response, ensuring success");
                        if ([body containsString:@"\"code\":0"]) {
                            body = [body stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
                            data = [body dataUsingEncoding:NSUTF8StringEncoding];
                            DLOG(@"[NET-PATCH] Patched cert API code:0 -> 1");
                        }
                    }
                }
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

// UIViewController.presentViewController - OBSERVE + VERSION ALERT BLOCKING
// NOTE: presentViewController:animated:completion: is called ON THE PRESENTING VC,
// NOT on the presented VC. So we must hook UIViewController's version, not UIAlertController's!
// The previous hook on UIAlertController was NEVER triggered, and had WRONG param order causing SIGSEGV.
typedef void (*PresentVC_IMP)(id, SEL, UIViewController *, BOOL, void (^)(void));
static PresentVC_IMP orig_presentVC = NULL;
static void hook_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    @try {
        // Check if presented VC is UIAlertController - block version-related alerts HERE
        if (vc && [vc isKindOfClass:[UIAlertController class]]) {
            @try {
                UIAlertController *alert = (UIAlertController *)vc;
                NSString *title = [alert title];
                NSString *msg = [alert message];
                NSString *presenterClass = NSStringFromClass([self class]);
                DLOG(@"[UI] presentVC: UIAlertController title='%@' msg='%@' presenter=%@",
                     title ? title : @"<nil>", msg ? msg : @"<nil>", presenterClass);
                
                if (title || msg) {
                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";
                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";
                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] ||
                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||
                        [lowerMsg containsString:@"update"]) {
                        DLOG(@"[ALERT-BLOCK] Blocked version alert in hook_presentVC: title='%@' msg='%@'",
                             title ? title : @"", msg ? msg : @"");
                        return;  // Do NOT present!
                    }
                }
            } @catch (NSException *e) {
                DLOG(@"[UI] Exception checking alert: %@", e.reason);
                // Passthrough on error - don't lose the alert completely
            }
        } else {
            NSString *vcClass = vc ? NSStringFromClass([vc class]) : @"<nil>";
            DLOG(@"[UI] presentVC: %@ presenter=%@", vcClass, NSStringFromClass([self class]));
        }
    } @catch (NSException *e) {
        DLOG(@"[UI] Outer exception in hook_presentVC: %@", e.reason);
    }
    
    // Always call original (unless we returned early for blocked alerts)
    // Safe completion: copy to heap, fallback to empty block
    void (^safeCompletion)(void) = NULL;
    if (completion) {
        @try {
            safeCompletion = [completion copy];
        } @catch (...) {
            safeCompletion = NULL;
        }
    }
    if (!safeCompletion) {
        safeCompletion = ^{};
    }
    
    if (orig_presentVC) {
        orig_presentVC(self, _cmd, vc, animated, safeCompletion);
    }
}

// ============================================================
#pragma mark - Constructor - MINIMAL + observer hooks
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    if (!g_isActivated) {
        DLOG(@"[ACT] Not activated, waiting for activation...");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!g_isActivated) {
                DLOG(@"[ACT] Still not activated after 3 seconds");
            }
        });
        return;
    }
    
    installAllHooks();
}

static void installAllHooks(void) {
    DLOG(@"[VERSION] WangXianHook v36.109 - Fix SIGSEGV crash, all responses minimal 16-byte header only");
    DLOG(@"[ACT] Installing all hooks...");
    
#if !DISABLE_CRYPTO_HOOKS
    installSecurityHooks();
#endif
    installKeyboardProtection();
    
    orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    DLOG(@"[SOCK] Fallback originals: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p", orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg);
    
    installSocketHooks();
    
    // v36.103: Proactively patch C++ disconnect/heartbeat functions
    proactivePatchCppFunctions();
    
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
    
    // === DIAGNOSTIC: UIAlertView show hook ===
    Class alertCls = [UIAlertView class];
    if (alertCls) {
        Method m = class_getInstanceMethod(alertCls, @selector(show));
        if (m) { orig_alertViewShow = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertViewShow); _log(@"[INIT] UIAlertView.show: hook"); }
    }
    
    // === DIAGNOSTIC: UIAlertController hook ===
    // v36.59: REMOVED the UIAlertController.presentViewController hook!
    // REASON: presentViewController:animated:completion: is called ON THE PRESENTING VC,
    //         not on the UIAlertController itself. So this method was NEVER triggered.
    //         Worse, the function signature was WRONG (missing viewController param) which
    //         caused SIGSEGV when the IMP was called.
    //         The version alert blocking is NOW correctly done in hook_presentVC (UIViewController).
    // Class alertCtrlCls = [UIAlertController class];
    // if (alertCtrlCls) {
    //     Method m = class_getInstanceMethod(alertCtrlCls, @selector(presentViewController:animated:completion:));
    //     if (m) { orig_alertControllerPresent = ...; ... }
    // }
    _log(@"[INIT] UIAlertController: using correct hook_presentVC from UIViewController (blocked old sigfault hook)");
    
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
        if (m) { orig_judgeBase = (JudgeBaseIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeBase); _log(@"[INIT] SK.judgeAppInfoWithBaseUrl: ORIG"); }
        
        m = class_getClassMethod(skCls, @selector(handleAppInfoResult:));
        if (m) { orig_handleResult = (HandleResultIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_handleResult); _log(@"[INIT] SK.handleAppInfoResult: LOG"); }
        
        m = class_getClassMethod(skCls, @selector(judgeNet));
        if (m) { orig_judgeNet = (JudgeNetIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeNet); _log(@"[INIT] SK.judgeNet: BLOCK"); }
        
        m = class_getClassMethod(skCls, @selector(verifySignatureFromParameters:));
        if (m) { orig_verifySig = (VerifySigIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_verifySig); _log(@"[INIT] SK.verifySignatureFromParameters: ORIG"); }
        
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
        
        // Hook reloadData to detect when server list table is reloaded
        Method reloadData = class_getInstanceMethod(tableViewCls, @selector(reloadData));
        if (reloadData) {
            IMP orig_reload = method_getImplementation(reloadData);
            IMP new_reload = imp_implementationWithBlock(^(id self, SEL _cmd) {
                NSString *clsName = NSStringFromClass([self class]);
                DLOG(@"[TV-RELOAD] -[%@ reloadData] called", clsName);
                
                @try {
                    id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;
                    if (dataSource) {
                        NSString *dsCls = NSStringFromClass([dataSource class]);
                        DLOG(@"[TV-RELOAD] dataSource=%@", dsCls);
                        
                        if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {
                            id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];
                            if ([serverList isKindOfClass:[NSArray class]]) {
                                DLOG(@"[TV-RELOAD] serverList count=%lu", (unsigned long)[serverList count]);
                            }
                        }
                        
                        if ([dataSource respondsToSelector:@selector(numberOfSections)]) {
                            NSNumber *sectionsNum = [dataSource performSelector:@selector(numberOfSections)];
                            NSInteger sections = [sectionsNum integerValue];
                            DLOG(@"[TV-RELOAD] numberOfSections=%ld", (long)sections);
                            for (NSInteger s = 0; s < sections; s++) {
                                if ([dataSource respondsToSelector:@selector(numberOfRowsInSection:)]) {
                                    NSNumber *rowsNum = [dataSource performSelector:@selector(numberOfRowsInSection:) withObject:@(s)];
                                    NSInteger rows = [rowsNum integerValue];
                                    DLOG(@"[TV-RELOAD] numberOfRowsInSection:%ld=%ld", (long)s, (long)rows);
                                }
                            }
                        }
                    }
                } @catch (NSException *e) {
                    DLOG(@"[TV-RELOAD] Exception: %@", e);
                }
                
                ((void(*)(id, SEL))orig_reload)(self, _cmd);
            });
            method_setImplementation(reloadData, new_reload);
            DLOG(@"[TV-HOOK] Hooked UITableView reloadData");
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
    
    // === DEFERRED: Hook ALL crypto-related classes for RSA tracing ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            // v36.77: Search for ALL crypto-related classes in the game binary
            // EncryptUtils is a WeChat class, not the game's crypto handler
            NSArray *cryptoKeywords = @[@"Encrypt", @"Crypto", @"RSA", @"Cert", @"Key", 
                                         @"Session", @"Token", @"Login", @"Handshake",
                                         @"Protocol", @"Message", @"Network", @"Socket"];
            
            NSMutableArray *foundClasses = [NSMutableArray array];
            unsigned int totalClassCount = 0;
            Class *allClasses = objc_copyClassList(&totalClassCount);
            
            for (unsigned int i = 0; i < totalClassCount; i++) {
                Class cls = allClasses[i];
                NSString *clsName = NSStringFromClass(cls);
                if (!clsName) continue;
                
                // Skip Apple system classes (NS, UI, CA, etc.)
                if ([clsName hasPrefix:@"NS"] || [clsName hasPrefix:@"UI"] || 
                    [clsName hasPrefix:@"CA"] || [clsName hasPrefix:@"CF"] ||
                    [clsName hasPrefix:@"CG"] || [clsName hasPrefix:@"AB"] ||
                    [clsName hasPrefix:@"SK"] || [clsName hasPrefix:@"GK"] ||
                    [clsName hasPrefix:@"PK"] || [clsName hasPrefix:@"LK"] ||
                    [clsName hasPrefix:@"MK"] || [clsName hasPrefix:@"IK"] ||
                    [clsName hasPrefix:@"NE"] || [clsName hasPrefix:@"CK"] ||
                    [clsName hasPrefix:@"MS"] || [clsName hasPrefix:@"MC"] ||
                    [clsName hasPrefix:@"CL"] || [clsName hasPrefix:@"AL"] ||
                    [clsName hasPrefix:@"AV"] || [clsName hasPrefix:@"BE"] ||
                    [clsName hasPrefix:@"BF"] || [clsName hasPrefix:@"AB"] ||
                    [clsName hasPrefix:@"SP"] || [clsName hasPrefix:@"WK"] ||
                    [clsName hasPrefix:@"TP"] || [clsName hasPrefix:@"TL"] ||
                    [clsName hasPrefix:@"VM"] || [clsName hasPrefix:@"IM"] ||
                    [clsName hasPrefix:@"NS"] || [clsName hasPrefix:@"CF"] ||
                    [clsName hasPrefix:@"UIV"] || [clsName hasPrefix:@"NSV"]) {
                    continue;
                }
                
                // Check if class name contains crypto-related keywords
                BOOL isCryptoRelated = NO;
                for (NSString *keyword in cryptoKeywords) {
                    if ([clsName containsString:keyword]) {
                        isCryptoRelated = YES;
                        break;
                    }
                }
                
                if (isCryptoRelated) {
                    // Get both instance AND class methods
                    unsigned int instCount = 0;
                    Method *instMethods = class_copyMethodList(cls, &instCount);
                    
                    Class metaCls = object_getClass(cls);
                    unsigned int clsCount = 0;
                    Method *clsMethods = class_copyMethodList(metaCls, &clsCount);
                    
                    unsigned int totalMethods = instCount + clsCount;
                    
                    // Only log classes with methods (skip empty/placeholder classes)
                    if (totalMethods > 0 && totalMethods < 200) {
                        NSMutableString *methodList = [NSMutableString string];
                        
                        // List instance methods
                        for (unsigned int j = 0; j < instCount; j++) {
                            SEL sel = method_getName(instMethods[j]);
                            NSString *selName = NSStringFromSelector(sel);
                            [methodList appendFormat:@"\n    -%@", selName];
                        }
                        
                        // List class methods
                        for (unsigned int j = 0; j < clsCount; j++) {
                            SEL sel = method_getName(clsMethods[j]);
                            NSString *selName = NSStringFromSelector(sel);
                            [methodList appendFormat:@"\n    +%@", selName];
                        }
                        
                        DLOG(@"[CRYPTO-CLASS] %@ (%u methods total: %u inst, %u cls)%@", 
                             clsName, totalMethods, instCount, clsCount, methodList);
                        [foundClasses addObject:clsName];
                    }
                    
                    if (instMethods) free(instMethods);
                    if (clsMethods) free(clsMethods);
                }
            }
            if (allClasses) free(allClasses);
            
            DLOG(@"[CRYPTO-CLASS] Found %lu crypto-related classes", (unsigned long)foundClasses.count);
            
            // v36.77: Also specifically check EncryptUtils with metaclass
            Class encryptUtilsCls = NSClassFromString(@"EncryptUtils");
            if (encryptUtilsCls) {
                unsigned int instCount = 0;
                Method *instMethods = class_copyMethodList(encryptUtilsCls, &instCount);
                Class metaCls = object_getClass(encryptUtilsCls);
                unsigned int clsCount = 0;
                Method *clsMethods = class_copyMethodList(metaCls, &clsCount);
                
                DLOG(@"[ENCRYPT-UTILS] EncryptUtils: %u inst methods, %u cls methods", instCount, clsCount);
                
                NSMutableString *allMethods = [NSMutableString stringWithString:@"[ENCRYPT-UTILS] Instance methods:"];
                for (unsigned int i = 0; i < instCount; i++) {
                    SEL sel = method_getName(instMethods[i]);
                    [allMethods appendFormat:@"\n  -%@", NSStringFromSelector(sel)];
                }
                DLOG(@"%@", allMethods);
                
                NSMutableString *clsMethodList = [NSMutableString stringWithString:@"[ENCRYPT-UTILS] Class methods:"];
                for (unsigned int i = 0; i < clsCount; i++) {
                    SEL sel = method_getName(clsMethods[i]);
                    [clsMethodList appendFormat:@"\n  +%@", NSStringFromSelector(sel)];
                }
                DLOG(@"%@", clsMethodList);
                
                // v36.78: DO NOT hook EncryptUtils methods - va_list forwarding causes SIGSEGV
                // The game IS calling EncryptUtils (confirmed in v36.77 logs)
                // We just log the method names for reference, no hooking needed
                DLOG(@"[ENCRYPT-UTILS] %u inst + %u cls methods listed (no hooking - va_list crash risk)", instCount, clsCount);
                if (instMethods) free(instMethods);
                if (clsMethods) free(clsMethods);
            }
        } @catch (NSException *e) {
            DLOG(@"[CRYPTO-CLASS] Exception: %@", e);
        }
    });
    
    // === v36.96: Enhanced NetImpl/SocketClient hook ===
    // Try multiple approaches to prevent client disconnect after fake response
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        @try {
            DLOG(@"[NETIMPL-HOOK] v36.96: Starting enhanced search for disconnect functions...");
            
            // === Approach 1: Hook SocketClient send/recv to suppress network errors ===
            // The client may check socket state after recv returns 0
            // By hooking SocketClient, we can prevent error propagation
            NSArray *socketClsNames = @[@"SocketClient", @"Socket", @"TCPSocket", @"GameSocket", @"NetworkSocket"];
            for (NSString *clsName in socketClsNames) {
                Class cls = NSClassFromString(clsName);
                if (cls) {
                    DLOG(@"[NETIMPL-HOOK] v36.96: Found socket class: %@", clsName);
                    unsigned int mcount = 0;
                    Method *methods = class_copyMethodList(cls, &mcount);
                    for (unsigned int i = 0; i < mcount; i++) {
                        SEL sel = method_getName(methods[i]);
                        NSString *selName = NSStringFromSelector(sel);
                        // Hook methods that could trigger disconnect
                        if ([selName containsString:@"onDisconnect"] || [selName containsString:@"onError"] ||
                            [selName containsString:@"didDisconnect"] || [selName containsString:@"connectionLost"] ||
                            [selName containsString:@"networkError"] || [selName containsString:@"onNetworkError"]) {
                            DLOG(@"[NETIMPL-HOOK] v36.96: Hooking %@.%@", clsName, selName);
                            IMP noopImpl = imp_implementationWithBlock(^(void) {
                                DLOG(@"[NETIMPL-SUPPRESS] v36.96: SUPPRESSED %@.%@ (no-op)", clsName, selName);
                            });
                            method_setImplementation(methods[i], noopImpl);
                            if (!g_quitFromServerHooked) g_quitFromServerHooked = YES;
                        }
                    }
                    if (methods) free(methods);
                }
            }
            
            // === Approach 2: Search ALL images using dlopen for C++ disconnect functions ===
            DLOG(@"[NETIMPL-HOOK] v36.97: Searching ALL images using dlopen for C++ functions...");
            int imageCount = _dyld_image_count();
            
            // Lists of mangled names to search
            const char *disconnectNames[] = {
                "_ZN7NetImpl14quitFromServerEv",
                "_ZN7NetImpl13quitFromServerEv",
                "_ZN7NetImpl14quitFromServerEiv",
                "_ZN12SocketClient14quitFromServerEv",
                "_ZN12SocketClient13quitFromServerEv",
                "_ZN7NetImpl10disconnectEv",
                "_ZN12SocketClient10disconnectEv",
                "_ZN7NetImpl9closeGameEv",
                "_ZN12SocketClient9closeGameEv",
                NULL
            };
            
            const char *heartbeatNames[] = {
                "_ZN7NetImpl9heartbeatEv",
                "_ZN7NetImpl14sendHeartbeatEv",
                "_ZN7NetImpl15processHeartbeatEv",
                "_ZN12SocketClient14sendHeartbeatEv",
                "_ZN7NetImpl12checkConnectionEv",
                "_ZN12SocketClient12checkConnectionEv",
                NULL
            };
            
            void *foundDisconnectFunc = NULL;
            void *foundHeartbeatFunc = NULL;
            char foundDisconnectName[256] = {0};
            char foundHeartbeatName[256] = {0};
            
            // Search using dlopen (correct way to get symbol from specific image)
            for (int idx = 0; idx < imageCount; idx++) {
                const char *imageName = _dyld_get_image_name(idx);
                if (!imageName) continue;
                
                // Skip our own dylib
                if (strstr(imageName, "WangXianHook") || strstr(imageName, "lnSignature")) continue;
                
                void *handle = dlopen(imageName, RTLD_NOLOAD | RTLD_LAZY);
                if (!handle) continue;
                
                // Search disconnect functions
                for (int n = 0; disconnectNames[n] != NULL; n++) {
                    void *sym = dlsym(handle, disconnectNames[n]);
                    if (sym) {
                        foundDisconnectFunc = sym;
                        strncpy(foundDisconnectName, disconnectNames[n], sizeof(foundDisconnectName) - 1);
                        DLOG(@"[NETIMPL-HOOK] v36.97: FOUND disconnect: %s in image[%d]: %s at %p", 
                             disconnectNames[n], idx, imageName, foundDisconnectFunc);
                        break;
                    }
                }
                
                // Search heartbeat functions
                for (int n = 0; heartbeatNames[n] != NULL; n++) {
                    void *sym = dlsym(handle, heartbeatNames[n]);
                    if (sym) {
                        foundHeartbeatFunc = sym;
                        strncpy(foundHeartbeatName, heartbeatNames[n], sizeof(foundHeartbeatName) - 1);
                        DLOG(@"[NETIMPL-HOOK] v36.97: FOUND heartbeat: %s in image[%d]: %s at %p", 
                             heartbeatNames[n], idx, imageName, foundHeartbeatFunc);
                        break;
                    }
                }
                
                dlclose(handle);
                
                if (foundDisconnectFunc && foundHeartbeatFunc) break;
            }
            
            // === Approach 3: Try RTLD_DEFAULT as fallback ===
            if (!foundDisconnectFunc) {
                for (int n = 0; disconnectNames[n] != NULL; n++) {
                    void *sym = dlsym(RTLD_DEFAULT, disconnectNames[n]);
                    if (sym) {
                        foundDisconnectFunc = sym;
                        strncpy(foundDisconnectName, disconnectNames[n], sizeof(foundDisconnectName) - 1);
                        DLOG(@"[NETIMPL-HOOK] v36.97: FOUND disconnect via RTLD_DEFAULT: %s at %p", 
                             disconnectNames[n], foundDisconnectFunc);
                        break;
                    }
                }
            }
            
            if (!foundHeartbeatFunc) {
                for (int n = 0; heartbeatNames[n] != NULL; n++) {
                    void *sym = dlsym(RTLD_DEFAULT, heartbeatNames[n]);
                    if (sym) {
                        foundHeartbeatFunc = sym;
                        strncpy(foundHeartbeatName, heartbeatNames[n], sizeof(foundHeartbeatName) - 1);
                        DLOG(@"[NETIMPL-HOOK] v36.97: FOUND heartbeat via RTLD_DEFAULT: %s at %p", 
                             heartbeatNames[n], foundHeartbeatFunc);
                        break;
                    }
                }
            }
            
            // === Approach 4: Use rebindSymbol (fishhook) to hook C++ functions ===
            // This works if the C++ function is referenced through PLT/GOT
            const char *heartbeatSymbols[] = {
                "_ZN7NetImpl9heartbeatEv",
                "_ZN7NetImpl14sendHeartbeatEv",
                "_ZN7NetImpl15processHeartbeatEv",
                "_ZN7NetImpl12checkConnectionEv",
                "_ZN12SocketClient14sendHeartbeatEv",
                NULL
            };
            
            const char *disconnectSymbols[] = {
                "_ZN7NetImpl14quitFromServerEv",
                "_ZN7NetImpl13quitFromServerEv",
                "_ZN7NetImpl14quitFromServerEiv",
                "_ZN12SocketClient14quitFromServerEv",
                "_ZN7NetImpl10disconnectEv",
                "_ZN7NetImpl9closeGameEv",
                NULL
            };
            
            // Try to hook heartbeat functions via fishhook
            for (int n = 0; heartbeatSymbols[n] != NULL; n++) {
                // rebindSymbol expects symbol name WITHOUT leading underscore
                const char *symName = heartbeatSymbols[n] + 1;
                int patched = rebindSymbol(symName, (void *)noop_heartbeat, (void **)&orig_heartbeat_func);
                if (patched > 0) {
                    DLOG(@"[NETIMPL-HOOK] v36.97: Successfully hooked heartbeat %s via fishhook (patched=%d)", symName, patched);
                    g_quitFromServerHooked = YES;
                    break;
                }
            }
            
            // Try to hook disconnect functions via fishhook
            for (int n = 0; disconnectSymbols[n] != NULL; n++) {
                const char *symName = disconnectSymbols[n] + 1;
                int patched = rebindSymbol(symName, (void *)noop_disconnect, (void **)&orig_disconnect_func);
                if (patched > 0) {
                    DLOG(@"[NETIMPL-HOOK] v36.97: Successfully hooked disconnect %s via fishhook (patched=%d)", symName, patched);
                    g_quitFromServerHooked = YES;
                    break;
                }
            }
            
            // Also try to hook via symbol name with underscore (for symbols already loaded)
            if (!g_quitFromServerHooked) {
                for (int n = 0; heartbeatSymbols[n] != NULL; n++) {
                    int patched = rebindSymbol(heartbeatSymbols[n], (void *)noop_heartbeat, (void **)&orig_heartbeat_func);
                    if (patched > 0) {
                        DLOG(@"[NETIMPL-HOOK] v36.97: Hooked heartbeat %s (with underscore) via fishhook (patched=%d)", heartbeatSymbols[n], patched);
                        g_quitFromServerHooked = YES;
                        break;
                    }
                }
            }
            
            // === Approach 5: Hook Objective-C disconnect methods ===
            NSArray *disconnectClsNames = @[@"NetImpl", @"GameNetManager", @"NetworkManager", 
                                            @"GameNetwork", @"NetClient", @"GameSocket"];
            NSArray *methodPatterns = @[@"quitFromServer", @"disconnect", @"closeServer", 
                                        @"stopConnection", @"onDisconnect", @"connectionLost"];
            
            for (NSString *clsName in disconnectClsNames) {
                Class cls = NSClassFromString(clsName);
                if (!cls) continue;
                
                unsigned int mcount = 0;
                Method *methods = class_copyMethodList(cls, &mcount);
                for (unsigned int i = 0; i < mcount; i++) {
                    SEL sel = method_getName(methods[i]);
                    NSString *selName = NSStringFromSelector(sel);
                    
                    for (NSString *pattern in methodPatterns) {
                        if ([selName containsString:pattern]) {
                            DLOG(@"[NETIMPL-HOOK] v36.97: Hooking %@.%@ (matches '%@')", 
                                 clsName, selName, pattern);
                            IMP noopImpl = imp_implementationWithBlock(^(void) {
                                DLOG(@"[NETIMPL-BLOCK] v36.97: BLOCKED %@.%@ (no-op)", clsName, selName);
                            });
                            method_setImplementation(methods[i], noopImpl);
                            g_quitFromServerHooked = YES;
                            break;
                        }
                    }
                }
                if (methods) free(methods);
            }
            
            if (!g_quitFromServerHooked) {
                DLOG(@"[NETIMPL-HOOK] v36.97: INFO - No disconnect function found via ObjC runtime");
                DLOG(@"[NETIMPL-HOOK] v36.97: This is expected if NetImpl is pure C++ code");
                DLOG(@"[NETIMPL-HOOK] v36.97: Will rely on FAKE-RESP injection + EAGAIN protection");
            } else {
                DLOG(@"[NETIMPL-HOOK] v36.97: Successfully hooked disconnect functions!");
            }
            
        } @catch (NSException *e) {
            DLOG(@"[NETIMPL-HOOK] v36.96: Exception during hooking: %@", e);
        }
    });
}


