/**
 * Stub lnSignature.dylib v5 - NO HTTP requests, instant pass
 * JudgeApp: just sets g_verifyPassed = YES (no network)
 * exitApplication: blocked (does nothing)
 * showTipViewEND: blocked (does nothing)
 * Logs to same wxhook.log file as WangXianHook
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

static NSString *g_logPath = nil;
static BOOL g_verifyPassed = YES; // Always pass

static void slog(NSString *msg) {
    if (!g_logPath) return;
    NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
        if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
    }
    NSLog(@"[StubSig] %@", msg);
}

@interface SignatureCheck : NSObject
+ (void)load;
+ (void)JudgeApp;
+ (void)GetApp;
+ (void)PostApp;
+ (void)showTipViewEND:(id)arg;
+ (void)exitApplication;
@property (nonatomic, retain) id nettimes;
@end

@implementation SignatureCheck

+ (void)load {
    g_logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    slog(@"=== StubSignatureCheck v5 +load (instant pass) ===");
}

+ (void)JudgeApp {
    slog(@"JudgeApp called - instant pass (no HTTP)");
    g_verifyPassed = YES;
}

+ (void)GetApp { slog(@"GetApp (stub)"); }
+ (void)PostApp { slog(@"PostApp (stub)"); }
+ (void)showTipViewEND:(id)arg { slog([NSString stringWithFormat:@"showTipViewEND: BLOCKED: %@", arg]); }
+ (void)exitApplication { slog(@"exitApplication BLOCKED (stub)"); }

@end
