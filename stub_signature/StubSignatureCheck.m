/**
 * Stub lnSignature.dylib v4 - Real API calls with file logging
 * +load: only logs (NO network to avoid deadlock)
 * JudgeApp: calls real API (WangXianHook hooks are active by then)
 * Logs to same wxhook.log file as WangXianHook
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

static NSString *g_logPath = nil;
static NSDictionary *g_verifyResult = nil;
static BOOL g_verifyPassed = NO;

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

+ (void)doVerify:(NSString *)caller {
    slog([NSString stringWithFormat:@"doVerify from %@, current passed=%d", caller, g_verifyPassed]);
    
    NSString *bundleId = @"com.sqage.wangxianapp";
    NSString *udid = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"UNKNOWN-UDID";
    
    NSString *urlStr = [NSString stringWithFormat:
        @"http://ln_sign_cert.9iy.com/cert/judgeAppInfoApi?APPID=%@&UDID=%@",
        bundleId, udid];
    
    slog([NSString stringWithFormat:@"API URL: %@", urlStr]);
    
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) { slog(@"ERROR: invalid URL"); return; }
    
    NSURLRequest *req = [NSURLRequest requestWithURL:url
                                          cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                      timeoutInterval:15];
    
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSData *respData = nil;
    __block NSError *respErr = nil;
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            respData = data;
            respErr = error;
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    long waitResult = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    
    if (waitResult != 0) {
        slog(@"API TIMEOUT after 15s");
        return;
    }
    
    if (respData) {
        NSString *rawStr = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding];
        slog([NSString stringWithFormat:@"API raw response: %@", rawStr]);
        
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
        if (json) {
            g_verifyResult = json;
            NSString *ispass = json[@"ispass"];
            if (!ispass) ispass = json[@"result"][@"ispass"];
            slog([NSString stringWithFormat:@"ispass=%@", ispass]);
            if ([ispass isEqualToString:@"YES"]) {
                g_verifyPassed = YES;
                slog(@"VERIFICATION PASSED!");
            } else {
                slog(@"VERIFICATION FAILED - ispass is not YES");
            }
        } else {
            slog(@"ERROR: failed to parse JSON");
        }
    } else {
        slog([NSString stringWithFormat:@"API error: %@", respErr]);
    }
}

+ (void)load {
    // Init log path
    g_logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    slog(@"=== StubSignatureCheck v4 +load ===");
    slog(@"NO network request in +load (avoid deadlock)");
}

+ (void)JudgeApp {
    slog(@"JudgeApp called - performing real API verification");
    [self doVerify:@"JudgeApp"];
    slog([NSString stringWithFormat:@"JudgeApp done, passed=%d", g_verifyPassed]);
}

+ (void)GetApp { slog(@"GetApp"); }
+ (void)PostApp { slog(@"PostApp"); }
+ (void)showTipViewEND:(id)arg { slog([NSString stringWithFormat:@"showTipViewEND: %@", arg]); }
+ (void)exitApplication { slog(@"exitApplication BLOCKED"); }

@end
