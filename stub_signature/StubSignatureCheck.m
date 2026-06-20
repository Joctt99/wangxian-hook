/**
 * Stub lnSignature.dylib v2 - SignatureCheck that actually works
 * Calls the real API and stores the result for the game to use
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// Store verification result globally so the game can access it
static NSDictionary *g_verifyResult = nil;
static BOOL g_verifyPassed = NO;

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
    NSLog(@"[StubSig] SignatureCheck +load called - performing real verification");
    
    NSString *udid = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    
    NSString *urlStr = [NSString stringWithFormat:
        @"http://ln_sign_cert.9iy.com/cert/judgeAppInfoApi?APPID=%@&UDID=%@",
        bundleId, udid];
    
    NSLog(@"[StubSig] Calling API: %@", urlStr);
    
    NSURL *url = [NSURL URLWithString:urlStr];
    if (url) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:15];
        
        // Use NSURLSession with semaphore for synchronous call in +load
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block NSData *respData = nil;
        __block NSError *respErr = nil;
        
        NSURLSession *session = [NSURLSession sharedSession];
        NSURLSessionDataTask *task = [session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            respData = data;
            respErr = error;
            dispatch_semaphore_signal(sem);
        }];
        [task resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
        
        if (respData) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
            NSLog(@"[StubSig] API response: %@", json);
            if (json) {
                g_verifyResult = json;
                NSString *ispass = json[@"ispass"];
                if (!ispass) ispass = json[@"result"][@"ispass"];
                if ([ispass isEqualToString:@"YES"]) {
                    g_verifyPassed = YES;
                }
            }
        } else {
            NSLog(@"[StubSig] API error: %@", respErr);
        }
    }
    
    NSLog(@"[StubSig] Verification result: passed=%d", g_verifyPassed);
}

+ (void)JudgeApp {
    NSLog(@"[StubSig] JudgeApp called - result: %d", g_verifyPassed);
}

+ (void)GetApp {
    NSLog(@"[StubSig] GetApp called");
}

+ (void)PostApp {
    NSLog(@"[StubSig] PostApp called");
}

+ (void)showTipViewEND:(id)arg {
    NSLog(@"[StubSig] showTipViewEND called with: %@", arg);
}

+ (void)exitApplication {
    NSLog(@"[StubSig] exitApplication called - BLOCKED");
}

@end
