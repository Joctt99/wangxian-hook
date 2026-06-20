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
    // Perform real verification during load
    NSLog(@"[StubSig] SignatureCheck +load called - performing real verification");
    
    NSString *udid = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    
    // Build the API URL (same as original)
    NSString *urlStr = [NSString stringWithFormat:
        @"http://ln_sign_cert.9iy.com/cert/judgeAppInfoApi?APPID=%@&UDID=%@",
        bundleId, udid];
    
    NSLog(@"[StubSig] Calling API: %@", urlStr);
    
    // Make synchronous request (safe in +load since it runs on a background thread)
    NSURL *url = [NSURL URLWithString:urlStr];
    if (url) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:10];
        NSURLResponse *resp = nil;
        NSError *err = nil;
        NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&resp error:&err];
        
        if (data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSLog(@"[StubSig] API response: %@", json);
            if (json) {
                g_verifyResult = json;
                // Check if verification passed
                NSString *ispass = json[@"ispass"] ?: json[@"data"][@"ispass"];
                if ([ispass isEqualToString:@"YES"]) {
                    g_verifyPassed = YES;
                }
            }
        } else {
            NSLog(@"[StubSig] API error: %@", err);
        }
    }
    
    NSLog(@"[StubSig] Verification result: passed=%d", g_verifyPassed);
}

+ (void)JudgeApp {
    NSLog(@"[StubSig] JudgeApp called - result: %d", g_verifyPassed);
    // If verification didn't pass, try again
    if (!g_verifyPassed) {
        [self load];
    }
}

+ (void)GetApp {
    NSLog(@"[StubSig] GetApp called");
}

+ (void)PostApp {
    NSLog(@"[StubSig] PostApp called");
}

+ (void)showTipViewEND:(id)arg {
    NSLog(@"[StubSig] showTipViewEND called with: %@", arg);
    // Do nothing - don't show any tip
}

+ (void)exitApplication {
    NSLog(@"[StubSig] exitApplication called - BLOCKED");
    // Do nothing - don't exit
}

@end
/**
 * Stub lnSignature.dylib - provides SignatureCheck class
 * All methods are empty stubs to satisfy symbol resolution.
 */
#import <Foundation/Foundation.h>

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
+ (void)load {}
+ (void)JudgeApp {}
+ (void)GetApp {}
+ (void)PostApp {}
+ (void)showTipViewEND:(id)arg {}
+ (void)exitApplication {}
@end
