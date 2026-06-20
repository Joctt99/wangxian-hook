/**
 * Stub libSupport.dylib v2
 * SignatureKit: empty stubs (verification disabled)
 * LCNetworking: REAL HTTP via NSURLSession
 * OpenUDID: returns device UUID
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface SignatureKit : NSObject
+ (void)load;
+ (void)judgeNet;
+ (void)exitApplication;
+ (void)showAlert:(id)arg;
+ (void)handleAppInfoResult:(id)arg;
+ (id)judgeAppInfoWithBaseUrl:(id)arg;
+ (id)verifySignatureFromParameters:(id)arg;
+ (id)generateRequestParams;
+ (id)createSignatureParams:(id)arg;
+ (id)calculateMD5WithString:(id)arg;
+ (id)stringFromHex:(id)arg;
+ (id)generateRandomStringWithLength:(id)arg;
+ (id)getCurrentTimestampInBeijingTimezone;
+ (id)base64EncodeString:(id)arg;
+ (id)base64DecodeString:(id)arg;
@end

@implementation SignatureKit
+ (void)load {}
+ (void)judgeNet {}
+ (void)exitApplication {}
+ (void)showAlert:(id)arg {}
+ (void)handleAppInfoResult:(id)arg {}
+ (id)judgeAppInfoWithBaseUrl:(id)arg { return nil; }
+ (id)verifySignatureFromParameters:(id)arg { return nil; }
+ (id)generateRequestParams { return @{}; }
+ (id)createSignatureParams:(id)arg { return @{}; }
+ (id)calculateMD5WithString:(id)arg { return @""; }
+ (id)stringFromHex:(id)arg { return @""; }
+ (id)generateRandomStringWithLength:(id)arg { return @""; }
+ (id)getCurrentTimestampInBeijingTimezone { return @""; }
+ (id)base64EncodeString:(id)arg { return @""; }
+ (id)base64DecodeString:(id)arg { return @""; }
@end

typedef void (^LCSuccessBlock)(NSURLSessionDataTask *task, id responseObject);
typedef void (^LCFailureBlock)(NSURLSessionDataTask *task, NSError *error);

@interface LCNetworking : NSObject
+ (id)getWithURL:(id)url Params:(id)params success:(id)s failure:(id)f;
+ (id)PostWithURL:(id)url Params:(id)params success:(id)s failure:(id)f;
+ (void)showErrorInfoWithStatusCode:(id)arg;
+ (id)dealWithParam:(id)arg;
@end

@implementation LCNetworking

+ (NSURLSession *)sharedSession {
    static NSURLSession *s = nil;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSURLSessionConfiguration *c = [NSURLSessionConfiguration defaultSessionConfiguration];
        c.timeoutIntervalForRequest = 30;
        s = [NSURLSession sessionWithConfiguration:c];
    });
    return s;
}

+ (id)getWithURL:(id)url Params:(id)params success:(id)success failure:(id)failure {
    NSString *base = [url isKindOfClass:[NSString class]] ? url : [url description];
    NSMutableString *fullURL = [NSMutableString stringWithString:base];
    if ([params isKindOfClass:[NSDictionary class]] && [(NSDictionary *)params count] > 0) {
        NSMutableArray *pairs = [NSMutableArray array];
        [(NSDictionary *)params enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
            NSString *vs = [val isKindOfClass:[NSString class]] ? val : [val description];
            NSString *enc = [vs stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
            [pairs addObject:[NSString stringWithFormat:@"%@=%@", key, enc ?: vs]];
        }];
        [fullURL appendFormat:@"%@%@", [base containsString:@"?"] ? @"&" : @"?", [pairs componentsJoinedByString:@"&"]];
    }
    NSLog(@"[LCStub] GET %@", fullURL);
    NSURL *u = [NSURL URLWithString:fullURL];
    if (!u) { if (failure) ((LCFailureBlock)failure)(nil, nil); return nil; }
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    r.HTTPMethod = @"GET";
    NSURLSessionDataTask *task = [[self sharedSession] dataTaskWithRequest:r completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { NSLog(@"[LCStub] GET err: %@", err); if (failure) ((LCFailureBlock)failure)(nil, err); return; }
        id json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (!json && data) json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"[LCStub] GET ok %lu bytes", (unsigned long)data.length);
        if (success) ((LCSuccessBlock)success)(nil, json ?: data);
    }];
    [task resume];
    return task;
}

+ (id)PostWithURL:(id)url Params:(id)params success:(id)success failure:(id)failure {
    NSString *urlStr = [url isKindOfClass:[NSString class]] ? url : [url description];
    NSLog(@"[LCStub] POST %@", urlStr);
    NSURL *u = [NSURL URLWithString:urlStr];
    if (!u) { if (failure) ((LCFailureBlock)failure)(nil, nil); return nil; }
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    r.HTTPMethod = @"POST";
    [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    if ([params isKindOfClass:[NSDictionary class]]) r.HTTPBody = [NSJSONSerialization dataWithJSONObject:params options:0 error:nil];
    NSURLSessionDataTask *task = [[self sharedSession] dataTaskWithRequest:r completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { NSLog(@"[LCStub] POST err: %@", err); if (failure) ((LCFailureBlock)failure)(nil, err); return; }
        id json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (!json && data) json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"[LCStub] POST ok %lu bytes", (unsigned long)data.length);
        if (success) ((LCSuccessBlock)success)(nil, json ?: data);
    }];
    [task resume];
    return task;
}

+ (void)showErrorInfoWithStatusCode:(id)arg {}
+ (id)dealWithParam:(id)arg { return nil; }
@end

@interface OpenUDID : NSObject
+ (id)_generateFreshOpenUDID;
+ (id)value;
@end

@implementation OpenUDID
+ (id)_generateFreshOpenUDID {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"stub";
}
+ (id)value { return [self _generateFreshOpenUDID]; }
@end
