/**
 * Stub libSupport.dylib v2 - provides SignatureKit + LCNetworking + OpenUDID
 * LCNetworking methods are REAL - they perform actual HTTP requests via NSURLSession
 */
#import <Foundation/Foundation.h>

// ============================================================
// SignatureKit - all stubs (signature verification disabled)
// ============================================================
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

// ============================================================
// LCNetworking - REAL implementation using NSURLSession
// ============================================================
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
    static NSURLSession *session = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = 30;
        session = [NSURLSession sessionWithConfiguration:config];
    });
    return session;
}

+ (NSString *)buildURLString:(NSString *)baseURL params:(NSDictionary *)params {
    if (![params isKindOfClass:[NSDictionary class]] || params.count == 0) {
        return baseURL;
    }
    NSMutableArray *pairs = [NSMutableArray array];
    for (NSString *key in params) {
        id value = params[key];
        NSString *valStr = [value isKindOfClass:[NSString class]] ? value : [value description];
        NSString *encoded = [valStr stringByAddingPercentEncodingWithAllowedCharacters:
                             [NSCharacterSet URLQueryAllowedCharacterSet]];
        [pairs addObject:[NSString stringWithFormat:@"%@=%@", key, encoded ?: valStr]];
    }
    NSString *query = [pairs componentsJoinedByString:@"&"];
    if ([baseURL containsString:@"?"]) {
        return [NSString stringWithFormat:@"%@&%@", baseURL, query];
    }
    return [NSString stringWithFormat:@"%@?%@", baseURL, query];
}

+ (id)getWithURL:(id)url Params:(id)params success:(id)s failure:(id)f {
    NSString *urlStr = [url isKindOfClass:[NSString class]] ? url : [url description];
    NSString *fullURL = [self buildURLString:urlStr params:params];
    
    NSLog(@"[LCStub] GET: %@", fullURL);
    
    NSURL *nsURL = [NSURL URLWithString:fullURL];
    if (!nsURL) {
        if (f && [f isKindOfClass:NSClassFromString(@"NSBlock")]) {
            NSError *err = [NSError errorWithDomain:@"LCNetworking" code:-1
                                           userInfo:@{NSLocalizedDescriptionKey: @"Invalid URL"}];
            ((LCFailureBlock)f)(nil, err);
        }
        return nil;
    }
    
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:nsURL];
    req.HTTPMethod = @"GET";
    
    NSURLSessionDataTask *task = [[self sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                NSLog(@"[LCStub] GET Error: %@", error.localizedDescription);
                if (f) ((LCFailureBlock)f)(nil, error);
            } else {
                id json = nil;
                if (data) {
                    json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (!json) {
                        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                        json = str ?: data;
                    }
                }
                NSLog(@"[LCStub] GET OK: %@ bytes", @(data.length));
                if (s) ((LCSuccessBlock)s)(nil, json);
            }
        }];
    [task resume];
    return task;
}

+ (id)PostWithURL:(id)url Params:(id)params success:(id)s failure:(id)f {
    NSString *urlStr = [url isKindOfClass:[NSString class]] ? url : [url description];
    
    NSLog(@"[LCStub] POST: %@", urlStr);
    
    NSURL *nsURL = [NSURL URLWithString:urlStr];
    if (!nsURL) {
        if (f) ((LCFailureBlock)f)(nil, [NSError errorWithDomain:@"LCNetworking" code:-1
                                                       userInfo:@{NSLocalizedDescriptionKey: @"Invalid URL"}]);
        return nil;
    }
    
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:nsURL];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    
    if ([params isKindOfClass:[NSDictionary class]]) {
        NSData *body = [NSJSONSerialization dataWithJSONObject:params options:0 error:nil];
        req.HTTPBody = body;
    }
    
    NSURLSessionDataTask *task = [[self sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                NSLog(@"[LCStub] POST Error: %@", error.localizedDescription);
                if (f) ((LCFailureBlock)f)(nil, error);
            } else {
                id json = nil;
                if (data) {
                    json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (!json) {
                        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                        json = str ?: data;
                    }
                }
                NSLog(@"[LCStub] POST OK: %@ bytes", @(data.length));
                if (s) ((LCSuccessBlock)s)(nil, json);
            }
        }];
    [task resume];
    return task;
}

+ (void)showErrorInfoWithStatusCode:(id)arg {}
+ (id)dealWithParam:(id)arg { return nil; }
@end

// ============================================================
// OpenUDID - returns device identifier
// ============================================================
@interface OpenUDID : NSObject
+ (id)_generateFreshOpenUDID;
+ (id)value;
@end

@implementation OpenUDID
+ (id)_generateFreshOpenUDID {
    NSString *udid = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    return udid ?: @"stub-udid";
}
+ (id)value {
    return [self _generateFreshOpenUDID];
}
@end
/**
 * Stub libSupport.dylib - provides SignatureKit + LCNetworking + OpenUDID
 * All methods are empty stubs to satisfy symbol resolution.
 */
#import <Foundation/Foundation.h>

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

@interface LCNetworking : NSObject
+ (id)getWithURL:(id)url Params:(id)params success:(id)s failure:(id)f;
+ (id)PostWithURL:(id)url Params:(id)params success:(id)s failure:(id)f;
+ (void)showErrorInfoWithStatusCode:(id)arg;
+ (id)dealWithParam:(id)arg;
@end

@implementation LCNetworking
+ (id)getWithURL:(id)url Params:(id)params success:(id)s failure:(id)f { return nil; }
+ (id)PostWithURL:(id)url Params:(id)params success:(id)s failure:(id)f { return nil; }
+ (void)showErrorInfoWithStatusCode:(id)arg {}
+ (id)dealWithParam:(id)arg { return nil; }
@end

@interface OpenUDID : NSObject
+ (id)_generateFreshOpenUDID;
@end

@implementation OpenUDID
+ (id)_generateFreshOpenUDID { return @"stub"; }
@end
