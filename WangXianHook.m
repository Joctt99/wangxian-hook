/**
 * WangXianHook v11.0 - NSURLProtocol interceptor for qunhongtech.com
 * Intercepts ALL network requests including delegate-mode NSURLSession
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <dlfcn.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

static NSString *g_logPath = nil;

static void _log(NSString *msg) {
    if (!g_logPath) return;
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
        _log(@"=== WXHook v28.0 Early TaskDelegate ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
    }
}

// ============================================================
#pragma mark - ispass patch
// ============================================================

static NSData *patchIspass(NSData *data, NSString *url) {
    if (!data) return data;
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!str) return data;
    NSString *p = str;
    p = [p stringByReplacingOccurrencesOfString:@"\"ispass\":\"NO\"" withString:@"\"ispass\":\"YES\""];
    p = [p stringByReplacingOccurrencesOfString:@"\"ispass\": \"NO\"" withString:@"\"ispass\": \"YES\""];
    p = [p stringByReplacingOccurrencesOfString:@"\"ispass\":false" withString:@"\"ispass\":true"];
    p = [p stringByReplacingOccurrencesOfString:@"\"test\":\"NO\"" withString:@"\"test\":\"YES\""];
    NSData *nd = [p dataUsingEncoding:NSUTF8StringEncoding];
    if (nd && ![str isEqualToString:p]) { DLOG(@"[PATCH] ispass: %@", url); return nd; }
    return data;
}

// ============================================================
#pragma mark - NSURLConnection sync hook
// ============================================================

typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);
static SyncReqIMP orig_syncReq = NULL;
static NSData *hook_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **error) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] sync: %@", u);
    NSData *data = orig_syncReq ? orig_syncReq(self, _cmd, req, resp, error) : nil;
    if (data) { NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]; if (r && r.length < 1500) DLOG(@"[NET] sync resp: %@", r); }
    if (error && *error) DLOG(@"[NET] sync err: %@", (*error).localizedDescription);
    return patchIspass(data, u);
}

// ============================================================
#pragma mark - NSURLConnection async hook
// ============================================================

typedef void (^NSURLConnComp)(NSURLResponse *, NSData *, NSError *);
typedef id (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, NSURLConnComp);
static AsyncReqIMP orig_asyncReq = NULL;
static id hook_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *queue, NSURLConnComp handler) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] async: %@", u);
    NSURLConnComp wrapped = ^(NSURLResponse *resp, NSData *data, NSError *error) {
        if (data) { NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]; if (r && r.length < 1500) DLOG(@"[NET] async resp: %@", r); }
        if (handler) handler(resp, patchIspass(data, u), error);
    };
    return orig_asyncReq ? orig_asyncReq(self, _cmd, req, queue, wrapped) : nil;
}

// ============================================================
#pragma mark - NSURLSession hooks
// ============================================================

typedef void (^CompHandler)(NSData *, NSURLResponse *, NSError *);
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, CompHandler);
static DTReqCompIMP orig_dtwrc = NULL;
static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, CompHandler handler) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] session req: %@", u);
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) { NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]; if (r && r.length < 1500) DLOG(@"[NET] session resp: %@", r); }
        if (handler) handler(patchIspass(data, u), response, error);
    };
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, wrapped) : nil;
}

typedef NSURLSessionDataTask *(*DTUrlCompIMP)(id, SEL, NSURL *, CompHandler);
static DTUrlCompIMP orig_dtwuc = NULL;
static NSURLSessionDataTask *hook_dtwuc(id self, SEL _cmd, NSURL *url, CompHandler handler) {
    NSString *u = url.absoluteString ?: @"(null)";
    DLOG(@"[NET] session url: %@", u);
    CompHandler wrapped = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data) { NSString *r = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]; if (r && r.length < 1500) DLOG(@"[NET] session resp: %@", r); }
        if (handler) handler(patchIspass(data, u), response, error);
    };
    return orig_dtwuc ? orig_dtwuc(self, _cmd, url, wrapped) : nil;
}

// ============================================================
#pragma mark - NSUserDefaults hooks (CRITICAL - override license results)
// ============================================================

typedef id (*ObjForKeyIMP)(id, SEL, NSString *);
static ObjForKeyIMP orig_objectForKey = NULL;
typedef BOOL (*BoolForKeyIMP)(id, SEL, NSString *);
static BoolForKeyIMP orig_boolForKey = NULL;
typedef id (*StringForKeyIMP)(id, SEL, NSString *);
static StringForKeyIMP orig_stringForKey = NULL;

// Check if key is license-related
static BOOL isLicenseKey(NSString *key) {
    if (!key) return NO;
    NSString *lower = [key lowercaseString];
    return ([lower containsString:@"pass"] || [lower containsString:@"sign"] ||
            [lower containsString:@"licen"] || [lower containsString:@"verif"] ||
            [lower containsString:@"check"] || [lower containsString:@"valid"] ||
            [lower containsString:@"judge"] || [lower containsString:@"protect"] ||
            [lower containsString:@"anyou"] || [lower containsString:@"ispass"] ||
            [lower containsString:@"result"] || [lower containsString:@"status"]);
}

static id hook_objectForKey(id self, SEL _cmd, NSString *key) {
    id result = orig_objectForKey ? orig_objectForKey(self, _cmd, key) : nil;
    if (key) {
        // Log ALL keys on first read (to discover license keys)
        if (isLicenseKey(key)) {
            DLOG(@"[NSUD] objectForKey: %@ = %@", key, result);
        }
        // Override: if value looks like a failed check, force pass
        if (isLicenseKey(key) && result) {
            if ([result isKindOfClass:[NSString class]]) {
                NSString *str = (NSString *)result;
                if ([str isEqualToString:@"NO"] || [str isEqualToString:@"0"] || [str isEqualToString:@"false"]) {
                    DLOG(@"[OVERRIDE] '%@': '%@' -> 'YES'", key, str);
                    return @"YES";
                }
            } else if ([result isKindOfClass:[NSNumber class]]) {
                NSNumber *num = (NSNumber *)result;
                if ([num boolValue] == NO && [num intValue] == 0) {
                    DLOG(@"[OVERRIDE] '%@': %@ -> YES", key, num);
                    return @YES;
                }
            }
        }
    }
    return result;
}

static BOOL hook_boolForKey(id self, SEL _cmd, NSString *key) {
    BOOL result = orig_boolForKey ? orig_boolForKey(self, _cmd, key) : NO;
    if (key && isLicenseKey(key)) {
        DLOG(@"[NSUD] boolForKey: %@ = %d", key, result);
        if (!result) {
            DLOG(@"[OVERRIDE] boolForKey '%@': NO -> YES", key);
            return YES;
        }
    }
    return result;
}

static id hook_stringForKey(id self, SEL _cmd, NSString *key) {
    id result = orig_stringForKey ? orig_stringForKey(self, _cmd, key) : nil;
    if (key && isLicenseKey(key)) {
        DLOG(@"[NSUD] stringForKey: %@ = %@", key, result);
        if ([result isKindOfClass:[NSString class]]) {
            NSString *str = (NSString *)result;
            if ([str isEqualToString:@"NO"] || [str isEqualToString:@"0"]) {
                DLOG(@"[OVERRIDE] stringForKey '%@': '%@' -> 'YES'", key, str);
                return @"YES";
            }
        }
    }
    return result;
}

// ============================================================
#pragma mark - NSURLProtocol subclass (intercept qunhongtech.com)
// ============================================================

static NSString * const kWXProtocolHandled = @"WXProtocolHandled";

@interface WXInterceptor : NSURLProtocol
@end

@implementation WXInterceptor

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *urlStr = request.URL.absoluteString ?: @"(nil)";
    // Log ALL requests for debugging (first 30 only to avoid flood)
    static int canInitCount = 0;
    if (canInitCount < 30) {
        canInitCount++;
        _log([NSString stringWithFormat:@"[PROTO-CHECK] #%d %@", canInitCount, urlStr]);
    }
    if ([urlStr containsString:@"qunhongtech"] || [urlStr containsString:@"md5xor"] ||
        [urlStr containsString:@"judgeAppInfo"]) {
        if ([NSURLProtocol propertyForKey:kWXProtocolHandled inRequest:request]) {
            _log(@"[INTERCEPT] Already handled, skip");
            return NO;
        }
        _log([NSString stringWithFormat:@"[INTERCEPT] MATCH! URL=%@", urlStr]);
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSString *urlStr = self.request.URL.absoluteString ?: @"";
    _log([NSString stringWithFormat:@"[INTERCEPT] startLoading: %@", urlStr]);
    
    // Log request body if POST
    if (self.request.HTTPBody) {
        NSString *body = [[NSString alloc] initWithData:self.request.HTTPBody encoding:NSUTF8StringEncoding];
        if (body && body.length < 2000) {
            _log([NSString stringWithFormat:@"[INTERCEPT] Request body: %@", body]);
        }
    }
    
    // Return FAKE success response immediately
    NSDictionary *fakeResp = @{
        @"code": @0,
        @"msg": @"success",
        @"ispass": @"YES",
        @"status": @1,
        @"result": @"pass",
        @"pass": @"YES",
        @"verify": @"YES",
        @"data": @{@"ispass": @"YES", @"status": @1}
    };
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:fakeResp options:0 error:nil];
    NSString *jsonStr = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    _log([NSString stringWithFormat:@"[INTERCEPT] Fake response: %@", jsonStr]);
    
    NSHTTPURLResponse *httpResp = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:@{@"Content-Type": @"application/json"}];
    
    [self.client URLProtocol:self didReceiveResponse:httpResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:jsonData];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {
    // Nothing to clean up
}

@end

// ============================================================
#pragma mark - NSURLSession sessionWithConfiguration hooks
// ============================================================

typedef NSURLSession *(*SessionWithConfigIMP)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static SessionWithConfigIMP orig_sessionWithConfig = NULL;

static NSURLSession *hook_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *config, id delegate, NSOperationQueue *queue) {
    // Inject our protocol at the front
    NSMutableArray *protocols = [[config protocolClasses] mutableCopy];
    if (!protocols) protocols = [NSMutableArray array];
    if (![protocols containsObject:[WXInterceptor class]]) {
        [protocols insertObject:[WXInterceptor class] atIndex:0];
        [config setProtocolClasses:protocols];
        _log(@"[SESSION] Injected WXInterceptor into session config");
    }
    return orig_sessionWithConfig ? orig_sessionWithConfig(self, _cmd, config, delegate, queue) : nil;
}

typedef NSURLSession *(*SessionWithConfigOnlyIMP)(id, SEL, NSURLSessionConfiguration *);
static SessionWithConfigOnlyIMP orig_sessionWithConfigOnly = NULL;

static NSURLSession *hook_sessionWithConfigOnly(id self, SEL _cmd, NSURLSessionConfiguration *config) {
    NSMutableArray *protocols = [[config protocolClasses] mutableCopy];
    if (!protocols) protocols = [NSMutableArray array];
    if (![protocols containsObject:[WXInterceptor class]]) {
        [protocols insertObject:[WXInterceptor class] atIndex:0];
        [config setProtocolClasses:protocols];
        _log(@"[SESSION] Injected WXInterceptor into session config (no delegate)");
    }
    return orig_sessionWithConfigOnly ? orig_sessionWithConfigOnly(self, _cmd, config) : nil;
}

// Global tracking variables (declared early for use by all swizzle functions)
static NSMutableDictionary *g_taskDataMap = nil;   // taskIdentifier -> NSMutableData
static NSMutableDictionary *g_taskRespMap = nil;   // taskIdentifier -> NSURLResponse
static NSMutableDictionary *g_taskURLMap = nil;    // taskIdentifier -> NSString (URL)
static NSMutableSet *g_subclassedDelegates = nil;   // Set of delegate class names already subclassed
static NSMutableSet *g_fakeResponseTasks = nil;  // task IDs that need fake HTTP 200

// AFNetworking internal delegate swizzle for didReceiveResponse
typedef void (*AFRecvRespHandlerIMP)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSURLResponse *, void (^)(NSURLSessionResponseDisposition));
static AFRecvRespHandlerIMP orig_afRecvRespHandler = NULL;

static void swizzled_af_didReceiveResponseWithHandler(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *task, NSURLResponse *response, void (^completionHandler)(NSURLSessionResponseDisposition)) {
    NSNumber *tid = @(task.taskIdentifier);
    NSString *url = g_taskURLMap ? g_taskURLMap[tid] : nil;
    
    if (url && [response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        DLOG(@"[AF-RESP] Intercepted response task=%lu status=%ld url=%@", (unsigned long)task.taskIdentifier, (long)httpResp.statusCode, url);
        
        // Create fake HTTP 200 response
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:response.URL
                                                                 statusCode:200
                                                                HTTPVersion:@"HTTP/1.1"
                                                               headerFields:@{@"Content-Type": @"application/json"}];
        if (orig_afRecvRespHandler) {
            orig_afRecvRespHandler(self, _cmd, session, task, fakeResp, completionHandler);
        }
        return;
    }
    // Not our task
    if (orig_afRecvRespHandler) {
        orig_afRecvRespHandler(self, _cmd, session, task, response, completionHandler);
    }
}

// ============================================================
#pragma mark - NSURLSessionTask.response hook (fake HTTP 200)
// ============================================================

typedef NSURLResponse *(*TaskResponseIMP)(id, SEL);
static TaskResponseIMP orig_taskResponse = NULL;

static NSURLResponse *hook_taskResponse(id self, SEL _cmd) {
    NSURLSessionTask *task = (NSURLSessionTask *)self;
    NSNumber *tid = @(task.taskIdentifier);
    
    if (g_fakeResponseTasks && [g_fakeResponseTasks containsObject:tid]) {
        NSURLResponse *realResp = orig_taskResponse ? orig_taskResponse(self, _cmd) : nil;
        if (realResp && [realResp isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)realResp;
            if (httpResp.statusCode != 200) {
                DLOG(@"[RESP-HOOK] Faking HTTP 200 for taskID=%lu (was %ld)", (unsigned long)task.taskIdentifier, (long)httpResp.statusCode);
                return [[NSHTTPURLResponse alloc] initWithURL:realResp.URL
                                                   statusCode:200
                                                  HTTPVersion:@"HTTP/1.1"
                                                 headerFields:@{@"Content-Type": @"application/json"}];
            }
        }
    }
    return orig_taskResponse ? orig_taskResponse(self, _cmd) : nil;
}

// ============================================================
#pragma mark - Delegate method swizzling for response interception
// ============================================================

// Swizzled didReceiveResponse - fake HTTP 200 status
typedef void (*DidRecvRespIMP)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSURLResponse *);
static void swizzled_didReceiveResponse(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *task, NSURLResponse *response) {
    NSNumber *tid = @(task.taskIdentifier);
    NSString *url = g_taskURLMap[tid];
    if (url && [response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        DLOG(@"[DELEG] didReceiveResponse task=%lu status=%ld (faking 200)", (unsigned long)task.taskIdentifier, (long)httpResp.statusCode);
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:response.URL
                                                                 statusCode:200
                                                                HTTPVersion:@"HTTP/1.1"
                                                               headerFields:@{@"Content-Type": @"application/json"}];
        struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
        ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, fakeResp);
        return;
    }
    struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, response);
}

// completionHandler variant (AFNetworking uses this)
typedef void (*RecvRespCompletion)(NSURLSessionResponseDisposition);
static void swizzled_didReceiveResponseWithHandler(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *task, NSURLResponse *response, RecvRespCompletion completionHandler) {
    NSNumber *tid = @(task.taskIdentifier);
    NSString *url = g_taskURLMap[tid];
    if (url && [response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        DLOG(@"[DELEG] didReceiveResponse+handler task=%lu status=%ld (faking 200)", (unsigned long)task.taskIdentifier, (long)httpResp.statusCode);
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:response.URL
                                                                 statusCode:200
                                                                HTTPVersion:@"HTTP/1.1"
                                                               headerFields:@{@"Content-Type": @"application/json"}];
        struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
        ((void (*)(struct objc_super *, SEL, id, id, id, RecvRespCompletion))objc_msgSendSuper)(&superInfo, _cmd, session, task, fakeResp, completionHandler);
        return;
    }
    struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, id, id, id, RecvRespCompletion))objc_msgSendSuper)(&superInfo, _cmd, session, task, response, completionHandler);
}

// Swizzled didReceiveData - accumulate response data per task
typedef void (*DidRecvDataOrigIMP)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *);
static void swizzled_didReceiveData(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *task, NSData *data) {
    NSNumber *tid = @(task.taskIdentifier);
    NSString *url = g_taskURLMap[tid];
    if (url) {
        NSMutableData *accumulated = g_taskDataMap[tid];
        if (!accumulated) {
            accumulated = [NSMutableData data];
            g_taskDataMap[tid] = accumulated;
        }
        [accumulated appendData:data];
        DLOG(@"[DELEG] BLOCKED didReceiveData task=%lu len=%lu (not forwarding)", (unsigned long)task.taskIdentifier, (unsigned long)data.length);
        // DO NOT forward to original delegate - we'll deliver patched data later
        return;
    }
    // Not our task - forward normally
    struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, data);
}

// Swizzled didCompleteWithError - patch data and deliver to original delegate
typedef void (*DidCompleteOrigIMP)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *);
static void swizzled_didCompleteWithError(id self, SEL _cmd, NSURLSession *session, NSURLSessionTask *task, NSError *error) {
    NSNumber *tid = @(task.taskIdentifier);
    NSString *url = g_taskURLMap[tid];
    NSMutableData *data = g_taskDataMap[tid];
    
    if (url && data && data.length > 0) {
        NSString *respStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        DLOG(@"[DELEG] Original resp task=%lu: %@", (unsigned long)task.taskIdentifier, respStr);
        
        // Mark this task for fake HTTP 200 response
        if (!g_fakeResponseTasks) g_fakeResponseTasks = [NSMutableSet set];
        [g_fakeResponseTasks addObject:@(task.taskIdentifier)];
        
        // Create FAKE success response and deliver to delegate
        NSDictionary *fakeResp = @{
            @"timestamp": @"2026-06-20T14:42:12.039+0000",
            @"status": @200,
            @"code": @0,
            @"msg": @"success",
            @"ispass": @"YES",
            @"pass": @"YES",
            @"result": @"pass",
            @"verify": @"YES",
            @"data": @{@"ispass": @"YES", @"status": @1}
        };
        NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fakeResp options:0 error:nil];
        NSString *fakeStr = [[NSString alloc] initWithData:fakeData encoding:NSUTF8StringEncoding];
        DLOG(@"[DELEG] DELIVERING fake response: %@", fakeStr);
        
        // Deliver fake data to the original delegate
        SEL didRecvDataSel = @selector(URLSession:dataTask:didReceiveData:);
        struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
        if ([self respondsToSelector:didRecvDataSel]) {
            ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, didRecvDataSel, session, task, fakeData);
        }
        
        // Then deliver completion with no error
        ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, nil);
    } else if (url && error) {
        DLOG(@"[DELEG] Error on qunhongtech task: %@", error);
        // Mark for fake response
        if (!g_fakeResponseTasks) g_fakeResponseTasks = [NSMutableSet set];
        [g_fakeResponseTasks addObject:@(task.taskIdentifier)];
        // Even on error, deliver fake success
        NSDictionary *fakeResp = @{@"status": @200, @"ispass": @"YES", @"code": @0, @"msg": @"success"};
        NSData *fakeData = [NSJSONSerialization dataWithJSONObject:fakeResp options:0 error:nil];
        DLOG(@"[DELEG] DELIVERING fake response on error");
        SEL didRecvDataSel = @selector(URLSession:dataTask:didReceiveData:);
        struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
        if ([self respondsToSelector:didRecvDataSel]) {
            ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, didRecvDataSel, session, task, fakeData);
        }
        ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, nil);
    } else {
        // Not our task - forward normally
        struct objc_super superInfo = { self, class_getSuperclass(object_getClass(self)) };
        ((void (*)(struct objc_super *, SEL, id, id, id))objc_msgSendSuper)(&superInfo, _cmd, session, task, error);
    }
    
    // Cleanup
    [g_taskDataMap removeObjectForKey:tid];
    [g_taskRespMap removeObjectForKey:tid];
    [g_taskURLMap removeObjectForKey:tid];
    [g_fakeResponseTasks removeObject:tid];
}

static void swizzleDelegate(id delegate) {
    if (!delegate) return;
    
    Class origClass = object_getClass(delegate);
    NSString *className = NSStringFromClass(origClass);
    
    // Only subclass once per class
    if ([g_subclassedDelegates containsObject:className]) {
        DLOG(@"[DELEG] Already subclassed: %@", className);
        return;
    }
    
    // Check if delegate implements the methods we want to swizzle
    if (![delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)] &&
        ![delegate respondsToSelector:@selector(URLSession:task:didCompleteWithError:)]) {
        DLOG(@"[DELEG] %@ doesn't implement delegate methods", className);
        return;
    }
    
    // Create a dynamic subclass
    NSString *subClassName = [NSString stringWithFormat:@"WXHook_%@", className];
    Class subClass = objc_allocateClassPair(origClass, [subClassName UTF8String], 0);
    if (!subClass) {
        DLOG(@"[DELEG] Failed to create subclass for %@", className);
        return;
    }
    
    // Add overridden methods for AFHTTPSessionManager
    if ([delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveResponse:completionHandler:)]) {
        class_addMethod(subClass, @selector(URLSession:dataTask:didReceiveResponse:completionHandler:),
                       (IMP)swizzled_didReceiveResponseWithHandler, "v@:@@@@?");
    } else if ([delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveResponse:)]) {
        class_addMethod(subClass, @selector(URLSession:dataTask:didReceiveResponse:),
                       (IMP)swizzled_didReceiveResponse, "v@:@@@");
    }
    if ([delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)]) {
        class_addMethod(subClass, @selector(URLSession:dataTask:didReceiveData:),
                       (IMP)swizzled_didReceiveData, "v@:@@@@");
    }
    if ([delegate respondsToSelector:@selector(URLSession:task:didCompleteWithError:)]) {
        class_addMethod(subClass, @selector(URLSession:task:didCompleteWithError:),
                       (IMP)swizzled_didCompleteWithError, "v@:@@@@");
    }
    
    objc_registerClassPair(subClass);
    
    // Change this instance's class to the subclass
    object_setClass(delegate, subClass);
    [g_subclassedDelegates addObject:className];
    
    DLOG(@"[DELEG] Created subclass %@, swizzled instance", subClassName);
    
    // Swizzle AFURLSessionManagerTaskDelegate (AFNetworking internal class)
    @try {
        Class taskDelegateCls = objc_getClass("AFURLSessionManagerTaskDelegate");
        if (taskDelegateCls) {
            DLOG(@"[DELEG] Found AFURLSessionManagerTaskDelegate");
            SEL recvRespHandlerSel = @selector(URLSession:dataTask:didReceiveResponse:completionHandler:);
            
            // Try to find method directly on the class
            Method m = class_getInstanceMethod(taskDelegateCls, recvRespHandlerSel);
            if (m) {
                orig_afRecvRespHandler = (AFRecvRespHandlerIMP)method_getImplementation(m);
                method_setImplementation(m, (IMP)swizzled_af_didReceiveResponseWithHandler);
                DLOG(@"[DELEG] Swizzled TaskDelegate.didReceiveResponse:completionHandler: (found)");
            } else {
                // Method not found - might be dynamically resolved via forwardInvocation
                // Force add the method directly
                DLOG(@"[DELEG] TaskDelegate method not found, adding via class_addMethod");
                BOOL added = class_addMethod(taskDelegateCls, recvRespHandlerSel,
                                            (IMP)swizzled_af_didReceiveResponseWithHandler,
                                            "v@:@@@@?");
                if (added) {
                    DLOG(@"[DELEG] Added TaskDelegate.didReceiveResponse:completionHandler: via class_addMethod");
                } else {
                    DLOG(@"[DELEG] class_addMethod FAILED for TaskDelegate");
                }
            }
            
            // Also try to add/swizzle didCompleteWithError: on TaskDelegate
            SEL completeSel = @selector(URLSession:task:didCompleteWithError:);
            Method cm = class_getInstanceMethod(taskDelegateCls, completeSel);
            if (cm) {
                DLOG(@"[DELEG] TaskDelegate has URLSession:task:didCompleteWithError: (direct)");
            } else {
                DLOG(@"[DELEG] TaskDelegate does NOT have URLSession:task:didCompleteWithError: directly");
            }
            
            // List ALL methods on TaskDelegate for debugging
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(taskDelegateCls, &methodCount);
            DLOG(@"[DELEG] TaskDelegate direct methods: %u", methodCount);
            for (unsigned int i = 0; i < methodCount && i < 20; i++) {
                NSString *name = NSStringFromSelector(method_getName(methods[i]));
                DLOG(@"[DELEG]   - %@", name);
            }
            if (methods) free(methods);
        } else {
            DLOG(@"[DELEG] AFURLSessionManagerTaskDelegate not found");
        }
    } @catch (NSException *e) {
        DLOG(@"[DELEG] Exception swizzling TaskDelegate: %@", e);
    }
}

// ============================================================
#pragma mark - NSURLSession delegate mode logging
// ============================================================

typedef NSURLSessionDataTask *(*DTReqIMP)(id, SEL, NSURLRequest *);
static DTReqIMP orig_dtr = NULL;

static NSURLSessionDataTask *hook_dtr(id self, SEL _cmd, NSURLRequest *req) {
    NSString *u = req.URL.absoluteString ?: @"(null)";
    DLOG(@"[NET] delegate task: %@", u);
    
    // Track this task for delegate swizzling
    if ([u containsString:@"qunhongtech"] || [u containsString:@"md5xor"]) {
        // Initialize tracking maps
        if (!g_taskDataMap) g_taskDataMap = [NSMutableDictionary dictionary];
        if (!g_taskRespMap) g_taskRespMap = [NSMutableDictionary dictionary];
        if (!g_taskURLMap) g_taskURLMap = [NSMutableDictionary dictionary];
        if (!g_subclassedDelegates) g_subclassedDelegates = [NSMutableSet set];
        
        // Swizzle the session's delegate
        @try {
            id delegate = ((NSURLSession *)self).delegate;
            if (delegate) {
                swizzleDelegate(delegate);
                DLOG(@"[NET] Tracking task for delegate swizzle: %@", u);
            } else {
                DLOG(@"[NET] No delegate found for session");
            }
        } @catch (NSException *e) {
            DLOG(@"[NET] Delegate swizzle error: %@", e);
        }
    }
    
    NSURLSessionDataTask *task = orig_dtr ? orig_dtr(self, _cmd, req) : nil;
    
    // Record the task ID -> URL mapping AFTER task is created
    if (task && ([u containsString:@"qunhongtech"] || [u containsString:@"md5xor"])) {
        NSNumber *tid = @(task.taskIdentifier);
        g_taskURLMap[tid] = u;
        DLOG(@"[NET] Mapped taskID %lu -> %@", (unsigned long)task.taskIdentifier, u);
    }
    
    return task;
}

typedef NSURLSessionDataTask *(*DTUrlIMP)(id, SEL, NSURL *);
static DTUrlIMP orig_dtu = NULL;

static NSURLSessionDataTask *hook_dtu(id self, SEL _cmd, NSURL *url) {
    NSString *u = url.absoluteString ?: @"(null)";
    DLOG(@"[NET] delegate url: %@", u);
    return orig_dtu ? orig_dtu(self, _cmd, url) : nil;
}

// ============================================================
#pragma mark - NSURL creation hook (catch ALL URLs)
// ============================================================

typedef id (*URLWithStringIMP)(id, SEL, NSString *);
static URLWithStringIMP orig_urlWithString = NULL;

static id hook_urlWithString(id self, SEL _cmd, NSString *string) {
    id result = orig_urlWithString ? orig_urlWithString(self, _cmd, string) : nil;
    if (string && string.length > 0) {
        NSString *lower = [string lowercaseString];
        if ([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]) {
            DLOG(@"[URL] %@", string);
        }
    }
    return result;
}

// NSURLRequest initWithURL hook
typedef id (*ReqInitIMP)(id, SEL, NSURL *, NSUInteger, NSTimeInterval);
static ReqInitIMP orig_reqInit = NULL;

static id hook_reqInit(id self, SEL _cmd, NSURL *url, NSUInteger policy, NSTimeInterval timeout) {
    id result = orig_reqInit ? orig_reqInit(self, _cmd, url, policy, timeout) : nil;
    if (url) {
        DLOG(@"[REQ] %@", url.absoluteString);
    }
    return result;
}

// CFNetwork function hooks
#include <CoreFoundation/CoreFoundation.h>
typedef CFHTTPMessageRef (*CFHTTPMsgCreateReqFunc)(CFAllocatorRef, CFURLRef, CFStringRef, CFStringRef, CFStringRef);
static CFHTTPMsgCreateReqFunc orig_cfCreateReq = NULL;

static CFHTTPMessageRef hook_cfCreateReq(CFAllocatorRef alloc, CFURLRef url, CFStringRef method, CFStringRef version, CFStringRef unused) {
    if (url) {
        CFStringRef urlStr = CFURLGetString(url);
        if (urlStr) {
            NSString *nsStr = (__bridge NSString *)urlStr;
            DLOG(@"[CFNET] %@ %@", (__bridge NSString *)method, nsStr);
        }
    }
    return orig_cfCreateReq ? orig_cfCreateReq(alloc, url, method, version, unused) : NULL;
}

// ============================================================
#pragma mark - UIView.addSubview hook (catch ALL popups)
// ============================================================

typedef void (*AddSubviewIMP)(id, SEL, UIView *);
static AddSubviewIMP orig_addSubview = NULL;

static void dumpViewTree(UIView *v, int depth) {
    if (depth > 5) return;
    NSString *indent = [@"" stringByPaddingToLength:depth*2 withString:@" " startingAtIndex:0];
    NSString *cls = NSStringFromClass([v class]);
    NSString *text = @"";
    // Get text from UILabel, UIButton, UITextView, UITextField
    if ([v isKindOfClass:[UILabel class]]) {
        text = ((UILabel *)v).text ?: @"";
    } else if ([v isKindOfClass:[UIButton class]]) {
        text = ((UIButton *)v).currentTitle ?: @"";
    } else if ([v isKindOfClass:[UITextView class]]) {
        text = [((UITextView *)v).text substringToIndex:MIN(((UITextView *)v).text.length, 50)];
    }
    if (text.length > 0 || ![cls hasPrefix:@"_"]) {
        DLOG(@"[VIEW] %@%@ frame=%.0fx%.0f text='%@'", indent, cls, v.frame.size.width, v.frame.size.height, text);
    }
    for (UIView *sub in v.subviews) {
        dumpViewTree(sub, depth + 1);
    }
}

static void hook_addSubview(id self, SEL _cmd, UIView *view) {
    NSString *cls = NSStringFromClass([view class]);
    // Log interesting views (alerts, dialogs, popups, labels with Chinese text)
    BOOL interesting = NO;
    NSString *lower = [cls lowercaseString];
    if ([lower containsString:@"alert"] || [lower containsString:@"dialog"] || 
        [lower containsString:@"popup"] || [lower containsString:@"modal"] ||
        [lower containsString:@"tip"] || [lower containsString:@"banner"] ||
        [lower containsString:@"toast"] || [lower containsString:@"hud"]) {
        interesting = YES;
    }
    // Also check for UILabel with specific text
    if ([view isKindOfClass:[UILabel class]]) {
        NSString *text = ((UILabel *)view).text;
        if (text && ([text containsString:@"版本"] || [text containsString:@"过低"] || [text containsString:@"更新"])) {
            DLOG(@"[LABEL-CATCH] class=%@ text='%@'", cls, text);
            interesting = YES;
        }
    }
    if (interesting) {
        DLOG(@"[ADDVIEW] %@ added to %@", cls, NSStringFromClass([self class]));
        dumpViewTree(view, 0);
    }
    if (orig_addSubview) orig_addSubview(self, _cmd, view);
}

// ============================================================
#pragma mark - UILabel.setText hook
// ============================================================

typedef void (*SetTextIMP)(id, SEL, NSString *);
static SetTextIMP orig_setText = NULL;

static void hook_setText(id self, SEL _cmd, NSString *text) {
    if (text && ([text containsString:@"版本"] || [text containsString:@"过低"] || [text containsString:@"更新"])) {
        DLOG(@"[LABEL-TEXT] class=%@ text='%@'", NSStringFromClass([self class]), text);
        // Get call stack
        NSArray *stack = [NSThread callStackSymbols];
        for (int i = 0; i < MIN((int)stack.count, 8); i++) {
            DLOG(@"[STACK] %@", stack[i]);
        }
    }
    if (orig_setText) orig_setText(self, _cmd, text);
}

// ============================================================
#pragma mark - UIAlertController hook
// ============================================================

typedef void (*PresentVC_IMP)(id, SEL, id, BOOL, id);
static PresentVC_IMP orig_presentVC = NULL;
static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        DLOG(@"[ALERT] title: %@", alert.title ?: @"(nil)");
        DLOG(@"[ALERT] message: %@", alert.message ?: @"(nil)");
        for (UIAlertAction *action in alert.actions) {
            DLOG(@"[ALERT] action: %@", action.title ?: @"(nil)");
        }
    }
    if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark - SignatureKit showAlert: hook (suppress license alerts)
// ============================================================

typedef void (*ShowAlertIMP)(id, SEL, id);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, id message) {
    DLOG(@"[SIG] SignatureKit showAlert: %@", message);
    // Don't call original - suppress the alert!
    DLOG(@"[SIG] ALERT SUPPRESSED!");
}

// ============================================================
#pragma mark - SignatureKit exitApplication hook (block exit)
// ============================================================

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SIG] SignatureKit exitApplication BLOCKED!");
    // Don't call original - prevent exit!
}

// ============================================================
#pragma mark - SignatureKit judgeAppInfoWithBaseUrl: hook
// ============================================================

typedef void (*JudgeBaseIMP)(id, SEL, id);
static JudgeBaseIMP orig_judgeBase = NULL;
static void hook_judgeBase(id self, SEL _cmd, id baseUrl) {
    DLOG(@"[SIG] SignatureKit judgeAppInfoWithBaseUrl: %@", baseUrl);
    // Call original so verification proceeds
    if (orig_judgeBase) orig_judgeBase(self, _cmd, baseUrl);
}

// ============================================================
#pragma mark - SignatureKit handleAppInfoResult: hook
// ============================================================

typedef void (*HandleResultIMP)(id, SEL, id);
static HandleResultIMP orig_handleResult = NULL;
static void hook_handleResult(id self, SEL _cmd, id result) {
    DLOG(@"[SIG] SignatureKit handleAppInfoResult: %@", result);
    if (orig_handleResult) orig_handleResult(self, _cmd, result);
}

// ============================================================
#pragma mark - Floating LOG button
// ============================================================

@class WXHandler;
static UIButton *g_btn = nil;
static UITextView *g_tv = nil;
static UIView *g_panel = nil;
static WXHandler *g_handler = nil;

@interface WXHandler : NSObject
- (void)toggle;
- (void)copyLog;
@end

@implementation WXHandler
- (void)toggle {
    UIWindow *w = nil;
    for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (s.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *win in s.windows) { if (win.isKeyWindow) { w = win; break; } }
        }
    }
    if (!w) return;
    if (g_panel) { [g_panel removeFromSuperview]; g_panel = nil; return; }
    CGRect f = w.bounds;
    g_panel = [[UIView alloc] initWithFrame:f];
    g_panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 54, f.size.width - 32, 24)];
    lbl.text = @"WXHook v28.0";
    lbl.textColor = [UIColor greenColor];
    lbl.font = [UIFont boldSystemFontOfSize:16];
    [g_panel addSubview:lbl];
    UIButton *cp = [UIButton buttonWithType:UIButtonTypeSystem];
    cp.frame = CGRectMake(16, 84, 90, 34);
    [cp setTitle:@"Copy" forState:UIControlStateNormal];
    [cp setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    cp.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:0.2 alpha:1];
    cp.layer.cornerRadius = 8;
    [cp addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:cp];
    UIButton *cl = [UIButton buttonWithType:UIButtonTypeSystem];
    cl.frame = CGRectMake(f.size.width - 106, 84, 90, 34);
    [cl setTitle:@"Close" forState:UIControlStateNormal];
    [cl setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    cl.backgroundColor = [UIColor colorWithRed:0.8 green:0.2 blue:0.2 alpha:1];
    cl.layer.cornerRadius = 8;
    [cl addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:cl];
    g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 126, f.size.width - 16, f.size.height - 170)];
    g_tv.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.05 alpha:1];
    g_tv.textColor = [UIColor greenColor];
    g_tv.font = [UIFont fontWithName:@"Menlo" size:10];
    g_tv.editable = NO;
    // Dump current view hierarchy to log
    _log(@"[DUMP] === View Hierarchy ===");
    for (UIWindow *win in [UIApplication sharedApplication].windows) {
        dumpViewTree(win, 0);
    }
    _log(@"[DUMP] === End Hierarchy ===");
    
    g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"Empty";
    [g_panel addSubview:g_tv];
    [w addSubview:g_panel];
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
#pragma mark - Constructor - CRITICAL: NSUserDefaults hooked FIRST
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    // === PHASE 0: Pre-inject method into AFURLSessionManagerTaskDelegate ===
    // MUST be done BEFORE any NSURLSession is created, because NSURLSession
    // caches the delegate's method list at session creation time.
    @try {
        Class tdCls = objc_getClass("AFURLSessionManagerTaskDelegate");
        if (tdCls) {
            SEL sel = @selector(URLSession:dataTask:didReceiveResponse:completionHandler:);
            Method m = class_getInstanceMethod(tdCls, sel);
            if (m) {
                orig_afRecvRespHandler = (AFRecvRespHandlerIMP)method_getImplementation(m);
                method_setImplementation(m, (IMP)swizzled_af_didReceiveResponseWithHandler);
                _log(@"[INIT-EARLY] TaskDelegate.didReceiveResponse swizzled (found)");
            } else {
                BOOL added = class_addMethod(tdCls, sel,
                                            (IMP)swizzled_af_didReceiveResponseWithHandler,
                                            "v@:@@@@?");
                _log(added ? @"[INIT-EARLY] TaskDelegate.didReceiveResponse added" : @"[INIT-EARLY] TaskDelegate add FAILED");
            }
        } else {
            _log(@"[INIT-EARLY] AFURLSessionManagerTaskDelegate not found (class not loaded yet)");
        }
    } @catch (NSException *e) {
        _log([NSString stringWithFormat:@"[INIT-EARLY] Exception: %@", e]);
    }
    
    // === PHASE 1: Install NSUserDefaults hooks IMMEDIATELY ===
    // These must be active before any +load methods run
    Class udCls = [NSUserDefaults class];
    if (udCls) {
        Method m1 = class_getInstanceMethod(udCls, @selector(objectForKey:));
        if (m1) { orig_objectForKey = (ObjForKeyIMP)method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_objectForKey); }
        Method m2 = class_getInstanceMethod(udCls, @selector(boolForKey:));
        if (m2) { orig_boolForKey = (BoolForKeyIMP)method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_boolForKey); }
        Method m3 = class_getInstanceMethod(udCls, @selector(stringForKey:));
        if (m3) { orig_stringForKey = (StringForKeyIMP)method_getImplementation(m3); method_setImplementation(m3, (IMP)hook_stringForKey); }
        _log(@"[INIT] NSUserDefaults hooked (objectForKey + boolForKey + stringForKey)");
    }
    
    // === PHASE 2: Network hooks ===
    Class connCls = [NSURLConnection class];
    if (connCls) {
        Method sm = class_getClassMethod(connCls, @selector(sendSynchronousRequest:returningResponse:error:));
        if (sm) { orig_syncReq = (SyncReqIMP)method_getImplementation(sm); method_setImplementation(sm, (IMP)hook_sync); }
        Method am = class_getClassMethod(connCls, @selector(sendAsynchronousRequest:queue:completionHandler:));
        if (am) { orig_asyncReq = (AsyncReqIMP)method_getImplementation(am); method_setImplementation(am, (IMP)hook_async); }
        _log(@"[INIT] NSURLConnection hooked");
    }
    Class cls = [NSURLSession class];
    if (cls) {
        Method m1 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:completionHandler:));
        if (m1) { orig_dtwrc = (DTReqCompIMP)method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_dtwrc); }
        Method m2 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:completionHandler:));
        if (m2) { orig_dtwuc = (DTUrlCompIMP)method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_dtwuc); }
        // Also hook delegate mode (no completion handler)
        Method m3 = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
        if (m3) { orig_dtr = (DTReqIMP)method_getImplementation(m3); method_setImplementation(m3, (IMP)hook_dtr); }
        Method m4 = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
        if (m4) { orig_dtu = (DTUrlIMP)method_getImplementation(m4); method_setImplementation(m4, (IMP)hook_dtu); }
        _log(@"[INIT] NSURLSession hooked (completionHandler + delegate)");
        
        // Hook NSURLSessionTask.response getter to fake HTTP 200
        Class taskCls = [NSURLSessionTask class];
        Method respMethod = class_getInstanceMethod(taskCls, @selector(response));
        if (respMethod) {
            orig_taskResponse = (TaskResponseIMP)method_getImplementation(respMethod);
            method_setImplementation(respMethod, (IMP)hook_taskResponse);
            _log(@"[INIT] NSURLSessionTask.response hooked (fake HTTP 200)");
        }
        
        // NO scan code in constructor (causes crashes in v21-24)
        // NO AFHTTPSessionManager init hooks (never triggered, causes 2nd launch crash)
        
        // Register NSURLProtocol interceptor
        [NSURLProtocol registerClass:[WXInterceptor class]];
        _log(@"[INIT] NSURLProtocol interceptor registered for qunhongtech.com");
    }
    
    // === PHASE 2.5: NSURL creation hooks (catch ALL URLs at lowest level) ===
    Class urlCls = [NSURL class];
    Method usm = class_getClassMethod(urlCls, @selector(URLWithString:));
    if (usm) { orig_urlWithString = (URLWithStringIMP)method_getImplementation(usm); method_setImplementation(usm, (IMP)hook_urlWithString); _log(@"[INIT] NSURL.URLWithString hooked"); }
    
    // NSURLRequest init hook
    Class reqCls = [NSURLRequest class];
    Method rim = class_getInstanceMethod(reqCls, @selector(initWithURL:cachePolicy:timeoutInterval:));
    if (rim) { orig_reqInit = (ReqInitIMP)method_getImplementation(rim); method_setImplementation(rim, (IMP)hook_reqInit); _log(@"[INIT] NSURLRequest.initWithURL hooked"); }
    
    // CFNetwork function hook
    void *cfFunc = dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");
    if (cfFunc) {
        orig_cfCreateReq = (CFHTTPMsgCreateReqFunc)cfFunc;
        // Note: can't easily hook C functions with method_setImplementation
        // Instead, we rely on NSURL/NSURLRequest hooks above
        _log(@"[INIT] CFHTTPMessageCreateRequest found (logging via NSURL hooks)");
    }
    
    // === PHASE 3: UI hooks ===
    Class vcCls = [UIViewController class];
    Method pm = class_getInstanceMethod(vcCls, @selector(presentViewController:animated:completion:));
    if (pm) { orig_presentVC = (PresentVC_IMP)method_getImplementation(pm); method_setImplementation(pm, (IMP)hook_presentVC); _log(@"[INIT] UIAlertController hooked"); }
    
    // UIView.addSubview - catch ALL popups including custom ones
    Class viewCls = [UIView class];
    Method asv = class_getInstanceMethod(viewCls, @selector(addSubview:));
    if (asv) { orig_addSubview = (AddSubviewIMP)method_getImplementation(asv); method_setImplementation(asv, (IMP)hook_addSubview); _log(@"[INIT] UIView.addSubview hooked"); }
    
    // UILabel.setText - detect Chinese text changes
    Class lblCls = [UILabel class];
    Method stm = class_getInstanceMethod(lblCls, @selector(setText:));
    if (stm) { orig_setText = (SetTextIMP)method_getImplementation(stm); method_setImplementation(stm, (IMP)hook_setText); _log(@"[INIT] UILabel.setText hooked"); }
    
    // === PHASE 4: Deferred - SignatureKit hooks + UI ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // Hook SignatureKit critical methods
        Class skCls = NSClassFromString(@"SignatureKit");
        if (skCls) {
            Class metaCls = object_getClass(skCls);
            
            // showAlert: - SUPPRESS license alerts
            Method m = class_getClassMethod(skCls, @selector(showAlert:));
            if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); _log(@"[INIT] SignatureKit showAlert: hooked (SUPPRESS)"); }
            
            // exitApplication - BLOCK exit
            m = class_getClassMethod(skCls, @selector(exitApplication));
            if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); _log(@"[INIT] SignatureKit exitApplication hooked (BLOCK)"); }
            
            // judgeAppInfoWithBaseUrl: - LOG
            m = class_getClassMethod(skCls, @selector(judgeAppInfoWithBaseUrl:));
            if (m) { orig_judgeBase = (JudgeBaseIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeBase); _log(@"[INIT] SignatureKit judgeAppInfoWithBaseUrl: hooked"); }
            
            // handleAppInfoResult: - LOG
            m = class_getClassMethod(skCls, @selector(handleAppInfoResult:));
            if (m) { orig_handleResult = (HandleResultIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_handleResult); _log(@"[INIT] SignatureKit handleAppInfoResult: hooked"); }
            
            // Enumerate ALL methods again
            unsigned int mcount = 0;
            Method *methods = class_copyMethodList(metaCls, &mcount);
            for (unsigned int i = 0; i < mcount; i++) {
                DLOG(@"[SK] +[%@]", NSStringFromSelector(method_getName(methods[i])));
            }
            if (methods) free(methods);
        } else {
            _log(@"[INIT] WARNING: SignatureKit NOT found!");
        }
        
        // SignatureCheck hooks
        Class scCls = NSClassFromString(@"SignatureCheck");
        if (scCls) {
            _log(@"[INIT] SignatureCheck found");
        }
        
        // Dump NSUserDefaults to see what keys exist
        NSDictionary *allDefaults = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *key in allDefaults) {
            if (isLicenseKey(key)) {
                DLOG(@"[NSUD-DUMP] %@ = %@", key, allDefaults[key]);
            }
        }
        _log([NSString stringWithFormat:@"[NSUD-DUMP] Total keys: %lu", (unsigned long)allDefaults.count]);
        
        // Create button
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
