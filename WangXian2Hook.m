#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <sys/mman.h>
#import <CommonCrypto/CommonCrypto.h>
#import "fishhook.h"
#include <string>
#include <cstring>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:@"[%@] " fmt, _timestamp(), ##__VA_ARGS__])
#define DLOG_HEX(buf, len) _log_hex(buf, len)

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES;
static BOOL g_logHexEnabled = YES;
static BOOL g_logProtoEnabled = YES;
static NSUInteger g_logMaxSize = 10 * 1024 * 1024;

static NSString *g_rsaPublicKey = nil;
static NSString *readRsaPublicKey(void);

static char g_loginServerIP[64] = "47.100.222.229";
static int g_loginServerPort = 5678;
static BOOL g_forcePlainPassword = NO;

static UIButton *g_logBtn = nil;
static UIView *g_logPanel = nil;
static UITextView *g_logTextView = nil;
static UILabel *g_logStatusLbl = nil;

static NSString *_timestamp(void) {
    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"HH:mm:ss.SSS";
    return [fmt stringFromDate:[NSDate date]];
}

static void _log_rotate(void) {
    if (!g_logPath) return;
    @try {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        if (size > g_logMaxSize) {
            NSString *oldPath = [g_logPath stringByAppendingString:@".old"];
            [[NSFileManager defaultManager] removeItemAtPath:oldPath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:g_logPath toPath:oldPath error:nil];
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[WX2Hook] Log rotated (>%llu bytes)", size);
        }
    } @catch (NSException *e) {}
}

static void _log(NSString *msg) {
    if (!g_logPath || !g_logEnabled) return;
    
    _log_rotate();
    
    @try {
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
        if (data) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { 
                [fh seekToEndOfFile]; 
                [fh writeData:data]; 
                [fh closeFile]; 
            }
        }
        NSLog(@"[WX2Hook] %@", msg);
        
        if (g_logTextView && !g_logPanel.hidden) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
                if (content.length > g_logTextView.text.length + 5000) {
                    content = [content substringFromIndex:content.length - 50000];
                }
                g_logTextView.text = content;
                [g_logTextView scrollRangeToVisible:NSMakeRange(g_logTextView.text.length, 0)];
            });
        }
    } @catch (NSException *e) {}
}

static void _log_hex(const void *buf, ssize_t len) {
    if (!g_logHexEnabled || !buf || len <= 0) return;
    
    const unsigned char *p = (const unsigned char *)buf;
    NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:len];
    
    size_t showLen = len > 256 ? 256 : (size_t)len;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    
    if (len > 256) {
        [hex appendFormat:@"... (%zd more bytes)", len - 256];
        [ascii appendFormat:@"..."];
    }
    
    _log([NSString stringWithFormat:@"HEX: %@\nTXT: %@", hex, ascii]);
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wx2hook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        _log(@"=== WangXian2Hook v4.6 极简版 (无阻塞connect + SEND-DEBUG/RECV-DEBUG) ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
        _log([NSString stringWithFormat:@"Log max size: %lu bytes", (unsigned long)g_logMaxSize]);
        
        // 加载RSA公钥（如果存在）
        g_rsaPublicKey = readRsaPublicKey();
        if (g_rsaPublicKey) {
            DLOG(@"[RSA] Public key loaded, RSA encryption will be used for password");
        } else {
            DLOG(@"[RSA] No public key found, password will be sent in plaintext");
        }
    }
}

#pragma mark - Crypto Functions

static NSString *md5String(NSString *input) {
    if (!input) return nil;
    const char *cStr = [input UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), result);
    NSMutableString *md5Str = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [md5Str appendFormat:@"%02x", result[i]];
    }
    return md5Str;
}

static NSString *hmacSHA256String(NSString *input, NSString *key) {
    if (!input || !key) return nil;
    const char *cStr = [input UTF8String];
    const char *keyStr = [key UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyStr, (CC_LONG)strlen(keyStr), cStr, (CC_LONG)strlen(cStr), result);
    NSMutableString *hmacStr = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hmacStr appendFormat:@"%02x", result[i]];
    }
    return hmacStr;
}

static NSString *generateSign(NSString *username, NSString *password, NSString *deviceId, NSString *version) {
    NSString *signKey = @"SQAGE_MIESHI_LOGIN_KEY";
    NSString *input = [NSString stringWithFormat:@"%@%@%@%@%@", username, password, deviceId, version, signKey];
    NSString *sign = md5String(input);
    DLOG(@"[SIGN] Generated: username=%@ password=%@ deviceId=%@ version=%@", username, password, deviceId, version);
    DLOG(@"[SIGN] Input: %@", input);
    DLOG(@"[SIGN] Result: %@", sign);
    return sign;
}

static NSString *generateSignV2(NSString *username, NSString *password, NSString *deviceId) {
    NSString *signKey = @"SQAGE_MIESHI";
    NSString *input = [NSString stringWithFormat:@"%@%@%@%@", username, password, deviceId, signKey];
    NSString *sign = md5String(input);
    DLOG(@"[SIGN-V2] === SIGN GENERATION DETAILS ===");
    DLOG(@"[SIGN-V2] username: '%@' (len=%lu)", username, (unsigned long)username.length);
    DLOG(@"[SIGN-V2] password: '%@' (len=%lu)", password, (unsigned long)password.length);
    DLOG(@"[SIGN-V2] deviceId: '%@' (len=%lu)", deviceId, (unsigned long)deviceId.length);
    DLOG(@"[SIGN-V2] key: '%@' (len=%lu)", signKey, (unsigned long)signKey.length);
    DLOG(@"[SIGN-V2] INPUT: '%@' (len=%lu)", input, (unsigned long)input.length);
    DLOG(@"[SIGN-V2] RESULT: '%@'", sign);
    return sign;
}

#pragma mark - RSA Encryption

static NSString *readRsaPublicKey(void) {
    NSString *pkPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/pk.txt"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:pkPath]) {
        NSString *key = [NSString stringWithContentsOfFile:pkPath encoding:NSUTF8StringEncoding error:nil];
        if (key) {
            key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            DLOG(@"[RSA] Public key read from pk.txt (len=%lu)", (unsigned long)key.length);
            return key;
        }
    }
    DLOG(@"[RSA] pk.txt not found, using hardcoded public key");
    
    static NSString *hardcodedKey = @"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCSzpfizT72XGTfAoXnNtRUCAh+licr5QxhhVwXP1+cNZZ8GTrH/zRkuN37693qGKcM6Odq8ipK41EebhHpaVMPEhCUIh5blk9Q1EhZxTT90B+fidJQiWZ+p4IwkkojTjvmsuRkVQexy3JA+HCuteu/66jo/MoapVfGA+AGhH0giY2rg7nbUTGSpSrhVHwnF77VihHAUaucyqHGmEnRyTjSj6Tth9gsO/hT781yWtd8rvY2Q3C69oBUr8xMo/sZTchLsdYk0zXvKSDy8MXELnkqqDEqolsRdJHHYMIVcXOeXvQPnCoVXA+4uttLMsB2DDOdyvF23BsAKVIgTsRXaKlJAgMBAAECggEAFsnE3+rWNC3BZrCgknR7XxPkJaovKGwkkNq/ocgvkjLrShYsfrEJs/zSUHGbf+QVwjZA/ePbVsaUZ/HUC/RSdUtrkWL+bV8WrshU9sJa6G8vCXe+UswRQeXEmr+KjJJvT+9C7qQYTqvy70zhSO1qS99L1+athJdX2Z/uXXSha7RSL4g2nDx+ajCJ+CtlT1xG5K+GriPcn2lvIhaGjDxZwpv8aehRnw1hhyG6dcGN6lX7AOhZb1O4v6WA9YsSy8MGSNlAMlVjdm0dwqca0+fm8M6LEnxHiadSyAEvo8TuJ7EAj3YYmwKlPg+8TMub/pbO/JVresMxgzp96XInKK6LRQKBgQDKtrk1oWOASPADxTtEKmT/kwPMXIojdhE+fN7MIMXk4eKNbqwH8eVVmnSw2ecsOQ5Dk/yy8XnfibOzgc78AGA82H0Ajb4Sc++3Hv5zq0MDBxyywKTodjazJ1EpagcleUHBIT8ivOJcPnFBAEzHwt0eIU0id2Q+imvKb6vpBEwhtwKBgQC5ZbhRok8QN4o3xq4033Ev0oGOWbmfK4d4/e/uaPGpk5LE24WJIN8qGPL7MJjR/s4WFmCNOjh0hN6jkv2nbYk2S8j6PYgyTtgsJ7kb/joUaBs8wjvOG1VP6ILCPiLQe3M0lI80kFWosH4jLMdNEm/kwfX33Fi5v0voeYySH/WM/wKBgCj+PIP46As4NLk+eFa3kAcS7tCz4gd7x87wJ4n2Eq7PcyYQvF867pqaCoD8/7+0pgrKcW6qYG/xA9MILBhP5yZGzTiAcXB/23kXnnM7reh91rLbPD36MeOWztXmKB3O4Joyo/bdZZUr13FCo0Q+RsLiDxwqMq5nBZdBb+1GPjMPAoGAVaABLNLFqTu9fl0ogArif6+9Xj1aWYUFIIBHm9ikJCmgE4M/fUHNT+gN8K1VJ0eDbvgOx6sn/8iN+wYcWINiZ81AmTJqALIhbOM7vw3/TQV37uvWKy68jBdarNN9yMP7RUGHkkNHDI3W8+/ubE4jl4dtTnhaEg+jw06/+Y0BH4kCgYBN6HqRRL6LwYZkhv/5nhi7NpJRE7+ikuH2rrBh6qFvaBGqAVdG+ylc+Oe5+lz7ppZwfvlXsPy6v1rGgg0LvKVbVXt/nJDU2mAaRWPY/nItZT2ztPZ3uh73cI4398AXYCt2FlkoRe8EmVD54nyK+HB8X+VnxcfyjEDKCydHLuCg6g==";
    return hardcodedKey;
}

static NSString *rsaEncryptString(NSString *input, NSString *publicKeyStr) {
    if (!input || !publicKeyStr) {
        DLOG(@"[RSA] Error: input or publicKey is nil");
        return nil;
    }
    
    @try {
        NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
        NSData *keyData = [publicKeyStr dataUsingEncoding:NSUTF8StringEncoding];
        
        SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)keyData);
        if (!certificate) {
            DLOG(@"[RSA] Error: Cannot create certificate from public key");
            return nil;
        }
        
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustRef trust;
        OSStatus status = SecTrustCreateWithCertificates(certificate, policy, &trust);
        CFRelease(certificate);
        CFRelease(policy);
        
        if (status != errSecSuccess) {
            DLOG(@"[RSA] Error: SecTrustCreateWithCertificates failed (%d)", (int)status);
            return nil;
        }
        
        SecTrustResultType trustResult;
        status = SecTrustEvaluate(trust, &trustResult);
        if (status != errSecSuccess) {
            CFRelease(trust);
            DLOG(@"[RSA] Error: SecTrustEvaluate failed (%d)", (int)status);
            return nil;
        }
        
        SecKeyRef publicKey = SecTrustCopyPublicKey(trust);
        CFRelease(trust);
        
        if (!publicKey) {
            DLOG(@"[RSA] Error: Cannot extract public key from trust");
            return nil;
        }
        
        size_t keySize = SecKeyGetBlockSize(publicKey);
        size_t blockSize = keySize - 42;
        NSMutableData *encryptedData = [[NSMutableData alloc] init];
        
        const unsigned char *bytes = (const unsigned char *)inputData.bytes;
        size_t idx = 0;
        while (idx < inputData.length) {
            size_t dataLen = MIN(blockSize, inputData.length - idx);
            NSData *block = [NSData dataWithBytes:bytes + idx length:dataLen];
            
            size_t encryptedSize = keySize;
            unsigned char *encryptedBytes = (unsigned char *)malloc(encryptedSize);
            
            OSStatus encryptStatus = SecKeyEncrypt(publicKey, kSecPaddingPKCS1,
                (const unsigned char *)block.bytes, dataLen,
                encryptedBytes, &encryptedSize);
            
            if (encryptStatus == errSecSuccess) {
                [encryptedData appendBytes:encryptedBytes length:encryptedSize];
            } else {
                DLOG(@"[RSA] Error: SecKeyEncrypt failed (%d)", (int)encryptStatus);
                free(encryptedBytes);
                CFRelease(publicKey);
                return nil;
            }
            free(encryptedBytes);
            idx += dataLen;
        }
        
        CFRelease(publicKey);
        
        NSString *base64Str = [encryptedData base64EncodedStringWithOptions:0];
        DLOG(@"[RSA] Encryption OK: input='%@' (len=%lu) -> output='%@' (len=%lu)",
             input, (unsigned long)input.length,
             base64Str.length > 50 ? [base64Str substringToIndex:50] : base64Str,
             (unsigned long)base64Str.length);
        return base64Str;
    } @catch (NSException *e) {
        DLOG(@"[RSA] Exception: %@", e);
        return nil;
    }
}

#pragma mark - C++ Function Hooks (GameMessageFactory)

// 使用 std::string& 的正确函数签名（AAPCS64下引用=指针，ABI兼容）
// iOS二进制中只有v2，不需要v1的typedef
typedef void (*ConstructLoginReqV2Func)(std::string& out,
    const std::string& p0, const std::string& p1, const std::string& p2,
    const std::string& p3, const std::string& p4, const std::string& p5,
    const std::string& p6, const std::string& p7, const std::string& p8,
    const std::string& p9, const std::string& p10, const std::string& p11,
    const std::string& p12, const std::string& p13, const std::string& p14,
    const std::string& p15);

static ConstructLoginReqV2Func orig_construct_login_v2 = NULL;
static BOOL g_manualMode = NO;

static void _writeBE32(unsigned char *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF; buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;  buf[3] = val & 0xFF;
}

static void _writeBE16(unsigned char *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF; buf[1] = val & 0xFF;
}

static void _appendField(std::string& packet, const std::string& field) {
    unsigned char lenBuf[2];
    _writeBE16(lenBuf, (uint16_t)field.size());
    packet.append((const char *)lenBuf, 2);
    packet.append(field);
}

// 手动构造v2二进制包（fallback模式，完全不依赖游戏ABI）
static void manualConstructV2Packet(std::string& out,
    const std::string& username, const std::string& password,
    const std::string& deviceId, const std::string& channel,
    const std::string& os, const std::string& phoneModel,
    const std::string& subChannel, const std::string& sign) {

    DLOG(@"[MANUAL] Start manual v2 binary construction");

    std::string packet;
    packet.reserve(512);

    // 4字节pktLen占位（稍后回填）
    packet.append(4, '\0');
    // 4字节cmd = 0x002EE121 (大端)
    unsigned char cmdBuf[4] = {0x00, 0x2E, 0xE1, 0x21};
    packet.append((const char *)cmdBuf, 4);
    // 4字节status = 0
    packet.append(4, '\0');

    // 16个字符串字段（每个=2字节长度前缀+内容）
    _appendField(packet, username);     // 字段0
    _appendField(packet, password);     // 字段1
    _appendField(packet, deviceId);     // 字段2
    _appendField(packet, channel);      // 字段3
    _appendField(packet, os);           // 字段4
    _appendField(packet, phoneModel);   // 字段5
    _appendField(packet, "");           // 字段6
    _appendField(packet, "");           // 字段7
    _appendField(packet, subChannel);   // 字段8
    _appendField(packet, sign);         // 字段9
    _appendField(packet, "");           // 字段10
    _appendField(packet, "");           // 字段11
    _appendField(packet, "");           // 字段12
    _appendField(packet, "");           // 字段13
    _appendField(packet, "");           // 字段14
    _appendField(packet, "");           // 字段15

    // 回填pktLen（不包含自身的4字节）
    uint32_t pktLen = (uint32_t)(packet.size() - 4);
    _writeBE32((unsigned char *)&packet[0], pktLen);

    out = packet;

    DLOG(@"[MANUAL] v2 packet constructed, totalLen=%zu, pktLen=%u", out.size(), pktLen);
    if (out.size() <= 256) {
        DLOG_HEX(out.data(), out.size());
    }
}

// v2 Hook函数 - iOS游戏直接调用v2，拦截后检查sign并修正
// 参数映射: p0=username p1=password p2=deviceId p3=channel p4=os
//           p5=phoneModel p6=? p7=? p8=subChannel p9=sign
//           p10-p15=?
static void my_construct_login_v2(std::string& out,
    const std::string& p0, const std::string& p1, const std::string& p2,
    const std::string& p3, const std::string& p4, const std::string& p5,
    const std::string& p6, const std::string& p7, const std::string& p8,
    const std::string& p9, const std::string& p10, const std::string& p11,
    const std::string& p12, const std::string& p13, const std::string& p14,
    const std::string& p15) {

    NSLog(@"[HOOK] v2 intercepted: username=%s deviceId=%s sign=%s",
          p0.c_str(), p2.c_str(), p9.c_str());

    // 详细日志：记录所有16个参数
    DLOG(@"[HOOK] v2 intercepted - all 16 params:");
    DLOG(@"[HOOK]   p0(username)   = %s", p0.c_str());
    DLOG(@"[HOOK]   p1(password)   = %s", p1.c_str());
    DLOG(@"[HOOK]   p2(deviceId)   = %s", p2.c_str());
    DLOG(@"[HOOK]   p3(channel)    = %s", p3.c_str());
    DLOG(@"[HOOK]   p4(os)         = %s", p4.c_str());
    DLOG(@"[HOOK]   p5(phoneModel) = %s", p5.c_str());
    DLOG(@"[HOOK]   p6             = %s", p6.c_str());
    DLOG(@"[HOOK]   p7             = %s", p7.c_str());
    DLOG(@"[HOOK]   p8(subChannel) = %s", p8.c_str());
    DLOG(@"[HOOK]   p9(sign)       = %s", p9.c_str());
    DLOG(@"[HOOK]   p10            = %s", p10.c_str());
    DLOG(@"[HOOK]   p11            = %s", p11.c_str());
    DLOG(@"[HOOK]   p12            = %s", p12.c_str());
    DLOG(@"[HOOK]   p13            = %s", p13.c_str());
    DLOG(@"[HOOK]   p14            = %s", p14.c_str());
    DLOG(@"[HOOK]   p15            = %s", p15.c_str());

    // 检查sign（p9）- 如果为空则重新生成
    std::string signToUse = p9;
    BOOL signRegenerated = NO;

    if (p9.empty()) {
        DLOG(@"[HOOK] Sign is EMPTY - regenerating...");
        NSString *userNS = [NSString stringWithUTF8String:p0.c_str()];
        NSString *passNS = [NSString stringWithUTF8String:p1.c_str()];
        NSString *devNS = [NSString stringWithUTF8String:p2.c_str()];
        NSString *signNS = generateSignV2(userNS, passNS, devNS);
        signToUse = [signNS UTF8String];
        signRegenerated = YES;
        DLOG(@"[HOOK] Sign regenerated: %s", signToUse.c_str());
    } else {
        DLOG(@"[HOOK] Sign already present (len=%zu), using as-is", p9.size());
    }

    // 调用原始v2函数（使用可能修正后的sign）
    if (orig_construct_login_v2) {
        DLOG(@"[HOOK] Calling original v2 at %p...", orig_construct_login_v2);

        @try {
            orig_construct_login_v2(out,
                p0, p1, p2, p3, p4, p5, p6, p7, p8,
                signToUse, p10, p11, p12, p13, p14, p15);

            DLOG(@"[HOOK] v2 original called successfully, packet size=%zu", out.size());
            if (out.size() > 0 && out.size() <= 256) {
                DLOG_HEX(out.data(), out.size());
            }
            NSLog(@"[HOOK] v2 original called OK, size=%zu, signFixed=%d",
                  out.size(), signRegenerated);
            return;
        } @catch (NSException *e) {
            DLOG(@"[HOOK] *** EXCEPTION in v2 original: %@ ***", e);
            NSLog(@"[HOOK] v2 EXCEPTION: %@", e);
            g_manualMode = YES;
        }
    }

    // Fallback：手动构造二进制包
    DLOG(@"[HOOK] Fallback to manual binary construction");
    NSLog(@"[HOOK] Fallback to manual binary construction");

    @try {
        manualConstructV2Packet(out, p0, p1, p2, p3, p4, p5, p8, signToUse);
        DLOG(@"[HOOK] Manual v2 packet OK, size=%zu", out.size());
    } @catch (NSException *e) {
        DLOG(@"[HOOK] *** MANUAL CONSTRUCTION ALSO FAILED: %@ ***", e);
        DLOG(@"[HOOK] Last resort: returning empty packet");
        out = "";
    }
}

// 符号查找：多重fallback策略
static void *find_cpp_symbol_multi(const char *mangledName, const char *shortName) {
    // 策略1：dlsym在主进程中查找完整mangled name
    void *handle = dlopen(NULL, RTLD_NOW);
    if (handle) {
        void *sym = dlsym(handle, mangledName);
        if (sym) {
            DLOG(@"[SYMLOOKUP] Found '%s' via dlsym(main) at %p", shortName, sym);
            return sym;
        }
    }

    // 策略2：遍历所有已加载的镜像
    DLOG(@"[SYMLOOKUP] '%s' not in main image, searching %u images...", shortName, _dyld_image_count());
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;

        void *imgHandle = dlopen(imageName, RTLD_NOW);
        if (imgHandle) {
            void *imgSym = dlsym(imgHandle, mangledName);
            if (imgSym) {
                DLOG(@"[SYMLOOKUP] Found '%s' in %s at %p", shortName, imageName, imgSym);
                return imgSym;
            }
        }
    }

    // 策略3：尝试去掉前缀的变体（某些链接器会去掉前导下划线）
    if (mangledName[0] == '_') {
        const char *altName = mangledName + 1;
        void *altSym = dlsym(RTLD_DEFAULT, altName);
        if (altSym) {
            DLOG(@"[SYMLOOKUP] Found '%s' (no underscore) at %p", shortName, altSym);
            return altSym;
        }
    }

    DLOG(@"[SYMLOOKUP] *** '%s' NOT FOUND anywhere ***", shortName);
    return NULL;
}

static void init_cpp_hooks(void) {
    DLOG(@"[C++-HOOK] Initializing C++ function hooks (v4.2 iOS-corrected)...");
    NSLog(@"[HOOK] init_cpp_hooks starting");

    // CORRECTED: iOS binary uses NSt3__1 (standard libc++), NOT NSt6__ndk1 (Android NDK)
    // iOS二进制中只有v2，没有v1！v2的mangled name从iOS binary符号表直接提取
    const char *v2_sym = "_ZN18GameMessageFactory31construct_NEW_USER_LOGIN_REQ_v2ERNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_S7_";

    // 用fishhook Hook v2函数（iOS游戏直接调用v2，不存在v1）
    struct rebinding rebindings[1];
    rebindings[0].name = v2_sym;
    rebindings[0].replacement = (void *)my_construct_login_v2;
    rebindings[0].replaced = (void **)&orig_construct_login_v2;

    int result = rebind_symbols(rebindings, 1);
    DLOG(@"[C++-HOOK] fishhook rebind_symbols(v2) result: %d", result);

    if (orig_construct_login_v2) {
        DLOG(@"[C++-HOOK] v2 HOOKED successfully! Original saved at %p", orig_construct_login_v2);
    } else {
        DLOG(@"[C++-HOOK] v2 NOT hooked via fishhook - trying dlsym fallback (lookup only, no interception)");
        void *v2_func = find_cpp_symbol_multi(v2_sym, "construct_LOGIN_REQ_v2");
        if (v2_func) {
            orig_construct_login_v2 = (ConstructLoginReqV2Func)v2_func;
            DLOG(@"[C++-HOOK] v2 found via dlsym at %p (lookup only - fishhook may not intercept internal calls)", v2_func);
            DLOG(@"[C++-HOOK] WARNING: v2 is an internal function, fishhook may not intercept direct calls");
            DLOG(@"[C++-HOOK] Socket-level hook (hook_send) will handle v2 login packets as fallback");
        } else {
            DLOG(@"[C++-HOOK] v2 NOT FOUND anywhere - relying on socket-level hook only");
        }
    }

    // 汇报状态
    BOOL v2_hooked = (orig_construct_login_v2 != NULL);

    DLOG(@"[C++-HOOK] === Hook Status Summary ===");
    DLOG(@"[C++-HOOK]   v2 hooked (fishhook): %s", v2_hooked ? "YES" : "NO");
    DLOG(@"[C++-HOOK]   manual mode: %s", g_manualMode ? "FORCED" : "AUTO (fallback only)");

    if (v2_hooked) {
        DLOG(@"[C++-HOOK] MODE: v2 hook (intercept + log + fix sign + call original)");
    } else {
        DLOG(@"[C++-HOOK] MODE: C++ hook FAILED - relying on socket-level v2 handler");
        DLOG(@"[C++-HOOK] Socket hook will handle v2 login (cmd=0x002EE121) at TCP layer");
    }

    NSLog(@"[HOOK] init_cpp_hooks done: v2_hooked=%d manual=%d", v2_hooked, g_manualMode);
}

#pragma mark - Log Panel UI

@interface WX2Handler : NSObject
@property (nonatomic) BOOL panelVisible;
- (void)togglePanel;
- (void)clearLog;
- (void)toggleLogging;
- (void)copyLog;
- (void)exportLog;
- (void)refreshLog;
- (void)handlePan:(UIPanGestureRecognizer *)gesture;
- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture;
@end

@implementation WX2Handler

- (void)togglePanel {
    if (!g_logPanel) {
        [self createLogPanel];
    }
    self.panelVisible = !self.panelVisible;
    g_logPanel.hidden = !self.panelVisible;
    
    if (self.panelVisible) {
        [self refreshLog];
        DLOG(@"[UI] Log panel shown");
    } else {
        DLOG(@"[UI] Log panel hidden");
    }
}

- (void)createLogPanel {
    UIWindow *w = g_logBtn.window;
    if (!w) return;
    
    CGFloat pw = w.bounds.size.width - 32;
    CGFloat ph = w.bounds.size.height - 150;
    
    g_logPanel = [[UIView alloc] initWithFrame:CGRectMake(16, 100, pw, ph)];
    g_logPanel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
    g_logPanel.layer.cornerRadius = 12;
    g_logPanel.hidden = YES;
    
    UILabel *titleLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, pw - 200, 24)];
    titleLbl.text = @"WangXian2Hook v4.6 极简版";
    titleLbl.textColor = [UIColor greenColor];
    titleLbl.font = [UIFont boldSystemFontOfSize:14];
    [g_logPanel addSubview:titleLbl];
    
    g_logStatusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];
    g_logStatusLbl.text = @"日志: 开";
    g_logStatusLbl.textColor = [UIColor greenColor];
    g_logStatusLbl.font = [UIFont boldSystemFontOfSize:12];
    [g_logPanel addSubview:g_logStatusLbl];
    
    CGFloat bx = pw - 270;
    
    UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    onOffBtn.frame = CGRectMake(bx, 8, 50, 28);
    [onOffBtn setTitle:@"开关" forState:UIControlStateNormal];
    [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];
    [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:onOffBtn];
    
    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clearBtn.frame = CGRectMake(bx + 55, 8, 50, 28);
    [clearBtn setTitle:@"清除" forState:UIControlStateNormal];
    [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
    [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:clearBtn];
    
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(bx + 110, 8, 50, 28);
    [copyBtn setTitle:@"复制" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
    [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:copyBtn];
    
    UIButton *shareBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    shareBtn.frame = CGRectMake(bx + 165, 8, 50, 28);
    [shareBtn setTitle:@"导出" forState:UIControlStateNormal];
    [shareBtn setTitleColor:[UIColor magentaColor] forState:UIControlStateNormal];
    [shareBtn addTarget:self action:@selector(exportLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:shareBtn];
    
    UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshBtn.frame = CGRectMake(bx + 220, 8, 50, 28);
    [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];
    [refreshBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
    [refreshBtn addTarget:self action:@selector(refreshLog) forControlEvents:UIControlEventTouchUpInside];
    [g_logPanel addSubview:refreshBtn];
    
    g_logTextView = [[UITextView alloc] initWithFrame:CGRectMake(8, 62, pw - 16, ph - 72)];
    g_logTextView.backgroundColor = [UIColor blackColor];
    g_logTextView.textColor = [UIColor greenColor];
    g_logTextView.font = [UIFont fontWithName:@"Menlo" size:11];
    g_logTextView.editable = NO;
    [g_logPanel addSubview:g_logTextView];
    
    [w addSubview:g_logPanel];
}

- (void)clearLog {
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_logTextView.text = @"(cleared)";
    g_logEnabled = YES;
    g_logStatusLbl.text = @"日志: 开";
    g_logStatusLbl.textColor = [UIColor greenColor];
    DLOG(@"=== Log cleared ===");
}

- (void)toggleLogging {
    g_logEnabled = !g_logEnabled;
    g_logStatusLbl.text = g_logEnabled ? @"日志: 开" : @"日志: 关";
    g_logStatusLbl.textColor = g_logEnabled ? [UIColor greenColor] : [UIColor redColor];
    if (g_logEnabled) {
        DLOG(@"=== Logging resumed ===");
    }
}

- (void)copyLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [UIPasteboard generalPasteboard].string = content;
    DLOG(@">>> COPIED %lu chars >>>", (unsigned long)content.length);
    g_logTextView.text = [NSString stringWithFormat:@">>> COPIED %lu chars to clipboard <<<", (unsigned long)content.length];
}

- (void)exportLog {
    if (!g_logPath) {
        DLOG(@"[EXPORT] Error: log path is nil");
        return;
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:g_logPath]) {
        DLOG(@"[EXPORT] Error: log file does not exist");
        return;
    }
    
    NSData *fullData = [NSData dataWithContentsOfFile:g_logPath];
    NSData *exportData = fullData;
    if (fullData.length > 200 * 1024) {
        exportData = [fullData subdataWithRange:NSMakeRange(fullData.length - 200 * 1024, 200 * 1024)];
    }
    
    NSString *exportPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wx2hook_export.log"];
    [exportData writeToFile:exportPath atomically:YES];
    DLOG(@"[EXPORT] Log exported to: %@", exportPath);
    g_logTextView.text = [NSString stringWithFormat:@">>> EXPORTED to Documents/wx2hook_export.log <<<"];
}

- (void)refreshLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_logTextView.text = content;
    [g_logTextView scrollRangeToVisible:NSMakeRange(g_logTextView.text.length, 0)];
}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    if (!g_logBtn || g_logBtn.hidden) return;
    UIView *v = gesture.view;
    CGPoint translation = [gesture translationInView:v.superview];
    CGPoint newCenter = CGPointMake(v.center.x + translation.x, v.center.y + translation.y);
    CGRect bounds = v.superview.bounds;
    newCenter.x = MAX(25, MIN(bounds.size.width - 25, newCenter.x));
    newCenter.y = MAX(25, MIN(bounds.size.height - 25, newCenter.y));
    v.center = newCenter;
    [gesture setTranslation:CGPointZero inView:v.superview];
}

- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture {
    if (g_logBtn) {
        g_logBtn.hidden = !g_logBtn.hidden;
        if (!g_logBtn.hidden) {
            DLOG(@"[UI] Log button shown via double-tap");
        } else {
            DLOG(@"[UI] Log button hidden via double-tap");
            g_logPanel.hidden = YES;
            self.panelVisible = NO;
        }
    }
}

@end

static void createLogButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *w = [[[UIApplication sharedApplication] delegate] window];
        if (!w || g_logBtn) return;
        
        WX2Handler *handler = [[WX2Handler alloc] init];
        
        g_logBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        g_logBtn.frame = CGRectMake(w.bounds.size.width - 60, 200, 50, 50);
        g_logBtn.layer.cornerRadius = 25;
        g_logBtn.clipsToBounds = YES;
        
        [g_logBtn setTitle:@"LOG" forState:UIControlStateNormal];
        [g_logBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_logBtn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
        g_logBtn.titleLabel.font = [UIFont systemFontOfSize:10];
        g_logBtn.hidden = YES;
        g_logBtn.userInteractionEnabled = YES;
        
        [g_logBtn addTarget:handler action:@selector(togglePanel) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:g_logBtn];
        [w bringSubviewToFront:g_logBtn];
        
        UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:handler action:@selector(handlePan:)];
        panGesture.cancelsTouchesInView = NO;
        panGesture.requiresExclusiveTouchType = NO;
        [g_logBtn addGestureRecognizer:panGesture];
        
        UITapGestureRecognizer *doubleTap = [[UITapGestureRecognizer alloc] initWithTarget:handler action:@selector(handleDoubleTap:)];
        doubleTap.numberOfTapsRequired = 2;
        [w addGestureRecognizer:doubleTap];
        
        DLOG(@"[UI] Log button created (double-tap to show)");
    });
}

#pragma mark - Socket Tracking

#define MAX_FDS 64
static struct {
    char host[64];
    int port;
    int active;
} g_fdInfo[MAX_FDS] = {0};

static void trackFd(int fd, const char *host, int port) {
    if (fd >= 0 && fd < MAX_FDS) {
        strncpy(g_fdInfo[fd].host, host ?: "", sizeof(g_fdInfo[fd].host) - 1);
        g_fdInfo[fd].port = port;
        g_fdInfo[fd].active = 1;
    }
}

static const char *getHostForFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_fdInfo[fd].active) {
        return g_fdInfo[fd].host[0] ? g_fdInfo[fd].host : NULL;
    }
    return NULL;
}

static int getPortForFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS && g_fdInfo[fd].active) {
        return g_fdInfo[fd].port;
    }
    return 0;
}

static void releaseFd(int fd) {
    if (fd >= 0 && fd < MAX_FDS) {
        memset(&g_fdInfo[fd], 0, sizeof(g_fdInfo[fd]));
    }
}

#pragma mark - Socket Hooks

typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
typedef int (*CloseFunc)(int);

static RecvFunc orig_recv = NULL;
static RecvfromFunc orig_recvfrom = NULL;
static RecvmsgFunc orig_recvmsg = NULL;
static SendFunc orig_send = NULL;
static WriteFunc orig_write = NULL;
static ConnectFunc orig_connect = NULL;
static CloseFunc orig_close = NULL;

static void parseLoginServerFromResponse(unsigned char *buf, ssize_t len) {
    if (!buf || len < 12) return;
    
    char ipStr[64] = {0};
    int foundIP = 0;
    int foundPort = 0;
    
    for (ssize_t i = 12; i < len - 3; i++) {
        if (isdigit(buf[i]) || buf[i] == '.') {
            int j = i;
            while (j < len && (isdigit(buf[j]) || buf[j] == '.')) j++;
            
            if (j - i >= 7 && j - i <= 15) {
                memcpy(ipStr, buf + i, j - i);
                ipStr[j - i] = '\0';
                
                if (inet_addr(ipStr) != INADDR_NONE) {
                    DLOG(@"[SERVER-PARSE] Found IP address: %s at offset %zd", ipStr, i);
                    
                    for (int k = j; k < len - 1 && k < j + 10; k++) {
                        if (isdigit(buf[k])) {
                            int portStart = k;
                            while (k < len && isdigit(buf[k])) k++;
                            
                            char portStr[8] = {0};
                            memcpy(portStr, buf + portStart, k - portStart);
                            portStr[k - portStart] = '\0';
                            int port = atoi(portStr);
                            
                            if (port > 0 && port < 65536) {
                                DLOG(@"[SERVER-PARSE] Found port: %d at offset %d", port, (int)portStart);
                                foundIP = 1;
                                foundPort = port;
                                break;
                            }
                        }
                    }
                    
                    if (foundIP) break;
                }
            }
        }
    }
    
    if (foundIP) {
        strncpy(g_loginServerIP, ipStr, sizeof(g_loginServerIP) - 1);
        if (foundPort > 0) {
            g_loginServerPort = foundPort;
        }
        DLOG(@"[SERVER-PARSE] Updated login server to %s:%d", g_loginServerIP, g_loginServerPort);
    }
}

static void patchVersionCheckResponse(unsigned char *buf, ssize_t len) {
    if (!buf || len <= 0) return;
    
    BOOL patched = NO;
    
    if (len >= 8) {
        uint32_t pktLenBE = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                            ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
        uint32_t cmd = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                       ((uint32_t)buf[6] << 8)  | (uint32_t)buf[7];
        
        if (g_logProtoEnabled) {
            DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, len);
        }
        
        if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            parseLoginServerFromResponse(buf, len);
            DLOG(@"[PROTO-R] VERSION CHECK RESPONSE cmd=0x%08X pktLen=%u actualLen=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len);
            
            ssize_t maxPatch = (ssize_t)pktLenBE;
            if (maxPatch > len) maxPatch = len;
            
            if (maxPatch >= 12) {
                uint32_t status4 = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                   ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
                DLOG(@"[PROTO-R] Version check 4-byte status at offset 8-11: %u (0x%08X)", status4, status4);
                if (status4 != 0) {
                    DLOG(@"[PROTO-R-PATCH] Version check 4-byte status %u -> 0", status4);
                    memset(buf + 8, 0, 4);
                    patched = YES;
                }
            }
            
            if (maxPatch >= 13 && buf[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] Version check 1-byte status at offset 12: %u -> 0", buf[12]);
                buf[12] = 0;
                patched = YES;
            }
            
            if (maxPatch > 13) {
                DLOG(@"[PROTO-R-PATCH] Clearing error messages from offset 13 onwards (%zd bytes, within pktLen)", maxPatch - 13);
                memset(buf + 13, 0, maxPatch - 13);
                patched = YES;
            }
        } else if (cmd == 0x76666669) {
            DLOG(@"[PROTO-R] DEBUG ECHO RESPONSE cmd=0x%08X", cmd);
        } else if (cmd == 0x80000015) {
            DLOG(@"[PROTO-R] PING RESPONSE cmd=0x%08X", cmd);
        } else if (cmd == 0x800FF012 || cmd == 0x802EE113) {
            parseLoginServerFromResponse(buf, len);
            DLOG(@"[PROTO-R] SERVER LIST RESPONSE cmd=0x%08X pktLen=%u actualLen=%zd", cmd, pktLenBE, len);
            
            if (len >= 12) {
                uint32_t status4 = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                   ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
                if (status4 != 1) {
                    DLOG(@"[PROTO-R-PATCH] Server list status %u -> 1", status4);
                    buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x01;
                    patched = YES;
                }
            }
            
            if (len >= 30 && len < 100) {
                DLOG_HEX(buf, len);
            }
        } else if (cmd == 0x81EFBC8C) {
            DLOG(@"[PROTO-R] LARGE DATA RESPONSE cmd=0x%08X len=%zd", cmd, len);
        } else if (cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] NEW USER LOGIN RES v2 cmd=0x%08X pktLen=%u len=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len < 200 ? len : 200);
        } else if (cmd == 0x8234AB89) {
            DLOG(@"[PROTO-R] NEW USER LOGIN RES v1 cmd=0x%08X pktLen=%u len=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len < 200 ? len : 200);
        } else if (cmd == 0x800EAE03) {
            DLOG(@"[PROTO-R] GET RSA DATA RES cmd=0x%08X pktLen=%u len=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len < 200 ? len : 200);
        } else if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] NEW QUERY SERVER LIST RES cmd=0x%08X pktLen=%u len=%zd", cmd, pktLenBE, len);
            DLOG_HEX(buf, len < 200 ? len : 200);
        }
    }
    
    ssize_t searchLimit = len;
    if (len >= 4) {
        uint32_t firstPktLenBE = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                                 ((uint32_t)buf[2] << 8)  | (uint32_t)buf[3];
        searchLimit = (ssize_t)firstPktLenBE;
        if (searchLimit > len) searchLimit = len;
    }
    
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(buf + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-R] Detected '版本过低' at offset %zd", i);
            memset(buf + i, ' ', sizeof(verLow));
            patched = YES;
        }
    }
    
    static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(curVer); i++) {
        if (memcmp(buf + i, curVer, sizeof(curVer)) == 0) {
            DLOG(@"[PATCH-R] Detected '当前版本' at offset %zd", i);
            memset(buf + i, ' ', sizeof(curVer));
            patched = YES;
        }
    }
    
    static const unsigned char needUpdate[] = {0xE8,0xAF,0xB7,0xE6,0x9B,0xB4,0xE6,0x96,0xB0};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(needUpdate); i++) {
        if (memcmp(buf + i, needUpdate, sizeof(needUpdate)) == 0) {
            DLOG(@"[PATCH-R] Detected '请更新' at offset %zd", i);
            memset(buf + i, ' ', sizeof(needUpdate));
            patched = YES;
        }
    }
    
    static const unsigned char forceUpdate[] = {0xE5,0xBC,0xBA,0x5F,0xE6,0x9B,0xB4,0xE6,0x96,0xB0};
    for (ssize_t i = 0; i <= searchLimit - (ssize_t)sizeof(forceUpdate); i++) {
        if (memcmp(buf + i, forceUpdate, sizeof(forceUpdate)) == 0) {
            DLOG(@"[PATCH-R] Detected '强制更新' at offset %zd", i);
            memset(buf + i, ' ', sizeof(forceUpdate));
            patched = YES;
        }
    }
    
    if (patched) {
        DLOG(@"[PATCH] Version check response patched successfully!");
        DLOG_HEX(buf, len);
    }
}

static void parseLoginResponse(unsigned char *buf, ssize_t len) {
    if (len < 12) return;
    
    uint32_t cmd = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                   ((uint32_t)buf[6] << 8)  | (uint32_t)buf[7];
    uint32_t status = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                      ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
    
    if (cmd == 0x802EE121) {
        DLOG(@"[RECV-CMD] LOGIN RESPONSE v2 (cmd=0x%08X)", cmd);
        DLOG(@"[RECV-CMD] Status: %u (0=success, non-zero=error)", status);
        
        if (status == 0) {
            DLOG(@"[RECV-CMD] *** LOGIN SUCCESS ***");
        } else {
            DLOG(@"[RECV-CMD] *** LOGIN FAILED with status=%u ***", status);
        }
        
        // 解析响应字段（响应格式类似请求：2字节长度前缀+字符串）
        size_t pos = 12;
        int fieldNum = 0;
        while (pos + 2 <= len) {
            uint16_t flen = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
            if (pos + 2 + flen > len) break;
            
            char field[512] = {0};
            if (flen > 0 && flen < 512) memcpy(field, buf + pos + 2, flen);
            
            DLOG(@"[RECV-CMD]   resp_field[%d] = [%d] %s", fieldNum, flen, field);
            fieldNum++;
            pos += 2 + flen;
        }
        
        DLOG_HEX(buf, len < 256 ? len : 256);
    }
}

static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv || !buf) return -1;
    
    ssize_t ret = orig_recv(fd, buf, len, flags);
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    if (ret > 0) {
        DLOG(@"[RECV-DEBUG] fd=%d %s:%d len=%zd flags=%d", fd, host ?: "unknown", port, ret, flags);
        DLOG_HEX(buf, ret < 256 ? ret : 256);
        
        patchVersionCheckResponse((unsigned char *)buf, ret);
        parseLoginResponse((unsigned char *)buf, ret);
    } else if (ret == 0) {
        DLOG(@"[RECV-DEBUG] fd=%d %s:%d ret=0 (connection closed)", fd, host ?: "unknown", port);
    } else {
        DLOG(@"[RECV-DEBUG] fd=%d %s:%d ret=%zd err=%d (%s)", fd, host ?: "unknown", port, ret, errno, strerror(errno));
    }
    
    return ret;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom || !buf) return -1;
    
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) return ret;
    
    char host[64] = "unknown";
    int port = 0;
    
    if (src_addr && addrlen && *addrlen > 0) {
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[RECVFROM] fd=%d %s:%d len=%zd", fd, host, port, ret);
    
    patchVersionCheckResponse((unsigned char *)buf, ret);
    
    return ret;
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;
    
    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0) return ret;
    
    char host[64] = "unknown";
    int port = 0;
    
    if (msg->msg_name && msg->msg_namelen > 0) {
        struct sockaddr *src_addr = (struct sockaddr *)msg->msg_name;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[RECVMSG] fd=%d %s:%d len=%zd", fd, host, port, ret);
    
    struct iovec *iov = msg->msg_iov;
    if (iov->iov_base && iov->iov_len > 0) {
        patchVersionCheckResponse((unsigned char *)iov->iov_base, ret);
    }
    
    return ret;
}

static int hook_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    
    char host[64] = "unknown";
    int port = 0;
    
    if (addr && addrlen > 0) {
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
    }
    
    DLOG(@"[CONNECT] fd=%d %s:%d -> target=%s:%d", fd, host, port, g_loginServerIP, g_loginServerPort);
    
    const struct sockaddr *finalAddr = addr;
    struct sockaddr_in newAddr;
    if (port == 5678 || port == 12003) {
        memset(&newAddr, 0, sizeof(newAddr));
        newAddr.sin_family = AF_INET;
        inet_aton(g_loginServerIP, &newAddr.sin_addr);
        newAddr.sin_port = htons((uint16_t)g_loginServerPort);
        finalAddr = (const struct sockaddr *)&newAddr;
        addrlen = sizeof(newAddr);
        DLOG(@"[CONNECT] REWRITTEN to %s:%d", g_loginServerIP, g_loginServerPort);
    }
    
    DLOG(@"[CONNECT] Calling original connect...");
    int ret = orig_connect ? orig_connect(fd, finalAddr, addrlen) : -1;
    int err = errno;
    DLOG(@"[CONNECT] original connect returned: %d, errno: %d (%s)", ret, err, strerror(err));
    
    return ret;
}

static int hook_close(int fd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    releaseFd(fd);
    
    return orig_close ? orig_close(fd) : -1;
}

static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_send || !buf) return -1;

    const unsigned char *cbuf = (const unsigned char *)buf;
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    DLOG(@"[SEND-DEBUG] fd=%d %s:%d len=%zu flags=%d", fd, host ?: "unknown", port, len, flags);
    DLOG_HEX(buf, len < 256 ? len : 256);
    
    void *sendBuf = (void *)buf;
    BOOL modified = NO;
    
    if (len >= 8) {
        uint32_t cmd = ((uint32_t)cbuf[4] << 24) | ((uint32_t)cbuf[5] << 16) |
                       ((uint32_t)cbuf[6] << 8)  | (uint32_t)cbuf[7];
        
        DLOG(@"[SEND-DEBUG] cmd=0x%08X", cmd);
        
        if (cmd == 0x002EE118 || cmd == 0x002EE119 || cmd == 0x002EE120) {
            const char *oldVer = "7.5.0";
            const char *newVer = "7.6.0";
            size_t oldVerLen = strlen(oldVer);
            for (size_t i = 0; i <= len - oldVerLen; i++) {
                if (memcmp(cbuf + i, oldVer, oldVerLen) == 0) {
                    sendBuf = malloc(len);
                    memcpy(sendBuf, buf, len);
                    unsigned char *mp = (unsigned char *)sendBuf;
                    memcpy(mp + i, newVer, strlen(newVer));
                    modified = YES;
                    DLOG(@"[SEND-DEBUG] Version replaced 7.5.0->7.6.0");
                    break;
                }
            }
        } else if (cmd == 0x0234AB89) {
            DLOG(@"[SEND-DEBUG] v1 login -> converting to v2");
            
            unsigned char *newBuf = (unsigned char *)malloc(len + 100);
            memcpy(newBuf, buf, len);
            newBuf[4] = 0x00; newBuf[5] = 0x2E; newBuf[6] = 0xE1; newBuf[7] = 0x21;

            size_t pos = 12;
            NSString *username = nil, *password = nil, *deviceId = nil;
            for (int f = 0; f < 7 && pos + 2 <= len; f++) {
                uint16_t fieldLen = ((uint16_t)newBuf[pos] << 8) | newBuf[pos + 1];
                if (pos + 2 + fieldLen > len) break;
                char field[256] = {0};
                if (fieldLen > 0 && fieldLen < 256) memcpy(field, newBuf + pos + 2, fieldLen);
                if (f == 0) username = [NSString stringWithUTF8String:field];
                else if (f == 1) password = [NSString stringWithUTF8String:field];
                else if (f == 2) deviceId = [NSString stringWithUTF8String:field];
                pos += 2 + fieldLen;
            }

            NSString *sign = generateSign(username, password, deviceId, @"7.6.0");
            const char *signCStr = [sign UTF8String];
            size_t signLen = strlen(signCStr);

            size_t insertPos = len;
            if (newBuf[len - 1] == 0x00) insertPos = len - 1;
            size_t finalLen = insertPos + 2 + signLen + 16;

            unsigned char *finalBuf = (unsigned char *)malloc(finalLen);
            memcpy(finalBuf, newBuf, insertPos);
            finalBuf[insertPos] = (signLen >> 8) & 0xFF;
            finalBuf[insertPos + 1] = signLen & 0xFF;
            memcpy(finalBuf + insertPos + 2, signCStr, signLen);
            memset(finalBuf + insertPos + 2 + signLen, 0, 16);

            uint32_t newPktLen = (uint32_t)finalLen;
            finalBuf[0] = (newPktLen >> 24) & 0xFF;
            finalBuf[1] = (newPktLen >> 16) & 0xFF;
            finalBuf[2] = (newPktLen >> 8) & 0xFF;
            finalBuf[3] = newPktLen & 0xFF;

            free(newBuf);
            sendBuf = finalBuf;
            len = finalLen;
            modified = YES;
            DLOG(@"[SEND-DEBUG] v1->v2 converted, newLen=%zu", len);
        } else if (cmd == 0x002EE121) {
            DLOG(@"[SEND-DEBUG] v2 login request");
            
            size_t pos = 12;
            char fields[16][256] = {0};
            uint16_t fieldLens[16] = {0};
            int fieldCount = 0;
            
            for (int f = 0; f < 16 && pos + 2 <= len; f++) {
                uint16_t flen = ((uint16_t)cbuf[pos] << 8) | cbuf[pos + 1];
                if (pos + 2 + flen > len) break;
                if (flen > 0 && flen < 256) memcpy(fields[f], cbuf + pos + 2, flen);
                fieldLens[f] = flen;
                fieldCount++;
                pos += 2 + flen;
            }
            
            const char *oldVer = "7.5.0";
            const char *newVer = "7.6.0";
            for (size_t i = 0; i <= len - strlen(oldVer); i++) {
                if (memcmp(cbuf + i, oldVer, strlen(oldVer)) == 0) {
                    sendBuf = malloc(len);
                    memcpy(sendBuf, buf, len);
                    unsigned char *mp = (unsigned char *)sendBuf;
                    memcpy(mp + i, newVer, strlen(newVer));
                    cbuf = (const unsigned char *)sendBuf;
                    modified = YES;
                    DLOG(@"[SEND-DEBUG] v2 login version replaced");
                    break;
                }
            }
            
            if (!g_forcePlainPassword && g_rsaPublicKey && fieldLens[1] > 0) {
                NSString *plainPassword = [NSString stringWithUTF8String:fields[1]];
                DLOG(@"[SEND-DEBUG] RSA encrypt: '%@' (len=%d)", plainPassword, fieldLens[1]);
                NSString *encryptedPassword = rsaEncryptString(plainPassword, g_rsaPublicKey);
                if (encryptedPassword) {
                    const char *encPassCStr = [encryptedPassword UTF8String];
                    size_t encPassLen = strlen(encPassCStr);
                    DLOG(@"[SEND-DEBUG] RSA result len=%zu", encPassLen);
                    
                    size_t passFieldPos = 12;
                    uint16_t passFieldLen = 0;
                    for (int f = 0; f < 1 && passFieldPos + 2 <= len; f++) {
                        passFieldLen = ((uint16_t)cbuf[passFieldPos] << 8) | cbuf[passFieldPos + 1];
                        passFieldPos += 2 + passFieldLen;
                    }
                    
                    size_t extraBytes = encPassLen - passFieldLen;
                    if (extraBytes != 0) {
                        unsigned char *newBuf = (unsigned char *)malloc(len + extraBytes);
                        if (newBuf) {
                            size_t passStartPos = passFieldPos - 2 - passFieldLen;
                            memcpy(newBuf, cbuf, passStartPos);
                            newBuf[passStartPos] = (encPassLen >> 8) & 0xFF;
                            newBuf[passStartPos + 1] = encPassLen & 0xFF;
                            memcpy(newBuf + passStartPos + 2, encPassCStr, encPassLen);
                            memcpy(newBuf + passStartPos + 2 + encPassLen,
                                   cbuf + passStartPos + 2 + passFieldLen,
                                   len - passStartPos - 2 - passFieldLen);
                            
                            uint32_t newPktLen = (uint32_t)((len + extraBytes) - 4);
                            newBuf[0] = (newPktLen >> 24) & 0xFF;
                            newBuf[1] = (newPktLen >> 16) & 0xFF;
                            newBuf[2] = (newPktLen >> 8) & 0xFF;
                            newBuf[3] = newPktLen & 0xFF;
                            
                            if (sendBuf != buf) free(sendBuf);
                            sendBuf = newBuf;
                            len += extraBytes;
                            modified = YES;
                            DLOG(@"[SEND-DEBUG] RSA encrypted, len=%zu", len);
                        }
                    }
                } else {
                    DLOG(@"[SEND-DEBUG] RSA encrypt failed, keeping plaintext");
                }
            }
            
            if (fieldCount >= 10 && fieldLens[9] == 0) {
                NSString *username = [NSString stringWithUTF8String:fields[0]];
                NSString *password = [NSString stringWithUTF8String:fields[1]];
                NSString *deviceId = [NSString stringWithUTF8String:fields[2]];
                NSString *signNS = generateSignV2(username, password, deviceId);
                const char *signCStr = [signNS UTF8String];
                size_t signLen = strlen(signCStr);
                
                size_t extraBytes = 2 + signLen;
                unsigned char *newBuf = (unsigned char *)malloc(len + extraBytes);
                if (newBuf) {
                    size_t signFieldPos = 12;
                    for (int f = 0; f < 9 && signFieldPos + 2 <= len; f++) {
                        uint16_t flen = ((uint16_t)cbuf[signFieldPos] << 8) | cbuf[signFieldPos + 1];
                        signFieldPos += 2 + flen;
                    }
                    
                    memcpy(newBuf, cbuf, signFieldPos);
                    newBuf[signFieldPos] = (signLen >> 8) & 0xFF;
                    newBuf[signFieldPos + 1] = signLen & 0xFF;
                    memcpy(newBuf + signFieldPos + 2, signCStr, signLen);
                    memcpy(newBuf + signFieldPos + 2 + signLen,
                           cbuf + signFieldPos + 2, len - signFieldPos - 2);
                    
                    uint32_t newPktLen = (uint32_t)(len + extraBytes - 4);
                    newBuf[0] = (newPktLen >> 24) & 0xFF;
                    newBuf[1] = (newPktLen >> 16) & 0xFF;
                    newBuf[2] = (newPktLen >> 8) & 0xFF;
                    newBuf[3] = newPktLen & 0xFF;
                    
                    if (sendBuf != buf) free(sendBuf);
                    sendBuf = newBuf;
                    len += extraBytes;
                    modified = YES;
                    DLOG(@"[SEND-DEBUG] Sign injected, len=%zu", len);
                }
            }
        }
    }
    
    ssize_t ret = orig_send(fd, sendBuf, len, flags);
    DLOG(@"[SEND-DEBUG] orig_send returned: %zd", ret);
    
    if (modified && sendBuf != buf) {
        free(sendBuf);
    }
    
    return ret;
}

#pragma mark - URLSession Hooks

static NSURLSessionDataTask *(*orig_dtwrc)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;

static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {
    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;
    if (comp) {
        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (data && data.length > 0) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (body) {
                    if ([body containsString:@"版本"] || [body containsString:@"更新"] || 
                        [body containsString:@"升级"] || [body containsString:@"status"]) {
                        DLOG(@"[NET] Version-related HTTP response detected (len=%lu)", (unsigned long)data.length);
                        DLOG(@"[NET] Original response: %@", body.length > 1000 ? [body substringToIndex:1000] : body);
                        
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":5" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":6" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"result\":\"fail\"" withString:@"\"result\":\"success\""];
                        body = [body stringByReplacingOccurrencesOfString:@"版本过低" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"请更新" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"强制更新" withString:@""];
                        
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Modified response, new len=%lu", (unsigned long)data.length);
                        DLOG(@"[NET-PATCH] Modified response: %@", body.length > 1000 ? [body substringToIndex:1000] : body);
                    }
                }
            }
            comp(data, resp, err);
        } copy];
    }
    
    if (orig_dtwrc) return orig_dtwrc(self, _cmd, req, wrappedComp);
    return nil;
}

#pragma mark - Alert Hooks

static void (*orig_alertShow)(id, SEL) = NULL;
static void hook_alertShow(id self, SEL _cmd) {
    NSString *title = @"";
    NSString *msg = @"";
    @try {
        if ([self respondsToSelector:@selector(title)]) title = [self performSelector:@selector(title)] ?: @"";
        if ([self respondsToSelector:@selector(message)]) msg = [self performSelector:@selector(message)] ?: @"";
    } @catch (NSException *e) {}
    
    NSString *lowerMsg = [msg lowercaseString];
    NSString *lowerTitle = [title lowercaseString];
    
    if ([lowerMsg containsString:@"版本"] || [lowerMsg containsString:@"更新"] || 
        [lowerMsg containsString:@"升级"] || [lowerTitle containsString:@"版本"]) {
        DLOG(@"[ALERT-BLOCK] Blocked version alert: title='%@' msg='%@'", title, msg);
        return;
    }
    
    if (orig_alertShow) orig_alertShow(self, _cmd);
}

#pragma mark - SignatureKit/SignatureCheck Hooks

typedef void (*ShowAlertIMP)(id, SEL, id);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, id msg) {
    DLOG(@"[SK] showAlert: SUPPRESSED: %@", msg);
}

typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

#pragma mark - Symbol Rebinding

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

__attribute__((constructor))
static void entry(void) {
    log_init();
    DLOG(@"[INIT] WangXian2Hook initialized");
    
    int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);
    int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);
    int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
    int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);
    
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    DLOG(@"[SOCK] Patched: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d close=%d", c, s, r, rf, rm, cl);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p close=%p", orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg, orig_close);
    
    if (!orig_connect) DLOG(@"[SOCK-WARN] connect hook failed");
    if (!orig_recv) DLOG(@"[SOCK-WARN] recv hook failed");
    
    Class sessCls = [NSURLSession class];
    if (sessCls) {
        Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
        if (m) { 
            orig_dtwrc = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)))method_getImplementation(m); 
            method_setImplementation(m, (IMP)hook_dtwrc); 
            DLOG(@"[INIT] NSURLSession hooked");
        }
    }
    
    Class alertCls = [UIAlertView class];
    if (alertCls) {
        Method m = class_getInstanceMethod(alertCls, @selector(show));
        if (m) { 
            orig_alertShow = (void (*)(id, SEL))method_getImplementation(m); 
            method_setImplementation(m, (IMP)hook_alertShow); 
            DLOG(@"[INIT] UIAlertView hooked");
        }
    }
    
    Class alertCtrlCls = [UIAlertController class];
    if (alertCtrlCls) {
        Method m = class_getInstanceMethod(alertCtrlCls, @selector(presentViewController:animated:completion:));
        if (m) { 
            method_setImplementation(m, (IMP)hook_alertShow); 
            DLOG(@"[INIT] UIAlertController hooked");
        }
    }
    
    Class skCls = NSClassFromString(@"SignatureKit");
    if (skCls) {
        Method m = class_getClassMethod(skCls, @selector(showAlert:));
        if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); DLOG(@"[INIT] SK.showAlert hooked"); }
        
        m = class_getClassMethod(skCls, @selector(exitApplication));
        if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SK.exitApplication hooked"); }
    }
    
    Class scCls = NSClassFromString(@"SignatureCheck");
    if (scCls) {
        Method m = class_getClassMethod(scCls, @selector(exitApplication));
        if (m) { method_setImplementation(m, (IMP)hook_exitApp); DLOG(@"[INIT] SC.exitApplication hooked"); }
    }
    
    init_cpp_hooks();
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        createLogButton();
    });
    
    DLOG(@"[INIT] All hooks installed successfully!");
}