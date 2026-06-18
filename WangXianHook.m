/**
 * WangXianHook.dylib - Empty test (no hooks at all)
 * Just to verify injection mechanism works.
 */

#import <Foundation/Foundation.h>

__attribute__((constructor))
static void wangxian_hook_entry(void) {
    // Do absolutely nothing
    NSLog(@"[WXHook] Empty dylib loaded.");
}
