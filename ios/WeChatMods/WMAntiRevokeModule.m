#import "WMAntiRevokeModule.h"

#import <objc/runtime.h>

static BOOL WMAntiRevokeInstalled = NO;

static void WMHandleRevokeMessage(
    __unused id object,
    __unused SEL selector,
    __unused id message
) {
}

@implementation WMAntiRevokeModule

+ (BOOL)install {
    @synchronized(self) {
        if (WMAntiRevokeInstalled) {
            return YES;
        }
        Class messageManager = NSClassFromString(@"CMessageMgr");
        SEL revokeSelector = NSSelectorFromString(@"onRevokeMsg:");
        if (messageManager == Nil) {
            return NO;
        }
        Method revokeMethod =
            class_getInstanceMethod(messageManager, revokeSelector);
        if (revokeMethod == NULL ||
            method_getNumberOfArguments(revokeMethod) != 3) {
            return NO;
        }
        const char *typeEncoding = method_getTypeEncoding(revokeMethod);
        if (typeEncoding == NULL || typeEncoding[0] != 'v') {
            return NO;
        }
        method_setImplementation(
            revokeMethod,
            (IMP)WMHandleRevokeMessage
        );
        WMAntiRevokeInstalled = YES;
        return YES;
    }
}

@end
