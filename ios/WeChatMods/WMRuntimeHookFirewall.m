#import "WMRuntimeHookFirewall.h"

#import <dlfcn.h>
#import <objc/runtime.h>
#import <string.h>

#import "../../vendor/fishhook/fishhook.h"

static NSString *const WMBlockedHookEventsKey =
    @"wechatmods.blocked-hook-events";
static NSUInteger const WMMaximumBlockedEvents = 200;

typedef void (*WMMSHookMessageExFunction)(
    Class targetClass,
    SEL selector,
    IMP replacement,
    IMP *_Nullable original
);

static IMP (*WMOriginalMethodSetImplementation)(Method, IMP);
static void (*WMOriginalMethodExchangeImplementations)(Method, Method);
static BOOL (*WMOriginalClassAddMethod)(Class, SEL, IMP, const char *);
static IMP (*WMOriginalClassReplaceMethod)(Class, SEL, IMP, const char *);
static void *_Nullable (*WMOriginalDlsym)(void *, const char *);
static WMMSHookMessageExFunction WMOriginalMSHookMessageEx;
static BOOL WMFirewallInstalled = NO;
static __thread BOOL WMRecordingBlockedHook = NO;

static NSSet<NSString *> *WMRegisteredPluginImages(void) {
    static NSSet<NSString *> *images;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        images = [NSSet setWithArray:@[
            @"blocktljump.dylib",
            @"hbb9.1.2.dylib",
            @"hbwechathelper.dylib",
            @"libsubstrote.dylib",
            @"libsubstrate.dylib",
            @"miyou.dylib",
            @"pkcwechattools.dylib",
            @"tltdlimitation.dylib",
            @"wechatku.dylib",
            @"wechattweak.dylib",
            @"wcpureextension.dylib",
            @"xnsp.dylib",
        ]];
    });
    return images;
}

static NSSet<NSString *> *WMProtectedSelectors(void) {
    static NSSet<NSString *> *selectors;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        selectors = [NSSet setWithArray:@[
            @"HasInstallJailbreakPlugin:",
            @"HasInstallJailbreakPluginInvalidIAPPurchase",
            @"IsJailBreak",
            @"JailBroken",
            @"addLogInfo:withMessage:",
            @"privateConfirmLoginWithInfo:",
            @"reportAppList:",
            @"sendLoginConfirmRequest",
            @"setAutoLogin:",
            @"setBundleId:",
            @"setClientSeqId:",
            @"setDeviceName:",
            @"setShowAutoLoginEntrance:",
            @"showExtraDeviceLoginViewControllerWithExtInfo:",
        ]];
    });
    return selectors;
}

static NSString *_Nullable WMImageNameForAddress(const void *address) {
    if (address == NULL) {
        return nil;
    }
    Dl_info info = {0};
    if (dladdr(address, &info) == 0 || info.dli_fname == NULL) {
        return nil;
    }
    return [
        [NSString stringWithUTF8String:info.dli_fname]
        lastPathComponent
    ];
}

BOOL WMIsAddressFromRegisteredPlugin(const void *address) {
    NSString *image = WMImageNameForAddress(address).lowercaseString;
    return image.length > 0 &&
        [WMRegisteredPluginImages() containsObject:image];
}

static BOOL WMShouldBlockSelector(
    SEL selector,
    const void *caller
) {
    if (selector == NULL ||
        !WMIsAddressFromRegisteredPlugin(caller)) {
        return NO;
    }
    return [WMProtectedSelectors()
        containsObject:NSStringFromSelector(selector)];
}

static void WMRecordBlockedHook(
    NSString *operation,
    SEL selector,
    const void *caller
) {
    if (WMRecordingBlockedHook) {
        return;
    }
    WMRecordingBlockedHook = YES;
    @try {
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        NSMutableArray<NSDictionary<NSString *, id> *> *events = [
            [defaults arrayForKey:WMBlockedHookEventsKey] mutableCopy
        ] ?: [NSMutableArray array];
        [events addObject:@{
            @"operation": operation,
            @"selector": NSStringFromSelector(selector),
            @"image": WMImageNameForAddress(caller) ?: @"unknown",
            @"timestamp": @([NSDate.date timeIntervalSince1970]),
            @"status": @"plugin_hook_blocked",
        }];
        if (events.count > WMMaximumBlockedEvents) {
            [events removeObjectsInRange:NSMakeRange(
                0,
                events.count - WMMaximumBlockedEvents
            )];
        }
        [defaults setObject:events forKey:WMBlockedHookEventsKey];
    } @finally {
        WMRecordingBlockedHook = NO;
    }
}

static IMP WMGuardedMethodSetImplementation(
    Method method,
    IMP replacement
) {
    const void *caller = __builtin_return_address(0);
    SEL selector = method == NULL ? NULL : method_getName(method);
    if (WMShouldBlockSelector(selector, caller)) {
        WMRecordBlockedHook(
            @"method_setImplementation",
            selector,
            caller
        );
        return method == NULL ? NULL : method_getImplementation(method);
    }
    return WMOriginalMethodSetImplementation == NULL
        ? NULL
        : WMOriginalMethodSetImplementation(method, replacement);
}

static void WMGuardedMethodExchangeImplementations(
    Method first,
    Method second
) {
    const void *caller = __builtin_return_address(0);
    SEL firstSelector = first == NULL ? NULL : method_getName(first);
    SEL secondSelector = second == NULL ? NULL : method_getName(second);
    if (WMShouldBlockSelector(firstSelector, caller) ||
        WMShouldBlockSelector(secondSelector, caller)) {
        WMRecordBlockedHook(
            @"method_exchangeImplementations",
            WMShouldBlockSelector(firstSelector, caller)
                ? firstSelector
                : secondSelector,
            caller
        );
        return;
    }
    if (WMOriginalMethodExchangeImplementations != NULL) {
        WMOriginalMethodExchangeImplementations(first, second);
    }
}

static BOOL WMGuardedClassAddMethod(
    Class targetClass,
    SEL selector,
    IMP replacement,
    const char *types
) {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockSelector(selector, caller)) {
        WMRecordBlockedHook(@"class_addMethod", selector, caller);
        return NO;
    }
    return WMOriginalClassAddMethod != NULL &&
        WMOriginalClassAddMethod(
            targetClass,
            selector,
            replacement,
            types
        );
}

static IMP WMGuardedClassReplaceMethod(
    Class targetClass,
    SEL selector,
    IMP replacement,
    const char *types
) {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockSelector(selector, caller)) {
        WMRecordBlockedHook(@"class_replaceMethod", selector, caller);
        return class_getMethodImplementation(targetClass, selector);
    }
    return WMOriginalClassReplaceMethod == NULL
        ? NULL
        : WMOriginalClassReplaceMethod(
            targetClass,
            selector,
            replacement,
            types
        );
}

static void WMGuardedMSHookMessageEx(
    Class targetClass,
    SEL selector,
    IMP replacement,
    IMP *_Nullable original
) {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockSelector(selector, caller)) {
        if (original != NULL) {
            *original = class_getMethodImplementation(
                targetClass,
                selector
            );
        }
        WMRecordBlockedHook(@"MSHookMessageEx", selector, caller);
        return;
    }
    if (WMOriginalMSHookMessageEx != NULL) {
        WMOriginalMSHookMessageEx(
            targetClass,
            selector,
            replacement,
            original
        );
    }
}

static void *_Nullable WMGuardedDlsym(
    void *handle,
    const char *symbol
) {
    if (WMOriginalDlsym == NULL) {
        return NULL;
    }
    void *resolved = WMOriginalDlsym(handle, symbol);
    const void *caller = __builtin_return_address(0);
    if (!WMIsAddressFromRegisteredPlugin(caller) || symbol == NULL) {
        return resolved;
    }
    if (strcmp(symbol, "method_setImplementation") == 0) {
        return (void *)WMGuardedMethodSetImplementation;
    }
    if (strcmp(symbol, "method_exchangeImplementations") == 0) {
        return (void *)WMGuardedMethodExchangeImplementations;
    }
    if (strcmp(symbol, "class_addMethod") == 0) {
        return (void *)WMGuardedClassAddMethod;
    }
    if (strcmp(symbol, "class_replaceMethod") == 0) {
        return (void *)WMGuardedClassReplaceMethod;
    }
    if (strcmp(symbol, "MSHookMessageEx") == 0) {
        WMOriginalMSHookMessageEx =
            (WMMSHookMessageExFunction)resolved;
        return (void *)WMGuardedMSHookMessageEx;
    }
    return resolved;
}

@implementation WMRuntimeHookFirewall

+ (BOOL)isInstalled {
    return WMFirewallInstalled;
}

+ (BOOL)install {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct rebinding bindings[] = {
            {
                "method_setImplementation",
                (void *)WMGuardedMethodSetImplementation,
                (void **)&WMOriginalMethodSetImplementation,
            },
            {
                "method_exchangeImplementations",
                (void *)WMGuardedMethodExchangeImplementations,
                (void **)&WMOriginalMethodExchangeImplementations,
            },
            {
                "class_addMethod",
                (void *)WMGuardedClassAddMethod,
                (void **)&WMOriginalClassAddMethod,
            },
            {
                "class_replaceMethod",
                (void *)WMGuardedClassReplaceMethod,
                (void **)&WMOriginalClassReplaceMethod,
            },
            {
                "dlsym",
                (void *)WMGuardedDlsym,
                (void **)&WMOriginalDlsym,
            },
            {
                "MSHookMessageEx",
                (void *)WMGuardedMSHookMessageEx,
                (void **)&WMOriginalMSHookMessageEx,
            },
        };
        WMFirewallInstalled = rebind_symbols(
            bindings,
            sizeof(bindings) / sizeof(bindings[0])
        ) == 0;
    });
    return WMFirewallInstalled;
}

+ (NSArray<NSDictionary<NSString *, id> *> *)blockedEvents {
    return [
        NSUserDefaults.standardUserDefaults
        arrayForKey:WMBlockedHookEventsKey
    ] ?: @[];
}

@end
