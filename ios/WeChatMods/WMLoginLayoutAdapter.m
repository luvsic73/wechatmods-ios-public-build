#import "WMLoginLayoutAdapter.h"

#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

static void *WMLoginBackgroundKey = &WMLoginBackgroundKey;
static NSMutableDictionary<NSString *, NSValue *> *
    WMLoginViewDidLoadOriginals;
static NSMutableDictionary<NSString *, NSValue *> *
    WMLoginViewDidLayoutOriginals;

static NSArray<NSString *> *WMLoginControllerNames(void) {
    return @[
        @"WCAccountLoginFirstViewController",
        @"WCAccountLoginLastUserViewController",
        @"WCAccountMainLoginViewController",
        @"WCAccountLoginByQRCodeViewController",
        @"WCAccountOneClickLoginViewController"
    ];
}

static NSString *WMOriginalKey(Class targetClass, SEL selector) {
    return [NSString stringWithFormat:
        @"%@:%@",
        NSStringFromClass(targetClass),
        NSStringFromSelector(selector)
    ];
}

static IMP WMOriginalForObject(
    NSDictionary<NSString *, NSValue *> *originals,
    id object,
    SEL selector
) {
    for (Class current = object_getClass(object);
         current != Nil;
         current = class_getSuperclass(current)) {
        NSValue *value =
            originals[WMOriginalKey(current, selector)];
        if (value != nil) {
            return value.pointerValue;
        }
    }
    return NULL;
}

static UIView *WMLoginBackgroundExtension(UIViewController *controller) {
    UIView *existing =
        objc_getAssociatedObject(controller, WMLoginBackgroundKey);
    if (existing != nil) {
        return existing;
    }

    UIView *background = [UIView new];
    background.backgroundColor =
        controller.view.backgroundColor ?: UIColor.systemBackgroundColor;
    background.accessibilityIdentifier =
        @"wechatmods.login-full-bleed-background";

    Class extensionClass =
        NSClassFromString(@"UIBackgroundExtensionView");
    UIView *container = extensionClass != Nil
        ? [extensionClass new]
        : [UIView new];
    container.accessibilityIdentifier =
        @"wechatmods.login-background-extension";
    container.translatesAutoresizingMaskIntoConstraints = NO;
    container.userInteractionEnabled = NO;
    container.accessibilityElementsHidden = YES;

    SEL setContentView = NSSelectorFromString(@"setContentView:");
    if ([container respondsToSelector:setContentView]) {
        void (*setObject)(id, SEL, id) =
            (void (*)(id, SEL, id))objc_msgSend;
        setObject(container, setContentView, background);
    } else {
        background.translatesAutoresizingMaskIntoConstraints = NO;
        [container addSubview:background];
        [NSLayoutConstraint activateConstraints:@[
            [background.leadingAnchor
                constraintEqualToAnchor:container.leadingAnchor],
            [background.trailingAnchor
                constraintEqualToAnchor:container.trailingAnchor],
            [background.topAnchor
                constraintEqualToAnchor:container.topAnchor],
            [background.bottomAnchor
                constraintEqualToAnchor:container.bottomAnchor]
        ]];
    }

    [controller.view insertSubview:container atIndex:0];
    [NSLayoutConstraint activateConstraints:@[
        [container.leadingAnchor
            constraintEqualToAnchor:controller.view.leadingAnchor],
        [container.trailingAnchor
            constraintEqualToAnchor:controller.view.trailingAnchor],
        [container.topAnchor
            constraintEqualToAnchor:controller.view.topAnchor],
        [container.bottomAnchor
            constraintEqualToAnchor:controller.view.bottomAnchor]
    ]];
    objc_setAssociatedObject(
        controller,
        WMLoginBackgroundKey,
        container,
        OBJC_ASSOCIATION_RETAIN_NONATOMIC
    );
    return container;
}

static void WMApplyLoginLayout(UIViewController *controller) {
    controller.edgesForExtendedLayout = UIRectEdgeAll;
    controller.extendedLayoutIncludesOpaqueBars = YES;
    controller.additionalSafeAreaInsets = UIEdgeInsetsZero;
    controller.view.clipsToBounds = NO;
    controller.view.insetsLayoutMarginsFromSafeArea = NO;
    controller.view.preservesSuperviewLayoutMargins = NO;
    UINavigationBar *navigationBar =
        controller.navigationController.navigationBar;
    navigationBar.translucent = YES;
    WMLoginBackgroundExtension(controller);
}

static void WMLoginViewDidLoad(id object, SEL selector) {
    IMP original = WMOriginalForObject(
        WMLoginViewDidLoadOriginals,
        object,
        selector
    );
    if (original != NULL) {
        ((void (*)(id, SEL))original)(object, selector);
    }
    if ([object isKindOfClass:UIViewController.class]) {
        WMApplyLoginLayout(object);
    }
}

static void WMLoginViewDidLayoutSubviews(id object, SEL selector) {
    IMP original = WMOriginalForObject(
        WMLoginViewDidLayoutOriginals,
        object,
        selector
    );
    if (original != NULL) {
        ((void (*)(id, SEL))original)(object, selector);
    }
    if ([object isKindOfClass:UIViewController.class]) {
        WMApplyLoginLayout(object);
    }
}

static BOOL WMInstallLoginHook(
    Class targetClass,
    SEL selector,
    IMP replacement,
    NSMutableDictionary<NSString *, NSValue *> *originals
) {
    NSString *key = WMOriginalKey(targetClass, selector);
    if (originals[key] != nil) {
        return YES;
    }
    Method method = class_getInstanceMethod(targetClass, selector);
    if (method == NULL ||
        method_getNumberOfArguments(method) != 2 ||
        method_getTypeEncoding(method)[0] != 'v') {
        return NO;
    }

    IMP original = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (!class_addMethod(targetClass, selector, replacement, types)) {
        original = method_setImplementation(method, replacement);
    }
    if (original == NULL) {
        return NO;
    }
    originals[key] = [NSValue valueWithPointer:original];
    return YES;
}

static BOOL WMAttemptLoginLayoutInstall(void) {
    BOOL installedAny = NO;
    @synchronized(WMLoginLayoutAdapter.class) {
        if (WMLoginViewDidLoadOriginals == nil) {
            WMLoginViewDidLoadOriginals =
                [NSMutableDictionary dictionary];
            WMLoginViewDidLayoutOriginals =
                [NSMutableDictionary dictionary];
        }
        for (NSString *name in WMLoginControllerNames()) {
            Class targetClass = NSClassFromString(name);
            if (targetClass == Nil) {
                continue;
            }
            BOOL didLoad = WMInstallLoginHook(
                targetClass,
                NSSelectorFromString(@"viewDidLoad"),
                (IMP)WMLoginViewDidLoad,
                WMLoginViewDidLoadOriginals
            );
            BOOL didLayout = WMInstallLoginHook(
                targetClass,
                NSSelectorFromString(@"viewDidLayoutSubviews"),
                (IMP)WMLoginViewDidLayoutSubviews,
                WMLoginViewDidLayoutOriginals
            );
            installedAny = installedAny || (didLoad && didLayout);
        }
    }
    return installedAny;
}

@implementation WMLoginLayoutAdapter

+ (BOOL)install {
    static dispatch_once_t observerToken;
    dispatch_once(&observerToken, ^{
        NSNotificationCenter *center =
            NSNotificationCenter.defaultCenter;
        for (NSNotificationName name in @[
            UIApplicationDidFinishLaunchingNotification,
            UIApplicationDidBecomeActiveNotification
        ]) {
            [center addObserverForName:name
                               object:nil
                                queue:NSOperationQueue.mainQueue
                           usingBlock:^(
                               __unused NSNotification *notification
                           ) {
                               WMAttemptLoginLayoutInstall();
                           }];
        }
    });
    return WMAttemptLoginLayoutInstall();
}

@end
