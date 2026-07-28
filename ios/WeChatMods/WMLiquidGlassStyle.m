#import "WMLiquidGlassStyle.h"

#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

static void *WMLiquidGlassBackdropKey = &WMLiquidGlassBackdropKey;
static IMP WMCustomNavigationDidMoveOriginal = NULL;
static IMP WMCustomTabDidMoveOriginal = NULL;
static IMP WMCustomNavigationLayoutOriginal = NULL;
static IMP WMCustomTabLayoutOriginal = NULL;
static BOOL WMCustomNavigationHookInstalled = NO;
static BOOL WMCustomTabHookInstalled = NO;

static UIVisualEffect *WMGlassEffect(void) {
    Class effectClass = NSClassFromString(@"UIGlassEffect");
    if (effectClass != Nil) {
        id effect = [effectClass new];
        SEL setInteractive = NSSelectorFromString(@"setInteractive:");
        if ([effect respondsToSelector:setInteractive]) {
            void (*setBool)(id, SEL, BOOL) =
                (void (*)(id, SEL, BOOL))objc_msgSend;
            setBool(effect, setInteractive, NO);
        }
        if ([effect isKindOfClass:UIVisualEffect.class]) {
            return effect;
        }
    }
    return [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
}

static void WMInstallGlassBackdrop(UIView *bar) {
    UIVisualEffectView *backdrop =
        objc_getAssociatedObject(bar, WMLiquidGlassBackdropKey);
    if (backdrop != nil && backdrop.superview == bar) {
        return;
    }
    if (backdrop == nil) {
        backdrop = [[UIVisualEffectView alloc] initWithEffect:WMGlassEffect()];
        backdrop.translatesAutoresizingMaskIntoConstraints = NO;
        backdrop.userInteractionEnabled = NO;
        backdrop.accessibilityElementsHidden = YES;
        backdrop.accessibilityIdentifier =
            @"wechatmods.liquid-glass-backdrop";
        objc_setAssociatedObject(
            bar,
            WMLiquidGlassBackdropKey,
            backdrop,
            OBJC_ASSOCIATION_RETAIN_NONATOMIC
        );
    }
    [bar insertSubview:backdrop atIndex:0];
    [NSLayoutConstraint activateConstraints:@[
        [backdrop.leadingAnchor constraintEqualToAnchor:bar.leadingAnchor],
        [backdrop.trailingAnchor constraintEqualToAnchor:bar.trailingAnchor],
        [backdrop.topAnchor constraintEqualToAnchor:bar.topAnchor],
        [backdrop.bottomAnchor constraintEqualToAnchor:bar.bottomAnchor]
    ]];
}

static void WMGlassifyCustomBar(UIView *bar) {
    bar.opaque = NO;
    bar.backgroundColor = UIColor.clearColor;
    WMInstallGlassBackdrop(bar);
}

static void WMCustomNavigationDidMove(
    UIView *bar,
    SEL selector
) {
    if (WMCustomNavigationDidMoveOriginal != NULL) {
        ((void (*)(id, SEL))WMCustomNavigationDidMoveOriginal)(
            bar,
            selector
        );
    }
    if (bar.window != nil) {
        WMGlassifyCustomBar(bar);
    }
}

static void WMCustomTabDidMove(UIView *bar, SEL selector) {
    if (WMCustomTabDidMoveOriginal != NULL) {
        ((void (*)(id, SEL))WMCustomTabDidMoveOriginal)(
            bar,
            selector
        );
    }
    if (bar.window != nil) {
        WMGlassifyCustomBar(bar);
    }
}

static void WMCustomNavigationLayout(
    UIView *bar,
    SEL selector
) {
    if (WMCustomNavigationLayoutOriginal != NULL) {
        ((void (*)(id, SEL))WMCustomNavigationLayoutOriginal)(
            bar,
            selector
        );
    }
    if (bar.window != nil) {
        WMGlassifyCustomBar(bar);
    }
}

static void WMCustomTabLayout(UIView *bar, SEL selector) {
    if (WMCustomTabLayoutOriginal != NULL) {
        ((void (*)(id, SEL))WMCustomTabLayoutOriginal)(
            bar,
            selector
        );
    }
    if (bar.window != nil) {
        WMGlassifyCustomBar(bar);
    }
}

static BOOL WMInstallHook(
    Class viewClass,
    SEL selector,
    IMP replacement,
    IMP *original
) {
    if (viewClass == Nil) {
        return NO;
    }
    Method method = class_getInstanceMethod(viewClass, selector);
    if (method == NULL) {
        return NO;
    }
    IMP inherited = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (class_addMethod(viewClass, selector, replacement, types)) {
        *original = inherited;
        return YES;
    }
    *original = method_setImplementation(method, replacement);
    return *original != NULL;
}

static BOOL WMInstallCustomBarHooks(
    Class viewClass,
    IMP didMoveReplacement,
    IMP *didMoveOriginal,
    IMP layoutReplacement,
    IMP *layoutOriginal
) {
    BOOL didMoveInstalled = WMInstallHook(
        viewClass,
        NSSelectorFromString(@"didMoveToWindow"),
        didMoveReplacement,
        didMoveOriginal
    );
    BOOL layoutInstalled = WMInstallHook(
        viewClass,
        NSSelectorFromString(@"layoutSubviews"),
        layoutReplacement,
        layoutOriginal
    );
    return didMoveInstalled && layoutInstalled;
}

static BOOL WMUsesNativeNavigationGlass(Class viewClass) {
    return viewClass != Nil &&
        [viewClass isSubclassOfClass:UINavigationBar.class];
}

static BOOL WMUsesNativeTabGlass(Class viewClass) {
    return viewClass != Nil &&
        [viewClass isSubclassOfClass:UITabBar.class];
}

static void WMInstallDynamicBarHooks(void) {
    if (!WMCustomNavigationHookInstalled) {
        Class navigationClass = NSClassFromString(@"MMUINavigationBar");
        if (WMUsesNativeNavigationGlass(navigationClass)) {
            WMCustomNavigationHookInstalled = YES;
        } else {
            WMCustomNavigationHookInstalled = WMInstallCustomBarHooks(
                navigationClass,
                (IMP)WMCustomNavigationDidMove,
                &WMCustomNavigationDidMoveOriginal,
                (IMP)WMCustomNavigationLayout,
                &WMCustomNavigationLayoutOriginal
            );
        }
    }
    if (!WMCustomTabHookInstalled) {
        Class tabClass = NSClassFromString(@"MMTabBar");
        if (WMUsesNativeTabGlass(tabClass)) {
            WMCustomTabHookInstalled = YES;
        } else {
            WMCustomTabHookInstalled = WMInstallCustomBarHooks(
                tabClass,
                (IMP)WMCustomTabDidMove,
                &WMCustomTabDidMoveOriginal,
                (IMP)WMCustomTabLayout,
                &WMCustomTabLayoutOriginal
            );
        }
    }
}

static void WMRefreshVisibleLayouts(void) {
    for (UIWindow *window in UIApplication.sharedApplication.windows) {
        UIView *rootView = window.rootViewController.view;
        [rootView setNeedsLayout];
        [rootView layoutIfNeeded];
    }
}

@implementation WMLiquidGlassStyle

+ (void)install {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        WMInstallDynamicBarHooks();
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        for (NSNotificationName name in @[
            UIApplicationDidFinishLaunchingNotification,
            UIApplicationDidBecomeActiveNotification,
            UIWindowDidBecomeVisibleNotification
        ]) {
            [center addObserverForName:name
                               object:nil
                                queue:NSOperationQueue.mainQueue
                           usingBlock:^(
                               __unused NSNotification *notification
                           ) {
                               WMInstallDynamicBarHooks();
                               WMRefreshVisibleLayouts();
                           }];
        }
        WMRefreshVisibleLayouts();
    });
}

@end
