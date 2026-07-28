#import "WMSettingsEntry.h"

#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

#import "WMSettingsViewController.h"

static IMP WMOriginalSettingsViewDidLoad = NULL;
static IMP WMOriginalSettingsReload = NULL;
static Ivar WMSettingsTableManagerIvar = NULL;
static BOOL WMSettingsEntryInstalled = NO;
static BOOL WMSettingsViewDidLoadHookInstalled = NO;
static BOOL WMSettingsReloadHookInstalled = NO;
static void *WMSettingsEntryMarkerKey = &WMSettingsEntryMarkerKey;

static void WMOpenSettings(id object, __unused SEL selector) {
    if (![object isKindOfClass:UIViewController.class]) {
        return;
    }
    UIViewController *host = object;
    WMSettingsViewController *settings =
        [WMSettingsViewController new];
    if (host.navigationController != nil) {
        [host.navigationController
            pushViewController:settings
                     animated:YES];
    } else {
        UINavigationController *navigation =
            [[UINavigationController alloc]
                initWithRootViewController:settings];
        [host presentViewController:navigation
                           animated:YES
                         completion:nil];
    }
}

static void WMInsertSettingsRow(id object) {
    if ([objc_getAssociatedObject(
            object,
            WMSettingsEntryMarkerKey
        ) boolValue]) {
        return;
    }
    id tableManager = object_getIvar(
        object,
        WMSettingsTableManagerIvar
    );
    Class sectionClass =
        NSClassFromString(@"WCTableViewSectionManager");
    Class cellClass =
        NSClassFromString(@"WCTableViewNormalCellManager");
    SEL sectionFactory = NSSelectorFromString(@"sectionInfoDefaut");
    SEL cellFactory = NSSelectorFromString(
        @"normalCellForSel:target:title:accessoryType:"
    );
    SEL addCell = NSSelectorFromString(@"addCell:");
    SEL insertSection = NSSelectorFromString(@"insertSection:At:");
    if (tableManager == nil ||
        ![sectionClass respondsToSelector:sectionFactory] ||
        ![cellClass respondsToSelector:cellFactory] ||
        ![tableManager respondsToSelector:insertSection]) {
        return;
    }

    id (*makeSection)(id, SEL) =
        (id (*)(id, SEL))objc_msgSend;
    id section = makeSection(sectionClass, sectionFactory);
    if (section == nil || ![section respondsToSelector:addCell]) {
        return;
    }

    id (*makeCell)(id, SEL, SEL, id, id, long long) =
        (id (*)(id, SEL, SEL, id, id, long long))objc_msgSend;
    id cell = makeCell(
        cellClass,
        cellFactory,
        NSSelectorFromString(@"wm_openWeChatModsSettings"),
        object,
        @"微信 Glass",
        UITableViewCellAccessoryDisclosureIndicator
    );
    if (cell == nil) {
        return;
    }

    void (*sendObject)(id, SEL, id) =
        (void (*)(id, SEL, id))objc_msgSend;
    sendObject(section, addCell, cell);
    void (*insert)(id, SEL, id, unsigned int) =
        (void (*)(id, SEL, id, unsigned int))objc_msgSend;
    insert(tableManager, insertSection, section, 0);
    objc_setAssociatedObject(
        object,
        WMSettingsEntryMarkerKey,
        @YES,
        OBJC_ASSOCIATION_RETAIN_NONATOMIC
    );

    SEL getTableView = NSSelectorFromString(@"getTableView");
    if ([tableManager respondsToSelector:getTableView]) {
        id (*getObject)(id, SEL) =
            (id (*)(id, SEL))objc_msgSend;
        UITableView *tableView = getObject(
            tableManager,
            getTableView
        );
        if ([tableView isKindOfClass:UITableView.class]) {
            [tableView reloadData];
        }
    }
}

static void WMSettingsViewDidLoad(id object, SEL selector) {
    if (WMOriginalSettingsViewDidLoad != NULL) {
        ((void (*)(id, SEL))WMOriginalSettingsViewDidLoad)(
            object,
            selector
        );
    }
    WMInsertSettingsRow(object);
}

static void WMSettingsReload(id object, SEL selector) {
    objc_setAssociatedObject(
        object,
        WMSettingsEntryMarkerKey,
        nil,
        OBJC_ASSOCIATION_ASSIGN
    );
    if (WMOriginalSettingsReload != NULL) {
        ((void (*)(id, SEL))WMOriginalSettingsReload)(
            object,
            selector
        );
    }
    WMInsertSettingsRow(object);
}

static BOOL WMInstallNoArgumentHook(
    Class targetClass,
    SEL selector,
    IMP replacement,
    IMP *original
) {
    Method method = class_getInstanceMethod(targetClass, selector);
    if (method == NULL ||
        method_getNumberOfArguments(method) != 2 ||
        method_getTypeEncoding(method)[0] != 'v') {
        return NO;
    }
    IMP inherited = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (class_addMethod(targetClass, selector, replacement, types)) {
        *original = inherited;
        return YES;
    }
    *original = method_setImplementation(method, replacement);
    return *original != NULL;
}

static void WMScheduleSettingsEntryInstall(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [WMSettingsEntry install];
    });
    for (NSInteger delay = 1; delay <= 3; delay++) {
        dispatch_after(
            dispatch_time(
                DISPATCH_TIME_NOW,
                (int64_t)delay * NSEC_PER_SEC
            ),
            dispatch_get_main_queue(),
            ^{
                [WMSettingsEntry install];
            }
        );
    }
}

@implementation WMSettingsEntry

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
                               WMScheduleSettingsEntryInstall();
                           }];
        }
    });

    @synchronized(self) {
        if (WMSettingsEntryInstalled) {
            return YES;
        }
        Class settingsClass =
            NSClassFromString(@"NewSettingViewController");
        WMSettingsTableManagerIvar =
            class_getInstanceVariable(settingsClass, "m_tableViewMgr");
        if (settingsClass == Nil ||
            WMSettingsTableManagerIvar == NULL) {
            return NO;
        }

        SEL openSelector =
            NSSelectorFromString(@"wm_openWeChatModsSettings");
        if (![settingsClass instancesRespondToSelector:openSelector] &&
            !class_addMethod(
                settingsClass,
                openSelector,
                (IMP)WMOpenSettings,
                "v@:"
            )) {
            return NO;
        }

        if (!WMSettingsViewDidLoadHookInstalled) {
            WMSettingsViewDidLoadHookInstalled =
                WMInstallNoArgumentHook(
                    settingsClass,
                    NSSelectorFromString(@"viewDidLoad"),
                    (IMP)WMSettingsViewDidLoad,
                    &WMOriginalSettingsViewDidLoad
                );
        }
        if (!WMSettingsReloadHookInstalled) {
            WMSettingsReloadHookInstalled =
                WMInstallNoArgumentHook(
                    settingsClass,
                    NSSelectorFromString(@"reloadTableData"),
                    (IMP)WMSettingsReload,
                    &WMOriginalSettingsReload
                );
        }
        WMSettingsEntryInstalled =
            WMSettingsViewDidLoadHookInstalled &&
            WMSettingsReloadHookInstalled;
        return WMSettingsEntryInstalled;
    }
}

@end
