#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "WMActivationPlanner.h"
#import "WMFeatureStore.h"
#import "WMLiquidGlassStyle.h"
#import "WMLoginLayoutAdapter.h"
#import "WMModuleCatalog.h"
#import "WMModuleDescriptor.h"
#import "WMModuleRuntime.h"
#import "WMPluginNetworkFirewall.h"
#import "WMRuntimeHookFirewall.h"
#import "WMSafeModeController.h"
#import "WMSettingsEntry.h"

static NSString *const WMBlockedModulesKey =
    @"wechatmods.blocked-modules";
static NSString *const WMRiskFlagsKey =
    @"wechatmods.risk-flags";
static NSString *const WMHookFirewallInstalledKey =
    @"wechatmods.hook-firewall-installed";
static NSString *const WMNetworkFirewallInstalledKey =
    @"wechatmods.network-firewall-installed";
static BOOL WMStableLaunchTimerArmed = NO;

static void WMArmStableLaunchTimer(
    WMSafeModeController *safeMode
) {
    if (WMStableLaunchTimerArmed) {
        return;
    }
    WMStableLaunchTimerArmed = YES;
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
        dispatch_get_main_queue(),
        ^{
            WMStableLaunchTimerArmed = NO;
            UIApplicationState state =
                UIApplication.sharedApplication.applicationState;
            if (state == UIApplicationStateBackground) {
                return;
            }
            [safeMode markLaunchStable];
        }
    );
}

static void WMBootstrap(void) {
    BOOL hookFirewallInstalled = [WMRuntimeHookFirewall install];
    BOOL networkFirewallInstalled = [WMPluginNetworkFirewall install];
    BOOL riskControlsReady =
        hookFirewallInstalled && networkFirewallInstalled;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setBool:hookFirewallInstalled
               forKey:WMHookFirewallInstalledKey];
    [defaults setBool:networkFirewallInstalled
               forKey:WMNetworkFirewallInstalledKey];

    [WMLiquidGlassStyle install];
    [WMLoginLayoutAdapter install];
    [WMSettingsEntry install];

    WMModuleCatalog *catalog = WMModuleCatalog.sharedCatalog;
    NSArray<WMModuleDescriptor *> *descriptors =
        catalog.descriptors;
    NSArray<NSString *> *moduleIDs =
        [descriptors valueForKey:@"moduleID"];
    [WMFeatureStore prepareForSchemaVersion:catalog.schemaVersion
                                  moduleIDs:moduleIDs];

    NSString *version = [
        NSBundle.mainBundle
        objectForInfoDictionaryKey:@"CFBundleShortVersionString"
    ] ?: @"";
    NSArray<NSString *> *requestedModuleIDs =
        WMFeatureStore.enabledModuleIDs;
    NSArray<NSString *> *validatedRequests =
        catalog.loadErrors.count == 0 && riskControlsReady
            ? requestedModuleIDs
            : @[];
    WMActivationPlan *plan = [
        WMActivationPlanner
        planForDescriptors:descriptors
        requestedModuleIDs:validatedRequests
        version:version
    ];
    NSDictionary<NSString *, NSArray<NSString *> *> *blockedReasons =
        plan.blockedReasons;
    if (catalog.loadErrors.count > 0) {
        NSMutableDictionary<NSString *, NSArray<NSString *> *> *
            catalogBlocked = [blockedReasons mutableCopy];
        for (NSString *moduleID in requestedModuleIDs) {
            catalogBlocked[moduleID] = @[@"catalog_invalid"];
        }
        blockedReasons = catalogBlocked;
    } else if (!riskControlsReady) {
        NSMutableDictionary<NSString *, NSArray<NSString *> *> *
            safetyBlocked = [blockedReasons mutableCopy];
        for (NSString *moduleID in requestedModuleIDs) {
            safetyBlocked[moduleID] = @[@"risk_control_unavailable"];
        }
        blockedReasons = safetyBlocked;
    }
    [defaults setObject:blockedReasons forKey:WMBlockedModulesKey];
    [defaults setObject:plan.riskFlags forKey:WMRiskFlagsKey];

    NSArray<NSString *> *eligibleModuleIDs =
        [plan.enabledDescriptors valueForKey:@"moduleID"];
    WMSafeModeController *safeMode =
        WMSafeModeController.sharedController;
    [safeMode beginLaunchWithEnabledModules:eligibleModuleIDs];
    if (safeMode.isSafeMode) {
        [WMModuleRuntime installModules:@[]
                        allDescriptors:descriptors];
    } else {
        [WMModuleRuntime installModules:plan.enabledDescriptors
                        allDescriptors:descriptors];
    }

    NSNotificationCenter *notifications =
        NSNotificationCenter.defaultCenter;
    [notifications
        addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
                    WMArmStableLaunchTimer(safeMode);
                }];
    [notifications
        addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil
                     queue:NSOperationQueue.mainQueue
                usingBlock:^(__unused NSNotification *notification) {
                    WMArmStableLaunchTimer(safeMode);
                }];

    UIApplicationState state =
        UIApplication.sharedApplication.applicationState;
    if (state != UIApplicationStateBackground) {
        WMArmStableLaunchTimer(safeMode);
    }
}

__attribute__((constructor))
static void WeChatModsConstructor(void) {
    [NSUserDefaults.standardUserDefaults
        setBool:YES
         forKey:@"wechatmods.loader-constructor-ran"];
    dispatch_async(dispatch_get_main_queue(), ^{
        WMBootstrap();
    });
}
