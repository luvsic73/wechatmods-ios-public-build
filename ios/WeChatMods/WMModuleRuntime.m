#import "WMModuleRuntime.h"

#import "WMAntiRevokeModule.h"
#import "WMFeatureCollectionAdapter.h"
#import "WMModuleDescriptor.h"

static NSString *const WMModuleHealthKey = @"wechatmods.module-health";

static NSDictionary<NSString *, id> *WMRuntimeHealth(
    NSString *status,
    NSString *reason
) {
    return @{
        @"status": status,
        @"reason": reason,
    };
}

@implementation WMModuleRuntime

+ (NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)
    installModules:(NSArray<WMModuleDescriptor *> *)enabledDescriptors
    allDescriptors:(NSArray<WMModuleDescriptor *> *)allDescriptors {
    NSMutableDictionary<
        NSString *,
        NSDictionary<NSString *, id> *
    > *health = [NSMutableDictionary dictionary];
    NSMutableArray<WMModuleDescriptor *> *collectionDescriptors =
        [NSMutableArray array];

    for (WMModuleDescriptor *descriptor in enabledDescriptors) {
        if ([descriptor.runtime isEqualToString:@"feature-collection"]) {
            [collectionDescriptors addObject:descriptor];
            continue;
        }
        if ([descriptor.runtime isEqualToString:@"native"] &&
            [descriptor.moduleID isEqualToString:@"anti-revoke"]) {
            BOOL installed = [WMAntiRevokeModule install];
            health[descriptor.moduleID] = installed
                ? WMRuntimeHealth(@"ready", @"hook_installed")
                : WMRuntimeHealth(@"failed", @"method_signature_check_failed");
            continue;
        }
        if ([descriptor.runtime isEqualToString:@"native-account"]) {
            health[descriptor.moduleID] = WMRuntimeHealth(
                @"blocked",
                @"fixture-validation-required"
            );
            continue;
        }
        health[descriptor.moduleID] =
            WMRuntimeHealth(@"blocked", @"unsupported_runtime");
    }

    NSDictionary<NSString *, NSDictionary<NSString *, id> *> *
        collectionHealth = [
            WMFeatureCollectionAdapter
            applyAllDescriptors:allDescriptors
             enabledDescriptors:collectionDescriptors
        ];
    [health addEntriesFromDictionary:collectionHealth];

    [NSUserDefaults.standardUserDefaults setObject:health
                                            forKey:WMModuleHealthKey];
    return health;
}

@end
