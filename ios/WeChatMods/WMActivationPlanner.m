#import "WMActivationPlanner.h"

#import "WMModuleDescriptor.h"

@interface WMActivationPlan ()
@property(nonatomic, copy, readwrite)
    NSArray<WMModuleDescriptor *> *enabledDescriptors;
@property(nonatomic, copy, readwrite)
    NSDictionary<NSString *, NSArray<NSString *> *> *blockedReasons;
@property(nonatomic, copy, readwrite)
    NSDictionary<NSString *, NSArray<NSString *> *> *riskFlags;
@end

@implementation WMActivationPlan
@end

static void WMAddBlockedReason(
    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *blocked,
    NSString *moduleID,
    NSString *reason
) {
    NSMutableSet<NSString *> *reasons = blocked[moduleID];
    if (reasons == nil) {
        reasons = [NSMutableSet set];
        blocked[moduleID] = reasons;
    }
    [reasons addObject:reason];
}

static NSDictionary<NSString *, NSArray<NSString *> *> *
WMFreezeReasons(
    NSDictionary<NSString *, NSMutableSet<NSString *> *> *mutableReasons
) {
    NSMutableDictionary<NSString *, NSArray<NSString *> *> *result =
        [NSMutableDictionary dictionary];
    [mutableReasons enumerateKeysAndObjectsUsingBlock:
        ^(NSString *moduleID,
          NSMutableSet<NSString *> *reasons,
          __unused BOOL *stop) {
            result[moduleID] =
                [reasons.allObjects sortedArrayUsingSelector:@selector(compare:)];
        }];
    return result;
}

@implementation WMActivationPlanner

+ (WMActivationPlan *)planForDescriptors:
        (NSArray<WMModuleDescriptor *> *)descriptors
                     requestedModuleIDs:
        (NSArray<NSString *> *)requestedModuleIDs
                                 version:(NSString *)version {
    NSMutableDictionary<NSString *, WMModuleDescriptor *> *byID =
        [NSMutableDictionary dictionary];
    for (WMModuleDescriptor *descriptor in descriptors) {
        byID[descriptor.moduleID] = descriptor;
    }

    NSSet<NSString *> *requested =
        [NSSet setWithArray:requestedModuleIDs];
    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *blocked =
        [NSMutableDictionary dictionary];

    for (NSString *moduleID in requested) {
        WMModuleDescriptor *descriptor = byID[moduleID];
        if (descriptor == nil) {
            WMAddBlockedReason(blocked, moduleID, @"unknown_module");
            continue;
        }
        if (![descriptor isCompatibleWithVersion:version]) {
            WMAddBlockedReason(
                blocked,
                moduleID,
                [@"incompatible_version:" stringByAppendingString:version]
            );
        }
        if (![descriptor.activationGate isEqualToString:@"ready"]) {
            WMAddBlockedReason(
                blocked,
                moduleID,
                [@"activation_gate:"
                    stringByAppendingString:descriptor.activationGate]
            );
        }
        if (![descriptor passesHookPolicy]) {
            WMAddBlockedReason(blocked, moduleID, @"hook_policy:rejected");
        }
        for (NSString *dependency in descriptor.dependencies) {
            if (![requested containsObject:dependency]) {
                WMAddBlockedReason(
                    blocked,
                    moduleID,
                    [@"dependency_disabled:"
                        stringByAppendingString:dependency]
                );
            }
        }
        for (NSString *conflict in descriptor.conflicts) {
            if ([requested containsObject:conflict]) {
                WMAddBlockedReason(
                    blocked,
                    moduleID,
                    [@"explicit_conflict:"
                        stringByAppendingString:conflict]
                );
            }
        }
    }

    NSMutableDictionary<
        NSString *,
        NSMutableArray<WMModuleDescriptor *> *
    > *hookUsers = [NSMutableDictionary dictionary];
    for (NSString *moduleID in requested) {
        WMModuleDescriptor *descriptor = byID[moduleID];
        for (NSString *hook in descriptor.hooks) {
            NSMutableArray<WMModuleDescriptor *> *users = hookUsers[hook];
            if (users == nil) {
                users = [NSMutableArray array];
                hookUsers[hook] = users;
            }
            [users addObject:descriptor];
        }
    }
    [hookUsers enumerateKeysAndObjectsUsingBlock:
        ^(NSString *hook,
          NSMutableArray<WMModuleDescriptor *> *users,
          __unused BOOL *stop) {
            NSMutableSet<NSString *> *owners = [NSMutableSet set];
            for (WMModuleDescriptor *descriptor in users) {
                [owners addObject:descriptor.hookOwner];
            }
            if (owners.count > 1) {
                for (WMModuleDescriptor *descriptor in users) {
                    WMAddBlockedReason(
                        blocked,
                        descriptor.moduleID,
                        [@"hook_collision:" stringByAppendingString:hook]
                    );
                }
            }
        }];

    BOOL changed = YES;
    while (changed) {
        changed = NO;
        for (NSString *moduleID in requested) {
            if (blocked[moduleID] != nil) {
                continue;
            }
            WMModuleDescriptor *descriptor = byID[moduleID];
            for (NSString *dependency in descriptor.dependencies) {
                if (blocked[dependency] != nil) {
                    WMAddBlockedReason(
                        blocked,
                        moduleID,
                        [@"dependency_blocked:"
                            stringByAppendingString:dependency]
                    );
                    changed = YES;
                    break;
                }
            }
        }
    }

    NSMutableArray<WMModuleDescriptor *> *enabled =
        [NSMutableArray array];
    NSMutableDictionary<NSString *, NSArray<NSString *> *> *riskFlags =
        [NSMutableDictionary dictionary];
    for (NSString *moduleID in requested) {
        WMModuleDescriptor *descriptor = byID[moduleID];
        if (descriptor == nil || blocked[moduleID] != nil) {
            continue;
        }
        [enabled addObject:descriptor];
        if ([descriptor.riskLevel isEqualToString:@"high"] ||
            [descriptor.riskLevel isEqualToString:@"critical"]) {
            riskFlags[moduleID] = descriptor.riskReasons;
        }
    }
    [enabled sortUsingComparator:
        ^NSComparisonResult(WMModuleDescriptor *first,
                            WMModuleDescriptor *second) {
            return [first.moduleID compare:second.moduleID];
        }];

    WMActivationPlan *plan = [WMActivationPlan new];
    plan.enabledDescriptors = enabled;
    plan.blockedReasons = WMFreezeReasons(blocked);
    plan.riskFlags = riskFlags;
    return plan;
}

@end
