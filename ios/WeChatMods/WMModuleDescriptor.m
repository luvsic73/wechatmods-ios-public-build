#import "WMModuleDescriptor.h"

static BOOL WMIsStringArray(id value) {
    if (![value isKindOfClass:NSArray.class]) {
        return NO;
    }
    for (id item in (NSArray *)value) {
        if (![item isKindOfClass:NSString.class]) {
            return NO;
        }
    }
    return YES;
}

static NSSet<NSString *> *WMAllowedRiskLevels(void) {
    return [NSSet setWithArray:@[@"low", @"medium", @"high", @"critical"]];
}

static NSDictionary<NSString *, NSSet<NSString *> *> *
WMAllowedHooksByOwner(void) {
    return @{
        @"wechatmods-native": [NSSet setWithObject:
            @"CMessageMgr.onRevokeMsg:"],
    };
}

static NSString *WMOptionalString(NSDictionary *dictionary,
                                  NSString *key,
                                  NSString *fallback) {
    id value = dictionary[key];
    return [value isKindOfClass:NSString.class] ? value : fallback;
}

@implementation WMModuleDescriptor

+ (nullable instancetype)descriptorWithDictionary:(NSDictionary *)dictionary {
    if (![dictionary isKindOfClass:NSDictionary.class]) {
        return nil;
    }
    NSString *moduleID = dictionary[@"id"];
    NSString *title = dictionary[@"title"];
    NSString *group = dictionary[@"group"];
    NSString *runtime = dictionary[@"runtime"];
    NSArray *versions = dictionary[@"compatible_versions"];
    NSArray *dependencies = dictionary[@"dependencies"];
    NSArray *conflicts = dictionary[@"conflicts"];
    NSArray *hooks = dictionary[@"hooks"];
    NSString *healthCheck = dictionary[@"health_check"];
    NSString *risk = dictionary[@"risk"];
    NSArray *riskReasons = dictionary[@"risk_reasons"];
    NSNumber *enabled = dictionary[@"enabled"];
    if (![moduleID isKindOfClass:NSString.class] ||
        ![title isKindOfClass:NSString.class] ||
        ![group isKindOfClass:NSString.class] ||
        ![runtime isKindOfClass:NSString.class] ||
        !WMIsStringArray(versions) ||
        !WMIsStringArray(dependencies) ||
        !WMIsStringArray(conflicts) ||
        !WMIsStringArray(hooks) ||
        ![healthCheck isKindOfClass:NSString.class] ||
        ![risk isKindOfClass:NSString.class] ||
        ![WMAllowedRiskLevels() containsObject:risk] ||
        !WMIsStringArray(riskReasons) ||
        ![enabled isKindOfClass:NSNumber.class]) {
        return nil;
    }

    NSString *configClass =
        WMOptionalString(dictionary, @"config_class", @"");
    NSString *sharedSelector =
        WMOptionalString(dictionary, @"shared_selector", @"");
    NSString *setter = WMOptionalString(dictionary, @"setter", @"");
    if ([runtime isEqualToString:@"feature-collection"] &&
        (configClass.length == 0 ||
         sharedSelector.length == 0 ||
         setter.length == 0)) {
        return nil;
    }

    WMModuleDescriptor *descriptor = [self new];
    descriptor->_moduleID = [moduleID copy];
    descriptor->_title = [title copy];
    descriptor->_group = [group copy];
    descriptor->_runtime = [runtime copy];
    descriptor->_compatibleVersions = [versions copy];
    descriptor->_dependencies = [dependencies copy];
    descriptor->_conflicts = [conflicts copy];
    descriptor->_hooks = [hooks copy];
    descriptor->_hookOwner =
        [WMOptionalString(dictionary, @"hook_owner", @"") copy];
    descriptor->_healthCheck = [healthCheck copy];
    descriptor->_riskLevel = [risk copy];
    descriptor->_riskReasons = [riskReasons copy];
    descriptor->_configClassName = [configClass copy];
    descriptor->_sharedSelectorName = [sharedSelector copy];
    descriptor->_setterName = [setter copy];
    NSString *defaultGate = [runtime isEqualToString:@"feature-collection"]
        ? @"component-repair-required"
        : @"ready";
    descriptor->_activationGate = [
        WMOptionalString(dictionary, @"activation_gate", defaultGate)
        copy
    ];
    descriptor->_enabled = enabled.boolValue;
    return descriptor;
}

- (BOOL)isCompatibleWithVersion:(NSString *)version {
    return [self.compatibleVersions containsObject:version];
}

- (BOOL)passesHookPolicy {
    if (self.hooks.count == 0) {
        return YES;
    }
    NSSet<NSString *> *allowed = WMAllowedHooksByOwner()[self.hookOwner];
    if (allowed == nil) {
        return NO;
    }
    for (NSString *hook in self.hooks) {
        if (![allowed containsObject:hook]) {
            return NO;
        }
    }
    return YES;
}

// Closed gates remain visible to settings and health reports:
// "component-repair-required" and "fixture-validation-required".

@end
