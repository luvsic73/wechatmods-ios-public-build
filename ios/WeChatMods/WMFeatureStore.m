#import "WMFeatureStore.h"

static NSString *const WMModuleOverridesKey =
    @"wechatmods.module-overrides";
static NSString *const WMCatalogSchemaKey =
    @"wechatmods.catalog-schema-version";
static NSString *const WMKnownModuleIDsKey =
    @"wechatmods.known-module-ids";

@implementation WMFeatureStore

+ (void)prepareForSchemaVersion:(NSInteger)schemaVersion
                      moduleIDs:(NSArray<NSString *> *)moduleIDs {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSInteger previousVersion = [defaults integerForKey:WMCatalogSchemaKey];
    NSSet<NSString *> *known = [NSSet setWithArray:moduleIDs];
    NSDictionary<NSString *, NSNumber *> *stored =
        [defaults dictionaryForKey:WMModuleOverridesKey] ?: @{};
    NSMutableDictionary<NSString *, NSNumber *> *sanitized =
        [NSMutableDictionary dictionary];

    if (previousVersion == schemaVersion) {
        [stored enumerateKeysAndObjectsUsingBlock:
            ^(NSString *moduleID, NSNumber *value, __unused BOOL *stop) {
                if ([known containsObject:moduleID] &&
                    [value isKindOfClass:NSNumber.class]) {
                    sanitized[moduleID] = @(value.boolValue);
                }
            }];
    }

    // A schema transition starts from the catalog contract: every feature off.
    [defaults setObject:sanitized forKey:WMModuleOverridesKey];
    [defaults setObject:moduleIDs forKey:WMKnownModuleIDsKey];
    [defaults setInteger:schemaVersion forKey:WMCatalogSchemaKey];
}

+ (BOOL)isModuleEnabled:(NSString *)moduleID {
    NSDictionary<NSString *, NSNumber *> *overrides =
        [NSUserDefaults.standardUserDefaults
            dictionaryForKey:WMModuleOverridesKey];
    NSNumber *value = overrides[moduleID];
    return value != nil && value.boolValue;
}

+ (BOOL)isModuleEnabled:(NSString *)moduleID
           defaultValue:(__unused BOOL)defaultValue {
    return [self isModuleEnabled:moduleID];
}

+ (NSArray<NSString *> *)enabledModuleIDs {
    NSDictionary<NSString *, NSNumber *> *overrides =
        [NSUserDefaults.standardUserDefaults
            dictionaryForKey:WMModuleOverridesKey];
    NSSet<NSString *> *known = [NSSet setWithArray:
        [NSUserDefaults.standardUserDefaults
            arrayForKey:WMKnownModuleIDsKey] ?: @[]];
    NSMutableArray<NSString *> *enabled = [NSMutableArray array];
    [overrides enumerateKeysAndObjectsUsingBlock:
        ^(NSString *moduleID, NSNumber *value, __unused BOOL *stop) {
            if ([known containsObject:moduleID] && value.boolValue) {
                [enabled addObject:moduleID];
            }
        }];
    [enabled sortUsingSelector:@selector(compare:)];
    return enabled;
}

+ (void)setModule:(NSString *)moduleID enabled:(BOOL)enabled {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSArray<NSString *> *known = [defaults arrayForKey:WMKnownModuleIDsKey];
    if (known.count > 0 && ![known containsObject:moduleID]) {
        return;
    }
    NSMutableDictionary<NSString *, NSNumber *> *overrides =
        [[defaults dictionaryForKey:WMModuleOverridesKey]
            mutableCopy] ?: [NSMutableDictionary dictionary];
    overrides[moduleID] = @(enabled);
    [defaults setObject:overrides forKey:WMModuleOverridesKey];
}

@end
