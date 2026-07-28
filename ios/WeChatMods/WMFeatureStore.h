#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WMFeatureStore : NSObject

+ (void)prepareForSchemaVersion:(NSInteger)schemaVersion
                      moduleIDs:(NSArray<NSString *> *)moduleIDs;
+ (BOOL)isModuleEnabled:(NSString *)moduleID;
+ (BOOL)isModuleEnabled:(NSString *)moduleID
           defaultValue:(BOOL)defaultValue;
+ (NSArray<NSString *> *)enabledModuleIDs;
+ (void)setModule:(NSString *)moduleID enabled:(BOOL)enabled;

@end

NS_ASSUME_NONNULL_END
