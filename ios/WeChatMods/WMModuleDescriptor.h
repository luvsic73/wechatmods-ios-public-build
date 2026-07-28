#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WMModuleDescriptor : NSObject

@property(nonatomic, copy, readonly) NSString *moduleID;
@property(nonatomic, copy, readonly) NSString *title;
@property(nonatomic, copy, readonly) NSString *group;
@property(nonatomic, copy, readonly) NSString *runtime;
@property(nonatomic, copy, readonly) NSArray<NSString *> *compatibleVersions;
@property(nonatomic, copy, readonly) NSArray<NSString *> *dependencies;
@property(nonatomic, copy, readonly) NSArray<NSString *> *conflicts;
@property(nonatomic, copy, readonly) NSArray<NSString *> *hooks;
@property(nonatomic, copy, readonly) NSString *hookOwner;
@property(nonatomic, copy, readonly) NSString *healthCheck;
@property(nonatomic, copy, readonly) NSString *riskLevel;
@property(nonatomic, copy, readonly) NSArray<NSString *> *riskReasons;
@property(nonatomic, copy, readonly) NSString *configClassName;
@property(nonatomic, copy, readonly) NSString *sharedSelectorName;
@property(nonatomic, copy, readonly) NSString *setterName;
@property(nonatomic, copy, readonly) NSString *activationGate;
@property(nonatomic, assign, readonly, getter=isEnabled) BOOL enabled;

+ (nullable instancetype)descriptorWithDictionary:(NSDictionary *)dictionary;
- (BOOL)isCompatibleWithVersion:(NSString *)version;
- (BOOL)passesHookPolicy;

@end

NS_ASSUME_NONNULL_END
