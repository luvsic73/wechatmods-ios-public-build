#import <Foundation/Foundation.h>

@class WMModuleDescriptor;

NS_ASSUME_NONNULL_BEGIN

@interface WMActivationPlan : NSObject

@property(nonatomic, copy, readonly)
    NSArray<WMModuleDescriptor *> *enabledDescriptors;
@property(nonatomic, copy, readonly)
    NSDictionary<NSString *, NSArray<NSString *> *> *blockedReasons;
@property(nonatomic, copy, readonly)
    NSDictionary<NSString *, NSArray<NSString *> *> *riskFlags;

@end

@interface WMActivationPlanner : NSObject

+ (WMActivationPlan *)planForDescriptors:
        (NSArray<WMModuleDescriptor *> *)descriptors
                     requestedModuleIDs:
        (NSArray<NSString *> *)requestedModuleIDs
                                 version:(NSString *)version;

@end

NS_ASSUME_NONNULL_END
