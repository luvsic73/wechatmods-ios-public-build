#import <Foundation/Foundation.h>

@class WMModuleDescriptor;

NS_ASSUME_NONNULL_BEGIN

@interface WMFeatureCollectionAdapter : NSObject

+ (NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)
    applyAllDescriptors:(NSArray<WMModuleDescriptor *> *)allDescriptors
     enabledDescriptors:(NSArray<WMModuleDescriptor *> *)enabledDescriptors;

@end

NS_ASSUME_NONNULL_END
