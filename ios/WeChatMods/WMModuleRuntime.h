#import <Foundation/Foundation.h>

@class WMModuleDescriptor;

NS_ASSUME_NONNULL_BEGIN

@interface WMModuleRuntime : NSObject

+ (NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)
    installModules:(NSArray<WMModuleDescriptor *> *)enabledDescriptors
    allDescriptors:(NSArray<WMModuleDescriptor *> *)allDescriptors;

@end

NS_ASSUME_NONNULL_END
