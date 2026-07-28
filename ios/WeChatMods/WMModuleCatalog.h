#import <Foundation/Foundation.h>

@class WMModuleDescriptor;

NS_ASSUME_NONNULL_BEGIN

@interface WMModuleCatalog : NSObject

@property(class, nonatomic, readonly) WMModuleCatalog *sharedCatalog;
@property(nonatomic, assign, readonly) NSInteger schemaVersion;
@property(nonatomic, copy, readonly)
    NSArray<WMModuleDescriptor *> *descriptors;
@property(nonatomic, copy, readonly) NSArray<NSString *> *loadErrors;

@end

NS_ASSUME_NONNULL_END
