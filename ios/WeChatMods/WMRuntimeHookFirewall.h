#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT BOOL WMIsAddressFromRegisteredPlugin(
    const void *_Nullable address
);

@interface WMRuntimeHookFirewall : NSObject

@property(class, nonatomic, readonly, getter=isInstalled) BOOL installed;

+ (BOOL)install;
+ (NSArray<NSDictionary<NSString *, id> *> *)blockedEvents;

@end

NS_ASSUME_NONNULL_END
