#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WMPluginNetworkFirewall : NSObject

@property(class, nonatomic, readonly, getter=isInstalled) BOOL installed;

+ (BOOL)install;
+ (NSArray<NSDictionary<NSString *, id> *> *)blockedEvents;

@end

NS_ASSUME_NONNULL_END
