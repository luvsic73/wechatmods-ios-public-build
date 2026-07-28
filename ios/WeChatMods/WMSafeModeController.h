#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WMSafeModeController : NSObject

@property(nonatomic, assign, readonly, getter=isSafeMode) BOOL safeMode;
@property(nonatomic, copy, readonly) NSArray<NSString *> *lastEnabledModules;

+ (instancetype)sharedController;
- (void)beginLaunchWithEnabledModules:(NSArray<NSString *> *)moduleIDs;
- (void)markLaunchStable;

@end

NS_ASSUME_NONNULL_END
