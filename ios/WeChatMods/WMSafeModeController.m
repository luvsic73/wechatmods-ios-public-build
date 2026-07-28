#import "WMSafeModeController.h"

static NSString *const WMLaunchPendingKey = @"wechatmods.launch-pending";
static NSString *const WMCrashStreakKey = @"wechatmods.crash-streak";
static NSString *const WMSafeModeKey = @"wechatmods.safe-mode";
static NSString *const WMLastModulesKey = @"wechatmods.last-enabled-modules";
static NSInteger const WMSafeModeCrashThreshold = 2;

@interface WMSafeModeController ()
@property(nonatomic, assign, readwrite, getter=isSafeMode) BOOL safeMode;
@property(nonatomic, copy, readwrite) NSArray<NSString *> *lastEnabledModules;
@end

@implementation WMSafeModeController

+ (instancetype)sharedController {
    static WMSafeModeController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        controller = [self new];
    });
    return controller;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        _safeMode = [defaults boolForKey:WMSafeModeKey];
        _lastEnabledModules = [defaults arrayForKey:WMLastModulesKey] ?: @[];
    }
    return self;
}

- (void)beginLaunchWithEnabledModules:(NSArray<NSString *> *)moduleIDs {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSInteger crashStreak = [defaults integerForKey:WMCrashStreakKey];
    if ([defaults boolForKey:WMLaunchPendingKey]) {
        crashStreak += 1;
    }
    self.lastEnabledModules = [moduleIDs copy];
    self.safeMode = crashStreak >= WMSafeModeCrashThreshold;
    [defaults setInteger:crashStreak forKey:WMCrashStreakKey];
    [defaults setBool:self.safeMode forKey:WMSafeModeKey];
    [defaults setObject:self.lastEnabledModules forKey:WMLastModulesKey];
    [defaults setBool:YES forKey:WMLaunchPendingKey];
}

- (void)markLaunchStable {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setBool:NO forKey:WMLaunchPendingKey];
    [defaults setInteger:0 forKey:WMCrashStreakKey];
}

@end
