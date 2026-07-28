#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>

#import "../WeChatMods/WMLoginLayoutAdapter.h"

@interface MMUINavigationBar : UIView
@end

@implementation MMUINavigationBar
@end

@interface MMTabBar : UIView
@end

@implementation MMTabBar
@end

@interface WCTableViewNormalCellManager : NSObject
@property(nonatomic) SEL action;
@property(nonatomic, weak) id target;
@property(nonatomic, copy) NSString *title;
@property(nonatomic) UITableViewCellAccessoryType accessoryType;
+ (instancetype)normalCellForSel:(SEL)selector
                          target:(id)target
                           title:(NSString *)title
                   accessoryType:(long long)accessoryType;
@end

@implementation WCTableViewNormalCellManager

+ (instancetype)normalCellForSel:(SEL)selector
                          target:(id)target
                           title:(NSString *)title
                   accessoryType:(long long)accessoryType {
    WCTableViewNormalCellManager *cell = [self new];
    cell.action = selector;
    cell.target = target;
    cell.title = title;
    cell.accessoryType = (UITableViewCellAccessoryType)accessoryType;
    return cell;
}

@end

@interface WCTableViewSectionManager : NSObject
@property(nonatomic, strong) NSMutableArray<WCTableViewNormalCellManager *> *
    cells;
+ (instancetype)sectionInfoDefaut;
- (void)addCell:(WCTableViewNormalCellManager *)cell;
@end

@implementation WCTableViewSectionManager

+ (instancetype)sectionInfoDefaut {
    WCTableViewSectionManager *section = [self new];
    section.cells = [NSMutableArray array];
    return section;
}

- (void)addCell:(WCTableViewNormalCellManager *)cell {
    [self.cells addObject:cell];
}

@end

@interface WCTableViewManager
    : NSObject <UITableViewDataSource, UITableViewDelegate>
@property(nonatomic, strong) UITableView *tableView;
@property(nonatomic, strong)
    NSMutableArray<WCTableViewSectionManager *> *sections;
- (void)insertSection:(WCTableViewSectionManager *)section
                   At:(unsigned int)index;
- (UITableView *)getTableView;
@end

@implementation WCTableViewManager

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _sections = [NSMutableArray array];
        _tableView = [[UITableView alloc]
            initWithFrame:CGRectZero
                    style:UITableViewStyleInsetGrouped];
        _tableView.dataSource = self;
        _tableView.delegate = self;
        _tableView.translatesAutoresizingMaskIntoConstraints = NO;
    }
    return self;
}

- (void)insertSection:(WCTableViewSectionManager *)section
                   At:(unsigned int)index {
    NSUInteger safeIndex =
        MIN((NSUInteger)index, self.sections.count);
    [self.sections insertObject:section atIndex:safeIndex];
}

- (UITableView *)getTableView {
    return self.tableView;
}

- (NSInteger)numberOfSectionsInTableView:
    (__unused UITableView *)tableView {
    return self.sections.count;
}

- (NSInteger)tableView:(__unused UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section {
    return self.sections[(NSUInteger)section].cells.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *const reuseIdentifier = @"simulator.setting";
    UITableViewCell *cell = [tableView
        dequeueReusableCellWithIdentifier:reuseIdentifier];
    if (cell == nil) {
        cell = [[UITableViewCell alloc]
            initWithStyle:UITableViewCellStyleDefault
          reuseIdentifier:reuseIdentifier];
    }
    WCTableViewNormalCellManager *model =
        self.sections[(NSUInteger)indexPath.section]
            .cells[(NSUInteger)indexPath.row];
    cell.textLabel.text = model.title;
    cell.textLabel.font =
        [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.accessoryType = model.accessoryType;
    return cell;
}

- (void)tableView:(UITableView *)tableView
 didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    WCTableViewNormalCellManager *model =
        self.sections[(NSUInteger)indexPath.section]
            .cells[(NSUInteger)indexPath.row];
    if (model.target != nil &&
        [model.target respondsToSelector:model.action]) {
        void (*invoke)(id, SEL) =
            (void (*)(id, SEL))objc_msgSend;
        invoke(model.target, model.action);
    }
}

@end

@interface NewSettingViewController : UIViewController {
@public
    WCTableViewManager *m_tableViewMgr;
}
- (void)reloadTableData;
- (WCTableViewManager *)simulatorTableManager;
@end

@implementation NewSettingViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"设置";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    m_tableViewMgr = [WCTableViewManager new];
    [self.view addSubview:m_tableViewMgr.tableView];
    [NSLayoutConstraint activateConstraints:@[
        [m_tableViewMgr.tableView.leadingAnchor
            constraintEqualToAnchor:self.view.leadingAnchor],
        [m_tableViewMgr.tableView.trailingAnchor
            constraintEqualToAnchor:self.view.trailingAnchor],
        [m_tableViewMgr.tableView.topAnchor
            constraintEqualToAnchor:self.view.topAnchor],
        [m_tableViewMgr.tableView.bottomAnchor
            constraintEqualToAnchor:self.view.bottomAnchor]
    ]];
    [self reloadTableData];
}

- (void)reloadTableData {
    [m_tableViewMgr.sections removeAllObjects];
    [m_tableViewMgr.tableView reloadData];
}

- (WCTableViewManager *)simulatorTableManager {
    return m_tableViewMgr;
}

@end

@interface WCAccountLoginByQRCodeViewController : UIViewController
@end

@implementation WCAccountLoginByQRCodeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"登录布局（零账号夹具）";
    self.view.backgroundColor = UIColor.systemTealColor;

    UIStackView *stack = [[UIStackView alloc] initWithFrame:CGRectZero];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12.0;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.translatesAutoresizingMaskIntoConstraints = NO;

    UIImageView *symbol = [[UIImageView alloc]
        initWithImage:[UIImage systemImageNamed:@"qrcode.viewfinder"]];
    symbol.preferredSymbolConfiguration =
        [UIImageSymbolConfiguration
            configurationWithPointSize:68.0
                                 weight:UIImageSymbolWeightRegular];
    symbol.tintColor = UIColor.labelColor;
    UILabel *title = [UILabel new];
    title.text = @"不连接服务、不使用账号";
    title.font = [UIFont
        preferredFontForTextStyle:UIFontTextStyleHeadline];
    title.adjustsFontForContentSizeCategory = YES;
    [stack addArrangedSubview:symbol];
    [stack addArrangedSubview:title];
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor
            constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor
            constraintEqualToAnchor:self.view.centerYAnchor]
    ]];

    MMUINavigationBar *customNavigation = [MMUINavigationBar new];
    customNavigation.translatesAutoresizingMaskIntoConstraints = NO;
    customNavigation.layer.cornerRadius = 22.0;
    customNavigation.clipsToBounds = YES;
    UILabel *navigationLabel = [UILabel new];
    navigationLabel.translatesAutoresizingMaskIntoConstraints = NO;
    navigationLabel.text = @"原生自定义玻璃导航";
    [customNavigation addSubview:navigationLabel];

    MMTabBar *customControl = [MMTabBar new];
    customControl.translatesAutoresizingMaskIntoConstraints = NO;
    customControl.layer.cornerRadius = 22.0;
    customControl.clipsToBounds = YES;
    UILabel *controlLabel = [UILabel new];
    controlLabel.translatesAutoresizingMaskIntoConstraints = NO;
    controlLabel.text = @"原生自定义玻璃控制";
    [customControl addSubview:controlLabel];

    [self.view addSubview:customNavigation];
    [self.view addSubview:customControl];
    [NSLayoutConstraint activateConstraints:@[
        [customNavigation.topAnchor
            constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor
                           constant:64.0],
        [customNavigation.centerXAnchor
            constraintEqualToAnchor:self.view.centerXAnchor],
        [customNavigation.widthAnchor constraintEqualToConstant:240.0],
        [customNavigation.heightAnchor constraintEqualToConstant:44.0],
        [navigationLabel.centerXAnchor
            constraintEqualToAnchor:customNavigation.centerXAnchor],
        [navigationLabel.centerYAnchor
            constraintEqualToAnchor:customNavigation.centerYAnchor],
        [customControl.bottomAnchor
            constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor
                           constant:-112.0],
        [customControl.centerXAnchor
            constraintEqualToAnchor:self.view.centerXAnchor],
        [customControl.widthAnchor constraintEqualToConstant:240.0],
        [customControl.heightAnchor constraintEqualToConstant:44.0],
        [controlLabel.centerXAnchor
            constraintEqualToAnchor:customControl.centerXAnchor],
        [controlLabel.centerYAnchor
            constraintEqualToAnchor:customControl.centerYAnchor]
    ]];
}

@end

static NSInteger WMCountGlassEffects(UIView *view) {
    NSInteger count = 0;
    Class glassEffectClass = NSClassFromString(@"UIGlassEffect");
    if ([view isKindOfClass:UIVisualEffectView.class]) {
        UIVisualEffect *effect =
            ((UIVisualEffectView *)view).effect;
        if (glassEffectClass != Nil &&
            [effect isKindOfClass:glassEffectClass]) {
            count += 1;
        }
    }
    for (UIView *subview in view.subviews) {
        count += WMCountGlassEffects(subview);
    }
    return count;
}

static NSInteger WMCountViewsWithIdentifier(
    UIView *view,
    NSString *accessibilityIdentifier
) {
    NSInteger count = [view.accessibilityIdentifier
        isEqualToString:accessibilityIdentifier] ? 1 : 0;
    for (UIView *subview in view.subviews) {
        count += WMCountViewsWithIdentifier(
            subview,
            accessibilityIdentifier
        );
    }
    return count;
}

static void WMCollectEffectClassNames(
    UIView *view,
    NSMutableOrderedSet<NSString *> *names
) {
    if ([view isKindOfClass:UIVisualEffectView.class]) {
        UIVisualEffect *effect =
            ((UIVisualEffectView *)view).effect;
        if (effect != nil) {
            [names addObject:NSStringFromClass(effect.class)];
        }
    }
    for (UIView *subview in view.subviews) {
        WMCollectEffectClassNames(subview, names);
    }
}

static NSArray<NSNumber *> *WMRectComponents(CGRect rect) {
    if (CGRectIsNull(rect)) {
        return @[];
    }
    return @[
        @(CGRectGetMinX(rect)),
        @(CGRectGetMinY(rect)),
        @(CGRectGetWidth(rect)),
        @(CGRectGetHeight(rect))
    ];
}

static UIView *WMFindView(
    UIView *view,
    NSString *accessibilityIdentifier
) {
    if ([view.accessibilityIdentifier
            isEqualToString:accessibilityIdentifier]) {
        return view;
    }
    for (UIView *subview in view.subviews) {
        UIView *match =
            WMFindView(subview, accessibilityIdentifier);
        if (match != nil) {
            return match;
        }
    }
    return nil;
}

static NSInteger WMSettingsEntryCount(
    WCTableViewManager *manager
) {
    NSInteger count = 0;
    for (WCTableViewSectionManager *section in manager.sections) {
        for (WCTableViewNormalCellManager *cell in section.cells) {
            if ([cell.title isEqualToString:@"微信 Glass"]) {
                count += 1;
            }
        }
    }
    return count;
}

static BOOL WMRectNearlyEqual(CGRect left, CGRect right) {
    CGFloat tolerance = 1.0;
    return fabs(CGRectGetMinX(left) - CGRectGetMinX(right)) <= tolerance &&
        fabs(CGRectGetMinY(left) - CGRectGetMinY(right)) <= tolerance &&
        fabs(CGRectGetWidth(left) - CGRectGetWidth(right)) <= tolerance &&
        fabs(CGRectGetHeight(left) - CGRectGetHeight(right)) <= tolerance;
}

static void WMWriteDiagnostics(
    UIWindow *window,
    UINavigationController *settingsNavigation,
    NewSettingViewController *settingsController,
    WCAccountLoginByQRCodeViewController *loginController
) {
    WCTableViewManager *manager =
        settingsController.simulatorTableManager;
    NSInteger entryCount = WMSettingsEntryCount(manager);

    SEL openSelector =
        NSSelectorFromString(@"wm_openWeChatModsSettings");
    if ([settingsController respondsToSelector:openSelector]) {
        void (*open)(id, SEL) =
            (void (*)(id, SEL))objc_msgSend;
        open(settingsController, openSelector);
    }

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_MSEC),
        dispatch_get_main_queue(),
        ^{
            BOOL settingsOpened = [
                settingsNavigation.topViewController
                isKindOfClass:NSClassFromString(
                    @"WMSettingsViewController"
                )
            ];
            UITabBarController *tabs =
                (UITabBarController *)window.rootViewController;
            tabs.selectedIndex = 1;
            [window layoutIfNeeded];
            [loginController.view layoutIfNeeded];

            dispatch_after(
                dispatch_time(
                    DISPATCH_TIME_NOW,
                    400 * NSEC_PER_MSEC
                ),
                dispatch_get_main_queue(),
                ^{
                    [window layoutIfNeeded];
                    [loginController.view layoutIfNeeded];
                    NSInteger glassEffectCount =
                        WMCountGlassEffects(window);
                    NSInteger glassBackdropCount =
                        WMCountViewsWithIdentifier(
                            window,
                            @"wechatmods.liquid-glass-backdrop"
                        );
                    NSMutableOrderedSet<NSString *> *effectClassNames =
                        [NSMutableOrderedSet orderedSet];
                    WMCollectEffectClassNames(
                        window,
                        effectClassNames
                    );
                    UIView *extension = WMFindView(
                        loginController.view,
                        @"wechatmods.login-background-extension"
                    );
                    CGRect extensionFrame = extension == nil
                        ? CGRectNull
                        : [extension.superview
                            convertRect:extension.frame
                                 toView:loginController.view];
                    CGRect loginBounds =
                        loginController.view.bounds;
                    CGRect screenBounds =
                        UIScreen.mainScreen.bounds;
                    Class glassEffectClass =
                        NSClassFromString(@"UIGlassEffect");
                    id defaultGlassEffect = glassEffectClass == Nil
                        ? nil
                        : [glassEffectClass new];
                    NSDictionary *diagnostics = @{
                        @"loader_constructor_ran": @(
                            [NSUserDefaults.standardUserDefaults
                                boolForKey:
                                    @"wechatmods.loader-constructor-ran"]
                        ),
                        @"settings_entry_count": @(entryCount),
                        @"settings_controller_opened": @(
                            settingsOpened
                        ),
                        @"glass_effect_count": @(
                            glassEffectCount
                        ),
                        @"glass_backdrop_count": @(
                            glassBackdropCount
                        ),
                        @"glass_effect_api_available": @(
                            glassEffectClass != Nil
                        ),
                        @"glass_effect_default_initializer_available": @(
                            [defaultGlassEffect
                                isKindOfClass:UIVisualEffect.class]
                        ),
                        @"glass_effect_class_names":
                            effectClassNames.array,
                        @"window_matches_screen": @(
                            WMRectNearlyEqual(
                                window.frame,
                                screenBounds
                            )
                        ),
                        @"content_reaches_top_edge": @(
                            extension != nil &&
                            CGRectGetMinY(extensionFrame) <= 1.0
                        ),
                        @"content_reaches_bottom_edge": @(
                            extension != nil &&
                            CGRectGetMaxY(extensionFrame) >=
                                CGRectGetHeight(loginBounds) - 1.0
                        ),
                        @"extension_frame":
                            WMRectComponents(extensionFrame),
                        @"login_bounds":
                            WMRectComponents(loginBounds),
                        @"safe_area_insets": @{
                            @"top": @(window.safeAreaInsets.top),
                            @"left": @(window.safeAreaInsets.left),
                            @"bottom": @(window.safeAreaInsets.bottom),
                            @"right": @(window.safeAreaInsets.right)
                        },
                        @"system_version":
                            UIDevice.currentDevice.systemVersion,
                        @"device_model":
                            UIDevice.currentDevice.model
                    };
                    NSURL *documents = [[NSFileManager defaultManager]
                        URLsForDirectory:NSDocumentDirectory
                               inDomains:NSUserDomainMask].firstObject;
                    NSURL *output = [documents
                        URLByAppendingPathComponent:
                            @"SimulatorHostDiagnostics.json"];
                    NSData *json = [NSJSONSerialization
                        dataWithJSONObject:diagnostics
                                   options:
                                       NSJSONWritingPrettyPrinted |
                                       NSJSONWritingSortedKeys
                                     error:nil];
                    [json writeToURL:output atomically:YES];
                }
            );
        }
    );
}

@interface SimulatorHostAppDelegate : UIResponder
    <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong)
    NewSettingViewController *settingsController;
@property(nonatomic, strong)
    WCAccountLoginByQRCodeViewController *loginController;
@property(nonatomic, strong)
    UINavigationController *settingsNavigation;
@end

@implementation SimulatorHostAppDelegate

- (BOOL)application:(__unused UIApplication *)application
    didFinishLaunchingWithOptions:
        (__unused NSDictionary *)launchOptions {
    [WMLoginLayoutAdapter install];
    self.settingsController = [NewSettingViewController new];
    self.settingsController.tabBarItem =
        [[UITabBarItem alloc]
            initWithTitle:@"设置"
                    image:[UIImage systemImageNamed:@"gearshape"]
                      tag:0];
    self.settingsController.toolbarItems = @[
        [[UIBarButtonItem alloc]
            initWithImage:[UIImage systemImageNamed:@"checkmark.seal"]
                    style:UIBarButtonItemStylePlain
                   target:nil
                   action:nil],
        [UIBarButtonItem flexibleSpaceItem],
        [[UIBarButtonItem alloc]
            initWithTitle:@"iOS 26"
                    style:UIBarButtonItemStylePlain
                   target:nil
                   action:nil]
    ];
    self.settingsNavigation = [[UINavigationController alloc]
        initWithRootViewController:self.settingsController];
    self.settingsNavigation.toolbarHidden = NO;

    self.loginController =
        [WCAccountLoginByQRCodeViewController new];
    self.loginController.tabBarItem =
        [[UITabBarItem alloc]
            initWithTitle:@"登录布局"
                    image:[UIImage systemImageNamed:@"iphone"]
                      tag:1];
    UINavigationController *loginNavigation =
        [[UINavigationController alloc]
            initWithRootViewController:self.loginController];

    UITabBarController *tabs = [UITabBarController new];
    tabs.viewControllers = @[
        self.settingsNavigation,
        loginNavigation
    ];

    self.window = [[UIWindow alloc]
        initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = tabs;
    [self.window makeKeyAndVisible];

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 1400 * NSEC_PER_MSEC),
        dispatch_get_main_queue(),
        ^{
            [self.settingsController reloadTableData];
            [self.settingsController reloadTableData];
            WMWriteDiagnostics(
                self.window,
                self.settingsNavigation,
                self.settingsController,
                self.loginController
            );
        }
    );
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(
            argc,
            argv,
            nil,
            NSStringFromClass(SimulatorHostAppDelegate.class)
        );
    }
}
