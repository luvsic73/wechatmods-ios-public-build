#import "WMSettingsViewController.h"

#import "WMFeatureStore.h"
#import "WMModuleCatalog.h"
#import "WMModuleDescriptor.h"

static NSString *const WMModuleHealthKey = @"wechatmods.module-health";
static NSString *const WMBlockedModulesKey = @"wechatmods.blocked-modules";
static NSString *const WMSafeModeKey = @"wechatmods.safe-mode";

@interface WMSettingsViewController ()
@property(nonatomic, copy) NSArray<NSString *> *groups;
@property(nonatomic, copy) NSDictionary<
    NSString *,
    NSArray<WMModuleDescriptor *> *
> *descriptorsByGroup;
@end

@implementation WMSettingsViewController

- (instancetype)init {
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"微信 Glass";
    self.navigationItem.largeTitleDisplayMode =
        UINavigationItemLargeTitleDisplayModeNever;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 60.0;
    [self rebuildSections];
}

- (void)rebuildSections {
    NSMutableDictionary<
        NSString *,
        NSMutableArray<WMModuleDescriptor *> *
    > *mutableGroups = [NSMutableDictionary dictionary];
    for (WMModuleDescriptor *descriptor
         in WMModuleCatalog.sharedCatalog.descriptors) {
        NSMutableArray<WMModuleDescriptor *> *items =
            mutableGroups[descriptor.group];
        if (items == nil) {
            items = [NSMutableArray array];
            mutableGroups[descriptor.group] = items;
        }
        [items addObject:descriptor];
    }

    NSArray<NSString *> *preferredOrder = @[
        @"messages",
        @"media",
        @"groups",
        @"automation",
        @"interface",
        @"account",
        @"experimental",
        @"contacts",
        @"privacy",
    ];
    NSMutableArray<NSString *> *groups = [NSMutableArray array];
    for (NSString *group in preferredOrder) {
        if (mutableGroups[group].count > 0) {
            [groups addObject:group];
        }
    }
    for (NSString *group in [
        mutableGroups.allKeys
        sortedArrayUsingSelector:@selector(compare:)
    ]) {
        if (![groups containsObject:group]) {
            [groups addObject:group];
        }
    }
    self.groups = groups;
    self.descriptorsByGroup = mutableGroups;
}

- (nullable WMModuleDescriptor *)descriptorForIndexPath:
    (NSIndexPath *)indexPath {
    if (indexPath.section == 0 ||
        indexPath.section == (NSInteger)self.groups.count + 1) {
        return nil;
    }
    NSString *group = self.groups[indexPath.section - 1];
    NSArray<WMModuleDescriptor *> *descriptors =
        self.descriptorsByGroup[group];
    if (indexPath.row >= (NSInteger)descriptors.count) {
        return nil;
    }
    return descriptors[indexPath.row];
}

- (nullable WMModuleDescriptor *)descriptorForModuleID:
    (NSString *)moduleID {
    for (WMModuleDescriptor *descriptor
         in WMModuleCatalog.sharedCatalog.descriptors) {
        if ([descriptor.moduleID isEqualToString:moduleID]) {
            return descriptor;
        }
    }
    return nil;
}

- (NSInteger)numberOfSectionsInTableView:
    (__unused UITableView *)tableView {
    return (NSInteger)self.groups.count + 2;
}

- (NSInteger)tableView:(__unused UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section {
    if (section == 0) {
        return 2;
    }
    if (section == (NSInteger)self.groups.count + 1) {
        return 5;
    }
    NSString *group = self.groups[section - 1];
    return (NSInteger)self.descriptorsByGroup[group].count;
}

- (nullable NSString *)tableView:(__unused UITableView *)tableView
         titleForHeaderInSection:(NSInteger)section {
    if (section == 0) {
        return @"外观与加载";
    }
    if (section == (NSInteger)self.groups.count + 1) {
        return @"运行状态";
    }
    NSDictionary<NSString *, NSString *> *titles = @{
        @"messages": @"消息",
        @"media": @"媒体与文件",
        @"groups": @"群聊",
        @"automation": @"自动化",
        @"interface": @"界面与操作",
        @"account": @"账号、推送与多开",
        @"experimental": @"实验功能",
        @"contacts": @"联系人",
        @"privacy": @"隐私",
    };
    NSString *group = self.groups[section - 1];
    return titles[group] ?: group;
}

- (nullable NSString *)tableView:(__unused UITableView *)tableView
         titleForFooterInSection:(NSInteger)section {
    if (section > 0 && section <= (NSInteger)self.groups.count) {
        return @"每项独立控制；更改后重启微信生效。高风险项会再次确认。";
    }
    return nil;
}

- (UITableViewCell *)specialCellForTableView:(UITableView *)tableView
                                  indexPath:(NSIndexPath *)indexPath {
    static NSString *const identifier = @"wechatmods.special-cell";
    UITableViewCell *cell = [
        tableView
        dequeueReusableCellWithIdentifier:identifier
    ];
    if (cell == nil) {
        cell = [[UITableViewCell alloc]
            initWithStyle:UITableViewCellStyleValue1
          reuseIdentifier:identifier];
    }
    cell.accessoryView = nil;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;

    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
            cell.textLabel.text = @"Liquid Glass";
            cell.detailTextLabel.text = @"固定开启";
        } else {
            cell.textLabel.text = @"功能开关";
            cell.detailTextLabel.text = [NSString stringWithFormat:
                @"%lu 项 · 默认全关",
                (unsigned long)WMModuleCatalog.sharedCatalog.descriptors.count];
        }
        return cell;
    }

    NSDictionary *blocked = [
        NSUserDefaults.standardUserDefaults
        dictionaryForKey:WMBlockedModulesKey
    ] ?: @{};
    switch (indexPath.row) {
        case 0:
            cell.textLabel.text = @"Safe Mode";
            cell.detailTextLabel.text = [
                NSUserDefaults.standardUserDefaults
                boolForKey:WMSafeModeKey
            ] ? @"已启用" : @"正常";
            break;
        case 1:
            cell.textLabel.text = @"被阻断模块";
            cell.detailTextLabel.text =
                [NSString stringWithFormat:@"%lu",
                                           (unsigned long)blocked.count];
            break;
        case 2:
            cell.textLabel.text = @"目录校验";
            cell.detailTextLabel.text =
                WMModuleCatalog.sharedCatalog.loadErrors.count == 0
                ? @"正常"
                : [NSString stringWithFormat:
                    @"%lu 个错误",
                    (unsigned long)
                        WMModuleCatalog.sharedCatalog.loadErrors.count];
            break;
        case 3:
            cell.textLabel.text = @"微信基线";
            cell.detailTextLabel.text = @"8.0.75";
            break;
        case 4:
            cell.textLabel.text = @"共存标识";
            cell.detailTextLabel.text =
                NSBundle.mainBundle.bundleIdentifier;
            break;
    }
    return cell;
}

- (NSString *)riskSummaryForDescriptor:
    (WMModuleDescriptor *)descriptor {
    NSDictionary<NSString *, NSString *> *labels = @{
        @"low": @"低风险",
        @"medium": @"中风险",
        @"high": @"高风险",
        @"critical": @"极高风险",
    };
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithObject:
        labels[descriptor.riskLevel] ?: descriptor.riskLevel];
    if (![descriptor.activationGate isEqualToString:@"ready"]) {
        [parts addObject:@"等待离线验证"];
    }

    NSDictionary *health = [
        NSUserDefaults.standardUserDefaults
        dictionaryForKey:WMModuleHealthKey
    ];
    NSDictionary *moduleHealth = health[descriptor.moduleID];
    NSString *status = moduleHealth[@"status"];
    if ([status isKindOfClass:NSString.class]) {
        [parts addObject:status];
    }
    return [parts componentsJoinedByString:@" · "];
}

- (UITableViewCell *)moduleCellForTableView:(UITableView *)tableView
                                 descriptor:
    (WMModuleDescriptor *)descriptor {
    static NSString *const identifier = @"wechatmods.module-cell";
    UITableViewCell *cell = [
        tableView
        dequeueReusableCellWithIdentifier:identifier
    ];
    if (cell == nil) {
        cell = [[UITableViewCell alloc]
            initWithStyle:UITableViewCellStyleSubtitle
          reuseIdentifier:identifier];
    }
    NSString *title = descriptor.title;
    if (title.length == 0 &&
        [descriptor.moduleID isEqualToString:@"anti-revoke"]) {
        title = @"防撤回";
    }
    cell.textLabel.text = title;
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.text = [self riskSummaryForDescriptor:descriptor];
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.numberOfLines = 2;
    cell.detailTextLabel.textColor =
        [descriptor.riskLevel isEqualToString:@"critical"]
        ? UIColor.systemRedColor
        : ([descriptor.riskLevel isEqualToString:@"high"]
            ? UIColor.systemOrangeColor
            : UIColor.secondaryLabelColor);
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;

    UISwitch *toggle = [UISwitch new];
    toggle.on = [WMFeatureStore isModuleEnabled:descriptor.moduleID];
    toggle.enabled =
        [descriptor.activationGate isEqualToString:@"ready"];
    toggle.accessibilityIdentifier = descriptor.moduleID;
    toggle.accessibilityLabel = title;
    [toggle addTarget:self
               action:@selector(toggleChanged:)
     forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = toggle;
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    WMModuleDescriptor *descriptor =
        [self descriptorForIndexPath:indexPath];
    return descriptor == nil
        ? [self specialCellForTableView:tableView indexPath:indexPath]
        : [self moduleCellForTableView:tableView descriptor:descriptor];
}

- (void)tableView:(UITableView *)tableView
 didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    WMModuleDescriptor *descriptor =
        [self descriptorForIndexPath:indexPath];
    if (descriptor == nil ||
        ![descriptor.activationGate isEqualToString:@"ready"]) {
        return;
    }
    UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
    UISwitch *toggle = [cell.accessoryView isKindOfClass:UISwitch.class]
        ? (UISwitch *)cell.accessoryView
        : nil;
    if (toggle != nil) {
        [toggle setOn:!toggle.isOn animated:YES];
        [self toggleChanged:toggle];
    }
}

- (void)commitDescriptor:(WMModuleDescriptor *)descriptor
                 enabled:(BOOL)enabled {
    [WMFeatureStore setModule:descriptor.moduleID enabled:enabled];
    self.navigationItem.prompt = @"更改后重启微信生效";
    [self.tableView reloadData];
}

- (void)toggleChanged:(UISwitch *)toggle {
    WMModuleDescriptor *descriptor =
        [self descriptorForModuleID:toggle.accessibilityIdentifier];
    if (descriptor == nil) {
        [toggle setOn:NO animated:YES];
        return;
    }
    if (![descriptor.activationGate isEqualToString:@"ready"]) {
        [toggle setOn:NO animated:YES];
        self.navigationItem.prompt = @"该项等待离线验证";
        return;
    }
    BOOL highRisk =
        [descriptor.riskLevel isEqualToString:@"high"] ||
        [descriptor.riskLevel isEqualToString:@"critical"];
    if (!toggle.isOn || !highRisk) {
        [self commitDescriptor:descriptor enabled:toggle.isOn];
        return;
    }

    [toggle setOn:NO animated:YES];
    NSString *message = descriptor.riskReasons.count == 0
        ? @"该功能会改变运行行为。"
        : [descriptor.riskReasons componentsJoinedByString:@"、"];
    UIAlertController *alert = [
        UIAlertController
        alertControllerWithTitle:@"确认开启高风险功能"
                     message:message
              preferredStyle:UIAlertControllerStyleAlert
    ];
    [alert addAction:[
        UIAlertAction
        actionWithTitle:@"保持关闭"
                  style:UIAlertActionStyleCancel
                handler:nil
    ]];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[
        UIAlertAction
        actionWithTitle:@"确认开启"
                  style:UIAlertActionStyleDestructive
                handler:^(__unused UIAlertAction *action) {
                    [weakSelf commitDescriptor:descriptor enabled:YES];
                }
    ]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
