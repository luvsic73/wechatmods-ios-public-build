#import "WMModuleCatalog.h"

#import "WMModuleDescriptor.h"

@interface WMModuleCatalog ()
@property(nonatomic, assign, readwrite) NSInteger schemaVersion;
@property(nonatomic, copy, readwrite)
    NSArray<WMModuleDescriptor *> *descriptors;
@property(nonatomic, copy, readwrite) NSArray<NSString *> *loadErrors;
@end

@implementation WMModuleCatalog

+ (WMModuleCatalog *)sharedCatalog {
    static WMModuleCatalog *catalog;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        catalog = [self new];
    });
    return catalog;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [self loadManifest];
    }
    return self;
}

- (void)loadManifest {
    NSURL *manifestURL = [
        NSBundle.mainBundle.resourceURL
        URLByAppendingPathComponent:@"WeChatMods/module-manifest.json"
    ];
    NSData *data = [NSData dataWithContentsOfURL:manifestURL];
    if (data == nil) {
        self.schemaVersion = 0;
        self.descriptors = @[];
        self.loadErrors = @[@"manifest_missing"];
        return;
    }

    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data
                                                 options:0
                                                   error:&error];
    if (![object isKindOfClass:NSDictionary.class]) {
        self.schemaVersion = 0;
        self.descriptors = @[];
        self.loadErrors = @[
            error.localizedDescription ?: @"manifest_invalid"
        ];
        return;
    }

    NSDictionary *manifest = object;
    NSNumber *schema = manifest[@"schema_version"];
    NSArray *items = manifest[@"modules"];
    if (![schema isKindOfClass:NSNumber.class] ||
        ![items isKindOfClass:NSArray.class]) {
        self.schemaVersion = 0;
        self.descriptors = @[];
        self.loadErrors = @[@"manifest_schema_invalid"];
        return;
    }

    NSMutableArray<WMModuleDescriptor *> *descriptors =
        [NSMutableArray array];
    NSMutableArray<NSString *> *errors = [NSMutableArray array];
    NSMutableSet<NSString *> *seenModuleIDs = [NSMutableSet set];
    for (NSInteger index = 0; index < (NSInteger)items.count; index++) {
        WMModuleDescriptor *descriptor =
            [WMModuleDescriptor descriptorWithDictionary:items[index]];
        if (descriptor == nil) {
            [errors addObject:
                [NSString stringWithFormat:@"module_invalid:%ld",
                                           (long)index]];
            continue;
        }
        if ([seenModuleIDs containsObject:descriptor.moduleID]) {
            [errors addObject:
                [@"duplicate_module_id:"
                    stringByAppendingString:descriptor.moduleID]];
            continue;
        }
        [seenModuleIDs addObject:descriptor.moduleID];
        [descriptors addObject:descriptor];
    }
    self.schemaVersion = schema.integerValue;
    self.descriptors = descriptors;
    self.loadErrors = errors;
}

@end
