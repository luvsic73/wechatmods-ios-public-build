#import "WMFeatureCollectionAdapter.h"

#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <string.h>

#import "WMModuleDescriptor.h"

static NSString *const WMFeatureCollectionRelativePath =
    @"WeChatMods/FeatureCollection/MiYou.dylib";
static NSString *const WMFeatureCollectionSHA256 =
    @"846829A8351934AA805F4A77BE59E11DB6424FED53AD151758C8B4EFB480835F";

static NSDictionary<NSString *, id> *WMCollectionHealth(
    NSString *status,
    NSString *reason
) {
    return @{
        @"status": status,
        @"reason": reason,
    };
}

static NSString *_Nullable WMSHA256ForURL(NSURL *URL) {
    NSInputStream *stream = [NSInputStream inputStreamWithURL:URL];
    [stream open];
    if (stream.streamStatus == NSStreamStatusError) {
        return nil;
    }

    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    uint8_t buffer[64 * 1024];
    NSInteger count = 0;
    while ((count = [stream read:buffer maxLength:sizeof(buffer)]) > 0) {
        CC_SHA256_Update(&context, buffer, (CC_LONG)count);
    }
    [stream close];
    if (count < 0) {
        return nil;
    }

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    NSMutableString *hex =
        [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        [hex appendFormat:@"%02X", digest[index]];
    }
    return hex;
}

static NSString *_Nullable WMApplyCollectionValue(
    WMModuleDescriptor *descriptor,
    BOOL enabled
) {
    Class configClass = NSClassFromString(descriptor.configClassName);
    if (configClass == Nil) {
        return @"config_class_missing";
    }
    SEL sharedSelector =
        NSSelectorFromString(descriptor.sharedSelectorName);
    if (![configClass respondsToSelector:sharedSelector]) {
        return @"shared_selector_missing";
    }

    id (*sendObject)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id config = sendObject(configClass, sharedSelector);
    if (config == nil) {
        return @"shared_config_nil";
    }

    SEL setter = NSSelectorFromString(descriptor.setterName);
    NSMethodSignature *signature =
        [config methodSignatureForSelector:setter];
    if (signature == nil) {
        return @"setter_missing";
    }
    if (signature.numberOfArguments != 3 ||
        strcmp(signature.methodReturnType, @encode(void)) != 0) {
        return @"setter_signature_invalid";
    }
    const char *argumentType = [signature getArgumentTypeAtIndex:2];
    while (*argumentType == 'r' ||
           *argumentType == 'n' ||
           *argumentType == 'N' ||
           *argumentType == 'o' ||
           *argumentType == 'O' ||
           *argumentType == 'R' ||
           *argumentType == 'V') {
        argumentType++;
    }
    if (strcmp(argumentType, @encode(BOOL)) != 0 &&
        strcmp(argumentType, "B") != 0 &&
        strcmp(argumentType, "c") != 0) {
        return @"setter_argument_not_bool";
    }

    @try {
        NSInvocation *invocation =
            [NSInvocation invocationWithMethodSignature:signature];
        invocation.target = config;
        invocation.selector = setter;
        BOOL value = enabled;
        [invocation setArgument:&value atIndex:2];
        [invocation invoke];
    } @catch (__unused NSException *exception) {
        return @"setter_invocation_exception";
    }
    return nil;
}

@implementation WMFeatureCollectionAdapter

+ (NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)
    applyAllDescriptors:(NSArray<WMModuleDescriptor *> *)allDescriptors
     enabledDescriptors:(NSArray<WMModuleDescriptor *> *)enabledDescriptors {
    if (enabledDescriptors.count == 0) {
        return @{};
    }

    NSMutableDictionary<NSString *, NSDictionary<NSString *, id> *> *health =
        [NSMutableDictionary dictionary];
    NSURL *componentURL = [
        NSBundle.mainBundle.resourceURL
        URLByAppendingPathComponent:WMFeatureCollectionRelativePath
    ];
    NSString *calculatedHash = WMSHA256ForURL(componentURL);
    if (![calculatedHash isEqualToString:WMFeatureCollectionSHA256]) {
        NSString *reason = calculatedHash == nil
            ? @"component_missing"
            : @"component_hash_mismatch";
        for (WMModuleDescriptor *descriptor in enabledDescriptors) {
            health[descriptor.moduleID] =
                WMCollectionHealth(@"failed", reason);
        }
        return health;
    }

    void *handle = dlopen(
        componentURL.fileSystemRepresentation,
        RTLD_NOW | RTLD_LOCAL
    );
    if (handle == NULL) {
        const char *error = dlerror();
        NSString *reason = error == NULL
            ? @"dlopen_failed"
            : [NSString stringWithUTF8String:error];
        for (WMModuleDescriptor *descriptor in enabledDescriptors) {
            health[descriptor.moduleID] =
                WMCollectionHealth(@"failed", reason);
        }
        return health;
    }

    NSSet<NSString *> *enabledIDs = [NSSet setWithArray:
        [enabledDescriptors valueForKey:@"moduleID"]];
    NSMutableDictionary<NSString *, NSString *> *setterFailures =
        [NSMutableDictionary dictionary];
    for (WMModuleDescriptor *descriptor in allDescriptors) {
        if (![descriptor.runtime isEqualToString:@"feature-collection"]) {
            continue;
        }
        NSString *failure = WMApplyCollectionValue(
            descriptor,
            [enabledIDs containsObject:descriptor.moduleID]
        );
        if (failure != nil) {
            setterFailures[descriptor.moduleID] = failure;
        }
    }

    for (WMModuleDescriptor *descriptor in enabledDescriptors) {
        NSString *failure = setterFailures[descriptor.moduleID];
        health[descriptor.moduleID] = failure == nil
            ? WMCollectionHealth(@"ready", @"config_applied")
            : WMCollectionHealth(@"failed", failure);
    }
    return health;
}

@end
