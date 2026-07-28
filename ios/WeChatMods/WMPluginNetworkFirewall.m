#import "WMPluginNetworkFirewall.h"

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

#import "WMRuntimeHookFirewall.h"

static NSString *const WMPluginNetworkEventsKey =
    @"wechatmods.plugin-network-events";
static NSString *const WMPluginNetworkAllowlistKey =
    @"wechatmods.plugin-network-allowlist";
static NSUInteger const WMMaximumNetworkEvents = 200;
static BOOL WMNetworkFirewallInstalled = NO;
static __thread BOOL WMRecordingNetworkEvent = NO;

static BOOL WMHostMatchesSuffix(
    NSString *host,
    NSString *suffix
) {
    NSString *lowerHost = host.lowercaseString;
    NSString *lowerSuffix = suffix.lowercaseString;
    return [lowerHost isEqualToString:lowerSuffix] ||
        [lowerHost hasSuffix:
            [@"." stringByAppendingString:lowerSuffix]];
}

static NSArray<NSString *> *WMAllowedHostSuffixes(void) {
    NSMutableArray<NSString *> *suffixes =
        [NSMutableArray array];
    NSArray *configured = [
        NSUserDefaults.standardUserDefaults
        arrayForKey:WMPluginNetworkAllowlistKey
    ];
    for (id item in configured) {
        if ([item isKindOfClass:NSString.class] &&
            [item length] > 0) {
            [suffixes addObject:item];
        }
    }
    return suffixes;
}

static BOOL WMURLIsAllowed(NSURL *_Nullable URL) {
    if (URL == nil) {
        return YES;
    }
    NSString *scheme = URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] &&
        ![scheme isEqualToString:@"https"]) {
        return YES;
    }
    NSString *host = URL.host;
    if (host.length == 0) {
        return NO;
    }
    for (NSString *suffix in WMAllowedHostSuffixes()) {
        if (WMHostMatchesSuffix(host, suffix)) {
            return YES;
        }
    }
    return NO;
}

static void WMRecordNetworkBlock(
    NSString *operation,
    NSURL *_Nullable URL
) {
    if (WMRecordingNetworkEvent) {
        return;
    }
    WMRecordingNetworkEvent = YES;
    @try {
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        NSMutableArray<NSDictionary<NSString *, id> *> *events = [
            [defaults arrayForKey:WMPluginNetworkEventsKey] mutableCopy
        ] ?: [NSMutableArray array];
        [events addObject:@{
            @"operation": operation,
            @"scheme": URL.scheme ?: @"",
            @"host": URL.host ?: @"",
            @"timestamp": @([NSDate.date timeIntervalSince1970]),
            @"status": @"plugin_network_blocked",
        }];
        if (events.count > WMMaximumNetworkEvents) {
            [events removeObjectsInRange:NSMakeRange(
                0,
                events.count - WMMaximumNetworkEvents
            )];
        }
        [defaults setObject:events forKey:WMPluginNetworkEventsKey];
    } @finally {
        WMRecordingNetworkEvent = NO;
    }
}

static BOOL WMShouldBlockPluginURL(
    NSURL *_Nullable URL,
    const void *_Nullable caller
) {
    return WMIsAddressFromRegisteredPlugin(caller) &&
        !WMURLIsAllowed(URL);
}

static NSError *WMPluginNetworkError(NSURL *_Nullable URL) {
    return [NSError errorWithDomain:NSURLErrorDomain
                              code:NSURLErrorUnsupportedURL
                          userInfo:@{
        NSURLErrorFailingURLErrorKey: URL ?: NSNull.null,
        NSLocalizedDescriptionKey:
            @"The plugin network request was blocked.",
    }];
}

static BOOL WMSwizzleInstanceMethod(
    Class targetClass,
    SEL originalSelector,
    SEL replacementSelector
) {
    Method original = class_getInstanceMethod(
        targetClass,
        originalSelector
    );
    Method replacement = class_getInstanceMethod(
        targetClass,
        replacementSelector
    );
    if (original == NULL || replacement == NULL) {
        return NO;
    }
    method_exchangeImplementations(original, replacement);
    return YES;
}

@interface NSURLSession (WMPluginNetworkFirewall)
- (nullable NSURLSessionDataTask *)wm_dataTaskWithRequest:
        (NSURLRequest *)request
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler;
- (nullable NSURLSessionDataTask *)wm_dataTaskWithURL:(NSURL *)URL
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler;
- (nullable NSURLSessionDownloadTask *)wm_downloadTaskWithRequest:
        (NSURLRequest *)request
    completionHandler:(void (^_Nullable)(
        NSURL *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler;
- (nullable NSURLSessionUploadTask *)wm_uploadTaskWithRequest:
        (NSURLRequest *)request
    fromData:(nullable NSData *)bodyData
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler;
@end

@implementation NSURLSession (WMPluginNetworkFirewall)

- (nullable NSURLSessionDataTask *)wm_dataTaskWithRequest:
        (NSURLRequest *)request
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockPluginURL(request.URL, caller)) {
        WMRecordNetworkBlock(@"NSURLSession.dataTask", request.URL);
        if (completionHandler != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completionHandler(
                    nil,
                    nil,
                    WMPluginNetworkError(request.URL)
                );
            });
        }
        return nil;
    }
    return [self wm_dataTaskWithRequest:request
                     completionHandler:completionHandler];
}

- (nullable NSURLSessionDataTask *)wm_dataTaskWithURL:(NSURL *)URL
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockPluginURL(URL, caller)) {
        WMRecordNetworkBlock(@"NSURLSession.dataTask", URL);
        if (completionHandler != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completionHandler(
                    nil,
                    nil,
                    WMPluginNetworkError(URL)
                );
            });
        }
        return nil;
    }
    return [self wm_dataTaskWithURL:URL
                  completionHandler:completionHandler];
}

- (nullable NSURLSessionDownloadTask *)wm_downloadTaskWithRequest:
        (NSURLRequest *)request
    completionHandler:(void (^_Nullable)(
        NSURL *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockPluginURL(request.URL, caller)) {
        WMRecordNetworkBlock(@"NSURLSession.downloadTask", request.URL);
        if (completionHandler != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completionHandler(
                    nil,
                    nil,
                    WMPluginNetworkError(request.URL)
                );
            });
        }
        return nil;
    }
    return [self wm_downloadTaskWithRequest:request
                          completionHandler:completionHandler];
}

- (nullable NSURLSessionUploadTask *)wm_uploadTaskWithRequest:
        (NSURLRequest *)request
    fromData:(nullable NSData *)bodyData
    completionHandler:(void (^_Nullable)(
        NSData *_Nullable,
        NSURLResponse *_Nullable,
        NSError *_Nullable
    ))completionHandler {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockPluginURL(request.URL, caller)) {
        WMRecordNetworkBlock(@"NSURLSession.uploadTask", request.URL);
        if (completionHandler != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completionHandler(
                    nil,
                    nil,
                    WMPluginNetworkError(request.URL)
                );
            });
        }
        return nil;
    }
    return [self wm_uploadTaskWithRequest:request
                                fromData:bodyData
                       completionHandler:completionHandler];
}

@end

@interface UIApplication (WMPluginNetworkFirewall)
- (BOOL)wm_openURL:(NSURL *)URL;
- (void)wm_openURL:(NSURL *)URL
    options:(NSDictionary<UIApplicationOpenExternalURLOptionsKey, id> *)options
    completionHandler:(void (^_Nullable)(BOOL success))completion;
@end

@implementation UIApplication (WMPluginNetworkFirewall)

- (BOOL)wm_openURL:(NSURL *)URL {
    const void *caller = __builtin_return_address(0);
    if (WMIsAddressFromRegisteredPlugin(caller) &&
        [@[@"http", @"https"]
            containsObject:URL.scheme.lowercaseString]) {
        WMRecordNetworkBlock(@"UIApplication.openURL", URL);
        return NO;
    }
    return [self wm_openURL:URL];
}

- (void)wm_openURL:(NSURL *)URL
    options:(NSDictionary<UIApplicationOpenExternalURLOptionsKey, id> *)options
    completionHandler:(void (^_Nullable)(BOOL success))completion {
    const void *caller = __builtin_return_address(0);
    if (WMIsAddressFromRegisteredPlugin(caller) &&
        [@[@"http", @"https"]
            containsObject:URL.scheme.lowercaseString]) {
        WMRecordNetworkBlock(@"UIApplication.openURL", URL);
        if (completion != nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(NO);
            });
        }
        return;
    }
    [self wm_openURL:URL
             options:options
   completionHandler:completion];
}

@end

@interface WKWebView (WMPluginNetworkFirewall)
- (nullable WKNavigation *)wm_loadRequest:(NSURLRequest *)request;
@end

@implementation WKWebView (WMPluginNetworkFirewall)

- (nullable WKNavigation *)wm_loadRequest:(NSURLRequest *)request {
    const void *caller = __builtin_return_address(0);
    if (WMShouldBlockPluginURL(request.URL, caller)) {
        WMRecordNetworkBlock(@"WKWebView.loadRequest", request.URL);
        return nil;
    }
    return [self wm_loadRequest:request];
}

@end

@implementation WMPluginNetworkFirewall

+ (BOOL)isInstalled {
    return WMNetworkFirewallInstalled;
}

+ (BOOL)install {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        BOOL sessionRequest = WMSwizzleInstanceMethod(
            NSURLSession.class,
            @selector(dataTaskWithRequest:completionHandler:),
            @selector(wm_dataTaskWithRequest:completionHandler:)
        );
        BOOL sessionURL = WMSwizzleInstanceMethod(
            NSURLSession.class,
            @selector(dataTaskWithURL:completionHandler:),
            @selector(wm_dataTaskWithURL:completionHandler:)
        );
        BOOL sessionDownload = WMSwizzleInstanceMethod(
            NSURLSession.class,
            @selector(downloadTaskWithRequest:completionHandler:),
            @selector(wm_downloadTaskWithRequest:completionHandler:)
        );
        BOOL sessionUpload = WMSwizzleInstanceMethod(
            NSURLSession.class,
            @selector(uploadTaskWithRequest:fromData:completionHandler:),
            @selector(
                wm_uploadTaskWithRequest:fromData:completionHandler:
            )
        );
        BOOL legacyOpenURL = WMSwizzleInstanceMethod(
            UIApplication.class,
            @selector(openURL:),
            @selector(wm_openURL:)
        );
        BOOL openURL = WMSwizzleInstanceMethod(
            UIApplication.class,
            @selector(openURL:options:completionHandler:),
            @selector(wm_openURL:options:completionHandler:)
        );
        BOOL webView = WMSwizzleInstanceMethod(
            WKWebView.class,
            @selector(loadRequest:),
            @selector(wm_loadRequest:)
        );
        WMNetworkFirewallInstalled =
            sessionRequest &&
            sessionURL &&
            sessionDownload &&
            sessionUpload &&
            legacyOpenURL &&
            openURL &&
            webView;
    });
    return WMNetworkFirewallInstalled;
}

+ (NSArray<NSDictionary<NSString *, id> *> *)blockedEvents {
    return [
        NSUserDefaults.standardUserDefaults
        arrayForKey:WMPluginNetworkEventsKey
    ] ?: @[];
}

@end
