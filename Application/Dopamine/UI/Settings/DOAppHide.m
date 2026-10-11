//
//  DOAppHide.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHide.h"
#import <sys/stat.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <objc/runtime.h>
#import <objc/message.h>

// Same constants the LFDopamine build uses; keeping them identical means rules
// files are interchangeable between this mod and that build.
#define APP_HIDE_RULES_PATH @"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist"
#define APP_HIDE_RULES_OWNER 501
#define APP_HIDE_RULES_GROUP 501
#define APP_HIDE_RULES_MODE 0644

@implementation DOEnvironmentManager (AppHide)

- (NSString *)appHideRulesPath
{
    return APP_HIDE_RULES_PATH;
}

- (NSDictionary<NSString *, NSDictionary *> *)appHideRules
{
    NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:self.appHideRulesPath];
    if (![rules isKindOfClass:[NSDictionary class]]) return @{};
    return rules;
}

- (BOOL)writeAppHideRules:(NSDictionary<NSString *, NSDictionary *> *)rules error:(NSError **)error
{
    // The app itself is sandboxed and mobile, so the write has to happen as root
    // inside runUnsandboxed (identical to the stock Dopamine write pattern).
    __block BOOL ok = NO;
    __block NSError *writeError = nil;

    void (^work)(void) = ^{
        NSString *path = APP_HIDE_RULES_PATH;

        NSError *serError = nil;
        NSData *data = [NSData dataWithPropertyList:rules
                                            format:NSPropertyListXMLFormat_v1_0
                                           options:0
                                             error:&serError];
        if (!data) {
            writeError = [NSError errorWithDomain:@"AppHide" code:1 userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"failed to serialise rules: %@", serError]
            }];
            NSLog(@"[AppHide] failed to serialise rules: %@", serError);
            return;
        }

        if (![data writeToFile:path atomically:NO]) {
            int err = errno;
            NSLog(@"[AppHide] failed to write %@: %@ (errno %d)", path, strerror(err), err);
            writeError = [NSError errorWithDomain:@"AppHide" code:err userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"could not write %@ (errno %d: %s). Full Disk Access / TrollStore install may be missing.",
                    path, err, strerror(err)]
            }];
            return;
        }

        chown(path.fileSystemRepresentation, APP_HIDE_RULES_OWNER, APP_HIDE_RULES_GROUP);
        chmod(path.fileSystemRepresentation, APP_HIDE_RULES_MODE);

        NSDictionary *readBack = [NSDictionary dictionaryWithContentsOfFile:path];
        if (readBack && [readBack isEqualToDictionary:rules]) {
            ok = YES;
            NSLog(@"[AppHide] %@ -> %@ (write OK, %lu entries)", path, rules, (unsigned long)rules.count);
        }
        else {
            NSLog(@"[AppHide] write verification failed for %@ (wrote %lu entries, read back %lu)",
                  path, (unsigned long)rules.count, (unsigned long)readBack.count);
            writeError = [NSError errorWithDomain:@"AppHide" code:2 userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:
                    @"wrote %lu entries but read back %lu - jailbreak filesystem may be hidden or redirected.",
                    (unsigned long)rules.count, (unsigned long)readBack.count]
            }];
        }
    };

    if ([self isJailbroken]) {
        [self runAsRoot:^{
            [self runUnsandboxed:work];
        }];
    }
    else {
        // Not jailbroken: runUnsandboxed still helps for TrollStore installs
        [self runUnsandboxed:work];
    }

    if (!ok && error) *error = writeError;
    return ok;
}

- (BOOL)isEnvironmentHiddenForBundleID:(NSString *)bundleID
{
    NSDictionary *entry = self.appHideRules[bundleID];
    if (![entry isKindOfClass:[NSDictionary class]]) return NO;
    return [entry[@"HideEnvironment"] boolValue];
}

- (BOOL)isEnvironmentNoInjectForBundleID:(NSString *)bundleID
{
    NSDictionary *entry = self.appHideRules[bundleID];
    if (![entry isKindOfClass:[NSDictionary class]]) return NO;
    return [entry[@"HideNoInject"] boolValue];
}

- (void)setEnvironmentHidden:(BOOL)hidden forBundleID:(NSString *)bundleID
{
    if (!bundleID.length) return;

    NSMutableDictionary *rules = [self.appHideRules mutableCopy] ?: [NSMutableDictionary new];
    NSMutableDictionary *entry = [rules[bundleID] mutableCopy];

    if (!hidden) {
        // Disabling the hide removes the whole entry
        [rules removeObjectForKey:bundleID];
    }
    else {
        if (!entry) entry = [NSMutableDictionary new];
        entry[@"HideEnvironment"] = @YES;
        rules[bundleID] = entry;
    }

    NSError *error = nil;
    if (![self writeAppHideRules:rules error:&error]) {
        NSLog(@"[AppHide] setEnvironmentHidden:%d for %@ failed: %@", hidden, bundleID, error);
    }
}

- (void)setEnvironmentNoInject:(BOOL)noInject forBundleID:(NSString *)bundleID
{
    if (!bundleID.length) return;

    NSMutableDictionary *rules = [self.appHideRules mutableCopy] ?: [NSMutableDictionary new];
    NSMutableDictionary *entry = [rules[bundleID] mutableCopy] ?: [NSMutableDictionary new];

    if (noInject) {
        // NoInject implies HideEnvironment in the basebin side, so keep the file consistent
        entry[@"HideNoInject"] = @YES;
        entry[@"HideEnvironment"] = @YES;
    }
    else {
        [entry removeObjectForKey:@"HideNoInject"];
    }

    if (entry.count) {
        rules[bundleID] = entry;
    }
    else {
        [rules removeObjectForKey:bundleID];
    }

    NSError *error = nil;
    if (![self writeAppHideRules:rules error:&error]) {
        NSLog(@"[AppHide] setEnvironmentNoInject:%d for %@ failed: %@", noInject, bundleID, error);
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

- (NSArray<NSDictionary<NSString *, NSString *> *> *)appHideInstalledApps
{
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *apps = [NSMutableArray new];
    NSMutableSet<NSString *> *seen = [NSMutableSet new];

    // Preferred path: LaunchServices knows about every installed app, including
    // their icons and localized names.
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    id workspace = nil;
    if (workspaceClass) {
        workspace = [workspaceClass performSelector:NSSelectorFromString(@"defaultWorkspace")];
    }
    if (workspace && [workspace respondsToSelector:NSSelectorFromString(@"allApplications")]) {
        NSArray *proxies = [workspace performSelector:NSSelectorFromString(@"allApplications")];
        for (id proxy in proxies) {
            NSString *bundleID = [proxy respondsToSelector:NSSelectorFromString(@"applicationIdentifier")]
                               ? [proxy performSelector:NSSelectorFromString(@"applicationIdentifier")] : nil;
            if (!bundleID.length) continue;

            BOOL isSystem = NO;
            if ([proxy respondsToSelector:NSSelectorFromString(@"isSystemApplication")]) {
                isSystem = ((BOOL (*)(id, SEL))objc_msgSend)(proxy, NSSelectorFromString(@"isSystemApplication"));
            }
            if (isSystem) continue;

            NSString *name = [proxy respondsToSelector:NSSelectorFromString(@"localizedName")]
                           ? [proxy performSelector:NSSelectorFromString(@"localizedName")] : nil;
            NSURL *bundleURL = [proxy respondsToSelector:NSSelectorFromString(@"bundleURL")]
                             ? [proxy performSelector:NSSelectorFromString(@"bundleURL")] : nil;

            [seen addObject:bundleID];
            [apps addObject:@{
                @"bundleID": bundleID,
                @"name": name.length ? name : bundleID,
                @"path": bundleURL.path ?: @""
            }];
        }
    }

    // Fallback (LaunchServices unavailable / restricted): scan the app container.
    if (!apps.count) {
        for (NSString *root in @[@"/var/containers/Bundle/Application", @"/private/var/containers/Bundle/Application"]) {
            NSArray<NSString *> *uuids = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:root error:nil];
            for (NSString *uuid in uuids) {
                NSString *containerPath = [root stringByAppendingPathComponent:uuid];
                NSArray<NSString *> *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:containerPath error:nil];
                for (NSString *item in items) {
                    if (![item hasSuffix:@".app"]) continue;
                    NSString *appPath = [containerPath stringByAppendingPathComponent:item];
                    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                        [appPath stringByAppendingPathComponent:@"Info.plist"]];
                    NSString *bundleID = info[@"CFBundleIdentifier"];
                    if (!bundleID.length || [seen containsObject:bundleID]) continue;
                    [seen addObject:bundleID];
                    [apps addObject:@{
                        @"bundleID": bundleID,
                        @"name": info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bundleID,
                        @"path": appPath
                    }];
                }
            }
            if (apps.count) break;
        }
    }

    return [apps sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
}

#pragma clang diagnostic pop

@end
