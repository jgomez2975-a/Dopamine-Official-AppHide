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

// The rules file lives outside the app container. A sandboxed read returns nil
// even for a 0644 file, which makes every switch render as OFF when the panel is
// re-entered, so the read has to happen in the same unsandbox scope the write
// uses. One read per screen is enough; the cache is dropped on write and when
// the panel appears.
static NSDictionary *sAppHideRulesCache = nil;
static NSError *sAppHideLastError = nil;

- (void)appHideInvalidateRulesCache
{
    sAppHideRulesCache = nil;
}

- (NSDictionary<NSString *, NSDictionary *> *)appHideRulesFromDisk
{
    __block NSDictionary *rules = nil;
    [self runUnsandboxed:^{
        rules = [NSDictionary dictionaryWithContentsOfFile:APP_HIDE_RULES_PATH];
    }];
    NSDictionary *result = [rules isKindOfClass:[NSDictionary class]] ? rules : @{};
    sAppHideRulesCache = result;
    return result;
}

- (NSDictionary<NSString *, NSDictionary *> *)appHideRules
{
    if (sAppHideRulesCache) return sAppHideRulesCache;
    return [self appHideRulesFromDisk];
}

// Shown in the panel footer: what is really on disk right now, plus the reason
// the last write failed (errno text included) so a failure is never silent.
- (NSString *)appHideDiagnostics
{
    NSDictionary *onDisk = [self appHideRulesFromDisk];
    NSMutableString *out = [NSMutableString stringWithFormat:@"%@ — %lu entr%@ on disk",
        APP_HIDE_RULES_PATH, (unsigned long)onDisk.count, onDisk.count == 1 ? @"y" : @"ies"];
    if (sAppHideLastError) {
        [out appendFormat:@"\nlast write failed: %@", sAppHideLastError.localizedDescription];
    }
    return out;
}

- (BOOL)writeAppHideRules:(NSDictionary<NSString *, NSDictionary *> *)rules error:(NSError **)error
{
    // The app itself is sandboxed and mobile, so the write has to happen as root
    // inside runUnsandboxed (identical to the stock Dopamine write pattern).
    __block BOOL ok = NO;
    __block NSError *writeError = nil;

    void (^work)(void) = ^{
        NSString *path = APP_HIDE_RULES_PATH;

        // -[NSDictionary writeToFile:atomically:] emits an XML property list for
        // plist-able contents and reports the reason through errno, which is the
        // only signal that separates "sandbox blocked the write" (EPERM) from
        // "the filesystem is read-only" (EROFS). Keep errno for the alert text.
        errno = 0;
        if (![rules writeToFile:path atomically:YES]) {
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

    if (ok) {
        // keep the on-screen state identical to what landed on disk
        sAppHideRulesCache = rules;
        sAppHideLastError = nil;
    }
    else {
        sAppHideLastError = writeError;
        sAppHideRulesCache = nil;
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

- (BOOL)setEnvironmentHidden:(BOOL)hidden forBundleID:(NSString *)bundleID error:(NSError **)error
{
    if (!bundleID.length) return YES;

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

    BOOL ok = [self writeAppHideRules:rules error:error];
    if (!ok) {
        NSLog(@"[AppHide] setEnvironmentHidden:%d for %@ failed: %@", hidden, bundleID, error ? *error : nil);
    }
    return ok;
}

- (BOOL)setEnvironmentNoInject:(BOOL)noInject forBundleID:(NSString *)bundleID error:(NSError **)error
{
    if (!bundleID.length) return YES;

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

    BOOL ok = [self writeAppHideRules:rules error:error];
    if (!ok) {
        NSLog(@"[AppHide] setEnvironmentNoInject:%d for %@ failed: %@", noInject, bundleID, error ? *error : nil);
    }
    return ok;
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
    // /var/containers/Bundle/Application is outside this app's own container, so
    // the scan (and each Info.plist read) is sandbox-denied until the label is
    // dropped - an empty app list was the visible symptom.
    if (!apps.count) {
        [self runUnsandboxed:^{
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
        }];
    }

    return [apps sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
}

#pragma clang diagnostic pop

@end
