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

// Out-of-container access on a jailbroken device needs BOTH escalations, in this
// order:
//   * root first - the jbserver's ROOT domain rejects any client whose euid is not
//     0 (BaseBin/launchdhook/src/jbserver/jbdomain_root.c: root_domain_allowed is
//     `audit_token_to_euid(clientToken) == 0`), and
//   * then the sandbox drop - the MAC label, not the uid, is what blocks
//     /var/mobile/Library/Preferences.
// Stock Dopamine's runUnsandboxed: on its own is only sufficient for a TrollStore
// install, where the app already carries com.apple.private.security.no-sandbox.
// A self signed install has neither that entitlement nor root, so the label call
// is refused and the read stays sandboxed -> every switch renders OFF again.
// Returns YES only when the block really ran.
- (BOOL)appHideRunEscaped:(void (^)(void))block
{
    __block BOOL ran = NO;
    void (^wrapped)(void) = ^{
        block();
        ran = YES;
    };

    if (geteuid() == 0) {
        [self runUnsandboxed:wrapped];
    }
    else if ([self isJailbroken]) {
        // runAsRoot: escalates through jbclient_dopamine_get_root(), which patches
        // the kernel ucred (no entitlement involved: the DOPAMINE domain only
        // verifies that the caller's executable lives inside Dopamine.app).
        [self runAsRoot:^{
            [self runUnsandboxed:wrapped];
        }];
    }
    else {
        // Not jailbroken: TrollStore installs are already unsandboxed.
        [self runUnsandboxed:wrapped];
    }
    return ran;
}

// The rules file lives outside the app container. A sandboxed read returns nil
// even for a 0644 file, which makes every switch render as OFF when the panel is
// re-entered, so the read has to happen in the same escaped scope the write
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
    BOOL ran = [self appHideRunEscaped:^{
        rules = [NSDictionary dictionaryWithContentsOfFile:APP_HIDE_RULES_PATH];
    }];
    NSDictionary *result = [rules isKindOfClass:[NSDictionary class]] ? rules : @{};
    sAppHideRulesCache = result;
    if (!ran) {
        sAppHideLastError = [NSError errorWithDomain:@"AppHide" code:3 userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:
                @"could not escalate to read %@ (jailbreak privilege escalation refused)", APP_HIDE_RULES_PATH]
        }];
    }
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
    [out appendFormat:@"\n%@", [self appHideCollectLogs]];
    return out;
}

// The basebin side can only write inside the container of the app it is hiding
// (a sandboxed process may not touch /var/mobile/Library/Preferences), so
// Dopamine does the collecting: as root and unsandboxed, copy every
// .DopamineAppHide.log into Documents/AppHideLogs. That folder is exposed to the
// Files app through UIFileSharingEnabled, which is how the user can see exactly
// which paths a bank app probed - no Filza, no SSH, no cable.
static NSString *const kAppHideLogDir  = @"AppHideLogs";
static NSString *const kAppHideLogName = @".DopamineAppHide.log";
static NSString *const kAppHideCrashDir = @"CrashReports";
static const NSUInteger kAppHideLogKeep = 40;
static const NSUInteger kAppHideCrashKeep = 12;

- (NSString *)appHideCollectLogs
{
    __block NSUInteger copied = 0;
    __block NSUInteger found = 0;
    __block NSUInteger crashCopied = 0;

    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!documents) return @"检测日志：拿不到 Documents 目录";

    NSString *outDir = [documents stringByAppendingPathComponent:kAppHideLogDir];

    [self appHideRunEscaped:^{
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:outDir withIntermediateDirectories:YES attributes:nil error:nil];

        NSString *root = @"/var/mobile/Containers/Data/Application";
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:root error:nil]) {
            NSString *logPath = [[root stringByAppendingPathComponent:uuid]
                stringByAppendingPathComponent:[@"Library/Caches" stringByAppendingPathComponent:kAppHideLogName]];

            NSDictionary *attrs = [fm attributesOfItemAtPath:logPath error:nil];
            if (!attrs) continue;
            found++;

            NSDate *mtime = attrs[NSFileModificationDate] ?: [NSDate date];
            NSString *destName = [NSString stringWithFormat:@"%@-%.0f.log", uuid, mtime.timeIntervalSince1970];
            NSString *dest = [outDir stringByAppendingPathComponent:destName];
            if ([fm fileExistsAtPath:dest]) continue;
            if ([fm copyItemAtPath:logPath toPath:dest error:nil]) copied++;
        }

        NSArray<NSString *> *existing = [[fm contentsOfDirectoryAtPath:outDir error:nil]
            sortedArrayUsingSelector:@selector(compare:)];
        if (existing.count > kAppHideLogKeep) {
            for (NSUInteger i = 0; i + kAppHideLogKeep < existing.count; i++) {
                [fm removeItemAtPath:[outDir stringByAppendingPathComponent:existing[i]] error:nil];
            }
        }

        // Crash reports. If a hidden app is killed at launch, its .ips is the only
        // way to tell WHY without a cable - it names the faulting image and the
        // faulting instruction, which is what distinguishes "a hook smashed a
        // neighbouring symbol" from "the app detected the jailbreak and exited".
        NSString *crashRoot = @"/var/mobile/Library/Logs/CrashReporter";
        NSString *crashDir = [outDir stringByAppendingPathComponent:kAppHideCrashDir];
        NSDate *cutoff = [NSDate dateWithTimeIntervalSinceNow:-24 * 3600];
        NSMutableArray<NSDictionary *> *recent = [NSMutableArray new];
        for (NSString *name in [fm contentsOfDirectoryAtPath:crashRoot error:nil]) {
            if (![name hasSuffix:@".ips"]) continue;
            NSString *src = [crashRoot stringByAppendingPathComponent:name];
            NSDate *mtime = [fm attributesOfItemAtPath:src error:nil][NSFileModificationDate];
            if (!mtime || [mtime compare:cutoff] == NSOrderedAscending) continue;
            [recent addObject:@{ @"path": src, @"mtime": mtime }];
        }
        [recent sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [b[@"mtime"] compare:a[@"mtime"]];
        }];
        if (recent.count > 0) {
            [fm createDirectoryAtPath:crashDir withIntermediateDirectories:YES attributes:nil error:nil];
            NSUInteger limit = MIN(recent.count, (NSUInteger)kAppHideCrashKeep);
            for (NSUInteger i = 0; i < limit; i++) {
                NSString *src = recent[i][@"path"];
                NSString *dest = [crashDir stringByAppendingPathComponent:src.lastPathComponent];
                if ([fm fileExistsAtPath:dest]) continue;
                if ([fm copyItemAtPath:src toPath:dest error:nil]) crashCopied++;
            }
        }
    }];

    if (found == 0 && crashCopied == 0) return @"检测日志：还没有 App 探过被隐藏的路径（先跑一次目标 App）";
    return [NSString stringWithFormat:
            @"检测日志：%lu 个 App 有记录，新导出 %lu 个日志、%lu 个崩溃报告到 文件App/我的iPhone/Dopamine/%@",
            (unsigned long)found, (unsigned long)copied, (unsigned long)crashCopied, kAppHideLogDir];
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

    BOOL ran = [self appHideRunEscaped:work];
    if (!ran && !writeError) {
        writeError = [NSError errorWithDomain:@"AppHide" code:3 userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:
                @"could not escalate (jailbroken=%d): %@ was not written",
                (int)[self isJailbroken], APP_HIDE_RULES_PATH]
        }];
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
        [self appHideRunEscaped:^{
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
