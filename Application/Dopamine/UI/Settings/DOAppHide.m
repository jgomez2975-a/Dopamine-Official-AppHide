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

// Breadcrumbs land in the app's own Documents folder - the one place the Files app
// can read with no tooling - so a launch or a panel load that dies still leaves
// evidence of how far it got. Deliberately tiny and exception proof: a breadcrumb
// must never be the reason something fails.
void DOAppHideTrace(NSString *message)
{
    @try {
        NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (documents.length == 0) return;

        NSString *dir = [documents stringByAppendingPathComponent:@"AppHideLogs"];
        NSString *path = [dir stringByAppendingPathComponent:@"boot.log"];
        NSFileManager *fm = [NSFileManager defaultManager];

        NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
        if ([attrs[NSFileSize] unsignedLongValue] > 64 * 1024) {
            [fm removeItemAtPath:path error:nil];
        }
        else if (!attrs) {
            [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        }

        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], message ?: @"?"];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            return;
        }
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (NSException *e) {
    }
}

@implementation DOEnvironmentManager (AppHide)

// Written before anything else can fail, so the file exists even if the app dies
// later in this category's +load.
+ (void)load
{
    DOAppHideTrace(@"DOAppHide category +load");
}

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
// Panel-open path only: the log/crash copy walks every app container as root, so it
// lives behind the export row instead of running on every screen load.
- (NSString *)appHideDiagnostics
{
    NSDictionary *onDisk = [self appHideRulesFromDisk];
    NSMutableString *out = [NSMutableString stringWithFormat:@"%@ — %lu entr%@ on disk",
        APP_HIDE_RULES_PATH, (unsigned long)onDisk.count, onDisk.count == 1 ? @"y" : @"ies"];
    if (sAppHideLastError) {
        [out appendFormat:@"\nlast write failed: %@", sAppHideLastError.localizedDescription];
    }
    [out appendString:@"\n日志 / 崩溃报告：点下面那一行导出到 Documents/AppHideLogs"];
    [out appendFormat:@"\n%@", [self appHideEnvironmentSelfCheck]];
    return out;
}

// The basebin side can only write inside the container of the app it is hiding
// (a sandboxed process may not touch /var/mobile/Library/Preferences), so
// Dopamine does the collecting: as root and unsandboxed, copy every
// .DopamineAppHide.log into Documents/AppHideLogs. That folder is exposed to the

// "Hide Jailbreak Environment" can only work if the basebin that is actually installed is
// this mod's basebin: the switch writes a rules file, and systemhook is what consults it and
// hides the paths. An un-updated environment (app updated, the environment never re-staged)
// leaves a stock basebin in place, and then every switch looks correct and changes nothing -
// which is exactly the failure being chased. So look for the mod's own strings inside the
// installed systemhook.
//
// launchdhook.dylib is NOT part of this: the mod does not patch it, so scoring it against
// systemhook's markers produced a false "部分匹配 ⚠️" on devices where the installation was
// in fact correct. It is still reported, for information only, and cannot change the verdict.

static NSString *sAppHideSelfCheckText = nil;
static NSUInteger sAppHideSystemhookHits = 0;
static NSUInteger sAppHideSystemhookTotal = 0;
static NSTimeInterval sAppHideSelfCheckAt = 0;

- (NSString *)appHideEnvironmentSelfCheck
{
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if (sAppHideSelfCheckText && now - sAppHideSelfCheckAt < 2.0) {
        return sAppHideSelfCheckText;
    }

    __block NSString *result = nil;
    __block NSUInteger systemhookHits = 0;
    __block NSUInteger markerTotal = 0;

    [self appHideRunEscaped:^{
        NSString *root = @"/var/jb";
        if (![[NSFileManager defaultManager] fileExistsAtPath:root]) root = @"/";

        // engine v10 / 8 byte thunk hook / the spawn decision log only exist in a build
        // that carries the short-hook path and the xpcproxy-aware rules lookup, so a
        // clean systemhook cannot fake them.
        NSArray<NSString *> *markers = @[@"app_hide_install", @"canOpenURL",
                                        @".DopamineAppHideRules.plist", @"engine v10",
                                        @"8 byte thunk hook",
                                        @".DopamineAppHide.spawn.log",
                                        @"hide=%d noinject=%d"];
        markerTotal = markers.count;
        if (markerTotal == 0) markerTotal = 1;   // never divide by zero

        NSString *systemhookPath = [root stringByAppendingPathComponent:@"basebin/systemhook.dylib"];
        NSData *systemhook = [NSData dataWithContentsOfFile:systemhookPath options:0 error:nil];

        NSMutableArray<NSString *> *lines = [NSMutableArray new];
        if (!systemhook.length) {
            [lines addObject:@"systemhook.dylib：读不到"];
        } else {
            for (NSString *marker in markers) {
                if ([systemhook rangeOfData:[marker dataUsingEncoding:NSUTF8StringEncoding]
                                    options:0
                                      range:NSMakeRange(0, systemhook.length)].location != NSNotFound) {
                    systemhookHits++;
                }
            }
            [lines addObject:[NSString stringWithFormat:@"systemhook.dylib：%@（%lu/%lu 标记，%.1f MB）",
                              systemhookHits == markers.count ? @"魔改版 ✅" : (systemhookHits ? @"部分匹配 ⚠️" : @"原版 ❌"),
                              (unsigned long)systemhookHits, (unsigned long)markers.count,
                              systemhook.length / 1024.0 / 1024.0]];
        }

        // Information only - see the note above.
        NSString *launchdhookPath = [root stringByAppendingPathComponent:@"basebin/launchdhook.dylib"];
        NSData *launchdhook = [NSData dataWithContentsOfFile:launchdhookPath options:0 error:nil];
        [lines addObject:launchdhook.length
            ? @"launchdhook.dylib：原版（本 mod 不改它，属正常，不影响判定）"
            : @"launchdhook.dylib：读不到"];

        // The rules file and the launch-time decisions. These separate "the app was never
        // matched by the rules" from "it was matched and something else is still visible".
        // Both are read as root - a sandboxed app cannot see either file.
        NSString *rulesPath = @"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist";
        NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:rulesPath];
        if (rules.count) {
            NSMutableArray<NSString *> *ruleLines = [NSMutableArray new];
            for (NSString *key in [rules.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                id entry = rules[key];
                BOOL hide = [entry isKindOfClass:[NSDictionary class]] ? [entry[@"HideEnvironment"] boolValue] : NO;
                BOOL noInject = [entry isKindOfClass:[NSDictionary class]] ? [entry[@"HideNoInject"] boolValue] : NO;
                [ruleLines addObject:[NSString stringWithFormat:@"  %@  hide=%d noinject=%d",
                                      key, hide ? 1 : 0, noInject ? 1 : 0]];
            }
            [lines addObject:[NSString stringWithFormat:@"规则文件：%lu 条\n%@",
                              (unsigned long)rules.count, [ruleLines componentsJoinedByString:@"\n"]]];
        } else {
            [lines addObject:@"规则文件：读不到或为空（开关没写进 .DopamineAppHideRules.plist）"];
        }

        NSString *spawnLogPath = @"/var/mobile/Library/Preferences/.DopamineAppHide.spawn.log";
        NSData *spawnData = [NSData dataWithContentsOfFile:spawnLogPath];
        if (spawnData.length) {
            NSString *spawnText = [[NSString alloc] initWithData:spawnData encoding:NSUTF8StringEncoding];
            NSArray<NSString *> *spawnLines = [spawnText componentsSeparatedByString:@"\n"];
            NSUInteger from = spawnLines.count > 13 ? spawnLines.count - 13 : 0;
            NSMutableArray<NSString *> *logTail = [NSMutableArray new];
            for (NSUInteger i = from; i < spawnLines.count; i++) {
                if (spawnLines[i].length) [logTail addObject:spawnLines[i]];
            }
            [lines addObject:[NSString stringWithFormat:@"启动判定（最近 %lu 条）：\n%@",
                              (unsigned long)logTail.count, [logTail componentsJoinedByString:@"\n"]]];
        } else {
            [lines addObject:@"启动判定日志：还没有（装完这版后启动任意 App 再回来看）"];
        }

        result = [lines componentsJoinedByString:@"\n"];
    }];

    if (!result.length) {
        result = @"systemhook.dylib：读不到（先越狱，再点上面那行「重装隐藏引擎」）";
    }

    sAppHideSelfCheckText = [NSString stringWithFormat:@"环境自检：\n%@", result];
    sAppHideSystemhookHits = systemhookHits;
    sAppHideSystemhookTotal = markerTotal;
    sAppHideSelfCheckAt = now;
    return sAppHideSelfCheckText;
}

// The verdict is about the dylib this mod actually patches, and nothing else.
- (NSString *)appHideBasebinVerdict
{
    [self appHideEnvironmentSelfCheck];

    if (sAppHideSystemhookTotal == 0) return @"未知";
    if (sAppHideSystemhookHits == 0) return @"原版 ❌";
    if (sAppHideSystemhookHits < sAppHideSystemhookTotal) return @"部分匹配 ⚠️";
    return @"魔改版 ✅";
}

static NSString *const kAppHideLogDir  = @"AppHideLogs";
static NSString *const kAppHideLogName = @".DopamineAppHide.log";
static NSString *const kAppHideCrashDir = @"CrashReports";
static const NSUInteger kAppHideLogKeep = 40;
static const NSUInteger kAppHideCrashKeep = 12;

- (NSString *)appHideCollectLogs
{
    DOAppHideTrace(@"export: start");

    @try {
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

    DOAppHideTrace([NSString stringWithFormat:@"export: %lu logs, %lu crashes",
                    (unsigned long)copied, (unsigned long)crashCopied]);

    if (found == 0 && crashCopied == 0) return @"检测日志：还没有 App 探过被隐藏的路径（先跑一次目标 App）";
    return [NSString stringWithFormat:
            @"检测日志：%lu 个 App 有记录，新导出 %lu 个日志、%lu 个崩溃报告到 文件App/我的iPhone/Dopamine/%@",
            (unsigned long)found, (unsigned long)copied, (unsigned long)crashCopied, kAppHideLogDir];
    }
    @catch (NSException *e) {
        DOAppHideTrace([@"export: NSException " stringByAppendingString:e.reason ?: @"?"]);
        return [NSString stringWithFormat:@"导出失败：%@", e.reason ?: @"未知异常"];
    }
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
