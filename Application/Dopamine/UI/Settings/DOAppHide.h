//
//  DOAppHide.h
//  Dopamine (App Hiding mod)
//
//  Per-app jailbreak hiding: a rules file that launchdhook consults on every
//  posix_spawn / execve so selected apps are launched without the jailbreak
//  environment.
//
//  Rules file: /var/mobile/Library/Preferences/.DopamineAppHideRules.plist
//  Schema    : <CFBundleIdentifier> -> { HideEnvironment: bool, HideNoInject: bool }
//

#import <Foundation/Foundation.h>
#import "DOEnvironmentManager.h"

NS_ASSUME_NONNULL_BEGIN

// Breadcrumb written into Documents/AppHideLogs/boot.log, which the Files app can
// read even when the app dies before the UI appears. No root and no escalation: it
// only ever touches the app's own container. Used to find where a launch or a panel
// load stops.
FOUNDATION_EXPORT void DOAppHideTrace(NSString *message);

@interface DOEnvironmentManager (AppHide)

// Absolute path of the rules file (same path the basebin side reads).
- (NSString *)appHideRulesPath;

// Parsed rules: bundleID -> @{ @"HideEnvironment": @(BOOL), @"HideNoInject": @(BOOL) }
// Both accessors read the file inside the same unsandbox scope the write uses;
// a sandboxed read of /var/mobile/Library/Preferences returns nil, which would
// make every switch render as OFF.
- (NSDictionary<NSString *, NSDictionary *> *)appHideRules;
- (NSDictionary<NSString *, NSDictionary *> *)appHideRulesFromDisk;
- (void)appHideInvalidateRulesCache;

// Human readable state for the panel footer: path, entry count on disk and the
// reason the last write failed (if it did).
- (NSString *)appHideDiagnostics;

// Panel footer diagnostic: reads the installed /var/jb/basebin dylibs and reports
// whether they are this mod's build. Without that basebin the switches write a rules
// file that nothing ever consults.
- (NSString *)appHideEnvironmentSelfCheck;

// One word answer for a row title, because a settings footer truncates a multi line
// string and the verdict then exists but cannot be seen:
// "魔改版 ✅" / "部分匹配 ⚠️" / "原版 ❌" / "读不到".
- (NSString *)appHideBasebinVerdict;

// A hidden app can only write inside its own container, so the basebin side logs
// every path it denied to <container>/Library/Caches/.DopamineAppHide.log. This
// copies those files into Dopamine's Documents (exposed through the Files app) and
// returns a one line summary. Runs root + unsandboxed.
- (NSString *)appHideCollectLogs;

// Serialises and installs the rules file as root + unsandboxed, then reads it back
// and compares. Sets *error (with the real errno) when the write is denied.
- (BOOL)writeAppHideRules:(NSDictionary<NSString *, NSDictionary *> *)rules error:(NSError **)error;

- (BOOL)isEnvironmentHiddenForBundleID:(NSString *)bundleID;
- (BOOL)isEnvironmentNoInjectForBundleID:(NSString *)bundleID;

// Mirrors the basebin semantics: enabling NoInject also enables HideEnvironment;
// disabling HideEnvironment removes the entry completely. Returns NO (and fills
// *error) when the rules file could not be written.
- (BOOL)setEnvironmentHidden:(BOOL)hidden forBundleID:(NSString *)bundleID error:(NSError **)error;
- (BOOL)setEnvironmentNoInject:(BOOL)noInject forBundleID:(NSString *)bundleID error:(NSError **)error;

// Installed user apps as @[ @{@"bundleID":.., @"name":.., @"path":..} ], sorted by name.
- (NSArray<NSDictionary<NSString *, NSString *> *> *)appHideInstalledApps;

@end

NS_ASSUME_NONNULL_END
