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
