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
- (NSDictionary<NSString *, NSDictionary *> *)appHideRules;

// Serialises and installs the rules file as root + unsandboxed, then reads it back
// and compares. Sets *error (with the real errno) when the write is denied.
- (BOOL)writeAppHideRules:(NSDictionary<NSString *, NSDictionary *> *)rules error:(NSError **)error;

- (BOOL)isEnvironmentHiddenForBundleID:(NSString *)bundleID;
- (BOOL)isEnvironmentNoInjectForBundleID:(NSString *)bundleID;

// Mirrors the basebin semantics: enabling NoInject also enables HideEnvironment;
// disabling HideEnvironment removes the entry completely.
- (void)setEnvironmentHidden:(BOOL)hidden forBundleID:(NSString *)bundleID;
- (void)setEnvironmentNoInject:(BOOL)noInject forBundleID:(NSString *)bundleID;

// Installed user apps as @[ @{@"bundleID":.., @"name":.., @"path":..} ], sorted by name.
- (NSArray<NSDictionary<NSString *, NSString *> *> *)appHideInstalledApps;

@end

NS_ASSUME_NONNULL_END
