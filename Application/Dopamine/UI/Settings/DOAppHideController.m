//
//  DOAppHideController.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHideController.h"
#import "DOAppHide.h"
#import "DOEnvironmentManager.h"
#import <UIKit/UIKit.h>

// Name matching for the search field. Substring first, then subsequence, so the
// short forms people actually type still find the app: "农行" -> 中国农业银行
// (农 and 行 are in order), "wx" -> WeChat. Bundle identifiers are matched as a
// plain substring as well, so the full id always works.
static BOOL DOAppHideFuzzyMatch(NSString *haystack, NSString *needle)
{
    if (needle.length == 0) return YES;
    if (haystack.length == 0) return NO;

    if ([haystack rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
        return YES;
    }

    NSString *lowerHaystack = haystack.lowercaseString;
    NSString *lowerNeedle = needle.lowercaseString;
    NSUInteger cursor = 0;
    for (NSUInteger i = 0; i < lowerNeedle.length; i++) {
        unichar wanted = [lowerNeedle characterAtIndex:i];
        BOOL found = NO;
        while (cursor < lowerHaystack.length) {
            unichar candidate = [lowerHaystack characterAtIndex:cursor++];
            if (candidate == wanted) { found = YES; break; }
        }
        if (!found) return NO;
    }
    return YES;
}

@interface DOAppHideController () <UISearchBarDelegate>
// Built once per screen load, then filtered. Every app block is two switch
// specifiers plus its group header, so the filter works on whole blocks.
@property (nonatomic, strong) NSArray<PSSpecifier *> *appHideAllSpecifiers;
@property (nonatomic, strong) UISearchBar *appHideSearchBar;
@property (nonatomic, copy) NSString *appHideQuery;
@end

@implementation DOAppHideController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // In case the OS asks for specifiers before the view appears.
    [self appHideBuildAllSpecifiers];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    // Re-read the rules file every time the panel is entered: the file is the
    // single source of truth, and it lives outside the container.
    [[DOEnvironmentManager sharedManager] appHideInvalidateRulesCache];
    self.appHideAllSpecifiers = nil;
    _specifiers = nil;
    [self appHideInstallSearchBar];
}

#pragma mark - search

- (void)appHideInstallSearchBar
{
    if (!self.appHideSearchBar) {
        UISearchBar *bar = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, self.table.bounds.size.width, 44)];
        bar.delegate = self;
        bar.placeholder = @"搜索 App 名称或 Bundle ID（如 农行 / abchina）";
        bar.autocapitalizationType = UITextAutocapitalizationTypeNone;
        bar.autocorrectionType = UITextAutocorrectionTypeNo;
        bar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        bar.searchBarStyle = UISearchBarStyleMinimal;
        self.appHideSearchBar = bar;
    }
    if (self.table.tableHeaderView != self.appHideSearchBar) {
        self.table.tableHeaderView = self.appHideSearchBar;
    }
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText
{
    NSString *trimmed = [searchText stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([trimmed isEqualToString:self.appHideQuery ?: @""]) return;
    self.appHideQuery = trimmed;
    // Drop the cache so PSListController asks for the filtered list.
    _specifiers = nil;
    [self reloadSpecifiers];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar
{
    [searchBar resignFirstResponder];
}

#pragma mark - specifiers

- (NSArray *)specifiers
{
    if (!_specifiers) {
        _specifiers = [self appHideFilteredSpecifiers];
    }
    return _specifiers;
}

- (NSArray<PSSpecifier *> *)appHideBuildAllSpecifiers
{
    if (self.appHideAllSpecifiers) return self.appHideAllSpecifiers;

    NSMutableArray<PSSpecifier *> *specifiers = [NSMutableArray new];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];

    NSArray<NSDictionary *> *apps = [envManager appHideInstalledApps];
    NSUInteger hiddenCount = 0;
    for (NSDictionary *app in apps) {
        if ([envManager isEnvironmentHiddenForBundleID:app[@"bundleID"]]) hiddenCount++;
    }

    PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
    headerGroup.name = @"App Hiding";
    [headerGroup setProperty:[NSString stringWithFormat:
                                 @"共 %lu 个 App，已隐藏 %lu 个。隐藏的 App 启动时不会带上越狱环境，改完下次启动生效（不用注销）。\n%@",
                                 (unsigned long)apps.count, (unsigned long)hiddenCount,
                                 [envManager appHideDiagnostics]]
                     forKey:@"footerText"];
    [specifiers addObject:headerGroup];

    for (NSDictionary *app in apps) {
        NSString *bundleID = app[@"bundleID"];

        PSSpecifier *appGroup = [PSSpecifier emptyGroupSpecifier];
        appGroup.name = app[@"name"];
        [appGroup setProperty:bundleID forKey:@"footerText"];
        [specifiers addObject:appGroup];

        PSSpecifier *hideSpecifier = [PSSpecifier preferenceSpecifierNamed:@"Hide Jailbreak Environment"
                                                                   target:self
                                                                      set:@selector(setHidden:specifier:)
                                                                      get:@selector(readHidden:)
                                                                   detail:nil
                                                                     cell:PSSwitchCell
                                                                     edit:nil];
        [hideSpecifier setProperty:@YES forKey:@"enabled"];
        [hideSpecifier setProperty:bundleID forKey:@"bundleID"];
        [hideSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:hideSpecifier];

        PSSpecifier *noInjectSpecifier = [PSSpecifier preferenceSpecifierNamed:@"No Injection"
                                                                       target:self
                                                                          set:@selector(setNoInject:specifier:)
                                                                          get:@selector(readNoInject:)
                                                                       detail:nil
                                                                         cell:PSSwitchCell
                                                                         edit:nil];
        [noInjectSpecifier setProperty:@YES forKey:@"enabled"];
        [noInjectSpecifier setProperty:bundleID forKey:@"bundleID"];
        [noInjectSpecifier setProperty:@NO forKey:@"default"];
        [specifiers addObject:noInjectSpecifier];
    }

    self.appHideAllSpecifiers = specifiers;
    return specifiers;
}

- (NSArray<PSSpecifier *> *)appHideFilteredSpecifiers
{
    NSArray<PSSpecifier *> *all = [self appHideBuildAllSpecifiers];
    NSString *query = self.appHideQuery;
    if (query.length == 0) return all;

    // Layout is exactly [header, (group, hide, noInject) * N]; anything else means
    // this code and the builder drifted apart, in which case showing everything is
    // the only safe answer.
    if (all.count < 4 || (all.count - 1) % 3 != 0) return all;

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    NSMutableArray<PSSpecifier *> *filtered = [NSMutableArray new];
    [filtered addObject:all[0]];

    for (NSUInteger i = 1; i + 2 < all.count; i += 3) {
        PSSpecifier *group = all[i];
        NSString *bundleID = [group propertyForKey:@"footerText"] ?: @"";

        BOOL matches = DOAppHideFuzzyMatch(group.name, query) || DOAppHideFuzzyMatch(bundleID, query);
        // Already enabled apps stay visible whatever the query is: hiding one must
        // never make it impossible to unhide it again.
        BOOL enabled = [envManager isEnvironmentHiddenForBundleID:bundleID] ||
                       [envManager isEnvironmentNoInjectForBundleID:bundleID];
        if (!matches && !enabled) continue;

        [filtered addObject:group];
        [filtered addObject:all[i + 1]];
        [filtered addObject:all[i + 2]];
    }

    if (filtered.count == 1) {
        PSSpecifier *emptyGroup = [PSSpecifier emptyGroupSpecifier];
        emptyGroup.name = @"没有匹配的 App";
        [emptyGroup setProperty:[NSString stringWithFormat:@"没有 App 名称或 Bundle ID 匹配“%@”。", query]
                        forKey:@"footerText"];
        [filtered addObject:emptyGroup];
    }
    return filtered;
}

#pragma mark - switch handlers

- (NSNumber *)readHidden:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    return @([[DOEnvironmentManager sharedManager] isEnvironmentHiddenForBundleID:bundleID]);
}

- (void)setHidden:(NSNumber *)value specifier:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];

    NSError *error = nil;
    if (![[DOEnvironmentManager sharedManager] setEnvironmentHidden:value.boolValue
                                                       forBundleID:bundleID
                                                             error:&error]) {
        // Never fail silently: the switch would just snap back with no reason.
        [self presentAppHideError:error];
    }
    // Re-read from disk so the switch shows what actually landed (NoInject also
    // implies Hidden on the basebin side).
    [self reloadSpecifiers];
}

- (NSNumber *)readNoInject:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    return @([[DOEnvironmentManager sharedManager] isEnvironmentNoInjectForBundleID:bundleID]);
}

- (void)setNoInject:(NSNumber *)value specifier:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];

    NSError *error = nil;
    if (![[DOEnvironmentManager sharedManager] setEnvironmentNoInject:value.boolValue
                                                         forBundleID:bundleID
                                                               error:&error]) {
        [self presentAppHideError:error];
    }
    [self reloadSpecifiers];
}

- (void)presentAppHideError:(NSError *)error
{
    NSString *message = error.localizedDescription ?: @"The rules file could not be written.";
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"App Hiding"
                                                                  message:message
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
