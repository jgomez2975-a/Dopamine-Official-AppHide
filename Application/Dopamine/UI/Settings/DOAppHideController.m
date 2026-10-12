//
//  DOAppHideController.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHideController.h"
#import "DOAppHide.h"
#import "DOEnvironmentManager.h"
#import <UIKit/UIKit.h>

// Version of the panel code itself, shown in the first row. The engine inside the
// basebin has its own version (it logs "engine vN"), and keeping them visible together
// is how "the app updated but the basebin did not" stops being invisible.
#define APP_HIDE_PANEL_VERSION @"v9"

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

@interface DOAppHideController () <UISearchBarDelegate, UISearchResultsUpdating>
// Built once per screen load, then filtered. Every app block is two switch
// specifiers plus its group header, so the filter works on whole blocks.
@property (nonatomic, strong) NSArray<PSSpecifier *> *appHideAllSpecifiers;
@property (nonatomic, strong) UISearchBar *appHideSearchBar;
@property (nonatomic, copy) NSString *appHideQuery;

- (NSArray<PSSpecifier *> *)appHideBuildAllSpecifiers;
- (NSArray<PSSpecifier *> *)appHideFilteredSpecifiers;
- (void)appHideInstallSearchBar;
- (void)appHideApplyQuery:(NSString *)text;
@end

@implementation DOAppHideController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // v7: nothing but the breadcrumb here. v5 built the whole app list in viewDidLoad,
    // which meant the first root escalation (jbclient runAsRoot + the sandbox label
    // drop) happened while the view hierarchy was still loading - and that build is the
    // one that started crashing the moment the panel was opened. The list is built
    // lazily from -specifiers instead, exactly like v4 did.
    DOAppHideTrace(@"panel viewDidLoad");
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    DOAppHideTrace(@"panel viewWillAppear");
    // Re-read the rules file every time the panel is entered: the file is the
    // single source of truth, and it lives outside the container.
    [[DOEnvironmentManager sharedManager] appHideInvalidateRulesCache];
    // Only the mod's own cache is dropped. `_specifiers` (PSListController's ivar) is
    // NEVER touched: it has companion index maps that are not public, so nil-ing the
    // array alone leaves them pointing at the previous specifier objects and the next
    // table reload dies. That single line was the difference between v4, which ran, and
    // v5-v8, which crashed as soon as the panel was opened.
    self.appHideAllSpecifiers = nil;
    [self appHideInstallSearchBar];
}

#pragma mark - search

- (void)appHideInstallSearchBar
{
    @try {
        if (self.appHideSearchBar) return;

        // Navigation bar only. A search bar installed as the table's header view has to
        // cooperate with PSListController's own table handling, and this panel's job is
        // to be boringly reliable.
        UISearchController *controller = [[UISearchController alloc] initWithSearchResultsController:nil];
        controller.obscuresBackgroundDuringPresentation = NO;
        controller.searchResultsUpdater = self;
        controller.searchBar.placeholder = @"搜索 App 名称或 Bundle ID（如 农行 / abchina）";
        controller.searchBar.autocapitalizationType = UITextAutocapitalizationTypeNone;
        controller.searchBar.autocorrectionType = UITextAutocorrectionTypeNo;

        self.definesPresentationContext = YES;
        self.navigationItem.searchController = controller;
        self.navigationItem.hidesSearchBarWhenScrolling = NO;
        self.appHideSearchBar = controller.searchBar;
    } @catch (NSException *e) {
        DOAppHideTrace([@"search bar failed: " stringByAppendingString:e.reason ?: @"?"]);
    }
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    [self appHideApplyQuery:searchController.searchBar.text];
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText
{
    [self appHideApplyQuery:searchText];
}

- (void)appHideApplyQuery:(NSString *)text
{
    NSString *trimmed = [text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([trimmed isEqualToString:self.appHideQuery ?: @""]) return;
    self.appHideQuery = trimmed;
    DOAppHideTrace([NSString stringWithFormat:@"search: %@", trimmed]);
    // reloadSpecifiers re-asks this controller for its list; the ivar stays untouched.
    [self reloadSpecifiers];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar
{
    [searchBar resignFirstResponder];
}

#pragma mark - specifiers

- (NSArray *)specifiers
{
    // Recomputed on every ask (the expensive part is cached inside
    // appHideBuildAllSpecifiers) and never stored into PSListController's own ivar: that
    // array has companion index maps which are not public, so writing it by hand is how
    // the panel used to kill itself.
    @try {
        return [self appHideFilteredSpecifiers];
    } @catch (NSException *e) {
        DOAppHideTrace([@"specifiers failed: " stringByAppendingString:e.reason ?: @"?"]);
        PSSpecifier *group = [PSSpecifier emptyGroupSpecifier];
        group.name = @"App Hiding";
        [group setProperty:[NSString stringWithFormat:@"面板加载失败：%@", e.reason ?: @"未知异常"]
                    forKey:@"footerText"];
        return @[group];
    }
}

- (NSArray<PSSpecifier *> *)appHideBuildAllSpecifiers
{
    if (self.appHideAllSpecifiers) return self.appHideAllSpecifiers;

    DOAppHideTrace(@"specifiers: build start");

    NSMutableArray<PSSpecifier *> *specifiers = [NSMutableArray new];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];

    NSArray<NSDictionary *> *apps = [envManager appHideInstalledApps];
    DOAppHideTrace([NSString stringWithFormat:@"specifiers: %lu installed apps", (unsigned long)apps.count]);

    NSUInteger hiddenCount = 0;
    for (NSDictionary *app in apps) {
        if ([envManager isEnvironmentHiddenForBundleID:app[@"bundleID"]]) hiddenCount++;
    }

    PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
    // The verdict goes in the row TITLE, not only in the footer: a settings footer is
    // grey small print that gets truncated, and the user reported exactly that - the
    // self check was there and could not be seen.
    headerGroup.name = [NSString stringWithFormat:@"App Hiding %@ — basebin %@",
                        APP_HIDE_PANEL_VERSION, [envManager appHideBasebinVerdict]];
    [headerGroup setProperty:[NSString stringWithFormat:
                                 @"共 %lu 个 App，已隐藏 %lu 个。隐藏的 App 启动时不会带上越狱环境，改完下次启动生效（不用注销）。\n%@",
                                 (unsigned long)apps.count, (unsigned long)hiddenCount,
                                 [envManager appHideDiagnostics]]
                     forKey:@"footerText"];
    [specifiers addObject:headerGroup];

    // Environment self check as its own row: tap to see which basebin is really
    // installed. Shown before anything else because if the installed basebin is the
    // stock one, every switch below writes a rules file that nothing reads.
    PSSpecifier *checkSpecifier = [PSSpecifier preferenceSpecifierNamed:@"环境自检（点开看 basebin 详情）"
                                                                 target:self
                                                                    set:nil
                                                                    get:nil
                                                                 detail:nil
                                                                   cell:PSButtonCell
                                                                   edit:nil];
    [checkSpecifier setProperty:@YES forKey:@"enabled"];
    [checkSpecifier setProperty:NSStringFromSelector(@selector(appHideEnvironmentCheck)) forKey:@"action"];
    [specifiers addObject:checkSpecifier];

    // Log / crash-report export on demand. The copy walks every app container as root
    // and is the slowest thing in this screen, so it is a row the user taps instead of
    // work done on every panel open.
    PSSpecifier *exportSpecifier = [PSSpecifier preferenceSpecifierNamed:@"导出检测日志 / 崩溃报告"
                                                                  target:self
                                                                     set:nil
                                                                     get:nil
                                                                  detail:nil
                                                                    cell:PSButtonCell
                                                                    edit:nil];
    [exportSpecifier setProperty:@YES forKey:@"enabled"];
    [exportSpecifier setProperty:NSStringFromSelector(@selector(appHideExportLogs)) forKey:@"action"];
    [specifiers addObject:exportSpecifier];

    for (NSDictionary *app in apps) {
        NSString *bundleID = app[@"bundleID"];

        PSSpecifier *appGroup = [PSSpecifier emptyGroupSpecifier];
        appGroup.name = app[@"name"];
        [appGroup setProperty:bundleID forKey:@"footerText"];
        // Tag every row of an app block with its bundle id: the search filter groups
        // rows by this instead of by position, so extra rows (the export button above)
        // cannot shift the blocks apart.
        [appGroup setProperty:bundleID forKey:@"appHideBundleID"];
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
        [hideSpecifier setProperty:bundleID forKey:@"appHideBundleID"];
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
        [noInjectSpecifier setProperty:bundleID forKey:@"appHideBundleID"];
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

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    NSMutableArray<PSSpecifier *> *filtered = [NSMutableArray new];

    // Rows are grouped by the bundle id they carry, not by their position: the header
    // and the export row are added without one, so no extra row can shift the blocks.
    NSUInteger i = 0;
    while (i < all.count) {
        PSSpecifier *specifier = all[i];
        NSString *bundleID = [specifier propertyForKey:@"appHideBundleID"];
        if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) {
            [filtered addObject:specifier];
            i++;
            continue;
        }

        NSUInteger start = i;
        while (i < all.count && [[all[i] propertyForKey:@"appHideBundleID"] isEqual:bundleID]) i++;
        NSUInteger end = i;

        BOOL matches = DOAppHideFuzzyMatch(specifier.name, query) || DOAppHideFuzzyMatch(bundleID, query);
        // Already enabled apps stay visible whatever the query is: hiding one must
        // never make it impossible to unhide it again.
        BOOL enabled = [envManager isEnvironmentHiddenForBundleID:bundleID] ||
                       [envManager isEnvironmentNoInjectForBundleID:bundleID];
        if (!matches && !enabled) continue;

        for (NSUInteger j = start; j < end; j++) [filtered addObject:all[j]];
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

#pragma mark - log export

- (void)appHideEnvironmentCheck
{
    DOAppHideTrace(@"self-check row tapped");

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    NSString *detail = [envManager appHideEnvironmentSelfCheck];
    NSString *verdict = [envManager appHideBasebinVerdict];

    NSString *message = [NSString stringWithFormat:
                         @"面板版本：%@\nbasebin 判定：%@\n\n%@\n\n"
                         @"说明：魔改版 ✅ = 装上的 basebin 是这一版（开关才会真的生效）；"
                         @"原版 ❌ = App 换了但 basebin 没换，回 Dopamine 首页点一次 Update Environment 再 respring。",
                         APP_HIDE_PANEL_VERSION, verdict, detail];
    DOAppHideTrace([@"self-check: " stringByAppendingString:verdict]);

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"环境自检"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)appHideExportLogs
{
    DOAppHideTrace(@"export row tapped");
    NSString *summary = [[DOEnvironmentManager sharedManager] appHideCollectLogs];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"导出结果"
                                                                   message:summary
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
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
    DOAppHideTrace([NSString stringWithFormat:@"toggle HideEnv %@ -> %@", bundleID, value]);

    NSError *error = nil;
    if (![[DOEnvironmentManager sharedManager] setEnvironmentHidden:value.boolValue
                                                       forBundleID:bundleID
                                                             error:&error]) {
        // Never fail silently: the switch would just snap back with no reason.
        DOAppHideTrace([NSString stringWithFormat:@"toggle HideEnv FAILED: %@", error.localizedDescription]);
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
    DOAppHideTrace([NSString stringWithFormat:@"toggle NoInject %@ -> %@", bundleID, value]);

    NSError *error = nil;
    if (![[DOEnvironmentManager sharedManager] setEnvironmentNoInject:value.boolValue
                                                         forBundleID:bundleID
                                                               error:&error]) {
        DOAppHideTrace([NSString stringWithFormat:@"toggle NoInject FAILED: %@", error.localizedDescription]);
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
