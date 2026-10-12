//
//  DOAppHideController.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHideController.h"
#import "DOAppHide.h"
// Upstream Dopamine renders every button in this app with DOButtonCell; a bare
// PSButtonCell does not dispatch the specifier action on this OS version.
#import "DOButtonCell.h"
#import "DOEnvironmentManager.h"
#import <UIKit/UIKit.h>

// Version of the panel code itself, shown in the first row. The engine inside the
// basebin has its own version (it logs "engine vN"), and keeping them visible together
// is how "the app updated but the basebin did not" stops being invisible.
#define APP_HIDE_PANEL_VERSION @"v15"

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
- (NSArray<PSSpecifier *> *)appHideCurrentList;
- (NSArray<PSSpecifier *> *)appHideFilter:(NSArray<PSSpecifier *> *)all query:(NSString *)query;
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
    // Rebuild in place and hand the base class a consistent pair. Leaving `_specifiers`
    // nil here (v5-v8) crashed the panel; leaving it untouched and unfiltered (v9) left it
    // empty. Assign, then let reloadSpecifiers redo the index maps.
    self.appHideAllSpecifiers = nil;
    _specifiers = [self appHideCurrentList];
    [self reloadSpecifiers];
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
    // Assign the new list first, then ask for a reload: the base class rebuilds its index
    // maps from whatever `_specifiers` holds, so it must never see nil.
    _specifiers = [self appHideCurrentList];
    [self reloadSpecifiers];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar
{
    [searchBar resignFirstResponder];
}

#pragma mark - specifiers

// PSListController keeps its own `_specifiers` array and a set of non-public index maps
// built from it. Two rules follow, and both of them were learned the hard way:
//   * build into `_specifiers` (the stock pattern) - leaving it nil while the table
//     reloads is what crashed the panel in v5-v8;
//   * never leave it nil at any point: whenever it is rebuilt, the rebuild is followed
//     immediately by -reloadSpecifiers so the index maps are redone alongside it.
// v9 read the first rule as "never touch the ivar at all", which is why the panel came
// back alive and empty: the base class had nothing to render.
- (NSArray *)specifiers
{
    if (!_specifiers) {
        _specifiers = [self appHideCurrentList];
    }
    return _specifiers;
}

// Always returns at least the header plus the two action rows, so a failure further down
// produces a readable panel instead of a blank screen.
- (NSArray<PSSpecifier *> *)appHideCurrentList
{
    NSArray<PSSpecifier *> *all = [self appHideBuildAllSpecifiers];
    if (self.appHideQuery.length == 0) return all;
    return [self appHideFilter:all query:self.appHideQuery];
}

- (NSArray<PSSpecifier *> *)appHideBuildAllSpecifiers
{
    if (self.appHideAllSpecifiers) return self.appHideAllSpecifiers;

    DOAppHideTrace(@"specifiers: build start");

    NSMutableArray<PSSpecifier *> *specifiers = [NSMutableArray new];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];

    // Rows that depend on nothing else go in first: even if the app list below fails, the
    // panel still shows a title, the self check and the export row.
    NSString *verdict = @"未知";
    NSString *checkText = @"（自检未执行）";
    @try {
        verdict = [envManager appHideBasebinVerdict];
        // Full detail is rendered into a group footer below, so the answer does not sit
        // behind a button that can fail.
        checkText = [envManager appHideEnvironmentSelfCheck];
    } @catch (NSException *e) {
        checkText = [NSString stringWithFormat:@"自检失败：%@", e.reason ?: @"未知异常"];
        DOAppHideTrace([@"self check failed: " stringByAppendingString:e.reason ?: @"?"]);
    }

    PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
    // The verdict goes in the row TITLE, not only in the footer: a settings footer is
    // grey small print that gets truncated, and the user reported exactly that - the
    // self check was there and could not be seen.
    headerGroup.name = [NSString stringWithFormat:@"App Hiding %@ — basebin %@",
                        APP_HIDE_PANEL_VERSION, verdict];
    [specifiers addObject:headerGroup];

    // Environment self check as its own row: tap to see which basebin is really
    // installed. Shown before anything else because if the installed basebin is the
    // stock one, every switch below writes a rules file that nothing reads.
    //
    // The cellClass property is not optional: upstream wires every button in this app as
    // a DOButtonCell, and a bare PSButtonCell does not dispatch the `action` property on
    // this OS version - tapping it does nothing at all, which is exactly what happened.
    PSSpecifier *checkSpecifier = [PSSpecifier preferenceSpecifierNamed:@"环境自检（点开看 basebin 详情）"
                                                                 target:self
                                                                    set:nil
                                                                    get:nil
                                                                 detail:nil
                                                                   cell:PSButtonCell
                                                                   edit:nil];
    [checkSpecifier setProperty:@YES forKey:@"enabled"];
    [checkSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
    [checkSpecifier setProperty:@"appHideEnvironmentCheck" forKey:@"action"];
    checkSpecifier.buttonAction = NSSelectorFromString(@"appHideEnvironmentCheck");
    [specifiers addObject:checkSpecifier];

    // The stock "Update Environment" button only appears when Dopamine sees the installed
    // basebin version differ from its own, and this mod keeps upstream's version number, so
    // on a device that already has that version the button never shows - and the new basebin
    // never gets installed. This row calls the same upstream method the stock button calls.
    PSSpecifier *updateSpecifier = [PSSpecifier preferenceSpecifierNamed:@"重装隐藏引擎（Update Environment）"
                                                                  target:self
                                                                     set:nil
                                                                     get:nil
                                                                  detail:nil
                                                                    cell:PSButtonCell
                                                                    edit:nil];
    [updateSpecifier setProperty:@YES forKey:@"enabled"];
    [updateSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
    [updateSpecifier setProperty:@"appHideStageUpdate" forKey:@"action"];
    updateSpecifier.buttonAction = NSSelectorFromString(@"appHideStageUpdate");
    [specifiers addObject:updateSpecifier];

    PSSpecifier *versionGroup = [PSSpecifier emptyGroupSpecifier];
    versionGroup.name = @"引擎版本对照";
    [versionGroup setProperty:[NSString stringWithFormat:
                                   @"本 App：%@\n已装 basebin：%@%@\n两者显示同一个版本号是正常的 —— "
                                   @"这也是首页不出现 Update Environment 的原因，所以重装入口放在上面。",
                               [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?",
                               [envManager jailbrokenVersion] ?: @"（未越狱 / 读不到）",
                               [envManager isJailbroken] ? @"" : @"（当前未越狱，重装会失败）"]
                       forKey:@"footerText"];
    [specifiers addObject:versionGroup];

    // The same text as a group footer, so the answer is on screen without any tap: two
    // broken buttons in a row is what this costs when a diagnostic hides behind one.
    PSSpecifier *checkGroup = [PSSpecifier emptyGroupSpecifier];
    checkGroup.name = @"环境自检详情";
    [checkGroup setProperty:checkText forKey:@"footerText"];
    [specifiers addObject:checkGroup];

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
    [exportSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
    [exportSpecifier setProperty:@"appHideExportLogs" forKey:@"action"];
    exportSpecifier.buttonAction = NSSelectorFromString(@"appHideExportLogs");
    [specifiers addObject:exportSpecifier];

    // Where the logs live, so the file route works even if every button misbehaves.
    PSSpecifier *logPathGroup = [PSSpecifier emptyGroupSpecifier];
    logPathGroup.name = @"日志位置";
    [logPathGroup setProperty:[NSString stringWithFormat:
                                   @"%@\n在「文件」App → 我的 iPhone → Dopamine → AppHideLogs 里可以直接看到",
                               [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/AppHideLogs"]]
                       forKey:@"footerText"];
    [specifiers addObject:logPathGroup];

    // The app list is the one part that depends on the jailbreak being up (it escalates to
    // root and reads the container layout). It is isolated: on failure the panel keeps the
    // three rows above and gains a row that says what went wrong, instead of going blank.
    NSUInteger appCount = 0;
    NSUInteger hiddenCount = 0;
    NSString *listNote = nil;

    @try {
        NSArray<NSDictionary *> *apps = [envManager appHideInstalledApps];
        appCount = apps.count;
        DOAppHideTrace([NSString stringWithFormat:@"specifiers: %lu installed apps", (unsigned long)appCount]);

        for (NSDictionary *app in apps) {
            NSString *bundleID = app[@"bundleID"];

            BOOL alreadyHidden = [envManager isEnvironmentHiddenForBundleID:bundleID];
            if (alreadyHidden) hiddenCount++;

            PSSpecifier *appGroup = [PSSpecifier emptyGroupSpecifier];
            appGroup.name = app[@"name"];
            [appGroup setProperty:bundleID forKey:@"footerText"];
            // Tag every row of an app block with its bundle id: the search filter groups
            // rows by this instead of by position, so extra rows (the buttons above)
            // cannot shift the blocks apart.
            [appGroup setProperty:bundleID forKey:@"appHideBundleID"];
            [specifiers addObject:appGroup];

            PSSpecifier *hideSpecifier = [PSSpecifier preferenceSpecifierNamed:(alreadyHidden ? @"Hide Jailbreak Environment ✅" : @"Hide Jailbreak Environment")
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
    } @catch (NSException *e) {
        listNote = [NSString stringWithFormat:@"读取 App 列表失败：%@", e.reason ?: @"未知异常"];
        DOAppHideTrace([@"app list failed: " stringByAppendingString:e.reason ?: @"?"]);

        PSSpecifier *failGroup = [PSSpecifier emptyGroupSpecifier];
        failGroup.name = @"App 列表读取失败";
        [failGroup setProperty:listNote forKey:@"footerText"];
        [specifiers addObject:failGroup];
    }

    if (appCount == 0 && !listNote) {
        listNote = @"没有读到已安装的 App（先越狱，并在 Dopamine 首页点一次 Update Environment）";

        // A row, not just footer text: an empty panel with an explanation buried in grey
        // print reads as a broken panel, which is exactly the report that produced v10.
        PSSpecifier *emptyGroup = [PSSpecifier emptyGroupSpecifier];
        emptyGroup.name = @"没有读到 App 列表";
        [emptyGroup setProperty:listNote forKey:@"footerText"];
        [specifiers addObject:emptyGroup];
    }

    NSString *summary = nil;
    @try {
        summary = [envManager appHideDiagnostics];
    } @catch (NSException *e) {
        summary = [NSString stringWithFormat:@"诊断信息读取失败：%@", e.reason ?: @"未知异常"];
    }

    [headerGroup setProperty:[NSString stringWithFormat:
                              @"共 %lu 个 App，已隐藏 %lu 个%@。隐藏的 App 启动时不会带上越狱环境，改完下次启动生效（不用注销）。\n%@",
                              (unsigned long)appCount, (unsigned long)hiddenCount,
                              listNote ? [NSString stringWithFormat:@"（%@）", listNote] : @"",
                              summary ?: @""]
                     forKey:@"footerText"];

    self.appHideAllSpecifiers = specifiers;
    return specifiers;
}

- (NSArray<PSSpecifier *> *)appHideFilter:(NSArray<PSSpecifier *> *)all query:(NSString *)query
{
    if (query.length == 0) return all;

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    NSMutableArray<PSSpecifier *> *filtered = [NSMutableArray new];

    // Rows are grouped by the bundle id they carry, not by their position: the header,
    // the two buttons and the empty-state row are added without one, so no extra row can
    // shift the blocks apart.
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

    // Header plus the two action rows only means "nothing matched": say so, or an empty
    // screen after typing reads as a broken panel.
    if (filtered.count <= 3) {
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
                         @"原版 ❌ = App 换了但 basebin 没换，点上面那行「重装隐藏引擎」再 respring。",
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

#pragma mark - basebin reinstall

// The stock button lives behind a version check that this mod cannot satisfy (upstream's
// version number is kept deliberately), so the same upstream call is exposed here.
- (void)appHideStageUpdate
{
    DOAppHideTrace(@"stage update tapped");

    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (![envManager isJailbroken]) {
        [self appHideAlertWithTitle:@"需要先越狱"
                           message:@"当前没有检测到越狱环境，写入 basebin 会失败。先在首页完成越狱，再回到这里点一次。"];
        return;
    }

    NSError *error = nil;
    @try {
        error = [envManager updateEnvironment];
    } @catch (NSException *e) {
        DOAppHideTrace([@"stage update threw: " stringByAppendingString:e.reason ?: @"?"]);
        [self appHideAlertWithTitle:@"重装失败"
                           message:[NSString stringWithFormat:@"写入时抛异常：%@", e.reason ?: @"未知"]];
        return;
    }

    DOAppHideTrace([NSString stringWithFormat:@"stage update: %@",
                    error ? error.description : @"staged, userspace reboot requested"]);
    if (error) {
        [self appHideAlertWithTitle:@"重装失败"
                           message:[NSString stringWithFormat:
                                    @"%@（错误码 %ld）\n先确认首页显示已越狱，然后重试。",
                                    error.localizedDescription ?: @"未知错误", (long)error.code]];
    }
    // Success path needs no alert: updateEnvironment asks for a userspace reboot itself.
}

- (void)appHideAlertWithTitle:(NSString *)title message:(NSString *)message
{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    });
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
