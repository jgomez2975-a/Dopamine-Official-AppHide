//
//  DOAppHideController.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHideController.h"
#import "DOAppHide.h"
#import "DOEnvironmentManager.h"

@implementation DOAppHideController

- (NSArray *)specifiers
{
    if (!_specifiers) {
        NSMutableArray *specifiers = [NSMutableArray new];
        DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];

        PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
        headerGroup.name = @"App Hiding";
        [headerGroup setProperty:@"Hidden apps are started without the jailbreak environment. "
                                 @"Changes apply the next time the app is launched (no respring needed). "
                                 @"Toggling a switch writes the rules file as root."
                         forKey:@"footerText"];
        [specifiers addObject:headerGroup];

        for (NSDictionary *app in [envManager appHideInstalledApps]) {
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

        _specifiers = specifiers;
    }
    return _specifiers;
}

- (NSNumber *)readHidden:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    return @([[DOEnvironmentManager sharedManager] isEnvironmentHiddenForBundleID:bundleID]);
}

- (void)setHidden:(NSNumber *)value specifier:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    [[DOEnvironmentManager sharedManager] setEnvironmentHidden:value.boolValue forBundleID:bundleID];

    // NoInject implies Hidden on the basebin side, keep the UI in sync
    if (!value.boolValue) {
        [self reloadSpecifiers];
    }
}

- (NSNumber *)readNoInject:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    return @([[DOEnvironmentManager sharedManager] isEnvironmentNoInjectForBundleID:bundleID]);
}

- (void)setNoInject:(NSNumber *)value specifier:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"bundleID"];
    [[DOEnvironmentManager sharedManager] setEnvironmentNoInject:value.boolValue forBundleID:bundleID];
    [self reloadSpecifiers];
}

@end
