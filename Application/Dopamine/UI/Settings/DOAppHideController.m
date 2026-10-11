//
//  DOAppHideController.m
//  Dopamine (App Hiding mod)
//

#import "DOAppHideController.h"
#import "DOAppHide.h"
#import "DOEnvironmentManager.h"
#import <UIKit/UIKit.h>

@implementation DOAppHideController

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    // Re-read the rules file every time the panel is entered: the file is the
    // single source of truth, and it lives outside the container.
    [[DOEnvironmentManager sharedManager] appHideInvalidateRulesCache];
}

- (NSArray *)specifiers
{
    if (!_specifiers) {
        NSMutableArray *specifiers = [NSMutableArray new];
        DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];

        PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
        headerGroup.name = @"App Hiding";
        [headerGroup setProperty:[NSString stringWithFormat:
                                     @"Hidden apps are started without the jailbreak environment. "
                                     @"Changes apply the next time the app is launched (no respring needed).\n"
                                     @"Rules: %@",
                                     [envManager appHideDiagnostics]]
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
