//
//  DOAppHideController.h
//  Dopamine (App Hiding mod)
//

#import "DOPSListController.h"

NS_ASSUME_NONNULL_BEGIN

// Settings list where every installed app gets a "Hide Jailbreak Environment"
// and a "No Injection" switch. Both write through DOEnvironmentManager (AppHide).
@interface DOAppHideController : DOPSListController

// Tapped row: copies the per-app engine logs and the recent crash reports into
// Documents/AppHideLogs, then reports what it found.
- (void)appHideExportLogs;

@end

NS_ASSUME_NONNULL_END
