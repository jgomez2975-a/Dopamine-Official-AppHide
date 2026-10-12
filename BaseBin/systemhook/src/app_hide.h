//
//  app_hide.h
//  Dopamine (App Hiding mod)
//
//  Per-process jailbreak invisibility for apps the user marked as hidden.
//
#ifndef SYSTEMHOOK_APP_HIDE_H
#define SYSTEMHOOK_APP_HIDE_H

#include <stdbool.h>

// Makes the current process look like it was never jailbroken: hides the
// jailbreak root and the classic jailbreak paths from the filesystem APIs, and
// rewrites the paths of the jailbreak dylibs this process still has loaded.
//
// Only does anything when launchdhook's spawn hook marked the process with
// DOPAMINE_APP_HIDE=1 (that is what the "Hide Jailbreak Environment" switch in
// the app writes). No-op in every other process.
//
// Must be called at the very END of systemhook's initializer: it hides the
// jailbreak root from the process, including from systemhook's own later file
// accesses, so check-in, tweak loading and cs revalidation have to be done.
void app_hide_install(void);

// The per-app flag the panel writes into the app's own container. Consulted by
// app_hide_install() and by should_enable_tweaks(), because a hidden app must not get
// tweaks loaded into it either.
bool app_hide_container_marker_present(void);

#endif
