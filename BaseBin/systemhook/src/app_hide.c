//
//  app_hide.c
//  Dopamine (App Hiding mod)
//
//  Makes the process the user marked as hidden look non jailbroken:
//
//   1. filesystem: stat / lstat / access / open / fopen / opendir / readlink stop
//      seeing the jailbreak root and the classic jailbreak artifact paths.
//   2. dyld: the paths of the jailbreak dylibs loaded into this process are
//      rewritten in place (public image list + LC_ID_DYLIB), so scanning the
//      image list for "systemhook" / "/var/jb" finds nothing.
//   3. environment: the variables the jailbreak needed to get us here
//      (DOPAMINE_APP_HIDE, DYLD_INSERT_LIBRARIES, safe mode markers) are removed
//      from environ, so reading the environment finds nothing either.
//
//  The hooks never call the function they replaced (litehook overwrites its
//  prologue), so every pass-through goes through the *at() sibling, which is not
//  hooked: stat -> fstatat, access -> faccessat, open -> openat, ...
//
#include "app_hide.h"
#include "litehook.h"

#include <dirent.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/task_info.h>
#include <mach/vm_region.h>
#include <libkern/OSCacheControl.h>
// NOTE: <mach/mach_vm.h> is unusable on iOS ("mach_vm.h unsupported."), so the
// protection dance below uses the vm_* API - vm_address_t is 64 bit on arm64. 
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>

// systemhook's check-in result: the real (resolved) jailbreak root. On rootless
// Dopamine that is /private/preboot/<uuid>/... - only that subtree is hidden,
// the rest of /private/preboot belongs to iOS and dyld needs it.
extern char *JB_RootPath;

#define APP_HIDE_JBROOT_MAX   1024
#define APP_HIDE_MAX_PREFIXES 96

static bool   gAppHideActive = false;
static size_t gHookedCount   = 0;
static char   gAppHideJBRoot[APP_HIDE_JBROOT_MAX];
static size_t gAppHideJBRootLen = 0;

typedef struct {
	const char *path;
	size_t len;
} app_hide_prefix_t;

static app_hide_prefix_t gAppHidePrefixes[APP_HIDE_MAX_PREFIXES];
static size_t gAppHidePrefixCount = 0;

// Jailbreak artifacts every detector checks. Nothing here is used by a normal
// (non jailbroken) app, so denying it cannot break the app.
static const char *kAppHideExactPaths[] = {
	"/var/jb",
	"/bin/bash",
	"/usr/bin/ssh",
	"/usr/sbin/sshd",
	"/usr/bin/cycript",
	"/usr/libexec/sftp-server",
	"/usr/lib/systemhook.dylib",
	"/usr/lib/libjailbreak.dylib",
	"/usr/lib/libhooker.dylib",
	"/usr/lib/libsubstrate.dylib",
	"/usr/lib/libsubstitute.dylib",
	"/usr/lib/libellekit.dylib",
	"/usr/lib/TweakLoader.dylib",
	"/Applications/Cydia.app",
	"/Applications/Sileo.app",
	"/Applications/Zebra.app",
	"/Applications/Filza.app",
	"/Library/MobileSubstrate",
	"/usr/lib/TweakInject",
	"/etc/apt",
	"/etc/ssh",
	"/var/cache/apt",
	"/var/lib/apt",
	"/var/lib/cydia",
	"/var/lib/dpkg",
	"/var/log/syslog",
	"/var/tmp/cydia.log",
	"/private/etc/apt",
	"/private/etc/ssh",
	"/private/var/cache/apt",
	"/private/var/lib/apt",
	"/private/var/lib/cydia",
	// our own rules file is a jailbreak artifact as well
	"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist",
	// jailbreak app preferences, a very common (and very lazy) detection check
	"/var/mobile/Library/Preferences/com.opa334.Dopamine.plist",
	"/var/mobile/Library/Preferences/com.opa334.Dopamine.roothide.plist",
	"/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist",
	"/var/mobile/Library/Preferences/ws.hbang.Terminal.plist",
	"/var/mobile/Library/Preferences/xyz.willy.Zebra.plist",
	"/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist",
	NULL
};

static const char *kAppHidePrefixPaths[] = {
	"/var/jb/",
	"/Applications/Cydia.app/",
	"/Applications/Sileo.app/",
	"/Applications/Zebra.app/",
	"/Applications/Filza.app/",
	"/Library/MobileSubstrate/",
	"/Library/PreferenceBundles/",
	"/Library/PreferenceLoader/",
	"/Library/Themes/",
	"/usr/lib/TweakInject/",
	"/usr/lib/substrate/",
	"/etc/apt/",
	"/etc/ssh/",
	"/var/cache/apt/",
	"/var/lib/apt/",
	"/var/lib/cydia/",
	"/var/lib/dpkg/",
	"/private/etc/apt/",
	"/private/var/cache/apt/",
	"/private/var/lib/apt/",
	"/private/var/lib/cydia/",
	NULL
};

// Substrings that identify a *loaded image* as part of the jailbreak. Used both
// for the public image list and for LC_ID_DYLIB, so a detector iterating
// _dyld_image_count() / _dyld_get_image_name() finds none of them.
static const char *kAppHideImageMarkers[] = {
	"systemhook",
	"libjailbreak",
	"libhooker",
	"ellekit",
	"Substrate",
	"substitute",
	"TweakInject",
	"TweakLoader",
	"forkfix",
	"rootlesshooks",
	"watchdoghook",
	"roothide",
	"Dopamine",
	"dopamine",
	"/var/jb/",
	NULL
};

// Neutral replacement names, first one that fits the original allocation wins.
static const char *kAppHideFakeNames[] = {
	"/usr/lib/libsystem_hooks.dylib",
	"/usr/lib/libsystem.dylib",
	"/usr/lib/libx.dylib",
	"/usr/lib/x.dylib",
	NULL
};

// Bundle identifiers of the apps that are themselves proof of a jailbreak. A
// bank app does not need the filesystem for this: it asks LaunchServices for the
// installed application list and looks for these.
static const char *kAppHideJBBundleIDs[] = {
	"com.opa334.Dopamine",
	"com.opa334.TrollStore",
	"com.opa334.TrollStoreLite",
	"org.coolstar.SileoStore",
	"org.coolstar.Sileo",
	"xyz.willy.Zebra",
	"com.tigisoftware.Filza",
	"ws.hbang.Terminal",
	"com.opa334.Dopamine.roothide",
	"org.coolstar.libhooker",
	NULL
};

// Process names that only exist on a jailbroken device (the Dopamine/Sileo apps
// are in this list too - a KERN_PROC scan for "Dopamine" is a common check).
static const char *kAppHideJBProcessNames[] = {
	"sshd",
	"ssh",
	"frida-server",
	"frida",
	"jbctl",
	"cycript",
	"sftp-server",
	"dropbear",
	"newtermd",
	"tweakd",
	"opainject",
	"bagbak",
	"Dopamine",
	"Sileo",
	"Zebra",
	"Filza",
	"TrollStore",
	NULL
};

// Environment entries that must not be visible through sysctl(KERN_PROCARGS2):
// unsetenv() only edits environ, while the kernel still hands out the copy that
// was placed on the stack at exec time.
static const char *kAppHideEnvPrefixes[] = {
	"DYLD_INSERT_LIBRARIES=",
	"DOPAMINE_APP_HIDE=",
	"_JBEnvMode=",
	"JB_ROOT_PATH=",
	"_SafeMode=",
	"_MSSafeMode=",
	"DYLD_IN_CACHE=",
	NULL
};

#define APP_HIDE_LOG_NAME       "/Library/Caches/.DopamineAppHide.log"
#define APP_HIDE_LOG_MAX_BYTES  (256 * 1024)

// The variable the basebin sets to tell systemhook "this app is hidden". Deliberately
// not named after the tweak: a hardening SDK that greps its own environment for
// "DOPAMINE" should not get a free hit. The old name is still accepted.
// iOS ships no <sys/ptrace.h>, and the ptrace numbers are fixed by the kernel ABI. The
// ptrace hook self-tests its own syscall number before installing (a bogus request answers
// EINVAL when the number is right and ENOSYS when it is not), so a wrong guess cannot break
// the process - it just leaves the hook uninstalled.
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef SYS_ptrace
#define SYS_ptrace 26
#endif

#define APP_HIDE_ENV_MARKER     "_JBEnvMode"

// Defined further down with the dyld machinery; declared here because the bundle
// id matcher reuses it.
static bool app_hide_suspicious_image_path(const char *path);

// Defined with the LaunchServices machinery further down. The hooked functions call
// it to run one-shot deferred setup from ordinary app code, which is the only place
// it is safe to swizzle a class.
static void app_hide_tick(void);
static void app_hide_register_image_callback(void);

// Every denial is reported twice: to the unified log (visible with Console /
// idevicesyslog) and into the hidden app's own container, which is the only
// place a sandboxed process may write. The Dopamine side copies those files into
// its Documents folder, so the user can read what the app actually probed
// without any extra tooling.
// syslog(3) can lazily open a connection to the logging daemon; doing that from a
// dyld constructor (which is where app_hide_install() runs) risks a deadlock on the
// loader lock, so the unified-log half stays off until app_hide_tick() has run from
// ordinary app code. The file half below never leaves the process.
static bool gAppHideSyslogReady = false;

// v16: set when the round 2 set is installed, consumed by the first tick. The image path
// rewrite and the add-image registration both touch structures dyld is still building while
// our constructor runs, and doing it there killed the app inside dyld's initializer loop
// (see the crash note in app_hide_install).
static bool gAppHideDeferredDyld = false;

static void app_hide_note(const char *func, const char *path)
{
	if (!func) return;

	if (gAppHideSyslogReady) syslog(LOG_ERR, "[AppHide] %s %s", func, path ? path : "-");

	const char *home = getenv("HOME");
	if (!home || home[0] != '/') return;

	char logPath[PATH_MAX];
	if (snprintf(logPath, sizeof(logPath), "%s" APP_HIDE_LOG_NAME, home) >= (int)sizeof(logPath)) return;

	// Deliberately the unhooked siblings: stat/open here would re-enter our own
	// hooks (harmless, but this keeps the logging path free of recursion).
	struct stat st;
	if (fstatat(AT_FDCWD, logPath, &st, 0) == 0 && st.st_size > APP_HIDE_LOG_MAX_BYTES) return;

	int fd = openat(AT_FDCWD, logPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0) return;

	char line[PATH_MAX + 64];
	int len = snprintf(line, sizeof(line), "%s %s\n", func, path ? path : "-");
	if (len > 0) (void)write(fd, line, (size_t)len);
	close(fd);
}

__attribute__((noinline))
static bool app_hide_jb_bundle_id(const char *identifier)
{
	if (!identifier) return false;
	for (size_t i = 0; kAppHideJBBundleIDs[i]; i++) {
		if (strcasestr(identifier, kAppHideJBBundleIDs[i])) return true;
	}
	return app_hide_suspicious_image_path(identifier);
}

// Never inline this into the hooks: clang -Os has a register allocation bug when
// the string matching body is inlined into a variadic hook (it ends up passing
// the hook's mode/flags argument to strncmp).
__attribute__((noinline))
static bool app_hide_hidden_path(const char *path)
{
	if (!gAppHideActive || !path) return false;

	// detectors only ever probe absolute paths
	if (path[0] != '/') return false;

	if (gAppHideJBRootLen &&
		strncmp(path, gAppHideJBRoot, gAppHideJBRootLen) == 0 &&
		(path[gAppHideJBRootLen] == '\0' || path[gAppHideJBRootLen] == '/')) {
		return true;
	}

	for (size_t i = 0; kAppHideExactPaths[i]; i++) {
		if (strcmp(path, kAppHideExactPaths[i]) == 0) return true;
	}

	for (size_t i = 0; i < gAppHidePrefixCount; i++) {
		const app_hide_prefix_t *prefix = &gAppHidePrefixes[i];
		if (strncmp(path, prefix->path, prefix->len) == 0) return true;
	}

	return false;
}

__attribute__((noinline))
static bool app_hide_suspicious_image_path(const char *path)
{
	if (!path) return false;

	if (gAppHideJBRootLen && strncmp(path, gAppHideJBRoot, gAppHideJBRootLen) == 0) {
		return true;
	}

	for (size_t i = 0; kAppHideImageMarkers[i]; i++) {
		if (strstr(path, kAppHideImageMarkers[i])) return true;
	}

	return false;
}

// Writes `len` bytes over an existing string, copying file backed pages first and
// restoring the original protection afterwards.
static bool app_hide_write_string(void *dst, const char *text, size_t len)
{
	vm_size_t pageSize = (vm_size_t)getpagesize();
	vm_address_t addr = (vm_address_t)dst;
	vm_address_t page = addr & ~((vm_address_t)pageSize - 1);
	vm_size_t span = (vm_size_t)(((addr + len) - page + pageSize - 1) & ~(pageSize - 1));

	vm_region_basic_info_data_64_t info;
	vm_size_t regionSize = 0;
	mach_port_t objectName = MACH_PORT_NULL;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	vm_address_t regionAddr = page;

	if (vm_region_64(mach_task_self(), &regionAddr, &regionSize, VM_REGION_BASIC_INFO_64,
			(vm_region_info_t)&info, &infoCount, &objectName) != KERN_SUCCESS) {
		return false;
	}

	vm_prot_t writable = info.protection | VM_PROT_WRITE;
	if (vm_protect(mach_task_self(), page, span, false, writable | VM_PROT_COPY) != KERN_SUCCESS) {
		// regions that are already private and writable can reject VM_PROT_COPY
		if (vm_protect(mach_task_self(), page, span, false, writable) != KERN_SUCCESS) {
			return false;
		}
	}

	memcpy(dst, text, len);

	vm_protect(mach_task_self(), page, span, false, info.protection);
	return true;
}

// The replacement has to be strictly shorter than the original string: the
// original buffer is reused, and the terminator must stay inside it.
static const char *app_hide_fake_name(size_t originalLen)
{
	for (size_t i = 0; kAppHideFakeNames[i]; i++) {
		if (strlen(kAppHideFakeNames[i]) < originalLen) return kAppHideFakeNames[i];
	}
	return NULL;
}

static bool app_hide_rewrite_string(char *string, size_t originalLen)
{
	const char *fake = app_hide_fake_name(originalLen);
	if (!fake) return false;
	return app_hide_write_string(string, fake, strlen(fake) + 1);
}

static void app_hide_rewrite_id_dylib(const struct mach_header_64 *header)
{
	if (!header || header->magic != MH_MAGIC_64) return;

	const uint8_t *cursor = (const uint8_t *)header + sizeof(struct mach_header_64);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		const struct load_command *cmd = (const struct load_command *)cursor;
		if (cmd->cmdsize < sizeof(struct load_command)) break;

		if (cmd->cmd == LC_ID_DYLIB) {
			const struct dylib_command *dylibCmd = (const struct dylib_command *)cmd;
			size_t offset = dylibCmd->dylib.name.offset;
			if (offset < cmd->cmdsize) {
				char *name = (char *)cmd + offset;
				size_t nameLen = strnlen(name, cmd->cmdsize - offset);
				if (nameLen && app_hide_suspicious_image_path(name)) {
					app_hide_rewrite_string(name, nameLen);
				}
			}
		}

		cursor += cmd->cmdsize;
	}
}

static void app_hide_hide_image_paths(void)
{
	// 1. the public image list: _dyld_image_count() and _dyld_get_image_name()
	//    read exactly these strings.
	task_dyld_info_data_t dyldInfo = {0};
	mach_msg_type_number_t dyldInfoCount = TASK_DYLD_INFO_COUNT;
	if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &dyldInfoCount) == KERN_SUCCESS) {
		struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
		if (infos && infos->infoArray) {
			for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
				char *name = (char *)infos->infoArray[i].imageFilePath;
				if (!name) continue;
				size_t nameLen = strnlen(name, 1024);
				if (nameLen < 12) continue;
				if (!app_hide_suspicious_image_path(name)) continue;
				app_hide_rewrite_string(name, nameLen);
			}
		}
	}

	// 2. the Mach-O headers, for detectors that parse LC_ID_DYLIB of every
	//    loaded image instead of using the public image list.
	uint32_t imageCount = _dyld_image_count();
	for (uint32_t i = 0; i < imageCount; i++) {
		const char *name = _dyld_get_image_name(i);
		if (!name || !app_hide_suspicious_image_path(name)) continue;
		app_hide_rewrite_id_dylib((const struct mach_header_64 *)_dyld_get_image_header(i));
	}
}

#pragma mark - filesystem hooks

static int app_hide_stat(const char *path, struct stat *buf)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("stat", path); errno = ENOENT; return -1; }
	return fstatat(AT_FDCWD, path, buf, 0);
}

static int app_hide_lstat(const char *path, struct stat *buf)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("lstat", path); errno = ENOENT; return -1; }
	return fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

static int app_hide_access(const char *path, int mode)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("access", path); errno = ENOENT; return -1; }
	return faccessat(AT_FDCWD, path, mode, 0);
}

static int app_hide_open(const char *path, int oflag, mode_t mode)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("open", path); errno = ENOENT; return -1; }
	return openat(AT_FDCWD, path, oflag, mode);
}

static ssize_t app_hide_readlink(const char *path, char *buf, size_t bufsize)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("readlink", path); errno = ENOENT; return -1; }
	return readlinkat(AT_FDCWD, path, buf, bufsize);
}

// fopen is reachable through openat + fdopen, so the original is not needed.
static FILE *app_hide_fopen(const char *path, const char *mode)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("fopen", path); errno = ENOENT; return NULL; }

	const char *m = mode ? mode : "r";
	bool plus = strchr(m, '+') != NULL;

	int flags;
	switch (m[0]) {
		case 'w': flags = plus ? (O_RDWR | O_CREAT | O_TRUNC) : (O_WRONLY | O_CREAT | O_TRUNC); break;
		case 'a': flags = plus ? (O_RDWR | O_CREAT | O_APPEND) : (O_WRONLY | O_CREAT | O_APPEND); break;
		default:  flags = plus ? O_RDWR : O_RDONLY; break;
	}
	if (strchr(m, 'x')) flags |= O_EXCL;
	if (strchr(m, 'e')) flags |= O_CLOEXEC;

	char fdMode[4];
	fdMode[0] = (m[0] == 'w') ? 'w' : (m[0] == 'a') ? 'a' : 'r';
	fdMode[1] = plus ? '+' : '\0';
	fdMode[2] = '\0';

	int fd = openat(AT_FDCWD, path, flags, 0666);
	if (fd < 0) return NULL;

	FILE *file = fdopen(fd, fdMode);
	if (!file) close(fd);
	return file;
}

// opendir is reachable through openat + fdopendir.
static DIR *app_hide_opendir(const char *path)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("opendir", path); errno = ENOENT; return NULL; }

	int fd = openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) return NULL;

	DIR *dir = fdopendir(fd);
	if (!dir) close(fd);
	return dir;
}

#pragma mark - dyld interposition (v17)

// The device log answered the "hiding does not hide anything" question with facts:
//
//     hook stat SKIPPED (short stub - neither the 20 byte patch nor the 8 byte thunk patch fit)
//     hook lstat SKIPPED ... hook access SKIPPED ... hook opendir SKIPPED ... hook readlink SKIPPED
//     install engine: 2 hooks active, 5 skipped
//
// Those five are 12-16 byte trampolines in the dyld shared cache. litehook overwrites a fixed 20
// bytes and the thunk path needs 8; neither fits without spilling into the neighbouring export,
// so app_hide_function_is_patchable() refuses them - correct, but the consequence had never been
// read back: inside a "hidden" app only open and fopen were ever filtered, and one stat("/var/jb")
// walked straight through to a banking SDK.
//
// Interposing does not patch code at all. dyld reads this section at load time and rebinds the
// symbol for the images loaded after us - for a dylib injected by the merged dyld at launch,
// that is the whole app. It is the mechanism Darwin provides for exactly this case, and it costs
// no code bytes in the shared cache.
//
// The handlers are unchanged and already safe for it: every pass-through above goes to the *at()
// sibling (fstatat / faccessat / openat / readlinkat), never to the interposed name, so an
// interposed call cannot re-enter itself. A process that is not being hidden has
// app_hide_hidden_path() return false, so its only cost is one predicate per call.
#define APP_HIDE_INTERPOSE(replacement, replacee)                                  \
	__attribute__((used)) static struct {                                          \
		const void *replacement;                                                   \
		const void *replacee;                                                      \
	} _app_hide_interpose_##replacee                                               \
		__attribute__((section("__DATA,__interpose"))) = {                         \
			(const void *)(unsigned long)&replacement,                             \
			(const void *)(unsigned long)&replacee,                                \
		}

// The five the patch guard refuses, plus the rest of the path-taking face of the engine so that
// the plain filesystem view is complete even with the advanced hook set switched off.
//
// Only handlers that (a) pass through with a raw syscall or an *at() sibling and (b) gate on
// app_hide_hidden_path() before deviating are listed here. fork/ptrace/sysctl/getfsstat are
// deliberately absent: they deviate unconditionally (fork always returns EPERM), which is correct
// when the engine is installed only inside a hidden process and wrong the moment the hook is
// global - interposing those would break fork and process listing for every process on the
// device. They stay in the advanced set, installed per app.
APP_HIDE_INTERPOSE(app_hide_stat,      stat);
APP_HIDE_INTERPOSE(app_hide_lstat,     lstat);
APP_HIDE_INTERPOSE(app_hide_access,    access);
APP_HIDE_INTERPOSE(app_hide_readlink,  readlink);
APP_HIDE_INTERPOSE(app_hide_opendir,   opendir);
APP_HIDE_INTERPOSE(app_hide_open,      open);
APP_HIDE_INTERPOSE(app_hide_fopen,     fopen);
// The *at() family: several SDKs call fstatat/openat directly and never touch the wrappers above,
// so leaving these out would leave the same hole one level down. Guarded exactly like the
// definitions, so a toolchain without the syscall number cannot produce a dangling reference.
#ifdef SYS_fstatat
APP_HIDE_INTERPOSE(app_hide_fstatat,   fstatat);
#endif
#ifdef SYS_faccessat
APP_HIDE_INTERPOSE(app_hide_faccessat, faccessat);
#endif
#ifdef SYS_openat
APP_HIDE_INTERPOSE(app_hide_openat,    openat);
#endif
#ifdef SYS_readlinkat
APP_HIDE_INTERPOSE(app_hide_readlinkat, readlinkat);
#endif
// Filesystem and attribute queries the path hooks above cannot cover.
APP_HIDE_INTERPOSE(app_hide_statfs,    statfs);
APP_HIDE_INTERPOSE(app_hide_getattrlist, getattrlist);

#pragma mark - hooks without a usable sibling (raw syscall passthrough)

static void app_hide_scrub_procargs(char *buffer, size_t length);
static void app_hide_filter_process_list(void *buffer, size_t *lengthPtr);


// sysctlbyname is a separate exported symbol from sysctl, and it is the form most hardening
// SDKs actually use. Hooking sysctl alone leaves it untouched. There is no original to call
// through (litehook destroyed the prologue), so it is reimplemented instead: the name is
// converted to a MIB and the request is handed to the same filter sysctl uses.
static int app_hide_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

static int app_hide_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	app_hide_tick();
	if (!name) { errno = EINVAL; return -1; }

	int mib[8];
	size_t miblen = sizeof(mib) / sizeof(mib[0]);
	if (sysctlnametomib(name, mib, &miblen) != 0) {
		errno = ENOENT;
		return -1;
	}
	return app_hide_sysctl(mib, (u_int)miblen, oldp, oldlenp, newp, newlen);
}

// statfs has been hooked since round 2, but statfs64 is a symbol of its own and was left
// open. Same shape as the *at family: filter first, otherwise re-issue the raw syscall.
static int app_hide_statfs64(const char *path, void *buf)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("statfs64", path); errno = ENOENT; return -1; }
#ifdef SYS_statfs64
	return (int)syscall(SYS_statfs64, path, buf);
#else
	errno = ENOTSUP;
	return -1;
#endif
}

// fork() is the classic sandbox test: on a stock device it fails for an app, on a
// jailbroken one it succeeds. Nothing an app does legitimately needs it.
static pid_t app_hide_fork(void)
{
	app_hide_tick();
	app_hide_note("fork", NULL);
	errno = EPERM;
	return -1;
}

// sysctl cannot call its own original (litehook destroys the prologue), so the
// call is reissued as a raw syscall. Only the process-argument and process-list
// queries are touched; everything else (hw.*, kern.osversion, ...) passes through
// untouched, which is what dyld and libsystem rely on.
static int app_hide_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	app_hide_tick();
#ifdef SYS_sysctl
	int ret = (int)syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
#else
	errno = ENOTSUP;
	return -1;
#endif
	if (ret != 0 || !name || namelen < 2 || !oldp || !oldlenp || *oldlenp == 0) return ret;

	if (name[0] != CTL_KERN) return ret;

	if (name[1] == KERN_PROCARGS2 || name[1] == KERN_PROCARGS) {
		app_hide_scrub_procargs((char *)oldp, *oldlenp);
	}
	else if (name[1] == KERN_PROC) {
		app_hide_filter_process_list(oldp, oldlenp);
	}
	return ret;
}

// { int argc; char exec_path[]; NUL padding; argv...; env... } - blank the first
// byte of every entry we planted, which removes it from the list a parser sees.
static void app_hide_scrub_procargs(char *buffer, size_t length)
{
	if (length <= sizeof(int) + 1) return;

	char *cursor = buffer + sizeof(int);
	char *end = buffer + length;

	while (cursor < end && *cursor) cursor++;      // exec path
	while (cursor < end && !*cursor) cursor++;     // padding + end of argv[0]

	while (cursor < end) {
		size_t remaining = (size_t)(end - cursor);
		size_t len = strnlen(cursor, remaining);
		if (len == 0) break;

		bool scrub = false;
		for (size_t i = 0; kAppHideEnvPrefixes[i]; i++) {
			size_t prefixLen = strlen(kAppHideEnvPrefixes[i]);
			if (len >= prefixLen && strncmp(cursor, kAppHideEnvPrefixes[i], prefixLen) == 0) {
				scrub = true;
				break;
			}
		}
		if (scrub) {
			app_hide_note("sysctl-procargs", cursor);
			*cursor = '\0';
		}
		cursor += len + 1;
	}
}

// kinfo_proc array (KERN_PROC_ALL / KERN_PROC_UID / ...): drop the entries whose
// p_comm is a jailbreak-only process (sshd, frida-server, and the jailbreak apps
// themselves).
static void app_hide_filter_process_list(void *buffer, size_t *lengthPtr)
{
	if (!buffer || !lengthPtr || *lengthPtr < sizeof(struct kinfo_proc)) return;

	struct kinfo_proc *list = (struct kinfo_proc *)buffer;
	size_t count = *lengthPtr / sizeof(struct kinfo_proc);

	for (size_t i = 0; i < count; i++) {
		bool drop = false;
		for (size_t n = 0; kAppHideJBProcessNames[n]; n++) {
			if (strcmp(list[i].kp_proc.p_comm, kAppHideJBProcessNames[n]) == 0) {
				drop = true;
				break;
			}
		}
		if (!drop) continue;

		app_hide_note("sysctl-proc", list[i].kp_proc.p_comm);
		memmove(&list[i], &list[i + 1], (count - i - 1) * sizeof(struct kinfo_proc));
		count--;
		i--;
	}

	*lengthPtr = count * sizeof(struct kinfo_proc);
}

static int app_hide_statfs(const char *path, struct statfs *buf)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("statfs", path); errno = ENOENT; return -1; }
#ifdef SYS_statfs
	return (int)syscall(SYS_statfs, path, buf);
#else
	errno = ENOTSUP;
	return -1;
#endif
}

// The *at() family. The open/stat/lstat/fopen hooks call through to these, so hooking them
// naively would recurse - but several SDKs call them directly, and then nothing above is
// reached. Re-issuing the raw syscall (the same trick the four thunk hooks use) removes the
// recursion completely: the syscall does not pass through libc.
//
// Each one is only installed after app_hide_syscall_ready() has proved that its SYS_ number
// actually works here: a wrong number would break every file operation in the process.

#ifdef SYS_openat
static int app_hide_openat(int dirfd, const char *path, int flags, mode_t mode)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("openat", path); errno = ENOENT; return -1; }
	return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
#endif

#ifdef SYS_fstatat
static int app_hide_fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("fstatat", path); errno = ENOENT; return -1; }
	return (int)syscall(SYS_fstatat, dirfd, path, st, flags);
}
#endif

#ifdef SYS_faccessat
static int app_hide_faccessat(int dirfd, const char *path, int mode, int flags)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("faccessat", path); errno = ENOENT; return -1; }
	return (int)syscall(SYS_faccessat, dirfd, path, mode, flags);
}
#endif

#ifdef SYS_readlinkat
static ssize_t app_hide_readlinkat(int dirfd, const char *path, char *buf, size_t size)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("readlinkat", path); errno = ENOENT; return -1; }
	return (ssize_t)syscall(SYS_readlinkat, dirfd, path, buf, size);
}
#endif

// getfsstat / getfsstat64: the per-path hooks cannot hide a mount table. Entries whose mount
// point or backing device mentions the jailbreak root are dropped, and the returned count is
// the filtered one - the buffer form and the count-only form both have to agree or the caller
// sizes its second call wrongly.
static bool app_hide_jb_mount(const struct statfs *fsx)
{
	if (!fsx) return false;
	if (strstr(fsx->f_mntonname, "/var/jb") || strstr(fsx->f_mntfromname, "/var/jb")) return true;
#ifdef JBROOT_PATH
	(void)0;
#endif
	if (gAppHideJBRootLen && strncmp(fsx->f_mntonname, gAppHideJBRoot, gAppHideJBRootLen) == 0) return true;
	return false;
}

#ifdef SYS_getfsstat
static int app_hide_getfsstat(struct statfs *buf, int bufsize, int flags)
{
	app_hide_tick();

	if (!buf) {
		struct statfs tmp[32];
		int n = (int)syscall(SYS_getfsstat, tmp, (int)sizeof(tmp), flags);
		if (n <= 0) return n;
		if (n > 32) n = 32;
		int kept = 0;
		for (int i = 0; i < n; i++) if (!app_hide_jb_mount(&tmp[i])) kept++;
		return kept;
	}

	size_t cap = (size_t)bufsize / sizeof(struct statfs);
	if (cap == 0) return (int)syscall(SYS_getfsstat, buf, bufsize, flags);

	struct statfs *tmp = (struct statfs *)malloc(cap * sizeof(struct statfs));
	if (!tmp) return (int)syscall(SYS_getfsstat, buf, bufsize, flags);

	int n = (int)syscall(SYS_getfsstat, tmp, (int)(cap * sizeof(struct statfs)), flags);
	int kept = 0;
	for (int i = 0; i < n && (size_t)i < cap; i++) {
		if (app_hide_jb_mount(&tmp[i])) { app_hide_note("getfsstat", tmp[i].f_mntonname); continue; }
		buf[kept++] = tmp[i];
	}
	free(tmp);
	return kept;
}
#endif


#ifdef SYS_getfsstat64
// On arm64 the 64 bit form is the same call and struct statfs is already the 64 bit layout;
// struct statfs64 is only declared (incomplete) in the iOS SDK, so the symbol is hooked and
// forwarded rather than reimplemented.
static int app_hide_getfsstat64(struct statfs *buf, int bufsize, int flags)
{
	return app_hide_getfsstat(buf, bufsize, flags);
}
#endif

// ptrace: only PT_DENY_ATTACH is answered locally. Everything else is forwarded as a raw
// syscall, so a legitimate ptrace call in a hidden app still behaves normally.
#ifdef SYS_ptrace
static int app_hide_ptrace(int request, pid_t pid, caddr_t addr, int data)
{
	app_hide_tick();
#ifdef PT_DENY_ATTACH
	if (request == PT_DENY_ATTACH) { app_hide_note("ptrace", "PT_DENY_ATTACH"); return 0; }
#endif
	return (int)syscall(SYS_ptrace, request, pid, addr, data);
}
#endif

// Runs the real syscall once with a path that always exists and a buffer that is big enough,
// so an install is only attempted when the number in this SDK really is the right one.
static bool app_hide_syscall_ready(const char *which)
{
#ifdef SYS_openat
	if (strcmp(which, "openat") == 0) {
		int fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
		if (fd >= 0) { close(fd); return true; }
		return false;
	}
#endif
#ifdef SYS_fstatat
	if (strcmp(which, "fstatat") == 0) {
		struct stat st;
		return (int)syscall(SYS_fstatat, AT_FDCWD, "/dev/null", &st, 0) == 0;
	}
#endif
#ifdef SYS_faccessat
	if (strcmp(which, "faccessat") == 0) {
		return (int)syscall(SYS_faccessat, AT_FDCWD, "/dev/null", F_OK, 0) == 0;
	}
#endif
#ifdef SYS_readlinkat
	if (strcmp(which, "readlinkat") == 0) {
		char buf[PATH_MAX];
		return (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, "/dev/fd/0", buf, sizeof(buf)) >= 0;
	}
#endif
#ifdef SYS_getfsstat
	if (strcmp(which, "getfsstat") == 0) {
		return (int)syscall(SYS_getfsstat, NULL, 0, 0) > 0;
	}
#endif
#ifdef SYS_getfsstat64
	if (strcmp(which, "getfsstat64") == 0) {
		return (int)syscall(SYS_getfsstat64, NULL, 0, 0) > 0;
	}
#endif
#ifdef SYS_ptrace
	if (strcmp(which, "ptrace") == 0) {
		// Bogus request: a valid syscall number answers EINVAL, a wrong one answers ENOSYS.
		errno = 0;
		(void)syscall(SYS_ptrace, 0x7fffffff, 0, NULL, 0);
		return errno != ENOSYS;
	}
#endif
	return false;
}

// getattrlist / getattrlistbulk are how NSFileManager asks about files on modern
// iOS, so a path check that only hooks stat() would be walked straight past.
static int app_hide_getattrlist(const char *path, void *attrList, void *attrBuf, size_t attrBufSize, unsigned long options)
{
	app_hide_tick();
	if (app_hide_hidden_path(path)) { app_hide_note("getattrlist", path); errno = ENOENT; return -1; }
#ifdef SYS_getattrlist
	return (int)syscall(SYS_getattrlist, path, attrList, attrBuf, attrBufSize, options);
#else
	errno = ENOTSUP;
	return -1;
#endif
}

#pragma mark - LaunchServices: installed application list

// The ObjC runtime symbols are resolved through dlsym so systemhook needs no new
// link flags; method_setImplementation (unlike litehook) keeps the original
// implementation callable, which is exactly what an app-list filter needs.
typedef void (*app_hide_imp_t)(void);
typedef struct app_hide_objc_object *app_hide_id;
typedef struct app_hide_objc_class *app_hide_class_t;
typedef struct app_hide_objc_selector *app_hide_sel_t;
typedef struct app_hide_objc_method *app_hide_method_t;

static app_hide_class_t (*p_objc_getClass)(const char *);
static app_hide_sel_t (*p_sel_registerName)(const char *);
static app_hide_method_t (*p_class_getInstanceMethod)(app_hide_class_t, app_hide_sel_t);
static app_hide_imp_t (*p_method_setImplementation)(app_hide_method_t, app_hide_imp_t);
static app_hide_imp_t (*p_method_getImplementation)(app_hide_method_t);
static void *(*p_objc_msgSend)(void);

static app_hide_imp_t gOrigAllApplications;
static app_hide_imp_t gOrigAllInstalledApplications;
static app_hide_imp_t gOrigCanOpenURL;
static bool gAppListHooked = false;

// URL schemes a jailbreak detector probes with -[UIApplication canOpenURL:]. This is a
// pure method replacement (no code patching, nothing to corrupt), and here the answer
// is simply NO - there is no legitimate reason for a hidden app to open these.
static const char *kAppHideJBURLSchemes[] = {
	"cydia://", "sileo://", "zebra://", "installer://", "filza://", "activator://",
	"undecimus://", "unc0ver://", "checkra1n://", "taurine://", "odyssey://",
	"trollstore://", "newterm://", "ssh://", "apt://", "frida://",
};

#define APP_HIDE_SEL(nameC) (p_sel_registerName(nameC))
#define APP_HIDE_MSGSEND(type, obj, sel, ...) ((type (*)(app_hide_id, app_hide_sel_t, ...))p_objc_msgSend)(obj, sel, ##__VA_ARGS__)

__attribute__((noinline))
static bool app_hide_is_jb_app(app_hide_id proxy)
{
	if (!proxy) return false;

	app_hide_sel_t idSel = APP_HIDE_SEL("applicationIdentifier");
	if (APP_HIDE_MSGSEND(bool, proxy, APP_HIDE_SEL("respondsToSelector:"), idSel)) {
		app_hide_id identifier = APP_HIDE_MSGSEND(app_hide_id, proxy, idSel);
		if (identifier) {
			const char *utf8 = APP_HIDE_MSGSEND(const char *, identifier, APP_HIDE_SEL("UTF8String"));
			if (app_hide_jb_bundle_id(utf8)) {
				app_hide_note("LSApplicationProxy-id", utf8);
				return true;
			}
		}
	}

	app_hide_sel_t urlSel = APP_HIDE_SEL("bundleURL");
	if (APP_HIDE_MSGSEND(bool, proxy, APP_HIDE_SEL("respondsToSelector:"), urlSel)) {
		app_hide_id url = APP_HIDE_MSGSEND(app_hide_id, proxy, urlSel);
		if (url) {
			app_hide_id path = APP_HIDE_MSGSEND(app_hide_id, url, APP_HIDE_SEL("path"));
			if (path) {
				const char *utf8 = APP_HIDE_MSGSEND(const char *, path, APP_HIDE_SEL("UTF8String"));
				if (app_hide_suspicious_image_path(utf8)) {
					app_hide_note("LSApplicationProxy-path", utf8);
					return true;
				}
			}
		}
	}

	return false;
}

static app_hide_id app_hide_filter_app_list(app_hide_id list)
{
	if (!list || !p_objc_msgSend) return list;

	unsigned long count = APP_HIDE_MSGSEND(unsigned long, list, APP_HIDE_SEL("count"));

	app_hide_class_t arrayClass = p_objc_getClass("NSMutableArray");
	if (!arrayClass) return list;
	app_hide_id filtered = APP_HIDE_MSGSEND(app_hide_id, (app_hide_id)arrayClass, APP_HIDE_SEL("array"));

	for (unsigned long i = 0; i < count; i++) {
		app_hide_id proxy = APP_HIDE_MSGSEND(app_hide_id, list, APP_HIDE_SEL("objectAtIndex:"), i);
		if (app_hide_is_jb_app(proxy)) continue;
		APP_HIDE_MSGSEND(void, filtered, APP_HIDE_SEL("addObject:"), proxy);
	}
	return filtered;
}

static app_hide_id app_hide_all_applications_hook(app_hide_id self, app_hide_sel_t _cmd)
{
	app_hide_id list = ((app_hide_id (*)(app_hide_id, app_hide_sel_t))gOrigAllApplications)(self, _cmd);
	return app_hide_filter_app_list(list);
}

static app_hide_id app_hide_all_installed_applications_hook(app_hide_id self, app_hide_sel_t _cmd)
{
	app_hide_id list = ((app_hide_id (*)(app_hide_id, app_hide_sel_t))gOrigAllInstalledApplications)(self, _cmd);
	return app_hide_filter_app_list(list);
}

static bool app_hide_is_jb_url(app_hide_id url)
{
	if (!url) return false;

	app_hide_id absolute = APP_HIDE_MSGSEND(app_hide_id, url, APP_HIDE_SEL("absoluteString"));
	if (!absolute) return false;

	const char *text = APP_HIDE_MSGSEND(const char *, absolute, APP_HIDE_SEL("UTF8String"));
	if (!text) return false;

	for (size_t i = 0; i < sizeof(kAppHideJBURLSchemes) / sizeof(kAppHideJBURLSchemes[0]); i++) {
		if (strncasecmp(text, kAppHideJBURLSchemes[i], strlen(kAppHideJBURLSchemes[i])) == 0) {
			app_hide_note("canOpenURL", text);
			return true;
		}
	}
	return false;
}

// Plain C here: BOOL/YES/NO do not exist, and on arm64 -[UIApplication canOpenURL:]
// is declared BOOL, which is `bool` in the arm64 ABI - so the return type matches.
static bool app_hide_can_open_url_hook(app_hide_id self, app_hide_sel_t _cmd, app_hide_id url)
{
	if (app_hide_is_jb_url(url)) return false;
	return ((bool (*)(app_hide_id, app_hide_sel_t, app_hide_id))gOrigCanOpenURL)(self, _cmd, url);
}

static void app_hide_install_app_list_hooks(void)
{
	if (gAppListHooked || !p_objc_getClass) return;
	gAppListHooked = true;   // each hook below carries its own one-shot guard

	// -[UIApplication canOpenURL:] first: UIApplication is present in every app, so
	// this one does not depend on a framework being loaded yet. A detector asking for
	// cydia:// / filza:// gets NO - and here that answer is a plain method replacement,
	// nothing to corrupt.
	app_hide_class_t appClass = p_objc_getClass("UIApplication");
	if (appClass && !gOrigCanOpenURL) {
		app_hide_method_t method = p_class_getInstanceMethod(appClass, APP_HIDE_SEL("canOpenURL:"));
		if (method) {
			app_hide_imp_t original = p_method_getImplementation(method);
			if (original) {
				gOrigCanOpenURL = original;
				p_method_setImplementation(method, (app_hide_imp_t)app_hide_can_open_url_hook);
				app_hide_note("hooked", "canOpenURL:");
			}
		}
	}

	app_hide_class_t workspaceClass = p_objc_getClass("LSApplicationWorkspace");
	if (!workspaceClass) return;   // not loaded yet: gAppListRetry will bring us back

	struct { const char *name; app_hide_imp_t *original; app_hide_imp_t hook; } hooks[] = {
		{ "allApplications",          &gOrigAllApplications,          (app_hide_imp_t)app_hide_all_applications_hook },
		{ "allInstalledApplications", &gOrigAllInstalledApplications, (app_hide_imp_t)app_hide_all_installed_applications_hook },
	};

	for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
		// One-shot per method: without this, a second pass would capture our own hook
		// as the "original" and recurse into itself on the first call.
		if (*hooks[i].original) continue;
		app_hide_method_t method = p_class_getInstanceMethod(workspaceClass, APP_HIDE_SEL(hooks[i].name));
		if (!method) continue;
		app_hide_imp_t original = p_method_getImplementation(method);
		if (!original) continue;
		*hooks[i].original = original;
		p_method_setImplementation(method, hooks[i].hook);
		app_hide_note("hooked", hooks[i].name);
	}
}

// LSApplicationWorkspace lives in a framework the app loads on demand. The hook is
// NOT installed from here: this callback runs on dyld's own thread while images are
// still being loaded, and swizzling a class at that point is what makes a launch
// unpredictable. Just raise the flag and let app_hide_tick() do it from ordinary app
// code.
static volatile bool gAppListRetry = false;

static void app_hide_image_added(const struct mach_header *header, intptr_t slide)
{
	(void)header; (void)slide;
	// The framework carrying the class just landed; let the next tick install.
	if (!gAppListHooked) gAppListRetry = true;
}

// Deferred, one-shot setup. Called from the hooked functions, i.e. from ordinary app
// execution well past dyld init. Cheap once done: one bool test per call.
static void app_hide_tick(void)
{
	static bool booted = false;
	if (!booted) {
		booted = true;
		gAppHideSyslogReady = true;

		// Reached from ordinary app code, i.e. after dyld has finished its initializer
		// loop - which is exactly why the dyld-touching work waits for it.
		if (gAppHideDeferredDyld) {
			gAppHideDeferredDyld = false;
			app_hide_hide_image_paths();
			app_hide_register_image_callback();
		}

		app_hide_install_app_list_hooks();   // no-op until the class exists
		return;
	}
	if (gAppListRetry) {
		gAppListRetry = false;
		app_hide_install_app_list_hooks();
	}
}

static void app_hide_setup_objc(void)
{
	// No dlopen here on purpose. This function runs inside systemhook's constructor,
	// where dyld still holds the loader lock - re-entering it to load an image can
	// deadlock the launch. libobjc is already mapped in any app process, and dlsym
	// simply returns NULL when it is not, which skips the feature.
	p_objc_getClass = (app_hide_class_t (*)(const char *))dlsym(RTLD_DEFAULT, "objc_getClass");
	p_sel_registerName = (app_hide_sel_t (*)(const char *))dlsym(RTLD_DEFAULT, "sel_registerName");
	p_class_getInstanceMethod = (app_hide_method_t (*)(app_hide_class_t, app_hide_sel_t))dlsym(RTLD_DEFAULT, "class_getInstanceMethod");
	p_method_setImplementation = (app_hide_imp_t (*)(app_hide_method_t, app_hide_imp_t))dlsym(RTLD_DEFAULT, "method_setImplementation");
	p_method_getImplementation = (app_hide_imp_t (*)(app_hide_method_t))dlsym(RTLD_DEFAULT, "method_getImplementation");
	p_objc_msgSend = dlsym(RTLD_DEFAULT, "objc_msgSend");

	// v16: only resolve here. Registering the callback from the constructor meant running
	// it while dyld was mid-update - the deferral to app_hide_tick() is what the crash
	// report demanded.
}

static void app_hide_deferred_dyld_body(void)
{
	app_hide_hide_image_paths();
	app_hide_register_image_callback();
	app_hide_note("install", "dyld image work ran in the deferred thread");
}

// dispatch_async_f, not dispatch_async: a block would need -fblocks for this translation unit,
// and there is no reason to depend on that flag for a one-shot callback.
static void app_hide_deferred_dyld_thread(void *context)
{
	(void)context;
	usleep(150 * 1000);   // dyld's initializer loop is long finished by here
	app_hide_deferred_dyld_body();
}

// v17: the deferral moved off the hooked-call path.
//
// v16 ran the dyld work from the first hooked call, which is fine for open/fopen (ordinary app
// code) and is what the crash report demanded instead of doing it in the constructor. v17 also
// interposes stat, though, and stat is called during libsystem startup - so the same crash could
// have come back through a different door. A thread that waits 150ms is deterministic for both:
// whatever the app calls first, dyld has certainly finished when it wakes.
static void app_hide_schedule_deferred_dyld(void)
{
	static bool scheduled = false;
	if (scheduled) return;
	scheduled = true;

	dispatch_async_f(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
	                 NULL, (dispatch_function_t)app_hide_deferred_dyld_thread);
	app_hide_note("install", "dyld image work scheduled on a background thread");
}

static void app_hide_register_image_callback(void)
{
	if (p_objc_getClass && p_sel_registerName && p_class_getInstanceMethod &&
	    p_method_setImplementation && p_method_getImplementation && p_objc_msgSend) {
		_dyld_register_func_for_add_image(app_hide_image_added);
	}
}

#pragma mark - hook installation guard

// litehook_hook_function() overwrites a FIXED 20 bytes at the target entry (five
// instructions: four MOVK x16 + BR x16) and does not look at the function's size or
// at instruction boundaries. On arm64 Darwin, libsystem_kernel exports most syscall
// entry points as 12 byte thunks
//
//     mov  x16, #nr        ; 4 bytes
//     svc  #0x80           ; 4 bytes
//     b    _cerror         ; 4 bytes
//
// and those thunks sit back to back in the dyld shared cache. Patching one therefore
// rewrites the first 8 bytes of the NEXT symbol in the same slice, and every caller
// of that neighbour executes garbage and dies - which is exactly what happened when
// fork/sysctl/statfs/getattrlist were added: the app crashed on launch.
//
// So: only patch a function whose first five instructions are straight line code that
// cannot leave the patched window. Skipping a hook costs coverage; patching a thunk
// costs the launch.
#define APP_HIDE_HOOK_MAX 24
#define APP_HIDE_ENGINE_VERSION "v17"

typedef struct {
	const char *name;
	bool installed;
	bool shortHook;
	const char *skipReason;
} app_hide_hook_result;

static app_hide_hook_result gAppHideHooks[APP_HIDE_HOOK_MAX];
static size_t gAppHideHookCount = 0;
static size_t gSkippedCount = 0;   // gHookedCount is declared with the other globals

#ifdef __arm64__
static bool app_hide_insn_leaves_flow(uint32_t insn)
{
	if ((insn & 0xFFFFFC1F) == 0xD65F0000) return true;   // ret
	if ((insn & 0xFFFFFC1F) == 0xD61F0000) return true;   // br  xN
	if ((insn & 0xFFFFFC1F) == 0xD63F0000) return true;   // blr xN
	if ((insn & 0xFC000000) == 0x14000000) return true;   // b   imm
	if ((insn & 0xFC000000) == 0x94000000) return true;   // bl  imm
	if ((insn & 0xFF000010) == 0x54000000) return true;   // b.cond
	if ((insn & 0x7E000000) == 0x34000000) return true;   // cbz / cbnz
	if ((insn & 0x7E000000) == 0x36000000) return true;   // tbz / tbnz
	if (insn == 0xD4000001) return true;                  // svc #0x80
	return false;
}

static bool app_hide_function_is_patchable(const void *function)
{
	if (!function) return false;

	const uint32_t *insn = (const uint32_t *)function;
	// litehook consumes instructions 1-4 and replaces the fifth, so none of the
	// first four may leave that window.
	for (size_t i = 0; i < 4; i++) {
		if (app_hide_insn_leaves_flow(insn[i])) return false;
	}
	return true;
}
#else
static bool app_hide_function_is_patchable(const void *function)
{
	return function != NULL;
}
#endif

#ifdef __arm64__
// litehook's function hook writes a FIXED 20 bytes: movz + 3x movk + br, which is why the
// guard above refuses Darwin's syscall thunks - they are three instructions wide
// (mov x16,#n / svc #0x80 / ret, 12 bytes) and live back to back in the shared cache, so a
// 20 byte write would take the next exported symbol with it.
//
// litehook_hook_memory() however takes an arbitrary byte count, so a thunk can still be
// detoured with two instructions: adrp x16, <page> / br x16 (8 bytes, ending exactly on the
// svc). The real jump - litehook's own movz/movk/br sequence, byte for byte - is placed at
// the start of a page allocated for it, which adrp reaches anywhere inside +/-4GB.
//
// Everything here is gated on the target actually being a syscall thunk measured at
// runtime: if the shape does not match, the hook is skipped exactly as before. Nothing about
// this path is speculative on a target that does not have that shape.

#define APP_HIDE_ADRP_REACH (1LL << 31)

static uint32_t app_hide_gen_movk(uint8_t reg, uint16_t value, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;   // movk Xd, #imm16, LSL #hw
	uint32_t hw = 0;
	if (lsl == 16) hw = 0b01 << 21;
	else if (lsl == 32) hw = 0b10 << 21;
	else if (lsl == 48) hw = 0b11 << 21;
	return base | hw | ((uint32_t)value << 5) | (reg & 0x1F);
}

static uint32_t app_hide_gen_br(uint8_t reg)
{
	return 0b11010110000111110000000000000000 | (((uint32_t)reg & 0x1F) << 5);
}

static uint32_t app_hide_gen_adrp(uint8_t reg, int64_t pageDelta)
{
	int64_t imm21 = pageDelta >> 12;
	uint32_t immlo = (uint32_t)(imm21 & 0x3);
	uint32_t immhi = (uint32_t)((imm21 >> 2) & 0x7FFFF);
	return 0x90000000u | (immlo << 29) | (immhi << 5) | (reg & 0x1F);
}

// mov x16,#n / svc #0x80 / ret, with the x16/x17 setup in the first slot.
static bool app_hide_is_syscall_thunk(const void *function)
{
	const uint32_t *insn = (const uint32_t *)function;
	if ((insn[0] & 0xFF800000) != 0xD2800000 &&      // movz Xd
	    (insn[0] & 0xFF800000) != 0xF2800000) {      // movk Xd
		return false;
	}
	if ((insn[0] & 0x1F) != 16 && (insn[0] & 0x1F) != 17) return false;
	if (insn[1] != 0xD4001001) return false;         // svc #0x80
	if ((insn[2] & 0xFFFFFC1F) != 0xD65F0000) return false;   // ret
	return true;
}

static void *app_hide_alloc_exec_page_near(void *near)
{
	const vm_size_t pageSize = 0x4000;

	// Mach honours a free hint, so aim at the page the thunk lives in first and then at
	// a few offsets inside the same 4GB window.
	for (int attempt = 0; attempt < 6; attempt++) {
		vm_address_t hint = (vm_address_t)((uintptr_t)near & ~(uintptr_t)(pageSize - 1));
		if (attempt > 0) hint += (vm_address_t)attempt * 0x20000000ULL;

		vm_address_t addr = hint;
		if (vm_allocate(mach_task_self(), &addr, pageSize, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
			continue;
		}
		int64_t distance = (int64_t)addr - (int64_t)(uintptr_t)near;
		if (distance > -APP_HIDE_ADRP_REACH && distance < APP_HIDE_ADRP_REACH) {
			return (void *)addr;
		}
		vm_deallocate(mach_task_self(), addr, pageSize);
	}
	return NULL;
}

static bool app_hide_short_hook(void *target, void *replacement)
{
	if (!app_hide_is_syscall_thunk(target)) return false;

	void *page = app_hide_alloc_exec_page_near(target);
	if (!page) return false;

	uint32_t *trampoline = (uint32_t *)page;
	uint64_t destination = (uint64_t)(uintptr_t)replacement;
	trampoline[0] = app_hide_gen_movk(16, (uint16_t)(destination >>  0),  0);
	trampoline[1] = app_hide_gen_movk(16, (uint16_t)(destination >> 16), 16);
	trampoline[2] = app_hide_gen_movk(16, (uint16_t)(destination >> 32), 32);
	trampoline[3] = app_hide_gen_movk(16, (uint16_t)(destination >> 48), 48);
	trampoline[4] = app_hide_gen_br(16);

	// __builtin___clear_cache lowers to ___clear_cache, which iOS does not link; the
	// platform entry point is the same one litehook uses internally.
	sys_icache_invalidate(page, 20);

	if (vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false,
	               VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
		vm_deallocate(mach_task_self(), (vm_address_t)page, 0x4000);
		return false;
	}

	uint32_t patch[2] = {
		app_hide_gen_adrp(16, (int64_t)(uintptr_t)page - (int64_t)(uintptr_t)target),
		app_hide_gen_br(16),
	};
	if (litehook_hook_memory(target, patch, sizeof(patch)) != KERN_SUCCESS) return false;

	// Read back: a patch that did not land must not be reported as installed.
	return ((const uint32_t *)target)[0] == patch[0] && ((const uint32_t *)target)[1] == patch[1];
}
#else
static bool app_hide_short_hook(void *target, void *replacement)
{
	(void)target; (void)replacement;
	return false;
}
#endif

static void app_hide_hook(const char *name, void *target, void *replacement)
{
	const char *skipReason = NULL;

	if (!target) {
		skipReason = "symbol not found";
	}

	bool installed = false;
	bool shortHook = false;
	if (!skipReason) {
		if (app_hide_function_is_patchable(target)) {
			installed = litehook_hook_function(target, replacement) == KERN_SUCCESS;
			if (!installed) skipReason = "litehook rejected the address";
		}
		else if (app_hide_short_hook(target, replacement)) {
			// A three instruction syscall thunk: 20 bytes were impossible, two are enough.
			installed = true;
			shortHook = true;
		}
		else {
			skipReason = "short stub - neither the 20 byte patch nor the 8 byte thunk patch fit";
		}
	}

	if (gAppHideHookCount < APP_HIDE_HOOK_MAX) {
		gAppHideHooks[gAppHideHookCount].name = name;
		gAppHideHooks[gAppHideHookCount].installed = installed;
		gAppHideHooks[gAppHideHookCount].shortHook = shortHook;
		gAppHideHooks[gAppHideHookCount].skipReason = skipReason;
		gAppHideHookCount++;
	}
	if (installed) gHookedCount++; else gSkippedCount++;
}

// Every hook outcome goes into the log the user can read from the Files app, so
// "which part of the engine is actually live on this iOS version" is a fact rather
// than a guess.
static void app_hide_report_hooks(void)
{
	char line[160];

	snprintf(line, sizeof(line), "engine " APP_HIDE_ENGINE_VERSION ": %zu hooks active, %zu skipped",
	         gHookedCount, gSkippedCount);
	app_hide_note("install", line);

	// v17: the five the patch guard refuses are covered by the interpose section instead, so the
	// counts above understate what is live - say so in the log the user can read.
	app_hide_note("install", "dyld interpose section active (stat/lstat/access/readlink/opendir/open/fopen/fstatat/faccessat/openat/readlinkat/statfs/getattrlist)");

	for (size_t i = 0; i < gAppHideHookCount; i++) {
		if (gAppHideHooks[i].installed) {
			snprintf(line, sizeof(line), "%s installed%s", gAppHideHooks[i].name,
			         gAppHideHooks[i].shortHook ? " (8 byte thunk hook)" : "");
		}
		else {
			snprintf(line, sizeof(line), "%s SKIPPED (%s)", gAppHideHooks[i].name,
			         gAppHideHooks[i].skipReason ? gAppHideHooks[i].skipReason : "unknown");
		}
		app_hide_note("hook", line);
	}
}

#pragma mark - install


#pragma mark - per-container marker

// The environment marker cannot be relied on for apps. A home screen launch is performed by
// runningboardd, not by launchd (where launchdhook sets _JBEnvMode), and the environment
// runningboardd hands an app is built from its own configuration, so the marker either never
// gets set or does not survive the launch. Device evidence: the spawn log held daemon xpcproxy
// lines only, and every hidden app stayed completely unhooked.
//
// A sandboxed app can always read its own container, and the panel can write there as root
// (it already does, for the rules file and the log collection). So the decision is carried by
// two files inside the app's own container:
//   Library/Caches/.DopamineAppHide.id    written by the engine, holds its executable path
//   Library/Caches/.DopamineAppHide.hide  written by the panel, means "hide this app"
static const char kAppHideContainerIdFile[]     = ".DopamineAppHide.id";
static const char kAppHideContainerHideFile[]   = ".DopamineAppHide.hide";
static const char kAppHideContainerEngineFile[] = ".DopamineAppHide.engine";
static const char kAppHideContainerSafeFile[]   = ".DopamineAppHide.safe";

static bool app_hide_container_path(const char *file, char *out, size_t outSize)
{
	if (out && outSize) out[0] = '\0';
	const char *home = getenv("HOME");
	if (!home || home[0] != '/') return false;
	snprintf(out, outSize, "%s/Library/Caches/%s", home, file);
	return true;
}

bool app_hide_container_marker_present(void)
{
	char path[PATH_MAX];
	if (!app_hide_container_path(kAppHideContainerHideFile, path, sizeof(path))) return false;
	struct stat st = {};
	return (stat(path, &st) == 0);
}

// The round 2 hook set is opt-in. It is the half that answers a banking SDK, and also the
// half made of Darwin's bare syscall thunks - the ones litehook's fixed 20 byte patch
// cannot rewrite without taking the next exported symbol with it. The first build that
// reached a real app crashed it on launch, so the caller has to ask for it explicitly:
// the panel writes "0" into the safe file for the apps where it is wanted.
bool app_hide_container_enhanced_mode(void)
{
	char path[PATH_MAX];
	if (!app_hide_container_path(kAppHideContainerSafeFile, path, sizeof(path))) return false;
	int fd = open(path, O_RDONLY);
	if (fd < 0) return false;
	char buf[8] = {};
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return false;
	buf[n] = '\0';
	return (buf[0] == '0');
}

static void app_hide_container_write(const char *file, const char *content)
{
	char path[PATH_MAX];
	if (!app_hide_container_path(file, path, sizeof(path))) return;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	(void)write(fd, content, strlen(content));
	close(fd);
}

// The id file is written once and ties a container to a bundle path; the engine file is
// rewritten on every launch and is what proves to the panel that this app's engine loaded
// at all - the difference between "no engine" and "engine but no marker" cost a round.
// Runs even when the process is not hidden.
static void app_hide_register_container(const char *execPath, const char *status)
{
	if (!execPath || !execPath[0]) return;

	char path[PATH_MAX];
	if (app_hide_container_path(kAppHideContainerIdFile, path, sizeof(path))) {
		struct stat st = {};
		if (stat(path, &st) != 0) app_hide_container_write(kAppHideContainerIdFile, execPath);
	}
	app_hide_container_write(kAppHideContainerEngineFile, status);
}

void app_hide_install(void)
{
	if (gAppHideActive) return;

	// Two ways in: the environment marker (set by launchdhook's spawn hook) and the
	// container marker (written by the panel; the one thing a sandboxed app can read).
	const char *marker = getenv(APP_HIDE_ENV_MARKER);
	if (!marker) marker = getenv("DOPAMINE_APP_HIDE");   // older basebin
	bool hiddenByEnv = (marker && strcmp(marker, "1") == 0);
	bool hiddenByContainer = app_hide_container_marker_present();
	bool hidden = (hiddenByEnv || hiddenByContainer);

	// Tell the panel what happened here, hidden or not: this file is the only proof that
	// the engine loaded inside this app.
	{
		char execPath[PATH_MAX];
		uint32_t execPathSize = sizeof(execPath);
		if (_NSGetExecutablePath(execPath, &execPathSize) == 0) {
			char status[224];
			snprintf(status, sizeof(status), "loaded  env=%d marker=%d hidden=%d enhanced=%d\n",
			         hiddenByEnv ? 1 : 0, hiddenByContainer ? 1 : 0, hidden ? 1 : 0,
			         app_hide_container_enhanced_mode() ? 1 : 0);
			app_hide_register_container(execPath, status);
		}
	}

	if (!hidden) return;

	app_hide_note("activate", hiddenByContainer ? "container marker" : "environment marker");

	// v14: round 2 is opt-in per app. Device evidence: the build that first reached a
	// bank app killed it on launch, and the aggressive half is exactly the set of
	// functions Darwin exports as bare syscall thunks. Default is therefore path hiding
	// only; the panel's per-app switch writes "0" into this app's safe file to turn the
	// extended set on, so the crash can be bisected on the device without a rebuild.
	bool aggressive = app_hide_container_enhanced_mode();
	if (marker && strcmp(marker, "0") == 0) aggressive = false;   // daemon side override

	if (JB_RootPath && JB_RootPath[0] == '/') {
		size_t len = strlen(JB_RootPath);
		if (len >= sizeof(gAppHideJBRoot)) len = sizeof(gAppHideJBRoot) - 1;
		memcpy(gAppHideJBRoot, JB_RootPath, len);
		gAppHideJBRoot[len] = '\0';
		while (len && gAppHideJBRoot[len - 1] == '/') gAppHideJBRoot[--len] = '\0';
		gAppHideJBRootLen = len;
	}

	for (size_t i = 0; kAppHidePrefixPaths[i] && gAppHidePrefixCount < APP_HIDE_MAX_PREFIXES; i++) {
		gAppHidePrefixes[gAppHidePrefixCount].path = kAppHidePrefixPaths[i];
		gAppHidePrefixes[gAppHidePrefixCount].len = strlen(kAppHidePrefixPaths[i]);
		gAppHidePrefixCount++;
	}

	gAppHideActive = true;

	// v15: the default set is only what can be re-issued as a raw syscall. fopen/opendir
	// have no raw syscall equivalent (they build a FILE*/DIR*), and the image path rewrite
	// edits the recorded names of already loaded images, which a complex app resolves
	// classes through. Both are in the round 2 set now, off by default - the build that
	// kept them here is the one that killed the bank app on launch.
	app_hide_hook("stat",     (void *)stat,     (void *)app_hide_stat);
	app_hide_hook("lstat",    (void *)lstat,    (void *)app_hide_lstat);
	app_hide_hook("access",   (void *)access,   (void *)app_hide_access);
	app_hide_hook("open",     (void *)open,     (void *)app_hide_open);
	app_hide_hook("readlink", (void *)readlink, (void *)app_hide_readlink);

	// Round 2: the checks a banking app's hardening SDK reaches for after the
	// plain file probes came back clean. OFF unless _JBEnvMode=2 - see the note at
	// the top of this function. When it is on, these are also the ones most likely to
	// be bare syscall thunks, in which case the guard skips them instead of
	// corrupting the shared cache next door.
	if (aggressive) {
		// Moved here in v15: see the note at the default set above.
		app_hide_hook("fopen",   (void *)fopen,   (void *)app_hide_fopen);
		app_hide_hook("opendir", (void *)opendir, (void *)app_hide_opendir);
		// v17: scheduled on a thread first, and kept as a tick backstop for processes without
		// libdispatch; see app_hide_schedule_deferred_dyld() for why the first hooked call
		// alone is no longer sufficient now that stat is interposed.
		app_hide_schedule_deferred_dyld();
		gAppHideDeferredDyld = true;   // image rewrite + add-image callback: first tick
		app_hide_note("install", "dyld image work deferred to the first tick");

		app_hide_hook("fork",        (void *)fork,        (void *)app_hide_fork);
		app_hide_hook("sysctl",      (void *)sysctl,      (void *)app_hide_sysctl);
		app_hide_hook("statfs",      (void *)statfs,      (void *)app_hide_statfs);
		app_hide_hook("getattrlist", (void *)getattrlist, (void *)app_hide_getattrlist);

		// Installed-application list (LaunchServices): resolved through dlsym and
		// installed later, from app_hide_tick() - never from here, because this runs
		// inside a dyld constructor and swizzling a class while images are still
		// being loaded is not safe. A process without the ObjC runtime skips it.
		app_hide_setup_objc();
		// The *at() family, each only after its syscall number has been proved live.
		{
			struct { const char *name; void *handler; bool (*ready)(const char *); } atHooks[] = {
#ifdef SYS_openat
				{ "openat",   (void *)app_hide_openat,   app_hide_syscall_ready },
#endif
#ifdef SYS_fstatat
				{ "fstatat",  (void *)app_hide_fstatat,  app_hide_syscall_ready },
#endif
#ifdef SYS_faccessat
				{ "faccessat", (void *)app_hide_faccessat, app_hide_syscall_ready },
#endif
#ifdef SYS_readlinkat
				{ "readlinkat", (void *)app_hide_readlinkat, app_hide_syscall_ready },
#endif
#ifdef SYS_getfsstat
				{ "getfsstat",  (void *)app_hide_getfsstat,  app_hide_syscall_ready },
#endif
#ifdef SYS_getfsstat64
				{ "getfsstat64", (void *)app_hide_getfsstat64, app_hide_syscall_ready },
#endif
#ifdef SYS_ptrace
				{ "ptrace",     (void *)app_hide_ptrace,     app_hide_syscall_ready },
#endif
			};
			for (size_t i = 0; i < sizeof(atHooks) / sizeof(atHooks[0]); i++) {
				if (!atHooks[i].ready(atHooks[i].name)) {
					app_hide_note("install", "at() hook not installed - syscall self test failed");
					continue;
				}
				app_hide_hook(atHooks[i].name, atHooks[i].handler, NULL);
				app_hide_note("install", atHooks[i].name);
			}
		}

		// v11: symbols the libc wrappers and the *at family still leave open.
		// sysctlbyname needs no original (it is reimplemented on top of sysctl), so it is
		// always installed. statfs64 is installed only after its syscall number has been
		// proved live here - a wrong number would make every statfs64 call in this process
		// fail, which is worse than not hooking it at all.
		app_hide_hook("sysctlbyname", (void *)sysctlbyname, (void *)app_hide_sysctlbyname);
		app_hide_note("install", "sysctlbyname");
		{
			// statfs64 has no prototype in the iOS SDK (only the symbol exists), so it is
			// resolved at runtime like every other optional entry point. A NULL result is
			// treated exactly like a failed self test: no hook.
			void *statfs64Target = dlsym(RTLD_DEFAULT, "statfs64");
			bool statfs64Ready = false;
#ifdef SYS_statfs64
			if (statfs64Target) {
				struct statfs probe = {};
				statfs64Ready = (syscall(SYS_statfs64, "/", &probe) == 0);
			}
#endif
			if (statfs64Ready) {
				app_hide_hook("statfs64", statfs64Target, (void *)app_hide_statfs64);
				app_hide_note("install", "statfs64");
			}
			else {
				app_hide_note("install", "statfs64 not installed - syscall self test failed");
			}
		}
	}
	else {
		app_hide_note("install", "round 2 (fork/sysctl/statfs/getattrlist/LS list) OFF - set _JBEnvMode=2 to enable");
	}

	app_hide_report_hooks();

	// The app must not see any of the variables that got us here. Safe now:
	// should_enable_tweaks() has already decided, and the check-in is done.
	unsetenv(APP_HIDE_ENV_MARKER);
	unsetenv("DOPAMINE_APP_HIDE");
	unsetenv("JB_ROOT_PATH");
	unsetenv("_SafeMode");
	unsetenv("_MSSafeMode");

	const char *insert = getenv("DYLD_INSERT_LIBRARIES");
	if (!insert || strstr(insert, "systemhook")) {
		unsetenv("DYLD_INSERT_LIBRARIES");
	}
}
