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
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/task_info.h>
#include <mach/vm_region.h>
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
	if (app_hide_hidden_path(path)) { errno = ENOENT; return -1; }
	return fstatat(AT_FDCWD, path, buf, 0);
}

static int app_hide_lstat(const char *path, struct stat *buf)
{
	if (app_hide_hidden_path(path)) { errno = ENOENT; return -1; }
	return fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

static int app_hide_access(const char *path, int mode)
{
	if (app_hide_hidden_path(path)) { errno = ENOENT; return -1; }
	return faccessat(AT_FDCWD, path, mode, 0);
}

static int app_hide_open(const char *path, int oflag, mode_t mode)
{
	if (app_hide_hidden_path(path)) { errno = ENOENT; return -1; }
	return openat(AT_FDCWD, path, oflag, mode);
}

static ssize_t app_hide_readlink(const char *path, char *buf, size_t bufsize)
{
	if (app_hide_hidden_path(path)) { errno = ENOENT; return -1; }
	return readlinkat(AT_FDCWD, path, buf, bufsize);
}

// fopen is reachable through openat + fdopen, so the original is not needed.
static FILE *app_hide_fopen(const char *path, const char *mode)
{
	if (app_hide_hidden_path(path)) { errno = ENOENT; return NULL; }

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
	if (app_hide_hidden_path(path)) { errno = ENOENT; return NULL; }

	int fd = openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) return NULL;

	DIR *dir = fdopendir(fd);
	if (!dir) close(fd);
	return dir;
}

#pragma mark - install

void app_hide_install(void)
{
	if (gAppHideActive) return;

	const char *marker = getenv("DOPAMINE_APP_HIDE");
	if (!marker || strcmp(marker, "1") != 0) return;

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

	// Do this before hooking: it uses _dyld_* and the raw Mach-O headers, none of
	// which goes through the functions we are about to replace.
	app_hide_hide_image_paths();

	if (litehook_hook_function((void *)stat,     (void *)app_hide_stat)     == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)lstat,    (void *)app_hide_lstat)    == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)access,   (void *)app_hide_access)   == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)open,     (void *)app_hide_open)     == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)fopen,    (void *)app_hide_fopen)    == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)opendir,  (void *)app_hide_opendir)  == KERN_SUCCESS) gHookedCount++;
	if (litehook_hook_function((void *)readlink, (void *)app_hide_readlink) == KERN_SUCCESS) gHookedCount++;

	// The app must not see any of the variables that got us here. Safe now:
	// should_enable_tweaks() has already decided, and the check-in is done.
	unsetenv("DOPAMINE_APP_HIDE");
	unsetenv("JB_ROOT_PATH");
	unsetenv("_SafeMode");
	unsetenv("_MSSafeMode");

	const char *insert = getenv("DYLD_INSERT_LIBRARIES");
	if (!insert || strstr(insert, "systemhook")) {
		unsetenv("DYLD_INSERT_LIBRARIES");
	}
}
