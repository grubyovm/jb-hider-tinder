/*
 * ImageVeil.c
 *
 * ElleKit-based function hook (NOT Frida -- real inline code patch, loaded
 * via Dopamine's TweakInject at process launch) hiding jailbreak-related
 * dyld images from FaceTecSDK (Tinder.app, com.cardify.tinder).
 *
 * Confirmed via static RE of FaceTecSDK.framework (2026-10-12 session):
 *
 *   1. InitFunc_1 (FaceTecSDK+0x18DE38) crashes (BRK @ +0x18E70C, matches
 *      real device crash log 1:1) when ANY MH_DYLIB image has
 *      LC_CODE_SIGNATURE present but no CSMAGIC_BLOBWRAPPER blob. Its
 *      prologue calls the resolved-table primitive idx=135
 *      (_dyld_image_count) before its 121-case dispatcher even starts --
 *      same enumeration pattern as the whole InitFunc_x family
 *      (_dyld_image_count() -> loop _dyld_get_image_header(i)).
 *   2. InitFunc_0/2/3/4/5/6/9/10/11/15 fingerprint the SAME image list via
 *      the SAME two primitives (non-crashing -- likely reported server-side
 *      as part of FaceTec's session risk signals, separately confirmed this
 *      session by decompiling the actual JSON upload payload).
 *   3. A SEPARATE ~31-function anti-tamper family (incl. -[oyFDweCB
 *      results], the BR-pattern hook-check self-test on vm_region_recurse_64)
 *      walks the SAME image list via task_info(TASK_DYLD_INFO=17) instead,
 *      through a shared helper (dyldinfo_enum_helper @0x14C2B8).
 *   4. CONFIRMED (manual disasm of every real call site of idx 55/135/8,
 *      incl. inside the "giant" functions): NONE of _dyld_image_count,
 *      _dyld_get_image_header, or task_info is ever fed into the SDK's
 *      BR-pattern inline-hook detector. That check (AND #0xFFFFFC1F; CMP
 *      against the BR-instruction bit pattern 0xD61F0000) is applied
 *      EXCLUSIVELY to the SDK's own vm_region_recurse_64 pointer (idx=225),
 *      across all 47 confirmed call sites. Hooking these three primitives
 *      is therefore not caught by that mechanism.
 *   5. A DIRECT in-place edit of the real dyld_all_image_infos.infoArray
 *      (via Frida Memory.protect+Memory.copy) was tried and failed: the
 *      backing page is hardware write-protected on iOS 18 regardless of
 *      Memory.protect("rwx") -- the write hard-faulted Frida's own agent
 *      thread (gum-js-loop), which hung the app's main thread until
 *      SpringBoard's watchdog SIGKILL'd the process after 10s. This hook
 *      sidesteps that entirely: we never write to the real struct, we
 *      intercept the FUNCTIONS that read it (patched via MSHookFunction,
 *      which rewrites the target's actual machine code -- unlike fishhook,
 *      this is NOT defeated by FaceTecSDK resolving these primitives via
 *      dlsym instead of the normal import table).
 *
 * Deploy: drop ImageVeil.dylib + ImageVeil.plist (same basename) into
 *   /var/jb/usr/lib/TweakInject/
 * (the TweakInject convention this exact jailbreak already uses --
 * confirmed from the live image dump: .../procursus/usr/lib/TweakInject/
 * already holds Choicy.dylib and 0BadooSpoofer.dylib there).
 *
 * Our own dylib's path also matches the blocklist below ("tweakinject"),
 * so once the hook is active it hides itself from the same enumeration too
 * -- otherwise an ad-hoc-signed dylib with no CMS blob would trip the exact
 * same InitFunc_1 crash we're trying to prevent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

#pragma mark - MSHookFunction, resolved at runtime (ElleKit is already loaded
#pragma mark   in-process -- TweakInject can't work without it -- so no SDK
#pragma mark   header/lib dependency needed at build time)

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

#pragma mark - Blocklist (confirmed on-device via dump_images.js, 2026-10-12)

// The random hex Dopamine uses to hide its jbroot path changes every boot --
// don't rely on it. "procursus" / "dopamine-" / "systemhook.dylib" /
// "tweakinject" are the stable substrings shared by every real JB artifact
// we actually observed in this process's image list.
static const char *kBlocked[] = {
    "procursus", "dopamine-", "systemhook.dylib", "tweakinject", NULL
};

static bool PathBlocked(const char *path) {
    if (!path) return false;
    for (int i = 0; kBlocked[i]; i++) {
        if (strstr(path, kBlocked[i])) return true;
    }
    return false;
}

#pragma mark - _dyld_image_count / _dyld_get_image_header / _dyld_get_image_name

static uint32_t (*orig_dyld_image_count)(void);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static const char *(*orig_dyld_get_image_name)(uint32_t);

static uint32_t *g_visible = NULL;
static uint32_t g_visibleCount = 0;
static pthread_once_t g_visibleOnce = PTHREAD_ONCE_INIT;

static void BuildVisibleList(void) {
    uint32_t real = orig_dyld_image_count();
    uint32_t *tmp = (uint32_t *)malloc(sizeof(uint32_t) * (real ? real : 1));
    uint32_t n = 0;
    for (uint32_t i = 0; i < real; i++) {
        const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(i) : NULL;
        if (!PathBlocked(name)) tmp[n++] = i;
    }
    g_visible = tmp;
    g_visibleCount = n;
}

static uint32_t Hooked_dyld_image_count(void) {
    pthread_once(&g_visibleOnce, BuildVisibleList);
    return g_visibleCount;
}

static const struct mach_header *Hooked_dyld_get_image_header(uint32_t idx) {
    pthread_once(&g_visibleOnce, BuildVisibleList);
    if (idx >= g_visibleCount) return NULL;
    return orig_dyld_get_image_header(g_visible[idx]);
}

static const char *Hooked_dyld_get_image_name(uint32_t idx) {
    pthread_once(&g_visibleOnce, BuildVisibleList);
    if (idx >= g_visibleCount) return NULL;
    return orig_dyld_get_image_name(g_visible[idx]);
}

#pragma mark - task_info(TASK_DYLD_INFO) -- fabricated struct in our own
#pragma mark   writable memory (the real one is hardware write-protected)

static kern_return_t (*orig_task_info)(task_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);

static struct dyld_all_image_infos *g_fakeAII = NULL;
static pthread_once_t g_fakeOnce = PTHREAD_ONCE_INIT;

static void BuildFakeAllImageInfos(void) {
    task_dyld_info_data_t real;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (orig_task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&real, &cnt) != KERN_SUCCESS)
        return;

    struct dyld_all_image_infos *realAII =
        (struct dyld_all_image_infos *)real.all_image_info_addr;
    if (!realAII) return;

    uint32_t n = realAII->infoArrayCount;
    struct dyld_image_info *filtered =
        (struct dyld_image_info *)malloc(sizeof(struct dyld_image_info) * (n ? n : 1));
    uint32_t kept = 0;
    for (uint32_t i = 0; i < n; i++) {
        struct dyld_image_info entry = realAII->infoArray[i];
        if (!PathBlocked(entry.imageFilePath)) filtered[kept++] = entry;
    }

    struct dyld_all_image_infos *fake =
        (struct dyld_all_image_infos *)calloc(1, sizeof(*fake));
    fake->version = realAII->version;
    fake->infoArrayCount = kept;
    fake->infoArray = filtered;
    g_fakeAII = fake;
}

static kern_return_t Hooked_task_info(task_t target, task_flavor_t flavor,
                                       task_info_t info, mach_msg_type_number_t *cnt) {
    kern_return_t kr = orig_task_info(target, flavor, info, cnt);
    if (kr == KERN_SUCCESS && flavor == TASK_DYLD_INFO && target == mach_task_self()) {
        pthread_once(&g_fakeOnce, BuildFakeAllImageInfos);
        if (g_fakeAII) {
            ((task_dyld_info_t)info)->all_image_info_addr = (uint64_t)g_fakeAII;
        }
    }
    return kr;
}

#pragma mark - init

__attribute__((constructor))
static void ImageVeilInit(void) {
    MSHookFunction_t MSHookFunction =
        (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!MSHookFunction) return; // ElleKit not present in this process -- bail out quietly

    void *p_count    = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    void *p_header   = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    void *p_name     = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    void *p_taskinfo = dlsym(RTLD_DEFAULT, "task_info");

    if (p_count)
        MSHookFunction(p_count, (void *)Hooked_dyld_image_count, (void **)&orig_dyld_image_count);
    if (p_header)
        MSHookFunction(p_header, (void *)Hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    if (p_name)
        MSHookFunction(p_name, (void *)Hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    if (p_taskinfo)
        MSHookFunction(p_taskinfo, (void *)Hooked_task_info, (void **)&orig_task_info);
}
