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
 *      LC_CODE_SIGNATURE present but no CSMAGIC_BLOBWRAPPER blob. CONFIRMED
 *      via raw disasm (not just a comment) at 0x190648-0x190654: it reads
 *      the resolved-table pointer for idx=55 (_dyld_get_image_header) and
 *      calls it with W0=[X23+0x84] (loop index), storing the result at
 *      [X23+0x3A0]; NULL -> end-of-enumeration state 107.
 *   2. InitFunc_0/2/3/4/5/6/9/10/11/15 fingerprint the SAME image list via
 *      the SAME two primitives (non-crashing -- likely reported server-side
 *      as part of FaceTec's session risk signals).
 *   3. A SEPARATE ~31-function anti-tamper family walks the SAME image list
 *      via task_info(TASK_DYLD_INFO=17) instead (dyldinfo_enum_helper
 *      @0x14C2B8).
 *   4. CONFIRMED (manual disasm of every real call site of idx 55/135/8,
 *      incl. inside the "giant" functions): NONE of these three primitives
 *      is ever fed into the SDK's BR-pattern inline-hook detector (that
 *      check is exclusive to vm_region_recurse_64, idx=225). Hooking these
 *      three is therefore not caught by that mechanism.
 *   5. A direct in-place edit of the real dyld_all_image_infos.infoArray
 *      (via Frida) failed: the backing page is hardware write-protected on
 *      iOS 18 regardless of Memory.protect("rwx"). This hook sidesteps that
 *      by intercepting the FUNCTIONS instead of writing to the struct.
 *
 * HISTORY (2026-10-12, live device):
 *   - First working build (dylib loaded, all 4 hooks installed per the
 *     on-disk log, filtering logic ran correctly) still crashed Tinder --
 *     but at a DIFFERENT address, ~0.86s after launch, EXC_BAD_ACCESS/NULL
 *     deref inside Tinder's own code on a background dispatch queue, with
 *     FaceTecSDK not even loaded yet. The on-disk log's last line was
 *     Hooked_task_info swapping in our fake dyld_all_image_infos -- i.e. the
 *     crash followed immediately. Root cause: the global hook on
 *     _dyld_image_count/_dyld_get_image_header/_dyld_get_image_name/
 *     task_info patches the function for EVERY caller in the process, not
 *     just FaceTecSDK. Sentry (visible in the crash log: io.sentry.default
 *     queue, SentryCrash Exception Handler threads) calls
 *     task_info(TASK_DYLD_INFO) too, for its own crash-symbolication image
 *     list, and reads fields of dyld_all_image_infos beyond
 *     version/infoArrayCount/infoArray (e.g. uuidArray,
 *     dyldAllImageInfosAddress, sharedCache info) -- our fake struct only
 *     populated those 3 fields and calloc'd the rest to zero, so any such
 *     read landed on a NULL pointer.
 *   - FIX (this version), per explicit instruction: scope the filtering to
 *     FaceTecSDK ONLY. Every Hooked_* function now checks its caller's
 *     return address via dladdr() and only applies the filtered/fake view
 *     when the caller's image path contains "FaceTecSDK"; every other
 *     caller (Sentry, Swift runtime, anything else) gets the real,
 *     unmodified data straight from orig_*. This removes the collateral-
 *     damage class of bug entirely, independent of the struct-field issue.
 *   - Also fixed defensively: BuildFakeAllImageInfos now copies the ENTIRE
 *     real struct (`*fake = *realAII`) before overriding infoArrayCount/
 *     infoArray, instead of calloc'ing a 3-field struct -- so even a
 *     FaceTecSDK code path that reads some other field we didn't think of
 *     gets the real value, not a zeroed one.
 *
 * Deploy: drop ImageVeil.dylib + ImageVeil.plist (same basename) into
 *   /var/jb/usr/lib/TweakInject/
 * After a crash, read the log from the app's OWN Data container (the only place a
 * sandboxed app can reliably write -- NOT /var/mobile, NOT /var/jb). On the device:
 *   find /var/mobile/Containers/Data/Application -name jbhide_log.txt
 *   cat  <the path it prints>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

#pragma mark - File-backed diagnostic log

static void JBLog(const char *fmt, ...) {
    // Write into the app's OWN Data container, which a sandboxed app can ALWAYS write to (no jailbreak path, no
    // /var/jb, no /var/mobile rootfs). The container path is resolved at runtime via NSHomeDirectory() (looked up
    // with dlsym -- Foundation is already loaded in Tinder, so nothing extra needs to be linked at build time).
    // Resulting file:
    //   /var/mobile/Containers/Data/Application/<GUID>/Documents/jbhide_log.txt
    // Find it on the device (shell / Filza):
    //   find /var/mobile/Containers/Data/Application -name jbhide_log.txt
    static int fd = -2; // -2 = not yet tried, -1 = failed, >=0 = open
    if (fd == -2) {
        fd = -1;
        void *(*p_home)(void)        = (void *(*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
        void *(*p_msgSend)(void *, void *) = (void *(*)(void *, void *))dlsym(RTLD_DEFAULT, "objc_msgSend");
        void *(*p_sel)(const char *) = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "sel_registerName");
        if (p_home && p_msgSend && p_sel) {
            void *home = p_home();   // NSString* = this app's sandbox container
            const char *(*msg_cstr)(void *, void *) = (const char *(*)(void *, void *))p_msgSend;
            const char *base = home ? msg_cstr(home, p_sel("fileSystemRepresentation")) : NULL;
            if (base && base[0]) {
                char path[1024];
                snprintf(path, sizeof(path), "%s/Documents/jbhide_log.txt", base);
                fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (fd < 0) {   // no Documents? fall back to the container root
                    snprintf(path, sizeof(path), "%s/jbhide_log.txt", base);
                    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
                }
                if (fd >= 0) fchmod(fd, 0666);
            }
        }
    }
    if (fd < 0) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) write(fd, buf, (size_t)n);
    write(fd, "\n", 1);
}

#pragma mark - MSHookFunction, resolved at runtime via ElleKit

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

#pragma mark - Caller scoping: only filter for FaceTecSDK, pass real data to
#pragma mark   every other caller (Sentry, Swift runtime, etc.)

static bool CallerIsFaceTecSDK(void *retAddr) {
    Dl_info info;
    if (dladdr(retAddr, &info) && info.dli_fname) {
        return strstr(info.dli_fname, "FaceTecSDK") != NULL;
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
        bool blocked = PathBlocked(name);
        if (!blocked) tmp[n++] = i;
    }
    g_visible = tmp;
    g_visibleCount = n;
    JBLog("[BuildVisibleList] DONE real=%u visible=%u", real, n);
}

static uint32_t Hooked_dyld_image_count(void) {
    if (!CallerIsFaceTecSDK(__builtin_return_address(0)))
        return orig_dyld_image_count();
    pthread_once(&g_visibleOnce, BuildVisibleList);
    JBLog("[Hooked_dyld_image_count] FaceTecSDK caller -> %u", g_visibleCount);
    return g_visibleCount;
}

static const struct mach_header *Hooked_dyld_get_image_header(uint32_t idx) {
    if (!CallerIsFaceTecSDK(__builtin_return_address(0)))
        return orig_dyld_get_image_header(idx);
    pthread_once(&g_visibleOnce, BuildVisibleList);
    if (idx >= g_visibleCount) {
        JBLog("[Hooked_dyld_get_image_header] FaceTecSDK idx=%u >= visibleCount=%u -> NULL", idx, g_visibleCount);
        return NULL;
    }
    const struct mach_header *h = orig_dyld_get_image_header(g_visible[idx]);
    JBLog("[Hooked_dyld_get_image_header] FaceTecSDK idx=%u -> real_idx=%u header=%p", idx, g_visible[idx], h);
    return h;
}

static const char *Hooked_dyld_get_image_name(uint32_t idx) {
    if (!CallerIsFaceTecSDK(__builtin_return_address(0)))
        return orig_dyld_get_image_name(idx);
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
    kern_return_t kr = orig_task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&real, &cnt);
    if (kr != KERN_SUCCESS) {
        JBLog("[BuildFakeAllImageInfos] orig_task_info FAILED kr=%d", kr);
        return;
    }

    struct dyld_all_image_infos *realAII =
        (struct dyld_all_image_infos *)real.all_image_info_addr;
    if (!realAII) {
        JBLog("[BuildFakeAllImageInfos] realAII is NULL");
        return;
    }

    uint32_t n = realAII->infoArrayCount;
    struct dyld_image_info *filtered =
        (struct dyld_image_info *)malloc(sizeof(struct dyld_image_info) * (n ? n : 1));
    uint32_t kept = 0;
    for (uint32_t i = 0; i < n; i++) {
        struct dyld_image_info entry = realAII->infoArray[i];
        if (!PathBlocked(entry.imageFilePath)) filtered[kept++] = entry;
    }

    // Copy the WHOLE real struct first (preserves uuidArray, dyldAllImageInfosAddress,
    // sharedCache fields, notification pointers, everything we don't know about) --
    // then override only the two fields we actually mean to change. A previous version
    // calloc'd a bare 3-field struct, which was fine for FaceTecSDK's own reads but
    // crashed any OTHER caller reading a field we'd zeroed -- moot now that this is
    // caller-scoped to FaceTecSDK only, but kept as defense in depth.
    struct dyld_all_image_infos *fake =
        (struct dyld_all_image_infos *)malloc(sizeof(*fake));
    *fake = *realAII;
    fake->infoArrayCount = kept;
    fake->infoArray = filtered;
    g_fakeAII = fake;
    JBLog("[BuildFakeAllImageInfos] DONE real=%u kept=%u fakeAII=%p", n, kept, (void *)fake);
}

static kern_return_t Hooked_task_info(task_t target, task_flavor_t flavor,
                                       task_info_t info, mach_msg_type_number_t *cnt) {
    kern_return_t kr = orig_task_info(target, flavor, info, cnt);
    if (kr == KERN_SUCCESS && flavor == TASK_DYLD_INFO && target == mach_task_self()
        && CallerIsFaceTecSDK(__builtin_return_address(0))) {
        pthread_once(&g_fakeOnce, BuildFakeAllImageInfos);
        if (g_fakeAII) {
            JBLog("[Hooked_task_info] FaceTecSDK caller, TASK_DYLD_INFO on self -> swapping in fakeAII=%p", (void *)g_fakeAII);
            ((task_dyld_info_t)info)->all_image_info_addr = (uint64_t)g_fakeAII;
        }
    }
    return kr;
}

#pragma mark - init

__attribute__((constructor))
static void ImageVeilInit(void) {
    JBLog("===== ImageVeilInit START pid=%d =====", getpid());

    MSHookFunction_t MSHookFunction =
        (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!MSHookFunction) {
        // ElleKit is NOT auto-mapped into every injected process on Dopamine: TweakInject is only the loader, it
        // does not export MSHookFunction into our namespace unless ElleKit's own dylib is actually loaded.
        const char *ek[] = { "/var/jb/usr/lib/libellekit.dylib", "/var/jb/usr/lib/libsubstrate.dylib",
                             "libellekit.dylib", "libsubstrate.dylib", NULL };
        for (int i = 0; ek[i] && !MSHookFunction; i++) {
            void *h = dlopen(ek[i], RTLD_NOW | RTLD_GLOBAL);
            JBLog("dlopen(%s) = %p", ek[i], h);
            MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
        }
    }
    JBLog("MSHookFunction @ %p", (void *)MSHookFunction);
    if (!MSHookFunction) {
        JBLog("ElleKit could not be loaded -- bailing out");
        return;
    }

    void *p_count    = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    void *p_header   = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    void *p_name     = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    void *p_taskinfo = dlsym(RTLD_DEFAULT, "task_info");
    JBLog("dlsym: _dyld_image_count=%p _dyld_get_image_header=%p _dyld_get_image_name=%p task_info=%p",
          p_count, p_header, p_name, p_taskinfo);

    if (p_count) {
        MSHookFunction(p_count, (void *)Hooked_dyld_image_count, (void **)&orig_dyld_image_count);
        JBLog("hooked _dyld_image_count, orig=%p", (void *)orig_dyld_image_count);
    }
    if (p_header) {
        MSHookFunction(p_header, (void *)Hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
        JBLog("hooked _dyld_get_image_header, orig=%p", (void *)orig_dyld_get_image_header);
    }
    if (p_name) {
        MSHookFunction(p_name, (void *)Hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        JBLog("hooked _dyld_get_image_name, orig=%p", (void *)orig_dyld_get_image_name);
    }
    if (p_taskinfo) {
        MSHookFunction(p_taskinfo, (void *)Hooked_task_info, (void **)&orig_task_info);
        JBLog("hooked task_info, orig=%p", (void *)orig_task_info);
    }

    JBLog("===== ImageVeilInit DONE =====");
}
