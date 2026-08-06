#define _GNU_SOURCE

#include <errno.h>
#include <linux/personality.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Wine 11.9 treats a successful PER_LINUX32 personality call as proof that
 * the host can execute ARM32 Windows binaries.  Some ARM64 container kernels
 * accept that personality while the Hangover release contains no arm-windows
 * runtime.  Wineboot then creates sysarm32 and stalls while starting its
 * missing rundll32 dependencies (STATUS_DLL_NOT_FOUND / c0000135).
 *
 * Reject only Wine's capability probe.  All other personality operations are
 * passed straight to the kernel so this shim cannot silently change unrelated
 * process behaviour.
 */
int personality(unsigned long persona)
{
    if (persona == PER_LINUX32)
    {
        errno = EOPNOTSUPP;
        return -1;
    }
    return (int)syscall(SYS_personality, persona);
}
