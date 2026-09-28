//go:build !windows

package secmem

// forcedExitStatus is the process status used when [InstallTerminationWipe] has
// to terminate the process itself because the signal cannot be re-raised to any
// effect.
//
// Reached here when the signal was INHERITED AS IGNORED (SIGINT or SIGHUP; the
// runtime respects an inherited SIG_IGN for those two): the re-raise would be
// accepted by the kernel and discarded, so the installer exits with this
// status instead. For every other signal the re-raise is a real kill(2)
// against a restored default disposition, terminates the process, and this
// constant is not consulted.
//
// 130 is the shell convention for "terminated by SIGINT" (128 + 2). It is used
// whichever of the handler's signals arrived — a `nohup` child exiting on an
// inherited-ignored SIGHUP reports 130 too — because the inherited ignore
// means there is no un-intercepted status to match, unlike on Windows.
const forcedExitStatus = 130
