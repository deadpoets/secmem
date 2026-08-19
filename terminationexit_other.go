//go:build !windows

package secmem

// forcedExitStatus is the process status used when [InstallTerminationWipe] has
// to terminate the process itself because the signal cannot be re-raised.
//
// Unreachable in practice here: everywhere except Windows the re-raise is a real
// kill(2) against a restored default disposition, so it terminates the process
// and this constant is never consulted. It exists so the fallback is defined
// rather than platform-conditional at the call site.
//
// 130 is the shell convention for "terminated by SIGINT" (128 + 2).
const forcedExitStatus = 130
