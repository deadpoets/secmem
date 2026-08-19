//go:build windows

package secmem

// forcedExitStatus is the process status used when [InstallTerminationWipe] has
// to terminate the process itself because the signal cannot be re-raised.
//
// 0xC000013A is STATUS_CONTROL_C_EXIT — exactly what Windows produces when a
// console Ctrl-C terminates a process that did not intercept it. Matching it is
// the point: a parent, a batch file or a CI step must not be able to tell a
// secmem-wrapped process apart from an un-wrapped one by its exit status, or
// installing the wipe would silently change how every caller's tooling reads a
// cancellation.
//
// Written as the signed 32-bit value so the constant fits an int on 386 as well
// as amd64; os.Exit narrows to int32 and Windows receives 0xC000013A either way.
const forcedExitStatus = -1073741510
