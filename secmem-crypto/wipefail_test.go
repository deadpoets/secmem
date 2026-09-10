package secmemcrypto

import "errors"

// errWipeSimulated stands in for a reflection wipe that could not locate
// its target, so the fail-closed contract of each caller can be exercised
// without a foreign toolchain.
var errWipeSimulated = errors.New("simulated: layout not found; NOT wiped")
