package secmem

// LockOrder returns this buffer's process-unique registration ordinal. The
// value is stable for the buffer's whole lifetime and independent of where the
// GC or the OS places its memory. It exists so a caller that must hold two
// buffers' locks at once (e.g. a constant-time comparison of two secrets) can
// acquire them in one global order - ascending ordinal - and so never deadlock,
// regardless of argument order. It is meaningful ONLY for comparison against
// another buffer's ordinal; it is not an address and encodes nothing about
// memory layout or contents. A nil or never-registered buffer returns 0.
func (b *SecureBuffer) LockOrder() uint64 {
	if b == nil {
		return 0
	}
	return uint64(b.janitorKey)
}
