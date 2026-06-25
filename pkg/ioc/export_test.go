package ioc

// NormalizeForTest exposes normalizeMatchInput to the external test
// package so the NFKC contract can be exercised end-to-end without
// promoting the helper to the public surface.
func NormalizeForTest(s string) string {
	return normalizeMatchInput(s)
}
