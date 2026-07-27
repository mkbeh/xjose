package jwt

// exceedsLimit reports whether the length of value exceeds limit.
func exceedsLimit(value string, limit int) bool {
	return len(value) > limit
}
