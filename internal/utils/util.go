package utils

// UniqueStringSlice returns a new slice with duplicate strings removed.
func UniqueStringSlice(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range input {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
