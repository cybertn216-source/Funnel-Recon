// Character-entropy heuristic used only with context, never alone.
package secretanalyzer

import "math"

// ShannonEntropy measures character variation, not credential validity.
// Apply it only after a contextual signature has already matched.
func ShannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[byte]int)
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(value))
		entropy -= p * math.Log2(p)
	}
	return entropy
}
