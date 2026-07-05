package capslock

import "github.com/google/capslock/interesting"

// LoadClassifierForTest exposes the merged classifier (Capslock builtin +
// gomodjail.cm overrides) to the pinning test in capslock_test.
func LoadClassifierForTest() (*interesting.Classifier, error) {
	return loadClassifier()
}
