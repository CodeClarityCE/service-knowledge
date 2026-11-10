// Package override swaps package variables, such as upstream URLs, for tests.
package override

// Set sets *v to value and returns a function that puts the old value back.
func Set[T any](v *T, value T) (restore func()) {
	original := *v
	*v = value
	return func() { *v = original }
}

// All returns a function that runs every restore, last first.
func All(restores ...func()) (restore func()) {
	return func() {
		for i := len(restores) - 1; i >= 0; i-- {
			restores[i]()
		}
	}
}
