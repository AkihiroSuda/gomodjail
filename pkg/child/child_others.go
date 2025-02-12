//go:build !linux

package child

import "errors"

func Main(_ []string) error {
	return errors.New("unexpected code path")
}
