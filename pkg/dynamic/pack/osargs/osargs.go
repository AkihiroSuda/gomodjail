package osargs

import "os"

var overridden []string

func OSArgs() []string {
	if overridden != nil {
		return overridden
	}
	return os.Args
}

func SetOSArgs(override []string) {
	overridden = override
}
