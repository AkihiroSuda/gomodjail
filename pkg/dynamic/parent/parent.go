package parent

import (
	"io"

	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/tracer"
	"github.com/AkihiroSuda/gomodjail/pkg/profile"
)

func Main(profile *profile.Profile, args []string) error {
	cmd, err := createCmd(args)
	if err != nil {
		return err
	}
	tr, err := tracer.New(cmd, profile)
	if err != nil {
		return err
	}
	if trC, ok := tr.(io.Closer); ok {
		defer trC.Close() //nolint:errcheck
	}
	return tr.Trace()
}
