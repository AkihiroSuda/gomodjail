package cache

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AkihiroSuda/gomodjail/pkg/env"
)

func ExecutableDir() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	cacheHome, err := Home()
	if err != nil {
		return "", fmt.Errorf("failed to resolve GOMODJAIL_CACHE_HOME: %w", err)
	}

	selfPathDigest := sha256sum([]byte(selfPath))
	selfPathDigestPartial := selfPathDigest[0:16]

	dir := filepath.Join(cacheHome, selfPathDigestPartial)
	return dir, nil
}

func sha256sum(b []byte) string {
	h := sha256.New()
	if _, err := h.Write(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Home candidates are:
// - $GOMODJAIL_CACHE_HOME
// - $XDG_CACHE_HOME/gomodjail
func Home() (string, error) {
	if cacheHome := os.Getenv(env.CacheHome); cacheHome != "" {
		return cacheHome, nil
	}
	osCacheHome, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cacheHome := filepath.Join(osCacheHome, "gomodjail")
	return cacheHome, nil
}
