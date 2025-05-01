package cache

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

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
// - $XDG_RUNTIME_DIR/gomodjail
// - $TMPDIR/gomodjail (macOS)
// - $XDG_CACHE_HOME/gomodjail
func Home() (string, error) {
	if cacheHome := os.Getenv(env.CacheHome); cacheHome != "" {
		return cacheHome, nil
	}
	if xrd := xdgRuntimeDir(); xrd != "" {
		cacheHome := filepath.Join(xrd, "gomodjail")
		return cacheHome, nil
	}
	if runtime.GOOS == "darwin" {
		// macOS allocates a unique TMPDIR per user
		if td := os.Getenv("TMPDIR"); td != "" {
			cacheHome := filepath.Join(td, "gomodjail")
			return cacheHome, nil
		}
	}
	osCacheHome, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cacheHome := filepath.Join(osCacheHome, "gomodjail")
	return cacheHome, nil
}

func xdgRuntimeDir() string {
	if xrd := os.Getenv("XDG_RUNTIME_DIR"); xrd != "" {
		return xrd
	}
	xrd := filepath.Join("run", "user", strconv.Itoa(os.Geteuid()))
	if _, err := os.Stat(xrd); err == nil {
		return xrd
	}
	return ""
}
