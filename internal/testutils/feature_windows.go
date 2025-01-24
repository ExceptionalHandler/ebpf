package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
)

func runtimeVersion(tb testing.TB) internal.Version {
	tb.Helper()
	// TODO(windows): We need a function which exposes the efW runtime version.
	// Probably need to contribute this upstream.
	tb.Fatal("runtimeVersion() not implemented yet")
	return internal.Version{}
}
