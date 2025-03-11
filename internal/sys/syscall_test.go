package sys

import (
	"errors"
	"math"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/errno"
	"github.com/cilium/ebpf/internal/testutils/testmain"

	"github.com/go-quicktest/qt"
)

func TestBPF(t *testing.T) {
	fd, err := MapCreate(&MapCreateAttr{
		MapType:    BPF_MAP_TYPE_HASH,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(fd.Close()))
}

func TestBPFAllocations(t *testing.T) {
	n := testing.AllocsPerRun(10, func() {
		var attr struct {
			Foo uint64
		}

		BPF(math.MaxUint32, unsafe.Pointer(&attr), 0)
	})
	qt.Assert(t, qt.Equals(n, 0))
}

func TestObjName(t *testing.T) {
	name := NewObjName("more_than_16_characters_long")
	if name[len(name)-1] != 0 {
		t.Error("NewBPFObjName doesn't null terminate")
	}
	if len(name) != BPF_OBJ_NAME_LEN {
		t.Errorf("Name is %d instead of %d bytes long", len(name), BPF_OBJ_NAME_LEN)
	}
}

func TestSyscallError(t *testing.T) {
	err := errors.New("foo")
	foo := Error(err, errno.EINVAL)

	if !errors.Is(foo, errno.EINVAL) {
		t.Error("SyscallError is not the wrapped errno")
	}

	if !errors.Is(foo, err) {
		t.Error("SyscallError is not the wrapped error")
	}

	if errors.Is(errno.EINVAL, foo) {
		t.Error("Errno is the SyscallError")
	}

	if errors.Is(err, foo) {
		t.Error("Error is the SyscallError")
	}
}

func TestMain(m *testing.M) {
	testmain.Run(m)
}
