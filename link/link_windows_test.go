package link

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/errno"
)

func testLinkArch(t *testing.T, link Link) {
	// TODO(windows): Are there win specific behaviour we should test?
}

func newRawLink(t *testing.T) (*RawLink, *ebpf.Program) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.WindowsBind,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { prog.Close() })

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsBind,
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { link.Close() })

	return link, prog
}

func TestProcessLink(t *testing.T) {
	array, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.WindowsArray,
		Name:       "process_state",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, qt.IsNil(err))
	defer array.Close()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.WindowsProcess,
		Name: "process_test",
		Instructions: asm.Instructions{
			// R1 = map
			asm.LoadMapPtr(asm.R1, array.FD()),
			// R2 = key
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),
			// R3 = value
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.Add.Imm(asm.R3, -4),
			asm.StoreImm(asm.R3, 0, 1, asm.Word),
			// R4 = flags
			asm.Mov.Imm(asm.R4, 0),
			// bpf_map_update_elem(map, key, value, flags)
			asm.WindowsFnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if errors.Is(err, errno.EINVAL) {
		t.Logf("Got %s: check that ntosebpfext is installed", err)
	}
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsProcess,
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()

	qt.Assert(t, qt.IsNil(exec.Command("cmd.exe", "/c", "exit 0").Run()))

	var value uint32
	qt.Assert(t, qt.IsNil(array.Lookup(uint32(0), &value)))
	qt.Assert(t, qt.Equals(value, 1), qt.Commentf("Executing a program should trigger the program"))

	qt.Assert(t, qt.IsNil(link.Close()))
}

func TestExec(t *testing.T) {

	spec, err := ebpf.LoadCollectionSpec("C:\\git\ntosebpfext\\x64\\Debug\\process_monitor_km\\process_monitor.o")
	qt.Assert(t, qt.IsNil(err))

	for name, m := range spec.Maps {
		fmt.Println(m.Type, name)
	}

	for name, p := range spec.Programs {
		fmt.Println(name, p.Type, p.SectionName)
	}
	var progSpec = spec.Programs["ProcessMonitor"]
	progSpec.Type = ebpf.WindowsProcess
	fmt.Println(progSpec.Instructions)
	prog, err := ebpf.NewProgram(progSpec)
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsProcess,
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()
}
