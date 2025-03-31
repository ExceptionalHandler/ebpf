package link

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// ntosebpfext has not yet assigned a stable enum value so we can't refer to
// it via that (https://github.com/microsoft/ntosebpfext/issues/152).
//
// See https://github.com/microsoft/ntosebpfext/blob/75ceaac38a0254e44f3219852d79a336d10ad9f3/include/ebpf_ntos_program_attach_type_guids.h
var (
	programTypeProcessGUID = makeGUID(0x22ea7b37, 0x1043, 0x4d0d, [8]byte{0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e})
	attachTypeProcessGUID  = makeGUID(0x66e20687, 0x9805, 0x4458, [8]byte{0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85})
)

func testLinkArch(t *testing.T, link Link) {}

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
		Type: windowsProgramTypeForGUID(t, programTypeProcessGUID),
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
	if errors.Is(err, unix.EINVAL) {
		t.Logf("Got %s: check that ntosebpfext is installed", err)
	}
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  windowsAttachTypeForGUID(t, attachTypeProcessGUID),
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()

	qt.Assert(t, qt.IsNil(exec.Command("cmd.exe", "/c", "exit 0").Run()))

	var value uint32
	qt.Assert(t, qt.IsNil(array.Lookup(uint32(0), &value)))
	qt.Assert(t, qt.Equals(value, 1), qt.Commentf("Executing a binary should trigger the program"))

	qt.Assert(t, qt.IsNil(link.Close()))
}

func makeGUID(data1 uint32, data2 uint16, data3 uint16, data4 [8]byte) windows.GUID {
	return windows.GUID{Data1: data1, Data2: data2, Data3: data3, Data4: data4}
}

func TestNativeExecGood(t *testing.T) {

	coll, err := ebpf.LoadCollection("C:\\git\\ntosebpfext\\x64\\Debug\\process_monitor_km\\process_monitor.sys")
	qt.Assert(t, qt.IsNil(err))
	defer coll.Close()

	for _, m := range coll.Maps {
		info, err := m.Info()
		qt.Assert(t, qt.IsNil(err))
		t.Log("map", info.Name)
		if strings.Contains(info.Name, "ring") {
			//ringBufMap = m
		}
	}

	link, err := AttachRawLink(RawLinkOptions{
		Program: coll.Programs["ProcessMonitor"],
		Attach:  windowsAttachTypeForGUID(t, attachTypeProcessGUID),
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()

	coll.Programs["ProcessMonitor"].Pin("__base__//process")

	ringBufMap := coll.Maps["process_ringbuf"]
	//commandMap := coll.Maps["command_map"]
	processMap := coll.Maps["process_map"]

	reader := efw.GetNewWindowsRingBufReader()
	err = reader.Init(ringBufMap.FD(), int(ringBufMap.MaxEntries()))
	qt.Assert(t, qt.IsNil(err))

	for {
		//var cmdline [1024]uint16
		var imageFile [1024]byte
		var procInfo *efw.ProcessInfo
		procInfo, err := reader.GetNextProcess()
		if (err == efw.ERR_RINGBUF_OFFSET_MISMATCH) || (err == efw.ERR_RINGBUF_UNKNOWN_ERROR) {
			break
		}
		if (err == efw.ERR_RINGBUF_TRY_AGAIN) || (err == efw.ERR_RINGBUF_RECORD_DISCARDED) {
			continue
		}
		if procInfo.Operation == 0 {
			t.Log("pid = ", procInfo.ProcessId)
			// commandMap.Lookup(procInfo.ProcessId, &cmdline)
			// pathStr := windows.UTF16ToString(cmdline[:])
			// t.Log("cmdLine = ", pathStr)

			mapErr := processMap.Lookup(procInfo.ProcessId, &imageFile)
			if mapErr != nil {
				t.Log("error  = ", mapErr.Error())
			}
			var s *uint16
			s = (*uint16)(unsafe.Pointer(&imageFile[0]))
			imageStr := windows.UTF16PtrToString(s)
			t.Log("imagePath  = ", imageStr)

		}

	}

}

func TestNativeExecBad(t *testing.T) {

	windows.MessageBox(0, windows.StringToUTF16Ptr("OK"), windows.StringToUTF16Ptr("ok"), windows.MB_OK)
	coll, err := ebpf.LoadCollection("C:\\git\\ntosebpfext\\x64\\Debug\\process_monitor_km\\process_monitor.sys")
	qt.Assert(t, qt.IsNil(err))
	defer coll.Close()

	for _, m := range coll.Maps {
		info, err := m.Info()
		qt.Assert(t, qt.IsNil(err))
		t.Log("map", info.Name)
		if strings.Contains(info.Name, "ring") {
			//ringBufMap = m
		}
	}

	_, err = AttachRawLink(RawLinkOptions{
		Program: coll.Programs["ProcessMonitor"],
		Attach:  windowsAttachTypeForGUID(t, attachTypeProcessGUID),
	})
	qt.Assert(t, qt.IsNil(err))

	coll.Programs["ProcessMonitor"].Pin("__base__//process")

	coll.Maps["process_ringbuf"].Pin("process::process_ringbuf")
	coll.Maps["command_map"].Pin("process::command_map")

}

func TestPreLoadedMaps(t *testing.T) {
	//windows.MessageBox(0, windows.StringToUTF16Ptr("OK"), windows.StringToUTF16Ptr("ok"), windows.MB_OK)
	runtime.LockOSThread()
	pinOpts := ebpf.LoadPinOptions{}
	ringBufMap, err := ebpf.LoadPinnedMap("process::process_ringbuf", &pinOpts)
	qt.Assert(t, qt.IsNil(err))
	pinOpts = ebpf.LoadPinOptions{}
	commandMap, err := ebpf.LoadPinnedMap("process::command_map", &pinOpts)
	qt.Assert(t, qt.IsNil(err))

	reader := efw.GetNewWindowsRingBufReader()
	err = reader.Init(ringBufMap.FD(), int(ringBufMap.MaxEntries()))
	qt.Assert(t, qt.IsNil(err))
	//reader.SyncOffsets()
	for {
		var path [1024]uint16
		var procInfo *efw.ProcessInfo
		procInfo, err := reader.GetNextProcess()
		if (err == efw.ERR_RINGBUF_OFFSET_MISMATCH) || (err == efw.ERR_RINGBUF_UNKNOWN_ERROR) {
			break
		}
		if (err == efw.ERR_RINGBUF_TRY_AGAIN) || (err == efw.ERR_RINGBUF_RECORD_DISCARDED) {
			continue
		}
		if procInfo.Operation == 0 {
			t.Log("pid = ", procInfo.ProcessId)
			commandMap.Lookup(procInfo.ProcessId, &path)
			pathStr := windows.UTF16ToString(path[:])
			t.Log("cmdLine = ", pathStr)
		}

	}

}

func TestUnpin(t *testing.T) {
	sys.Unpin("process::process_ringbuf")
	sys.Unpin("process::command_map")
	sys.Unpin("process::process_map")
}
