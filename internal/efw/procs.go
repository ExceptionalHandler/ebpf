//go:build windows

package efw

import (
	"unsafe"
)

// ebpf_result_t ebpf_dup_fd(fd_t fd, _Out_ fd_t* dup)
var ebpfDupFdProc = newProc("ebpf_dup_fd")

func EbpfDupFd(fd int) (int, error) {
	var dup FD
	err := ebpfDupFdProc.CallResult(uintptr(fd), uintptr(unsafe.Pointer(&dup)))
	return int(dup), err
}

/*
ebpf_result_t ebpf_object_load_native_fds(

	_In_z_ const char* file_name,
	_Inout_ size_t* count_of_maps,
	_Out_writes_opt_(count_of_maps) fd_t* map_fds,
	_Inout_ size_t* count_of_programs,
	_Out_writes_opt_(count_of_programs) fd_t* program_fds)
*/

// Call a function which returns a C int.
//
//go:uintptrescapes

// Call a function which returns fd_t.
//
//go:uintptrescapes
