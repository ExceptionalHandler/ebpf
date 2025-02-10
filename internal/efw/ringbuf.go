//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ()

var (
	ModuleNt                 = windows.NewLazySystemDLL("ntdll.dll")
	ModuleKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	NtQuerySystemInformation = ModuleNt.NewProc("NtQuerySystemInformation")
	CreateFileW              = ModuleKernel32.NewProc("CreateFileW")
	DeviceIoControl          = ModuleKernel32.NewProc("DeviceIoControl")
	WaitForSingleObject      = ModuleKernel32.NewProc("WaitForSingleObject")
	CreateEventW             = ModuleKernel32.NewProc("CreateEventW")
	ResetEvent               = ModuleKernel32.NewProc("ResetEvent")
)
var ebpfGetHandleFromFd = newProc("ebpf_get_handle_from_fd")

type _ebpf_operation_header struct {
	length uint16
	id     uint32
}

type _ebpf_operation_ring_buffer_map_query_buffer_request struct {
	header     _ebpf_operation_header
	map_handle uintptr
}

type _ebpf_operation_ring_buffer_map_query_buffer_reply struct {
	header          _ebpf_operation_header
	buffer_address  uint64
	consumer_offset uint64
}

type _ebpf_operation_ring_buffer_map_async_query_request struct {
	header          _ebpf_operation_header
	map_handle      uintptr
	consumer_offset uint64
}
type _ebpf_ring_buffer_map_async_query_result struct {
	producer uint64
	consumer uint64
}

type _ebpf_operation_ring_buffer_map_async_query_reply struct {
	header             _ebpf_operation_header
	async_query_result _ebpf_ring_buffer_map_async_query_result
}

type ebpf_ring_buffer_record struct {
	locked    uint8
	discarded uint8
	length    uint32
	data      [1]uint8
}

type process_info struct {
	process_id          uint32
	parent_process_id   uint32
	creating_process_id uint32
	creating_thread_id  uint32
	creation_time       uint64
	exit_time           uint64
	process_exit_code   uint32
	operation           uint8
}

var (
	hSync            uintptr = INVALID_HANDLE_VALUE
	hASync           uintptr = INVALID_HANDLE_VALUE
	hOverlappedEvent uintptr = INVALID_HANDLE_VALUE
	io_pending_err           = error(syscall.Errno(windows.ERROR_IO_PENDING))
	success_err              = error(syscall.Errno(windows.ERROR_SUCCESS))
)

const (
	ERROR_SUCCESS           = 0
	ERROR_ACCESS_DENIED     = 5
	ERROR_INVALID_PARAMETER = 87
	FILE_DEVICE_NETWORK     = 0x12
	FILE_ANY_ACCESS         = 0
	METHOD_BUFFERED         = 0
	INVALID_HANDLE_VALUE    = ^uintptr(0)
)

func CTL_CODE(DeviceType, Function, Method, Access uint32) uint32 {
	return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
}

func invokeIoctl(request unsafe.Pointer, dwReqSize uint32, response unsafe.Pointer, dwRespSize uint32, overlapped unsafe.Pointer) error {
	var actualReplySize uint32
	var requestSize uint32 = dwReqSize
	var requestPtr unsafe.Pointer = request
	var replySize uint32 = dwRespSize
	var replyPtr unsafe.Pointer = response
	var variableReplySize bool = false
	var err error
	var hDevice uintptr = INVALID_HANDLE_VALUE

	if overlapped == nil {
		if hSync == INVALID_HANDLE_VALUE {
			hSync, _, err = CreateFileW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`\\.\EbpfIoDevice`))),
				uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
				0,
				0,
				uintptr(syscall.CREATE_ALWAYS),
				0,
				0,
			)
			if hSync == INVALID_HANDLE_VALUE {
				return err
			}
			hDevice = hSync
		}
	} else {
		if hASync == INVALID_HANDLE_VALUE {
			hASync, _, err = CreateFileW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`\\.\EbpfIoDevice`))),
				uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
				0,
				0,
				uintptr(syscall.CREATE_ALWAYS),
				uintptr(syscall.FILE_FLAG_OVERLAPPED),
				0,
			)
			if hASync == INVALID_HANDLE_VALUE {
				return err
			}
		}
		hDevice = hASync
	}
	if hDevice == INVALID_HANDLE_VALUE {
		return fmt.Errorf("Erro Opening Device")
	}

	success, _, err := DeviceIoControl.Call(
		uintptr(hDevice),
		uintptr(CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)),
		uintptr(requestPtr),
		uintptr(requestSize),
		uintptr(replyPtr),
		uintptr(replySize),
		uintptr(unsafe.Pointer(&actualReplySize)),
		uintptr(overlapped),
	)
	if (overlapped != nil) && (success == 0) && (err == io_pending_err) {
		success = 1
		err = nil
	}

	if success == 0 {
		fmt.Printf("Device io control failed. Error = %d\n", syscall.GetLastError())
		return err
	}

	if actualReplySize != replySize && !variableReplySize {
		fmt.Printf("\nDevice io control incorrect reply. ")
		return err
	}
	return nil

}

func EbpfGetHandleFromFd(fd int) (uintptr, error) {
	var handle uintptr
	err := ebpfGetHandleFromFd.CallResult(uintptr(fd), uintptr(unsafe.Pointer(&handle)))
	return handle, err
}

func GetOverlappedEvent() uintptr {
	var err error
	if hOverlappedEvent == INVALID_HANDLE_VALUE {
		hOverlappedEvent, _, err = CreateEventW.Call(0, 0, 0, 0)
		if err != error(syscall.Errno(0)) {
			fmt.Printf("Error = %s", err.Error())
		}
		ResetEvent.Call(hOverlappedEvent)
	}
	return hOverlappedEvent
}

func EbpfRingBufferNextRecord(buffer []byte, bufferLength, consumer, producer uint64) *ebpf_ring_buffer_record {
	if producer < consumer {
		return nil
	}
	if producer == consumer {
		return nil
	}
	return (*ebpf_ring_buffer_record)(unsafe.Pointer(&buffer[consumer%bufferLength]))
}

func GetRigbufEvents(fd int, ring_buffer_size int) error {
	if fd <= 0 {
		return fmt.Errorf("Invalid FD provided")
	}
	handle, err := EbpfGetHandleFromFd(fd)
	if err != nil {
		return fmt.Errorf("Cannot get handle from FD")
	}
	var map_handle windows.Handle
	err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(handle), windows.CurrentProcess(), &map_handle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return fmt.Errorf("Cannot duplicate handle")
	}
	var req _ebpf_operation_ring_buffer_map_query_buffer_request
	req.map_handle = uintptr(handle)
	req.header.id = 28
	req.header.length = uint16(unsafe.Sizeof(req))
	var reply _ebpf_operation_ring_buffer_map_query_buffer_reply

	err = invokeIoctl(unsafe.Pointer(&req), uint32(unsafe.Sizeof(req)), unsafe.Pointer(&reply), uint32(unsafe.Sizeof(reply)), nil)
	if err != nil {
		return fmt.Errorf("Failed to do device io control")
	}
	var buffer uintptr
	buffer = uintptr(reply.buffer_address)
	byteBuf := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), ring_buffer_size)

	var async_query_request _ebpf_operation_ring_buffer_map_async_query_request
	async_query_request.header.length = uint16(unsafe.Sizeof(async_query_request))
	async_query_request.header.id = 29
	async_query_request.map_handle = uintptr(handle)
	async_query_request.consumer_offset = reply.consumer_offset

	for {
		var async_reply _ebpf_operation_ring_buffer_map_async_query_reply
		var overlapped syscall.Overlapped
		overlapped.HEvent = syscall.Handle(GetOverlappedEvent())
		err = invokeIoctl(unsafe.Pointer(&async_query_request), uint32(unsafe.Sizeof(async_query_request)), unsafe.Pointer(&async_reply), uint32(unsafe.Sizeof(async_reply)), unsafe.Pointer(&overlapped))
		if err == error(syscall.Errno(997)) {
			err = nil
		}
		if err != nil {
			fmt.Printf(err.Error())
			return fmt.Errorf("Failed to do async device io control")
		}
		waitReason, _, err := WaitForSingleObject.Call(uintptr(overlapped.HEvent), syscall.INFINITE)
		if err != success_err {
			return err
		}
		if waitReason != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("Failed in wait function")

		}
		windows.ResetEvent(windows.Handle(overlapped.HEvent))

		var async_query_result *_ebpf_ring_buffer_map_async_query_result = (*_ebpf_ring_buffer_map_async_query_result)(unsafe.Pointer(&(async_reply.async_query_result)))
		var consumer uint64 = async_query_result.consumer
		var producer uint64 = async_query_result.producer
		for {

			record := EbpfRingBufferNextRecord(byteBuf, uint64(ring_buffer_size), consumer, producer)
			if record == nil {
				break
			}
			procInfo := (*process_info)(unsafe.Pointer(&(record.data)))
			fmt.Printf("Pid = %d", procInfo.process_id)

			consumer += uint64(record.length)
		}
		async_query_request.consumer_offset = consumer
	}

}
