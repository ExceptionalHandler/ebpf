package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

func AttachRawLink(opts RawLinkOptions) (*RawLink, error) {
	if opts.Target != 0 || opts.BTF != 0 || opts.Flags != 0 {
		return nil, fmt.Errorf("specified option(s) %w", internal.ErrNotSupportedOnOS)
	}
	fmt.Println("Here 1")

	p, attachType := opts.Attach.Decode()
	if p != ebpf.Windows {
		return nil, fmt.Errorf("attach type %s: %w", opts.Attach, internal.ErrNotSupportedOnOS)
	}
	fmt.Println("Here 2")

	attachTypeGUID, err := efw.EbpfGetEbpfAttachType(attachType)
	if err != nil {
		return nil, fmt.Errorf("get attach type: %w", err)
	}
	fmt.Println("Here 3")

	raw, err := efw.EbpfProgramAttachByFd(opts.Program.FD(), &attachTypeGUID)
	if err != nil {
		return nil, fmt.Errorf("attach link: %w", err)
	}
	fmt.Println("Here 4")

	fd, err := sys.NewFD(int(raw))
	if err != nil {
		return nil, err
	}
	fmt.Println("Here 5")

	return &RawLink{fd: fd}, nil
}

func wrapRawLink(raw *RawLink) (Link, error) {
	return raw, nil
}
