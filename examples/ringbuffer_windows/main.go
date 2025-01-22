//go:build windows

package main

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Parse an ELF into a CollectionSpec.
	f, err := os.Open("process_monitor.o")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	spec, err := ebpf.LoadCollectionSpec("process_monitor.o")
	if err != nil {
		panic(err)
	}

	// Look up the MapSpec and ProgramSpec in the CollectionSpec.
	// for name, m := range spec.Maps {
	// 	fmt.Println(m.Type, name)
	// }

	// for name, p := range spec.Programs {
	// 	fmt.Println(name, p.Type, p.SectionName)
	// }
	var progSpec = spec.Programs["ProcessMonitor"]
	progSpec.Type = ebpf.WindowsProcess

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	link, err := link.AttachRawLink(link.RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsProcess,
	})
	if err != nil {
		panic(err)
	}
	defer link.Close()

	// Close the Collection before the enclosing function returns.
}
