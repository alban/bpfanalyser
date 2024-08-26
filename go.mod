module github.com/alban/bpfanalyser

go 1.22.5

require github.com/cilium/ebpf v0.16.0

replace github.com/cilium/ebpf => github.com/alban/ebpf v0.0.0-20240826095622-885ad1037ff8

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
