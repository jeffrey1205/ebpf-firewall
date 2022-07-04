all:
	make -C ebpf
	go build -ldflags="-s -w"

clean:
	rm -f ebpf-fw
	make -C ebpf clean
