all:
	clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o

clean:
	rm -f bpf.o