# ebpf-fw

Requires Linux >= 4.10 (ie. CentOS 8 or Ubuntu 17.04).

Great eBPF reference: [https://docs.cilium.io/en/v1.9/bpf/](https://docs.cilium.io/en/v1.9/bpf/)

## Requirements

Building requires the following on CentOS 8:
`yum install -y clang llvm go`
or on Ubuntu:
`apt install -y clang llvm golang make`

cgroup2 FS must be mounted. By default it looks for it on `/sys/fs/cgroup/unified` but if it's not mounted there you can do:

```
sudo mkdir /mnt/cgroup2
sudo mount -t cgroup2 none /mnt/cgroup2
```

and change the path to `/mnt/cgroup2` in `ebpf-fw.go`

## Building

`make`

## Running

**All must run as root**.

Configure rules:

./conf/rule.json

Load eBPF with:
`./ebpf-fw load`

Unload eBPF with:
`./ebpf-fw unload`

Show tracked connections with:
`./ebpf-fw show`

Issue rule:
`./ebpf-fw issue`

Revoke rule:
`./ebpf-fw revoke`
