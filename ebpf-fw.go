package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// cilium unmarshal使用，首字母需大写
type record struct {
	Flags uint16
	TTL   uint8
	Proto uint8
	DstIP uint32
	SrcIP uint32
	Sport uint16
	Dport uint16
	ID    uint32
}

const (
	rootCgroup      = "/sys/fs/cgroup/unified"
	ebpfFS          = "/sys/fs/bpf"
	flowMapName     = "flows_map"
	saddrMapName    = "saddr_map"
	daddrMapName    = "daddr_map"
	protoMapName    = "proto_map"
	sportMapName    = "sport_map"
	dportMapName    = "dport_map"
	actionMapName   = "action_map"
	bpfCodePath     = "./ebpf/bpf.o"
	egressProgName  = "egress"
	ingressProgName = "ingress"
)

var ingressProg, egressProg *ebpf.Program
var bpfOutputMap, bpfSaddrMap, bpfDaddrMap, bpfProtoMap, bpfSportMap, bpfDportMap, bpfActionMap *ebpf.Map

var ingressPinPath = filepath.Join(ebpfFS, ingressProgName)
var egressPinPath = filepath.Join(ebpfFS, egressProgName)
var flowPinPath = filepath.Join(ebpfFS, flowMapName)
var saddrPinPath = filepath.Join(ebpfFS, saddrMapName)
var daddrPinPath = filepath.Join(ebpfFS, daddrMapName)
var protoPinPath = filepath.Join(ebpfFS, protoMapName)
var sportPinPath = filepath.Join(ebpfFS, sportMapName)
var dportPinPath = filepath.Join(ebpfFS, dportMapName)
var actionPinPath = filepath.Join(ebpfFS, actionMapName)

func uintToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func ipToUint(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

// 大小端互换
func lbSwap16(val uint16) uint16 {
	return ((val&0x00ff)<<8 | (val&0xff00)>>8)
}

// 加载二进制代码到内核
func progLoad() {
	collec, err := ebpf.LoadCollection(bpfCodePath)
	if err != nil {
		fmt.Println("Load bpf code error:", err)
		return
	}

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		fmt.Println("Open root cgroup error:", err)
		return
	}
	defer cgroup.Close()

	ingressProg = collec.Programs[ingressProgName]
	if err = ingressProg.Pin(ingressPinPath); err != nil {
		fmt.Println("pin ingressPinPath error", err)
	}

	egressProg = collec.Programs[egressProgName]
	if err = egressProg.Pin(egressPinPath); err != nil {
		fmt.Println("pin egressPinPath error", err)
	}

	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: collec.Programs[ingressProgName],
	})
	if err != nil {
		fmt.Println("Attach ingress root cgroup error:", err)
		return
	}

	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: collec.Programs[egressProgName],
	})
	if err != nil {
		fmt.Println("Attach egress root cgroup error:", err)
		return
	}

	bpfOutputMap, _ = collec.Maps[flowMapName]
	if err = bpfOutputMap.Pin(flowPinPath); err != nil {
		fmt.Println("pin flowPinPath error", err)
	}

	bpfSaddrMap, _ = collec.Maps[saddrMapName]
	if err = bpfSaddrMap.Pin(saddrPinPath); err != nil {
		fmt.Println("pin saddrPinPath error", err)
	}

	bpfDaddrMap, _ = collec.Maps[daddrMapName]
	if err = bpfDaddrMap.Pin(daddrPinPath); err != nil {
		fmt.Println("pin daddrPinPath error", err)
	}

	bpfProtoMap, _ = collec.Maps[protoMapName]
	if err = bpfProtoMap.Pin(protoPinPath); err != nil {
		fmt.Println("pin protoPinPath error", err)
	}

	bpfSportMap, _ = collec.Maps[sportMapName]
	if err = bpfSportMap.Pin(sportPinPath); err != nil {
		fmt.Println("pin sportPinPath error", err)
	}

	bpfDportMap, _ = collec.Maps[dportMapName]
	if err = bpfDportMap.Pin(dportPinPath); err != nil {
		fmt.Println("pin dportPinPath error", err)
	}

	bpfActionMap, _ = collec.Maps[actionMapName]
	if err = bpfActionMap.Pin(actionPinPath); err != nil {
		fmt.Println("pin actionPinPath error", err)
	}

	fmt.Println("Load eBPF Success")
}

// 从内核卸载二进制代码
func progUnLoad() {
	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		fmt.Println("open cgroup error:", err)
		return
	}
	defer cgroup.Close()

	err = ingressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetIngress, 0)
	if err != nil {
		fmt.Println("Detach ingress error:", err)
	}

	err = egressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)
	if err != nil {
		fmt.Println("Detach egress error:", err)
	}

	// MAP是否需要unpin？

	os.Remove(ingressPinPath)
	os.Remove(egressPinPath)
	os.Remove(flowPinPath)
	os.Remove(saddrPinPath)
	os.Remove(daddrPinPath)
	os.Remove(protoPinPath)
	os.Remove(sportPinPath)
	os.Remove(dportPinPath)
	os.Remove(actionPinPath)
	fmt.Println("UnLoad eBPF Success")
}

//显示内核检测到的连接
func connShow() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	ticker := time.NewTicker(100 * time.Millisecond)

outer_loop:
	for {
		select {
		case <-ticker.C:
			var val record
			for bpfOutputMap.LookupAndDelete(nil, &val) == nil {
				if val.DstIP == 0 {
					continue
				}
				dstip := uintToIP(val.DstIP)
				srcip := uintToIP(val.SrcIP)
				egress := (val.Flags & 1) != 0
				blocked := (val.Flags & 2) != 0

				var pktFlow string
				if val.Proto == 6 {
					pktFlow = fmt.Sprintf("%v:%d -> %v:%d", srcip, lbSwap16(val.Sport), dstip, lbSwap16(val.Dport))
				} else {
					pktFlow = fmt.Sprintf("%v -> %v", srcip, dstip)
				}
				pktFlow += fmt.Sprintf(" TTL [%d]", val.TTL)
				pktFlow += fmt.Sprintf(" Protocol [%d]", val.Proto)

				if egress {
					pktFlow += " [OUT]"
				} else {
					pktFlow += " [IN]"
				}

				if blocked {
					pktFlow += " [BLOCKED]"
				}

				pktFlow += fmt.Sprintf(" ID [%d]", val.ID)
				fmt.Println(pktFlow)
			}
		case <-sigc:
			break outer_loop
		}
	}
}

func ruleConfig(action string) {
	if action == "issue" {
		if rules := loadRules(); rules != nil {
			compileRules(rules)
			issueRules()
		}
	} else if action == "revoke" {
		if rules := loadRules(); rules != nil {
			compileRules(rules)
			revokeRules()
		}
	}
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Give me an action: load, unload, show, issue or revoke")
		return
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		fmt.Println("Setrlimit error:", err)
		return
	}

	action := os.Args[1]
	if action == "load" {
		progLoad()
	} else {
		ingressProg, err = ebpf.LoadPinnedProgram(ingressPinPath, nil)
		if err != nil {
			fmt.Println("LoadPinnedProgram ingress", err)
			return
		}
		egressProg, err = ebpf.LoadPinnedProgram(egressPinPath, nil)
		if err != nil {
			fmt.Println("LoadPinnedProgram egress", err)
			return
		}

		if action == "show" {
			bpfOutputMap, err = ebpf.LoadPinnedMap(flowPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap flowPinPath", err)
				return
			}
			connShow()
		} else if action == "unload" {
			progUnLoad()
		} else if action == "issue" || action == "revoke" {
			bpfSaddrMap, err = ebpf.LoadPinnedMap(saddrPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap saddrPinPath", err)
				return
			}
			bpfDaddrMap, err = ebpf.LoadPinnedMap(daddrPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap daddrPinPath", err)
				return
			}
			bpfProtoMap, err = ebpf.LoadPinnedMap(protoPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap protoPinPath", err)
				return
			}
			bpfSportMap, err = ebpf.LoadPinnedMap(sportPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap sportPinPath", err)
				return
			}
			bpfDportMap, err = ebpf.LoadPinnedMap(dportPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap dportPinPath", err)
				return
			}
			bpfActionMap, err = ebpf.LoadPinnedMap(actionPinPath, nil)
			if err != nil {
				fmt.Println("LoadPinnedMap actionPinPath", err)
				return
			}
			// 加载策略
			ruleConfig(action)
		} else {
			fmt.Println("Unknown action given or wrong number of params:", action)
		}
	}
}
