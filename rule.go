package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

const ruleConfigPath string = "./conf/rule.json"

type ruleCfg struct {
	Name   string `json:"name"`
	ID     uint32 `json:"id"`
	Saddr  string `json:"saddr,omitempty"`
	Daddr  string `json:"daddr,omitempty"`
	Proto  uint8  `json:"proto,omitempty"`
	Sport  uint16 `json:"sport,omitempty"`
	Dport  uint16 `json:"dport,omitempty"`
	Action uint8  `json:"action"`
}

// key为五元组, value为id的并集
var saddrMap = make(map[uint32]uint32)
var daddrMap = make(map[uint32]uint32)
var protoMap = make(map[uint8]uint32)
var sportMap = make(map[uint16]uint32)
var dportMap = make(map[uint16]uint32)
var actionMap = make(map[uint32]uint8) //key为ID,value为action

// 从文件中读取规则
func loadRules() []ruleCfg {
	content, err := ioutil.ReadFile(ruleConfigPath)
	if err != nil {
		fmt.Println("read rule file error:", err)
		return nil
	}

	rules := []ruleCfg{}
	err = json.Unmarshal(content, &rules)
	if err != nil {
		fmt.Println("unmarsha rules error:", err)
		return nil
	}

	return rules
}

// 将规则下发到内核eBPF MAP
// 五元组、动作共6个MAP
// 五元组: 匹配项为KEY, ID为value, 如果多条队则都需匹配一个匹配项, 取并集。
//        如果一个规则某一个匹配项未配置, 则为通配项, 需要将该项加入到现有的匹配项中
// 动作: ID为KEY, 动作为value
func compileRules(rules []ruleCfg) {
	for _, rule := range rules {
		fmt.Printf("start compile rule: %+v\n", rule)

		if ipToUint(rule.Saddr) != 0 {
			saddrMap[ipToUint(rule.Saddr)] |= rule.ID
		}

		if ipToUint(rule.Daddr) != 0 {
			daddrMap[ipToUint(rule.Daddr)] |= rule.ID
		}

		if rule.Proto != 0 {
			protoMap[rule.Proto] |= rule.ID
		}

		// 只有TCP、UDP需要匹配端口号
		if rule.Proto == 6 || rule.Proto == 17 {
			if rule.Sport != 0 {
				sportMap[rule.Sport] |= rule.ID
			}

			if rule.Dport != 0 {
				dportMap[rule.Dport] |= rule.ID
			}
		}

		actionMap[rule.ID] = rule.Action
	}

	// 处理通配项
	for _, rule := range rules {
		if ipToUint(rule.Saddr) == 0 && len(saddrMap) > 0 {
			for k := range saddrMap {
				saddrMap[k] |= rule.ID
			}
		}

		if ipToUint(rule.Daddr) == 0 && len(daddrMap) > 0 {
			for k := range daddrMap {
				daddrMap[k] |= rule.ID
			}
		}

		if rule.Proto == 0 && len(protoMap) > 0 {
			for k := range protoMap {
				protoMap[k] |= rule.ID
			}
		}

		// 只有TCP、UDP需要匹配端口号
		if rule.Proto == 6 || rule.Proto == 17 {
			if rule.Sport == 0 && len(sportMap) > 0 {
				for k := range sportMap {
					sportMap[k] |= rule.ID
				}
			}

			if rule.Dport == 0 && len(dportMap) > 0 {
				for k := range dportMap {
					dportMap[k] |= rule.ID
				}
			}
		}
	}
}

// 下发规则到内核eBPF
func issueRules() {
	value0 := uint32(0)
	addr0 := uint32(0)
	proto0 := uint8(0)
	port0 := uint16(0)

	for saddr, value := range saddrMap {
		fmt.Printf("issue saddr rule: %x:%x\n", saddr, value)
		if err := bpfSaddrMap.Put(&saddr, &value); err != nil {
			fmt.Printf("put saddr %x %x error: %v\n", saddr, value, err)
		}
	}
	if len(saddrMap) != 0 { //如果规则个数不为0,添加一条0规则
		_ = bpfSaddrMap.Put(&addr0, &value0)
	}

	for daddr, value := range daddrMap {
		fmt.Printf("issue daddr rule: %x:%x\n", daddr, value)
		if err := bpfDaddrMap.Put(&daddr, &value); err != nil {
			fmt.Printf("put daddr %x %x error: %v\n", daddr, value, err)
		}
	}
	if len(daddrMap) != 0 {
		_ = bpfDaddrMap.Put(&addr0, &value0)
	}

	for proto, value := range protoMap {
		fmt.Printf("issue proto rule: %x:%x\n", proto, value)
		if err := bpfProtoMap.Put(&proto, &value); err != nil {
			fmt.Printf("put proto %d %x error: %v\n", proto, value, err)
		}
	}
	if len(protoMap) != 0 {
		_ = bpfProtoMap.Put(&proto0, &value0)
	}

	for port, value := range sportMap {
		fmt.Printf("issue sport rule: %d:%x\n", port, value)
		bPort := lbSwap16(port)
		if err := bpfSportMap.Put(&bPort, &value); err != nil {
			fmt.Printf("put sport %d %x error: %v\n", port, value, err)
		}
	}
	if len(sportMap) != 0 {
		_ = bpfSportMap.Put(&port0, &value0)
	}

	for port, value := range dportMap {
		fmt.Printf("issue dport rule: %d:%x\n", port, value)
		bPort := lbSwap16(port)
		if err := bpfDportMap.Put(&bPort, &value); err != nil {
			fmt.Printf("put dport %d %x error: %v\n", port, value, err)
		}
	}
	if len(dportMap) != 0 {
		_ = bpfDportMap.Put(&port0, &value0)
	}

	for id, value := range actionMap {
		fmt.Printf("issue action rule: %d:%d\n", id, value)
		if err := bpfActionMap.Put(&id, &value); err != nil {
			fmt.Printf("put action %d %x error: %v\n", id, value, err)
		}
	}
}

// 撤销下发到内核的策略
func revokeRules() {
	addr0 := uint32(0)
	proto0 := uint8(0)
	port0 := uint16(0)

	_ = bpfSaddrMap.Delete(&addr0)
	for saddr := range saddrMap {
		fmt.Printf("revoke saddr rule: %x\n", saddr)
		if err := bpfSaddrMap.Delete(&saddr); err != nil {
			fmt.Printf("revoke saddr %x error: %v\n", saddr, err)
		}
	}

	_ = bpfDaddrMap.Delete(&addr0)
	for daddr := range daddrMap {
		fmt.Printf("revoke daddr rule: %x\n", daddr)
		if err := bpfDaddrMap.Delete(&daddr); err != nil {
			fmt.Printf("revoke daddr %x error: %v\n", daddr, err)
		}
	}

	_ = bpfProtoMap.Delete(&proto0)
	for proto := range protoMap {
		fmt.Printf("revoke proto rule: %d\n", proto)
		if err := bpfProtoMap.Delete(&proto); err != nil {
			fmt.Printf("revoke proto %d error: %v\n", proto, err)
		}
	}

	_ = bpfSportMap.Delete(&port0)
	for port := range sportMap {
		fmt.Printf("revoke sport rule: %d\n", port)
		bPort := lbSwap16(port)
		if err := bpfSportMap.Delete(&bPort); err != nil {
			fmt.Printf("revoke sport %d error: %v\n", port, err)
		}
	}

	_ = bpfDportMap.Delete(&port0)
	for port := range dportMap {
		fmt.Printf("revoke dport rule: %d\n", port)
		bPort := lbSwap16(port)
		if err := bpfDportMap.Delete(&bPort); err != nil {
			fmt.Printf("revoke dport %d error: %v\n", port, err)
		}
	}

	for id := range actionMap {
		fmt.Printf("revoke action rule: %d\n", id)
		if err := bpfActionMap.Delete(&id); err != nil {
			fmt.Printf("revoke action %d error: %v\n", id, err)
		}
	}
}
