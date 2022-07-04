package main

import (
	"fmt"
	"testing"
)

func TestCompileRule(t *testing.T) {
	if rules := loadRules(); rules != nil {
		compileRules(rules)

		// 输出要下发的规则
		for saddr, value := range saddrMap {
			fmt.Printf("saddr rule: %x:%x\n", saddr, value)
		}

		for daddr, value := range daddrMap {
			fmt.Printf("daddr rule: %x:%x\n", daddr, value)
		}

		for proto, value := range protoMap {
			fmt.Printf("proto rule: %d:%x\n", proto, value)
		}

		for port, value := range sportMap {
			fmt.Printf("sport rule: %d:%x\n", port, value)
		}

		for port, value := range dportMap {
			fmt.Printf("dport rule: %d:%x\n", port, value)
		}

		for id, value := range actionMap {
			fmt.Printf("issue action rule: %d:%d\n", id, value)
		}
	}
}

// https://mp.weixin.qq.com/s/25mhUrNhF3HW8H6-ES7waA
func TestRuleMatch(t *testing.T) {
	if rules := loadRules(); rules != nil {
		compileRules(rules)

		saddr := "192.168.11.192"
		daddr := "192.168.11.182"
		protocol := uint8(6)
		source := uint16(23456)
		dest := uint16(22)
		// 规则查找
		saddrValue := saddrMap[ipToUint(saddr)]
		daddrValue := daddrMap[ipToUint(daddr)]
		protoValue := protoMap[protocol]
		sportValue := sportMap[source]
		dportValue := dportMap[dest]

		fmt.Printf("%x, %x, %x, %x, %x\n", saddrValue, daddrValue, protoValue, sportValue, dportValue)

		var bitMap uint32 = 0xFFFFFFFF
		if saddrValue > 0 {
			bitMap &= saddrValue
		} else if len(saddrMap) > 0 { // 没有匹配上saddr
			bitMap &= 0
		}

		if daddrValue > 0 {
			bitMap &= daddrValue
		} else if len(daddrMap) > 0 {
			bitMap &= 0
		}

		if protoValue > 0 {
			bitMap &= protoValue
		} else if len(protoMap) > 0 {
			bitMap &= 0
		}

		if sportValue > 0 {
			bitMap &= sportValue
		} else if len(sportMap) > 0 {
			bitMap &= 0
		}

		if dportValue > 0 {
			bitMap &= dportValue
		} else if len(dportMap) > 0 {
			bitMap &= 0
		}

		bitMap &= -bitMap // 取优先级高的规则
		fmt.Printf("%x\n", bitMap)
	}
}
