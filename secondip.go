package main

import (
	"fmt"
	"os"
)

var ss1 = `{
	"cmd": 44,
	"method": "POST",
	"success": true,
	"language": "CN",
	"sessionId": "a6083050dcbf98066712f3d1a1e01e124aeb0a00d9c1979da73ff312d8f7d5dd",
	"datas": [{
		"ip": "192.168.0.198",
		"interface": "br0:2",
		"remark": "add interface",
		"ippro": "IPV4",
		"enableRule": true
	},{
		"ip": "192.168.0.198",
		"interface": "br0:3",
		"remark": "add interface",
		"ippro": "IPV4",
		"enableRule": true
	}]
}`

func main() {
	f1, _ := os.OpenFile("test", os.O_CREATE|os.O_RDWR|os.O_SYNC, os.ModePerm)
	defer f1.Close()
	fmt.Fprintln(f1, ss1)

}
