package main

import (
	"flag"

	"github.com/elfinguard/cashier/judger"
)

var (
	keyGrantor = ""
	bchRpcInfo = ""
	listenAddr = "0.0.0.0:8832"
)

func main() {
	flag.StringVar(&keyGrantor, "key-grantor", keyGrantor, "key grantor RPC base URL")
	flag.StringVar(&bchRpcInfo, "bch-rpc-info", bchRpcInfo, "bch main chain client info: url,username,password")
	flag.StringVar(&listenAddr, "listen-addr", listenAddr, "listen addr, ip:port")
	flag.Parse()

	judger.StartServer(keyGrantor, listenAddr, bchRpcInfo)
}
