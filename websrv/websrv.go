/** Simple web server to run malwasm. */
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

// validateIP validates the IP address.
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validatePort checks if the port is within the valid range (1-65535).
func validatePort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return false
	}
	return true
}

func main() {

	// Define IP and Port flags.
	listenIP := flag.String("ip", "127.0.0.1", "IP address to run the server on. Default: 127.0.0.1")
	listenPort := flag.String("port", "8111", "Port to run the server on. Default 8111")

	// Parse flags.
	flag.Parse()

	// Validate IP address.
	if !validateIP(*listenIP) {
		fmt.Printf("Invalid IP address: %s\n", *listenIP)
		os.Exit(1)
	}

	// Validate port number.
	if !validatePort(*listenPort) {
		fmt.Printf("Invalid port: %s\n", *listenPort)
		os.Exit(1)
	}

	// Serve static files like index.html, wasm_exec.js, main.wasm, etc.
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	addr := fmt.Sprintf("%s:%s", *listenIP, *listenPort)
	log.Printf("Starting server on %s...\n", addr)
	log.Printf("Browse to http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
