package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hillu/go-yara/v4"
)

/** The yara scannning code is based on the simple-yara.go file from the go-yara repo:

https://github.com/hillu/go-yara/blob/master/_examples/simple-yara/simple-yara.go

*/

type Scanner struct {
	Rules *yara.Rules
}

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

// loadYaraRules compiles the Yara rules from a given directory.
func loadYaraRules(rulesDir string) (*yara.Rules, error) {

	log.Println("Loading Yara rules from directory:", rulesDir)

	compiler, err := yara.NewCompiler()
	if err != nil {

		log.Printf("Failed to initialize YARA compiler: %v", err)
		return nil, err

	}

	// Get yara rules from a directory. Can be custom rules.
	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {

		if err != nil {

			log.Printf("Error while walking through rules directory: %v", err)

			return err

		}

		// Only compile .yar or .yara files.
		if filepath.Ext(path) == ".yar" || filepath.Ext(path) == ".yara" {

			log.Printf("Compiling rule file: %s", path)

			file, err := os.Open(path)
			if err != nil {

				log.Printf("Could not open rule file %s: %v", path, err)
				return err

			}
			defer file.Close()

			err = compiler.AddFile(file, "")
			if err != nil {

				log.Printf("Could not parse rule file %s: %v", path, err)
				return err

			}

		}

		return nil

	})

	if err != nil {

		log.Printf("Failed to walk rules directory: %v", err)
		return nil, err

	}

	// Compile the rules.
	rules, err := compiler.GetRules()
	if err != nil {

		log.Printf("Failed to compile YARA rules: %v", err)
		return nil, err

	}

	log.Println("Successfully loaded and compiled YARA rules.")

	return rules, nil

}

// handleYaraScan handles the POST request to scan the uploaded file.
func handleYaraScan(w http.ResponseWriter, r *http.Request, scanner *Scanner) {

	log.Println("Received request to /scan")

	// Read the file data from the request body.
	fileBytes, err := io.ReadAll(r.Body)
	if err != nil {

		log.Printf("Failed to read file data: %v", err)
		http.Error(w, "Failed to read file data", http.StatusBadRequest)
		return

	}
	defer r.Body.Close()

	log.Printf("File size received: %d bytes", len(fileBytes))

	// Set up a scanner with the loaded rules.
	yaraScanner, err := yara.NewScanner(scanner.Rules)
	if err != nil {

		log.Printf("Failed to create Yara scanner: %v", err)
		http.Error(w, "Failed to create Yara scanner", http.StatusInternalServerError)
		return

	}

	// Perform Yara scan on the in-memory file data.
	var matches yara.MatchRules

	log.Println("Starting YARA scan...")
	err = yaraScanner.SetCallback(&matches).ScanMem(fileBytes)
	if err != nil {

		log.Printf("Failed to scan file data: %v", err)
		http.Error(w, "Failed to scan file data", http.StatusInternalServerError)
		return

	}

	log.Printf("YARA scan completed. Matches found: %d", len(matches))

	// Log and structure the matches for the client.
	matchesInfo := make([]map[string]interface{}, 0)
	for _, match := range matches {

		log.Printf("Match found: Rule %s in Namespace %s", match.Rule, match.Namespace)

		// Collect matching strings.
		stringsMatched := make([]map[string]string, 0)
		for _, s := range match.Strings {

			stringsMatched = append(stringsMatched, map[string]string{
				"name":  s.Name,
				"value": string(s.Data),
			})

		}

		// Build the match information.
		matchInfo := map[string]interface{}{
			"rule":      match.Rule,
			"namespace": match.Namespace,
			"strings":   stringsMatched,
		}
		matchesInfo = append(matchesInfo, matchInfo)
	}

	// Send the response back as JSON.
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]interface{}{

		"matches": matchesInfo,
	})

	if err != nil {

		log.Printf("Failed to encode JSON response: %v", err)
		http.Error(w, "Failed to encode JSON response", http.StatusInternalServerError)

	}

}

func main() {

	// Define IP and Port flags.
	listenIP := flag.String("ip", "127.0.0.1", "IP address to run the server on. Default: 127.0.0.1")
	listenPort := flag.String("port", "8111", "Port to run the server on. Default 8111")

	// Parse flags.
	flag.Parse()

	// Validate IP and port.
	if !validateIP(*listenIP) {

		log.Fatalf("Invalid IP address: %s", listenIP)

	}
	if !validatePort(*listenPort) {

		log.Fatalf("Invalid port: %s", listenPort)

	}

	// Load Yara rules.
	rulesDir := "./rules"

	rules, err := loadYaraRules(rulesDir)
	if err != nil {

		log.Fatalf("Error loading Yara rules: %v", err)

	}

	scanner := &Scanner{Rules: rules}

	// Serve static files like index.html, wasm_exec.js, main.wasm, etc.
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Handle scanning POST request.
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) { handleYaraScan(w, r, scanner) })

	// Start the web server.
	addr := fmt.Sprintf("%s:%s", *listenIP, *listenPort)
	log.Printf("Starting server on %s...\n", addr)
	log.Printf("Browse to http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))

}
