package pes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"syscall/js"

	"github.com/Binject/debug/pe"
)

var pe_file *pe.File

func peAnalyze(fileBytes []byte, pe_file *pe.File) string {

	result := "[+] PE Detected\n\n"

	// File hashes.
	md5_h := md5.Sum(fileBytes)
	sha1_h := sha1.Sum(fileBytes)
	sha256_h := sha256.Sum256(fileBytes)
	result += fmt.Sprintf("[*] MD5: %s\n", hex.EncodeToString(md5_h[:]))
	result += fmt.Sprintf("[*] SHA1: %s\n", hex.EncodeToString(sha1_h[:]))
	result += fmt.Sprintf("[*] SHA256: %s\n\n", hex.EncodeToString(sha256_h[:]))

	// Entropy calculation.
	freq := make(map[byte]int)
	for _, b := range fileBytes {

		freq[b]++

	}

	totalBytes := len(fileBytes)
	probs := make(map[byte]float64)

	for b, f := range freq {

		probs[b] = float64(f) / float64(totalBytes)

	}

	entropy := 0.0

	for _, p := range probs {

		if p > 0 {

			entropy -= p * math.Log2(p)

		}

	}

	result += fmt.Sprintf("[*] File entropy: %.4f\n\n", entropy)

	// DOS Header info.
	result += "[*] Parsing DOS header...\n"
	dosHeader := pe_file.DosHeader

	result += "[+] DOS Header:\n"
	result += fmt.Sprintf("  Magic: 0x%X\n", dosHeader.MZSignature)
	result += fmt.Sprintf("  New exe header addr: 0x%X\n", dosHeader.AddressOfNewExeHeader)

	result += "[*] Parsing File header...\n"

	// File header.
	result += "[+] File Header:\n"
	result += fmt.Sprintf("  Machine: 0x%X\n", pe_file.FileHeader.Machine)
	result += fmt.Sprintf("  Number of sections: 0x%X\n", pe_file.FileHeader.NumberOfSections)

	result += "[+] Symbols:\n"

	// Scan for function names (no lookup, just return the names)
	iat, _, _, err := pe_file.ImportDirectoryTable()
	if err != nil {

		return fmt.Sprintf("Failed to parse Import Directory Table: %v", err)

	}

	symbols, err := pe_file.ImportedSymbols()
	if err != nil {

		return fmt.Sprintf("Failed to retrieve imported symbols: %v", err)

	}

	// Counter to add a formatted output to symbols so those can be searched with the loadMalicious function in JS.
	// Get the loaded DLLs.
	counter := 1
	for _, imp := range iat {
		result += fmt.Sprintf("  DLL: %s\n", imp.DllName)

		// ...and their function calls.
		for _, sym := range symbols {

			// Increment the counter for each function call.
			counter++
			if strings.Split(sym, ":")[1] == imp.DllName {
				callName := strings.Split(sym, ":")[0]
				result += fmt.Sprintf("    %d. %s\n", counter, callName)
			}
		}
		result += "\n"
	}

	// Import Directory Table & Symbols.
	result += processImports(pe_file)

	return result
}

// Imported functions. Need to make other functions modular like entropy and
// listing DLLS and their symbols.
func processImports(pe_file *pe.File) string {

	result := "[+] Import Table:\n"

	iat, _, _, err := pe_file.ImportDirectoryTable()
	if err != nil {

		return fmt.Sprintf("Error importing directory table: %v", err)

	}

	symbols, err := pe_file.ImportedSymbols()
	if err != nil {

		return fmt.Sprintf("Error retrieving imported symbols: %v", err)

	}

	for _, imp := range iat {

		result += fmt.Sprintf("  DLL: %s\n", imp.DllName)

		for _, sym := range symbols {

			parts := strings.Split(sym, ":")
			if len(parts) > 1 && parts[1] == imp.DllName {

				callName := parts[0]
				result += fmt.Sprintf("    %s\n", callName)

			}

		}

		result += "\n"

	}

	return result

}

func AnalyzeWrapper(this js.Value, args []js.Value, fileBytes []byte, pe_file *pe.File) any {

	//fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	result := peAnalyze(fileBytes, pe_file)
	return js.ValueOf(result)

}
