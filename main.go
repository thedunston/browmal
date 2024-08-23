/**

References:

https://donatstudios.com/Read-User-Files-With-Go-WASM
https://d3ext.github.io/posts/malware-analysis-1/

I've been learning to use Go for parsing PE files. The main tutorial used for this code is from donatstudios.com.

I've been wanting to learn how to create a program that uses wasm and I learn best by creating something useful, well for me anyway. I saw the program that anticrypt.de created called OMAT and decided to do something similar. I just can't create pretty HTML reports.

After trying to figure out the best way to deal with files with wasm, I found 3ext.github.io/posts/malware-analysis-1/ example to upload a file.

The file is read in as a byte array due to limitations with wasm. Accordingly, some functions couldn't be performed because it requires low-level OS system API functions, which are not accssible via wasm.

However, this provides a good starting point to analyze a pe file.

*/

package main

import (
	"bytes"
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

// analyzePE parses the PE structure,
func analyzePE(fileBytes []byte, verbose bool) string {

	result := ""

	/** This mostly code from donatstudios.com */

	// This creates a reader to read the uploaded file as a byte array from JS.
	reader := bytes.NewReader(fileBytes)
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		return fmt.Sprintf("Error parsing PE file. Currently, only PE files are supported: %v", err)
	}
	defer pe_file.Close()

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
	if verbose {
		result += "[*] Parsing DOS header...\n"
	}
	dosHeader := pe_file.DosHeader
	result += "[+] DOS Header:\n"
	result += fmt.Sprintf("  Magic: 0x%X\n", dosHeader.MZSignature)
	result += fmt.Sprintf("  New exe header addr: 0x%X\n", dosHeader.AddressOfNewExeHeader)

	if verbose {
		result += "[*] Parsing File header...\n"
	}

	// File header.
	result += "[+] File Header:\n"
	result += fmt.Sprintf("  Machine: 0x%X\n", pe_file.FileHeader.Machine)
	result += fmt.Sprintf("  Number of sections: 0x%X\n", pe_file.FileHeader.NumberOfSections)

	// Scan for function names (no lookup, just return the names)
	iat, _, _, err := pe_file.ImportDirectoryTable()
	if err != nil {
		return fmt.Sprintf("Failed to parse Import Directory Table: %v", err)
	}

	symbols, err := pe_file.ImportedSymbols()
	if err != nil {
		return fmt.Sprintf("Failed to retrieve imported symbols: %v", err)
	}

	// Get the loaded DLLs.
	for _, imp := range iat {
		result += fmt.Sprintf("  DLL: %s\n", imp.DllName)

		// ...and their function calls.
		for _, sym := range symbols {

			if strings.Split(sym, ":")[1] == imp.DllName {
				callName := strings.Split(sym, ":")[0]
				result += fmt.Sprintf("    %s\n", callName)
			}
		}
		result += "\n"
	}
	
	// Import Directory Table & Symbols.
    	result += processImports(pe_file, verbose)

	return result
}

// analyzePEWrapper wraps the analyzePE function for WebAssembly JS interaction.
func analyzePEWrapper(this js.Value, args []js.Value) any {

	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	verbose := args[1].Bool()

	result := analyzePE(fileBytes, verbose)
	return js.ValueOf(result)
}

// Imported functions. Need to make other functions modular like entropy and
// listing DLLS and their symbols.
func processImports(pe_file *pe.File, verbose bool) string {

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
func main() {

	// This passes the results from the analyzePE function to Js.
	js.Global().Set("analyzePE", js.FuncOf(analyzePEWrapper))

	select {}

}
