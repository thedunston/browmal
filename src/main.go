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
	"browmal/elfs"
	"browmal/officedoc"
	"browmal/pes"
	"bytes"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/gabriel-vasile/mimetype"

	"github.com/Binject/debug/pe"
	"github.com/yalue/elf_reader"
)

// Check if a file is a PE file.
// This function now uses both signature-based detection and the pe library for better packed file support.
func checkPefile(fileBytes []byte) (bool, *pe.File) {
	// First check for PE signature manually to catch packed files
	if !hasPESignature(fileBytes) {
		return false, nil
	}

	result := false
	reader := bytes.NewReader(fileBytes)
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		// Even if pe.NewFile fails, we know it's a PE file by signature to handle packed files.
		result = true
		return result, nil
	} else {
		result = true
	}

	return result, pe_file
}

// hasPESignature checks if the file has the characteristic PE signature.
// This helps detect packed PE files that might not be fully parseable.
func hasPESignature(fileBytes []byte) bool {

	// Check minimum file size for a PE file.
	if len(fileBytes) < 64 {
		return false
	}

	// Check for "MZ" signature at the beginning
	if fileBytes[0] != 'M' || fileBytes[1] != 'Z' {
		return false
	}

	// Find the PE header offset (0x3C in the DOS header)
	if len(fileBytes) < 0x3E {
		return false
	}

	// Read the offset to the PE header
	peOffset := uint32(fileBytes[0x3C]) | (uint32(fileBytes[0x3D]) << 8) | 
		(uint32(fileBytes[0x3E]) << 16) | (uint32(fileBytes[0x3F]) << 24)

	// Check if the offset is within the file bounds
	if uint32(len(fileBytes)) <= peOffset+3 {
		return false
	}

	// Check for "PE\x00\x00" signature at the PE header
	peSignature := fileBytes[peOffset : peOffset+4]
	return peSignature[0] == 'P' && peSignature[1] == 'E' && 
		peSignature[2] == 0x00 && peSignature[3] == 0x00
}

// isPackedPE checks if a PE file appears to be packed based on section names.
// This is a heuristic-based approach to detect common packers like UPX.
func isPackedPE(fileBytes []byte) bool {

	// First check if it's a valid PE file
	if !hasPESignature(fileBytes) {
		return false
	}

	// Try to parse the PE file.
	reader := bytes.NewReader(fileBytes)
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		// If we can't parse it but it has a PE signature, it's likely packed.
		return true
	}
	defer pe_file.Close()

	// Check section names for common packer signatures
	for _, section := range pe_file.Sections {

		name := strings.Trim(string(section.Name[:]), "\x00")
		// Check for common packer section names
		if strings.Contains(strings.ToUpper(name), "UPX") ||
		   strings.Contains(strings.ToUpper(name), "ASPACK") ||
		   strings.Contains(strings.ToUpper(name), "PEPACK") ||
		   strings.Contains(strings.ToUpper(name), "MPRMMGVA") ||
		   strings.Contains(strings.ToUpper(name), "PETITE") ||
		   strings.Contains(strings.ToUpper(name), "FSG") ||
		   strings.Contains(strings.ToUpper(name), "MEW") ||
		   strings.Contains(strings.ToUpper(name), "SPRP") ||
		   strings.Contains(strings.ToUpper(name), "WWP32") {
			return true
		}
	}

	// Also check for packer signatures in the file content
	return hasPackerSignature(fileBytes)
}

// hasPackerSignature checks for common packer signatures in the file content
func hasPackerSignature(fileBytes []byte) bool {
	// Common packer signatures
	packerSignatures := []string{
		"UPX!", "ASPack", "PECompact", "NeoLite", "RLPack",
		"PEtite", "FSG!", "MEW", "WinUpack", "Yoda's Crypter",
		"Yoda's Protector", "ACProtect", "PELock NT", "PELock",
		"Armadillo", "EXECryptor", "eXPressor", "ASProtect",
		"Themida", "WinLicense", "VMProtect", "Enigma Protector",
		"Code Virtualizer", "SVKP", "PEBundle", "Morphine",
		"tELock", "kkrunchy", "Crinkler", "MPRMMGVA",
	}

	// Convert file bytes to string for searching.
	fileStr := string(fileBytes)

	// Check for each packer signature.
	for _, signature := range packerSignatures {
		if strings.Contains(fileStr, signature) {
			return true
		}
	}

	return false
}

// Check if it is an elf file.
func checkElffile(fileBytes []byte) (elf_reader.ELFFile, error) {
	return elf_reader.ParseELFFile(fileBytes)
}

func checkOfficeDocumentType(fileBytes []byte) bool {

	// Detect MIME type from the file data.
	mtype := mimetype.Detect(fileBytes)

	// Debug: Print detected MIME type.
	fmt.Printf("[DEBUG] Detected MIME type: %s\n", mtype.String())

	// Check for specific Office document types.
	if mtype.Is("application/vnd.openxmlformats-officedocument.wordprocessingml.document") || 
	   mtype.Is("application/msword") || 
	   mtype.Is("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") || 
	   mtype.Is("application/vnd.ms-excel") || 
	   mtype.Is("application/vnd.openxmlformats-officedocument.presentationml.presentation") || 
	   mtype.Is("application/vnd.ms-powerpoint") ||
	   mtype.Is("application/zip") {

		return true

	}

	// Additional check for OLE signature (legacy Office docs).
	if len(fileBytes) >= 8 && string(fileBytes[:8]) == "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
		fmt.Printf("[DEBUG] OLE signature detected\n")
		return true
	}

	return false

}

func analyzeWrapper(this js.Value, args []js.Value) any {

	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	result := ""

	isPe, pe_file := checkPefile(fileBytes)
	elf, isElf := checkElffile(fileBytes)
	isOffice := checkOfficeDocumentType(fileBytes)

	// Check if the file is a PE file and if not, then check if it's an ELF file before continuing using the functions.
	if isElf == nil {

		result += fmt.Sprintf("[+] ELF file detected.\n\n")
		return js.ValueOf(elfs.AnalyzeWrapper(this, args, elf))

	} else if isPe {

		result += fmt.Sprintf("[+] PE file detected.\n\n")
		
		// Check if the PE file is packed.
		if isPackedPE(fileBytes) || pe_file == nil {
			result += fmt.Sprintf("[!] Packed or obfuscated PE file detected.\n")
			result += fmt.Sprintf("[!] Full analysis not possible, but basic information will be shown.\n\n")
			return js.ValueOf(pes.AnalyzeBasicInfo(fileBytes))
		}

		return js.ValueOf(pes.AnalyzeWrapper(this, args, fileBytes, pe_file))

	} else if isOffice {

		fmt.Printf("[DEBUG] Office document detected, calling officedoc.AnalyzeWrapper\n")
		result += fmt.Sprintf("[+] Office document detected.\n\n")

		return js.ValueOf(officedoc.AnalyzeWrapper(this, args, fileBytes))
	} else {

		result += fmt.Sprintf("[+] Unknown file type.\n\n")
		return result

	}

}

// analyzePEWrapper wraps the analyzePE function for WebAssembly JS interaction.
func main() {

	// This passes the results from the analyzePE function to Js.
	js.Global().Set("analyzePE", js.FuncOf(analyzeWrapper))
	js.Global().Set("analyzeStrings", js.FuncOf(stringsAnalyzeWrapper))
	js.Global().Set("analyzeStringsInline", js.FuncOf(stringsAnalyzeInlineWrapper))
	js.Global().Set("analyzeSectionObjdump", js.FuncOf(sectionObjdumpWrapper))

	select {}

}

// stringsAnalyzeWrapper wraps the string analysis function for WebAssembly JS interaction.
func stringsAnalyzeWrapper(this js.Value, args []js.Value) any {
	return pes.StringsAnalysisWrapper(this, args)
}

// stringsAnalyzeInlineWrapper wraps the inline string analysis function for WebAssembly JS interaction.
func stringsAnalyzeInlineWrapper(this js.Value, args []js.Value) any {
	return pes.StringsAnalysisInlineWrapper(this, args)
}

// sectionObjdumpWrapper wraps the section objdump function for WebAssembly JS interaction.
func sectionObjdumpWrapper(this js.Value, args []js.Value) any {
	return pes.SectionObjdumpWrapper(this, args)
}
