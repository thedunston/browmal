package pes

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"syscall/js"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Binject/debug/pe"
	"github.com/glaslos/ssdeep"
)

var pe_file *pe.File

// MalwareHashResult represents the result from Team Cymru's Malware Hash Registry
type MalwareHashResult struct {
	Hash           string
	Timestamp      int64
	DetectionRate  string
	IsKnownMalware bool
	Error          string
}

// ExportDirectory represents the export directory structure
type ExportDirectory struct {
	ExportFlags       uint32
	TimeDateStamp     uint32
	MajorVersion      uint16
	MinorVersion      uint16
	NameRVA           uint32
	OrdinalBase       uint32
	NumberOfFunctions uint32
	NumberOfNames     uint32
	AddressTableAddr  uint32
	NameTableAddr     uint32
	OrdinalTableAddr  uint32
	DllName           string
}

// Export represents a single exported function
type Export struct {
	Ordinal        uint32
	Name           string
	VirtualAddress uint32
	Forward        string
}

func peAnalyze(fileBytes []byte, pe_file *pe.File) string {

	result := "[+] PE Detected\n\n"

	// File hashes.
	md5_h := md5.Sum(fileBytes)
	sha1_h := sha1.Sum(fileBytes)
	sha256_h := sha256.Sum256(fileBytes)
	md5_str := hex.EncodeToString(md5_h[:])
	sha1_str := hex.EncodeToString(sha1_h[:])
	sha256_str := hex.EncodeToString(sha256_h[:])
	result += fmt.Sprintf("[*] MD5: %s\n", md5_str)
	result += fmt.Sprintf("[*] SHA1: %s\n", sha1_str)
	result += fmt.Sprintf("[*] SHA256: %s\n", hex.EncodeToString(sha256_h[:]))

	// SSDeep fuzzy hash.
	ssdeep_h, err := ssdeep.FuzzyBytes(fileBytes)
	if err != nil {
		result += fmt.Sprintf("[*] SSDeep: Error calculating fuzzy hash: %v\n\n", err)
	} else {
		result += fmt.Sprintf("[*] SSDeep: %s\n\n", ssdeep_h)
	}

	// Team Cymru Malware Hash Registry lookup (https://hash.cymru.com/docs_dns)
	result += "=== MALWARE HASH LOOKUP ===\n"

	// Check MD5 hash first.
	md5Result := queryTeamCymruHash(md5_str)
	result += formatMalwareHashResult(md5Result)

	// If MD5 didn't find anything, also check SHA256.
	if !md5Result.IsKnownMalware && md5Result.Error == "" {
		sha256Result := queryTeamCymruHash(sha256_str)
		if sha256Result.IsKnownMalware || sha256Result.Error != "" {
			result += "[*] SHA256 lookup:\n"
			result += formatMalwareHashResult(sha256Result)
		}
	}

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

	result += fmt.Sprintf("[*] File entropy: %.4f\n", entropy)

	// Calculate imphash.
	imphash := calculateImphash(pe_file)
	if imphash != "" {
		result += fmt.Sprintf("[*] Imphash: %s\n", imphash)
	}

	// Packer detection.
	packer := detectPacker(fileBytes)
	if packer != "" {
		result += fmt.Sprintf("[+] Packer detected: %s\n", packer)
	} else {
		result += "[*] No known packer signatures detected\n"
	}
	result += "\n"

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

	// Section analysis.
	result += processSections(pe_file)

	result += "[+] Symbols:\n"

	// Scan for function names (no lookup, just return the names).
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

	// Export Directory Table & Exported Functions.
	result += processExports(pe_file)

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

// processSections analyzes and displays PE section information with objdump links.
func processSections(pe_file *pe.File) string {
	result := "[+] Sections:\n"

	sections := pe_file.Sections
	result += fmt.Sprintf("  Number of sections: %d\n\n", len(sections))

	for i, section := range sections {
		result += fmt.Sprintf("  > Section %d:\n", i+1)
		result += fmt.Sprintf("     Name: %s\n", section.Name)
		result += fmt.Sprintf("     Virtual Size: 0x%X (%d bytes)\n", section.VirtualSize, section.VirtualSize)
		result += fmt.Sprintf("     Virtual Address: 0x%X\n", section.VirtualAddress)
		result += fmt.Sprintf("     Size of Raw Data: 0x%X (%d bytes)\n", section.Size, section.Size)
		result += fmt.Sprintf("     Pointer to Raw Data: 0x%X\n", section.Offset)
		result += fmt.Sprintf("     Characteristics: 0x%X\n", section.Characteristics)

		// Decode section characteristics.
		characteristics := decodeSectionCharacteristics(section.Characteristics)
		if len(characteristics) > 0 {
			result += fmt.Sprintf("    Flags: %s\n", strings.Join(characteristics, ", "))
		}

		// Calculate section entropy if data is available.
		if section.Size > 0 {
			sectionData, err := section.Data()
			if err == nil && len(sectionData) > 0 {
				entropy := calculateSectionEntropy(sectionData)
				result += fmt.Sprintf("    Entropy: %.4f\n", entropy)
			}
		}

		// Add hex dump link for all sections with data.
		if section.Size > 0 {
			if section.Characteristics&0x20000000 != 0 {
				result += fmt.Sprintf("    <a href=\"javascript:void(0)\" onclick=\"showSectionObjdump(%d, '%s')\" class=\"objdump-link\">View Objdump</a>\n", i, section.Name)
			} else {
				result += fmt.Sprintf("    <a href=\"javascript:void(0)\" onclick=\"showSectionObjdump(%d, '%s')\" class=\"objdump-link\">View Hex Dump</a>\n", i, section.Name)
			}
		}

		result += "\n"
	}

	return result
}

// decodeSectionCharacteristics converts section characteristics flags to readable strings.
func decodeSectionCharacteristics(characteristics uint32) []string {
	var flags []string

	flagMap := map[uint32]string{
		0x00000020: "CODE",               // IMAGE_SCN_CNT_CODE
		0x00000040: "INITIALIZED_DATA",   // IMAGE_SCN_CNT_INITIALIZED_DATA
		0x00000080: "UNINITIALIZED_DATA", // IMAGE_SCN_CNT_UNINITIALIZED_DATA
		0x00000200: "LNK_INFO",           // IMAGE_SCN_LNK_INFO
		0x00000800: "LNK_REMOVE",         // IMAGE_SCN_LNK_REMOVE
		0x00001000: "LNK_COMDAT",         // IMAGE_SCN_LNK_COMDAT
		0x00008000: "GPREL",              // IMAGE_SCN_GPREL
		0x00020000: "MEM_PURGEABLE",      // IMAGE_SCN_MEM_PURGEABLE
		0x00040000: "MEM_16BIT",          // IMAGE_SCN_MEM_16BIT
		0x00080000: "MEM_LOCKED",         // IMAGE_SCN_MEM_LOCKED
		0x00100000: "MEM_PRELOAD",        // IMAGE_SCN_MEM_PRELOAD
		0x01000000: "LNK_NRELOC_OVFL",    // IMAGE_SCN_LNK_NRELOC_OVFL
		0x02000000: "MEM_DISCARDABLE",    // IMAGE_SCN_MEM_DISCARDABLE
		0x04000000: "MEM_NOT_CACHED",     // IMAGE_SCN_MEM_NOT_CACHED
		0x08000000: "MEM_NOT_PAGED",      // IMAGE_SCN_MEM_NOT_PAGED
		0x10000000: "MEM_SHARED",         // IMAGE_SCN_MEM_SHARED
		0x20000000: "MEM_EXECUTE",        // IMAGE_SCN_MEM_EXECUTE
		0x40000000: "MEM_READ",           // IMAGE_SCN_MEM_READ
		0x80000000: "MEM_WRITE",          // IMAGE_SCN_MEM_WRITE
	}

	for flag, name := range flagMap {
		if characteristics&flag != 0 {
			flags = append(flags, name)
		}
	}

	return flags
}

// calculateSectionEntropy calculates the entropy of section data.
func calculateSectionEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	totalBytes := len(data)
	entropy := 0.0

	for _, f := range freq {
		if f > 0 {
			p := float64(f) / float64(totalBytes)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// StringEncoding represents different string encoding types.
type StringEncoding int

const (
	ASCII7Bit StringEncoding = iota // s = 7-bit ASCII
	ASCII8Bit                       // S = 8-bit ASCII
	UTF16LE                         // l = 16-bit little-endian
	UTF16BE                         // b = 16-bit big-endian
	UTF32LE                         // L = 32-bit little-endian
	UTF32BE                         // B = 32-bit big-endian
)

// extractStrings extracts strings from PE file data using specified encoding.
func extractStrings(data []byte, encoding StringEncoding, minLength int) []string {
	var strings []string

	switch encoding {
	case ASCII7Bit:
		strings = extractASCII7BitStrings(data, minLength)
	case ASCII8Bit:
		strings = extractASCII8BitStrings(data, minLength)
	case UTF16LE:
		strings = extractUTF16LEStrings(data, minLength)
	case UTF16BE:
		strings = extractUTF16BEStrings(data, minLength)
	case UTF32LE:
		strings = extractUTF32LEStrings(data, minLength)
	case UTF32BE:
		strings = extractUTF32BEStrings(data, minLength)
	}

	return strings
}

// extractASCII7BitStrings extracts 7-bit ASCII strings.
func extractASCII7BitStrings(data []byte, minLength int) []string {
	var strings []string
	var current []byte

	for _, b := range data {
		// Printable 7-bit ASCII
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			if len(current) >= minLength {
				strings = append(strings, string(current))
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		strings = append(strings, string(current))
	}

	return strings
}

// extractASCII8BitStrings extracts 8-bit ASCII strings.
func extractASCII8BitStrings(data []byte, minLength int) []string {
	var strings []string
	var current []byte

	for _, b := range data {
		// Extended ASCII
		if (b >= 32 && b <= 126) || (b >= 128 && b <= 255) {
			current = append(current, b)
		} else {
			if len(current) >= minLength {
				strings = append(strings, string(current))
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		strings = append(strings, string(current))
	}

	return strings
}

// extractUTF16LEStrings extracts UTF-16 little-endian strings.
func extractUTF16LEStrings(data []byte, minLength int) []string {
	var strings []string
	var current []uint16

	for i := 0; i < len(data)-1; i += 2 {
		char := binary.LittleEndian.Uint16(data[i : i+2])
		// Printable ASCII range in UTF-16
		if char >= 32 && char <= 126 {
			current = append(current, char)
		} else if char == 0 || char < 32 || char > 0xFFFF {
			if len(current) >= minLength {
				str := string(utf16.Decode(current))
				if utf8.ValidString(str) {
					strings = append(strings, str)
				}
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		str := string(utf16.Decode(current))
		if utf8.ValidString(str) {
			strings = append(strings, str)
		}
	}

	return strings
}

// extractUTF16BEStrings extracts UTF-16 big-endian strings.
func extractUTF16BEStrings(data []byte, minLength int) []string {
	var strings []string
	var current []uint16

	for i := 0; i < len(data)-1; i += 2 {
		char := binary.BigEndian.Uint16(data[i : i+2])

		// Printable ASCII range in UTF-16
		if char >= 32 && char <= 126 {
			current = append(current, char)
		} else if char == 0 || char < 32 || char > 0xFFFF {
			if len(current) >= minLength {
				str := string(utf16.Decode(current))
				if utf8.ValidString(str) {
					strings = append(strings, str)
				}
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		str := string(utf16.Decode(current))
		if utf8.ValidString(str) {
			strings = append(strings, str)
		}
	}

	return strings
}

// extractUTF32LEStrings extracts UTF-32 little-endian strings.
func extractUTF32LEStrings(data []byte, minLength int) []string {
	var strings []string
	var current []rune

	for i := 0; i < len(data)-3; i += 4 {
		char := rune(binary.LittleEndian.Uint32(data[i : i+4]))
		// Printable ASCII range
		if char >= 32 && char <= 126 {
			current = append(current, char)
		} else if char == 0 || char < 32 || char > 0x10FFFF {
			if len(current) >= minLength {
				str := string(current)
				if utf8.ValidString(str) {
					strings = append(strings, str)
				}
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		str := string(current)
		if utf8.ValidString(str) {
			strings = append(strings, str)
		}
	}

	return strings
}

// extractUTF32BEStrings extracts UTF-32 big-endian strings
func extractUTF32BEStrings(data []byte, minLength int) []string {
	var strings []string
	var current []rune

	for i := 0; i < len(data)-3; i += 4 {
		char := rune(binary.BigEndian.Uint32(data[i : i+4]))

		// Printable ASCII range
		if char >= 32 && char <= 126 {
			current = append(current, char)
		} else if char == 0 || char < 32 || char > 0x10FFFF {
			if len(current) >= minLength {
				str := string(current)
				if utf8.ValidString(str) {
					strings = append(strings, str)
				}
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		str := string(current)
		if utf8.ValidString(str) {
			strings = append(strings, str)
		}
	}

	return strings
}

// processStrings extracts strings from PE file using multiple encodings
func processStrings(pe_file *pe.File, fileBytes []byte) map[string][]string {

	// Minimum string length
	minLength := 4
	results := make(map[string][]string)

	// Extract strings using different encodings.
	results["7-bit ASCII (s)"] = extractStrings(fileBytes, ASCII7Bit, minLength)
	results["8-bit ASCII (S)"] = extractStrings(fileBytes, ASCII8Bit, minLength)
	results["16-bit LE (l)"] = extractStrings(fileBytes, UTF16LE, minLength)
	results["16-bit BE (b)"] = extractStrings(fileBytes, UTF16BE, minLength)
	results["32-bit LE (L)"] = extractStrings(fileBytes, UTF32LE, minLength)
	results["32-bit BE (B)"] = extractStrings(fileBytes, UTF32BE, minLength)

	// Filter out duplicates and very common strings.
	for encoding, strs := range results {
		filtered := filterStrings(strs)
		results[encoding] = filtered
	}

	return results
}

// filterStrings removes duplicates and filters out common/noise strings.
func filterStrings(strings []string) []string {
	seen := make(map[string]bool)
	var filtered []string

	// Regex patterns to filter out noise.
	noisePatterns := []*regexp.Regexp{

		// Control characters
		regexp.MustCompile(`^[\x00-\x1F\x7F-\xFF]+$`),

		// Pure numbers
		regexp.MustCompile(`^[0-9]+$`),
		// Very short letter sequences
		regexp.MustCompile(`^[A-Za-z]{1,2}$`),
	}

	for _, str := range strings {
		if seen[str] || len(str) < 4 {
			continue
		}

		// Check against noise patterns.
		isNoise := false
		for _, pattern := range noisePatterns {
			if pattern.MatchString(str) {
				isNoise = true
				break
			}
		}

		if !isNoise {
			seen[str] = true
			filtered = append(filtered, str)
		}
	}

	return filtered
}

// StringsAnalysisWrapper exports string analysis to JavaScript with popup display.
func StringsAnalysisWrapper(this js.Value, args []js.Value) any {

	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	// Parse PE file.
	reader := strings.NewReader(string(fileBytes))
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("Error parsing PE file: %v", err))
	}
	defer pe_file.Close()

	// Extract strings with different encodings.
	stringResults := processStrings(pe_file, fileBytes)

	// Format results for popup display.
	popupContent := formatStringsForPopup(stringResults)

	// Create popup window with results.
	createStringsPopup(popupContent)

	return js.ValueOf("String analysis completed - check popup window")
}

// StringsAnalysisInlineWrapper exports string analysis to JavaScript for inline display.
func StringsAnalysisInlineWrapper(this js.Value, args []js.Value) any {

	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	// Parse PE file.
	reader := strings.NewReader(string(fileBytes))
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("Error parsing PE file: %v", err))
	}
	defer pe_file.Close()

	// Extract strings with different encodings.
	stringResults := processStrings(pe_file, fileBytes)

	// Format results for inline display.
	inlineContent := formatStringsForInline(stringResults)

	return js.ValueOf(inlineContent)
}

// formatStringsForPopup formats string results for HTML popup display.
// These are the same encoding formats formatted by the strings command.
func formatStringsForPopup(results map[string][]string) string {
	html := `
	<div style="font-family: 'Courier New', monospace; padding: 20px; max-height: 80vh; overflow-y: auto;">
		<h2 style="color: #333; margin-bottom: 20px;">PE String Analysis</h2>
		<div style="margin-bottom: 10px;">
			<strong>Encoding Legend:</strong><br>
			s = 7-bit ASCII, S = 8-bit ASCII<br>
			l = 16-bit LE, b = 16-bit BE<br>
			L = 32-bit LE, B = 32-bit BE
		</div>
	`

	encodingOrder := []string{"7-bit ASCII (s)", "8-bit ASCII (S)", "16-bit LE (l)", "16-bit BE (b)", "32-bit LE (L)", "32-bit BE (B)"}

	for _, encoding := range encodingOrder {
		strings := results[encoding]
		html += fmt.Sprintf(`
	<div style="margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; border-radius: 5px;">
		<h3 style="color: #0066cc; margin-top: 0;">%s</h3>
		<div style="color: #666; margin-bottom: 10px;">Found %d strings</div>
		<div style="max-height: 400px; overflow-y: auto; background: #f9f9f9; padding: 10px; border-radius: 3px;">
	`, encoding, len(strings))

		if len(strings) == 0 {
			html += "<em>No strings found</em>"
		} else {
			for i, str := range strings {
				// Show all strings without truncation
				html += fmt.Sprintf("<div>%d. %s</div>", i+1, htmlEscape(str))
			}
		}

		html += "</div></div>"
	}

	html += "</div>"
	return html
}

// formatStringsForInline formats string results for inline display.
func formatStringsForInline(results map[string][]string) string {
	var builder strings.Builder

	builder.WriteString("PE String Analysis Results\n\n")
	builder.WriteString("Encoding Legend:\n")
	builder.WriteString("s = 7-bit ASCII, S = 8-bit ASCII\n")
	builder.WriteString("l = 16-bit LE, b = 16-bit BE\n")
	builder.WriteString("L = 32-bit LE, B = 32-bit BE\n\n")

	encodingOrder := []string{"7-bit ASCII (s)", "8-bit ASCII (S)", "16-bit LE (l)", "16-bit BE (b)", "32-bit LE (L)", "32-bit BE (B)"}

	for _, encoding := range encodingOrder {
		strings := results[encoding]
		builder.WriteString(fmt.Sprintf("%s (Found %d strings):\n", encoding, len(strings)))

		if len(strings) == 0 {
			builder.WriteString("  No strings found\n")
		} else {
			for i, str := range strings {
				// No limit - show all strings
				// Limit string length for display
				displayStr := str
				if len(displayStr) > 100 {
					displayStr = displayStr[:100] + "..."
				}
				builder.WriteString(fmt.Sprintf("  %d. %s\n", i+1, displayStr))
			}
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// getString reads a null-terminated string from data at the given offset.
func getString(data []byte, offset int) (string, error) {
	if offset < 0 || offset >= len(data) {
		return "", fmt.Errorf("offset out of bounds")
	}

	var result []byte
	for i := offset; i < len(data); i++ {
		if data[i] == 0 {
			break
		}
		result = append(result, data[i])
	}

	return string(result), nil
}

// processExports analyzes and displays PE export information.
func processExports(pe_file *pe.File) string {
	result := "[+] Exports:\n"

	// Check if this is a 64-bit PE.
	// IMAGE_FILE_MACHINE_AMD64.
	pe64 := pe_file.Machine == 0x8664

	// Get the number of data directory entries.
	var ddLength uint32
	if pe64 {
		if oh64, ok := pe_file.OptionalHeader.(*pe.OptionalHeader64); ok {
			ddLength = oh64.NumberOfRvaAndSizes
		} else {
			return result + "  No exports found (invalid optional header)\n\n"
		}
	} else {
		if oh32, ok := pe_file.OptionalHeader.(*pe.OptionalHeader32); ok {
			ddLength = oh32.NumberOfRvaAndSizes
		} else {
			return result + "  No exports found (invalid optional header)\n\n"
		}
	}

	// Check if exports directory exists (index 0 = IMAGE_DIRECTORY_ENTRY_EXPORT).
	if ddLength < 1 {
		return result + "  No exports found (no data directories)\n\n"
	}

	// Get the export data directory entry.
	var edd pe.DataDirectory
	if pe64 {
		edd = pe_file.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[0]
	} else {
		edd = pe_file.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[0]
	}

	// Check if export directory exists.
	if edd.VirtualAddress == 0 || edd.Size == 0 {
		return result + "  No exports found\n\n"
	}

	// Find the section containing the export directory.
	var ds *pe.Section
	for _, s := range pe_file.Sections {
		if s.VirtualAddress <= edd.VirtualAddress && edd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}

	if ds == nil {
		return result + "  No exports found (export directory not in any section)\n\n"
	}

	// Get section data.
	d, err := ds.Data()
	if err != nil {
		return result + fmt.Sprintf("  Error reading section data: %v\n\n", err)
	}

	exportDirOffset := edd.VirtualAddress - ds.VirtualAddress
	if int(exportDirOffset) >= len(d) {
		return result + "  Export directory offset out of bounds\n\n"
	}

	// Parse export directory.
	dxd := d[exportDirOffset:]

	// Minimum size for export directory.
	if len(dxd) < 40 {
		return result + "  Export directory too small\n\n"
	}

	var dt ExportDirectory
	dt.ExportFlags = binary.LittleEndian.Uint32(dxd[0:4])
	dt.TimeDateStamp = binary.LittleEndian.Uint32(dxd[4:8])
	dt.MajorVersion = binary.LittleEndian.Uint16(dxd[8:10])
	dt.MinorVersion = binary.LittleEndian.Uint16(dxd[10:12])
	dt.NameRVA = binary.LittleEndian.Uint32(dxd[12:16])
	dt.OrdinalBase = binary.LittleEndian.Uint32(dxd[16:20])
	dt.NumberOfFunctions = binary.LittleEndian.Uint32(dxd[20:24])
	dt.NumberOfNames = binary.LittleEndian.Uint32(dxd[24:28])
	dt.AddressTableAddr = binary.LittleEndian.Uint32(dxd[28:32])
	dt.NameTableAddr = binary.LittleEndian.Uint32(dxd[32:36])
	dt.OrdinalTableAddr = binary.LittleEndian.Uint32(dxd[36:40])

	// Get DLL name.
	if dt.NameRVA >= ds.VirtualAddress && dt.NameRVA < ds.VirtualAddress+ds.VirtualSize {
		dt.DllName, _ = getString(d, int(dt.NameRVA-ds.VirtualAddress))
	}

	result += fmt.Sprintf("  DLL Name: %s\n", dt.DllName)
	result += fmt.Sprintf("  Number of Functions: %d\n", dt.NumberOfFunctions)
	result += fmt.Sprintf("  Number of Names: %d\n", dt.NumberOfNames)
	result += fmt.Sprintf("  Ordinal Base: %d\n", dt.OrdinalBase)
	result += fmt.Sprintf("  Timestamp: 0x%X\n", dt.TimeDateStamp)
	result += fmt.Sprintf("  Version: %d.%d\n\n", dt.MajorVersion, dt.MinorVersion)

	// Build ordinal->name mapping.
	ordinalTable := make(map[uint16]uint32)
	if dt.OrdinalTableAddr > ds.VirtualAddress && dt.NameTableAddr > ds.VirtualAddress {

		// Check bounds.
		ordinalOffset := dt.OrdinalTableAddr - ds.VirtualAddress
		nameOffset := dt.NameTableAddr - ds.VirtualAddress

		if int(ordinalOffset) < len(d) && int(nameOffset) < len(d) {
			dno := d[ordinalOffset:]
			dnn := d[nameOffset:]

			for n := uint32(0); n < dt.NumberOfNames; n++ {
				if int((n*2)+2) <= len(dno) && int((n*4)+4) <= len(dnn) {
					ord := binary.LittleEndian.Uint16(dno[n*2 : (n*2)+2])
					nameRVA := binary.LittleEndian.Uint32(dnn[n*4 : (n*4)+4])
					ordinalTable[ord] = nameRVA
				}
			}
		}
	}

	// Parse export address table.
	if dt.AddressTableAddr > ds.VirtualAddress {
		addrOffset := dt.AddressTableAddr - ds.VirtualAddress
		if int(addrOffset) < len(d) {
			dna := d[addrOffset:]

			result += "  Exported Functions:\n"
			for i := uint32(0); i < dt.NumberOfFunctions; i++ {
				if int((i*4)+4) <= len(dna) {
					var export Export
					export.VirtualAddress = binary.LittleEndian.Uint32(dna[i*4 : (i*4)+4])
					export.Ordinal = dt.OrdinalBase + i

					// Skip null entries.
					if export.VirtualAddress == 0 {
						continue
					}

					// Check if this is a forwarder (address points inside export section).
					if ds.VirtualAddress <= export.VirtualAddress && export.VirtualAddress < ds.VirtualAddress+ds.VirtualSize {
						export.Forward, _ = getString(d, int(export.VirtualAddress-ds.VirtualAddress))
					}

					// Check if we have a name for this ordinal.
					if nameRVA, ok := ordinalTable[uint16(i)]; ok {
						if nameRVA >= ds.VirtualAddress && nameRVA < ds.VirtualAddress+ds.VirtualSize {
							export.Name, _ = getString(d, int(nameRVA-ds.VirtualAddress))
						}
					}

					// Format output.
					if export.Name != "" {
						if export.Forward != "" {
							result += fmt.Sprintf("    %d. %s (Ordinal: %d, Forward: %s)\n", i+1, export.Name, export.Ordinal, export.Forward)
						} else {
							result += fmt.Sprintf("    %d. %s (Ordinal: %d, RVA: 0x%X)\n", i+1, export.Name, export.Ordinal, export.VirtualAddress)
						}
					} else {
						if export.Forward != "" {
							result += fmt.Sprintf("    %d. <unnamed> (Ordinal: %d, Forward: %s)\n", i+1, export.Ordinal, export.Forward)
						} else {
							result += fmt.Sprintf("    %d. <unnamed> (Ordinal: %d, RVA: 0x%X)\n", i+1, export.Ordinal, export.VirtualAddress)
						}
					}
				}
			}
		}
	}

	if dt.NumberOfFunctions == 0 {
		result += "    No exported functions found\n"
	}

	return result + "\n"
}

// htmlEscape escapes HTML special characters
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// createStringsPopup creates a popup window to display string analysis results
func createStringsPopup(content string) {
	// Create popup window with unique name to avoid reuse issues
	windowName := fmt.Sprintf("StringAnalysis_%d", js.Global().Get("Date").New().Call("getTime").Int())
	popup := js.Global().Call("open", "", windowName, "width=1200,height=800,scrollbars=yes,resizable=yes")

	// Create basic HTML structure first
	popup.Get("document").Call("write", `<!DOCTYPE html><html><head><title>PE String Analysis</title><style>
		body { margin: 0; padding: 0; font-family: 'Courier New', monospace; }
		.header { background: #0066cc; color: white; padding: 10px; position: sticky; top: 0; z-index: 100; }
		.content { padding: 0; }
	</style></head><body><div class="header"><h1 style="margin: 0;">PE String Analysis Results</h1></div><div class="content" id="content"></div></body></html>`)
	popup.Get("document").Call("close")

	// Set content using innerHTML to avoid JavaScript string escaping issues
	popup.Get("document").Call("getElementById", "content").Set("innerHTML", content)
}

// generatePopupHTML creates the complete HTML for the popup window
func generatePopupHTML(content string) string {
	return fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>PE String Analysis</title>
			<style>
				body { margin: 0; padding: 0; font-family: 'Courier New', monospace; }
				.header { background: #0066cc; color: white; padding: 10px; position: sticky; top: 0; z-index: 100; }
				.content { padding: 0; }
			</style>
		</head>
		<body>
			<div class="header">
				<h1 style="margin: 0;">PE String Analysis Results</h1>
			</div>
			<div class="content">%s</div>
		</body>
		</html>
	`, content)
}

// calculateImphash computes the import hash (imphash) of a PE file.
func calculateImphash(pe_file *pe.File) string {
	iat, _, _, err := pe_file.ImportDirectoryTable()
	if err != nil {
		return ""
	}

	symbols, err := pe_file.ImportedSymbols()
	if err != nil {
		return ""
	}

	var imports []string

	// Create a map to organize symbols by DLL.
	dllSymbols := make(map[string][]string)

	for _, sym := range symbols {
		parts := strings.Split(sym, ":")
		if len(parts) >= 2 {
			funcName := strings.ToLower(parts[0])
			dllName := strings.ToLower(parts[1])

			// Remove .dll extension if present.
			if strings.HasSuffix(dllName, ".dll") {
				dllName = dllName[:len(dllName)-4]
			}

			dllSymbols[dllName] = append(dllSymbols[dllName], funcName)
		}
	}

	// Build the import string in the format: dll.function,dll.function
	for _, imp := range iat {
		dllName := strings.ToLower(imp.DllName)
		if strings.HasSuffix(dllName, ".dll") {
			dllName = dllName[:len(dllName)-4]
		}

		if funcs, exists := dllSymbols[dllName]; exists {
			for _, funcName := range funcs {
				imports = append(imports, dllName+"."+funcName)
			}
		}
	}

	if len(imports) == 0 {
		return ""
	}

	// Join all imports with commas and compute MD5.
	importString := strings.Join(imports, ",")
	hash := md5.Sum([]byte(importString))
	return hex.EncodeToString(hash[:])
}

// SectionObjdumpWrapper exports section objdump analysis to JavaScript.
func SectionObjdumpWrapper(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return js.ValueOf("Error: insufficient arguments for section objdump")
	}

	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])
	sectionIndex := args[1].Int()

	// Parse PE file.
	reader := strings.NewReader(string(fileBytes))
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("Error parsing PE file: %v", err))
	}
	defer pe_file.Close()

	// Generate objdump for the specified section.
	objdumpResult := generateSectionObjdump(pe_file, sectionIndex, fileBytes)

	// Create popup with objdump results.
	createObjdumpPopup(objdumpResult, sectionIndex)

	return js.ValueOf("Section objdump completed - check popup window")
}

// generateSectionObjdump creates objdump output for a specific section. Trying to use a known format
// based on the linux output of objdump.
func generateSectionObjdump(pe_file *pe.File, sectionIndex int, fileBytes []byte) string {
	if sectionIndex < 0 || sectionIndex >= len(pe_file.Sections) {
		return "Error: Invalid section index"
	}

	section := pe_file.Sections[sectionIndex]
	result := fmt.Sprintf("Objdump for Section: %s\n", section.Name)
	result += fmt.Sprintf("Virtual Address: 0x%X\n", section.VirtualAddress)
	result += fmt.Sprintf("Size: 0x%X (%d bytes)\n", section.Size, section.Size)
	result += fmt.Sprintf("File Offset: 0x%X\n\n", section.Offset)

	// Get section data.
	sectionData, err := section.Data()
	if err != nil {
		return fmt.Sprintf("Error reading section data: %v", err)
	}

	if len(sectionData) == 0 {
		return result + "Section contains no data.\n"
	}

	// Generate hex dump with ASCII representation (objdump-style).
	result += "Hex Dump:\n"
	result += "Address          | Hex Data                                         | ASCII\n"
	result += "-----------------|--------------------------------------------------|------------------\n"

	baseAddr := section.VirtualAddress
	for i := 0; i < len(sectionData); i += 16 {
		addr := baseAddr + uint32(i)
		result += fmt.Sprintf("%08X         | ", addr)

		// Hex bytes.
		hexPart := ""
		asciiPart := ""
		for j := 0; j < 16; j++ {
			if i+j < len(sectionData) {
				b := sectionData[i+j]
				hexPart += fmt.Sprintf("%02X ", b)
				if b >= 32 && b <= 126 {
					asciiPart += string(b)
				} else {
					asciiPart += "."
				}
			} else {
				hexPart += "   "
				asciiPart += " "
			}
		}

		result += fmt.Sprintf("%-48s | %s\n", hexPart, asciiPart)
	}

	// Add disassembly hint for executable sections.
	// IMAGE_SCN_MEM_EXECUTE.
	if section.Characteristics&0x20000000 != 0 {
		result += "\n[Note: This is an executable section. For full disassembly, use external tools like IDA Pro, Ghidra, or objdump]\n"
		result += generateSimpleDisassembly(sectionData, baseAddr)
	}

	return result
}

// generateSimpleDisassembly provides basic instruction pattern recognition.
func generateSimpleDisassembly(data []byte, baseAddr uint32) string {
	result := "\nBasic Instruction Patterns:\n"
	result += "Address   | Bytes     | Pattern\n"
	result += "----------|-----------|------------------\n"

	for i := 0; i < len(data)-1; i++ {
		addr := baseAddr + uint32(i)

		// Look for common x86/x64 instruction patterns.
		if i+1 < len(data) {
			b1, b2 := data[i], data[i+1]

			// Common instruction patterns.
			switch {
			// NOP.
			case b1 == 0x90:
				result += fmt.Sprintf("%08X  | %02X        | NOP\n", addr, b1)
			// INT3 (breakpoint).
			case b1 == 0xCC:
				result += fmt.Sprintf("%08X  | %02X        | INT3 (breakpoint)\n", addr, b1)
			// RET.
			case b1 == 0xC3:
				result += fmt.Sprintf("%08X  | %02X        | RET\n", addr, b1)
			// CALL rel32.
			case b1 == 0xE8:
				if i+4 < len(data) {
					offset := binary.LittleEndian.Uint32(data[i+1 : i+5])
					result += fmt.Sprintf("%08X  | %02X %02X %02X %02X %02X | CALL 0x%X\n", addr, b1, data[i+1], data[i+2], data[i+3], data[i+4], addr+5+offset)
					i += 4
				}
			// JMP rel32.
			case b1 == 0xE9:
				if i+4 < len(data) {
					offset := binary.LittleEndian.Uint32(data[i+1 : i+5])
					result += fmt.Sprintf("%08X  | %02X %02X %02X %02X %02X | JMP 0x%X\n", addr, b1, data[i+1], data[i+2], data[i+3], data[i+4], addr+5+offset)
					i += 4
				}
			// MOV (x64).
			case b1 == 0x48 && b2 == 0x89:
				result += fmt.Sprintf("%08X  | %02X %02X     | MOV (x64)\n", addr, b1, b2)
				i++
			// PUSH EBP/RBP.
			case b1 == 0x55:
				result += fmt.Sprintf("%08X  | %02X        | PUSH EBP/RBP\n", addr, b1)
			// POP EBP/RBP.
			case b1 == 0x5D:
				result += fmt.Sprintf("%08X  | %02X        | POP EBP/RBP\n", addr, b1)
				result += fmt.Sprintf("%08X  | %02X        | POP EBP/RBP\n", addr, b1)
			}
		}
	}

	return result
}

// createObjdumpPopup creates a popup window to display objdump results.
func createObjdumpPopup(content string, sectionIndex int) {

	// Create popup window with unique name.
	windowName := fmt.Sprintf("SectionObjdump_%d_%d", sectionIndex, js.Global().Get("Date").New().Call("getTime").Int())
	popup := js.Global().Call("open", "", windowName, "width=1400,height=900,scrollbars=yes,resizable=yes")

	// Create HTML structure for objdump display.
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Section Objdump - Index %d</title>
	<style>
		body { 
			margin: 0; 
			padding: 0; 
			font-family: 'Courier New', monospace; 
			background: #1e1e1e; 
			color: #d4d4d4; 
		}
		.header { 
			background: #0e639c; 
			color: white; 
			padding: 15px; 
			position: sticky; 
			top: 0; 
			z-index: 100; 
			border-bottom: 2px solid #1177bb;
		}
		.content { 
			padding: 20px; 
			white-space: pre-wrap; 
			font-size: 12px; 
			line-height: 1.4;
		}
		.address { color: #569cd6; }
		.hex { color: #ce9178; }
		.ascii { color: #608b4e; }
		.instruction { color: #dcdcaa; }
		h1 { margin: 0; font-size: 18px; }
		.subtitle { font-size: 14px; opacity: 0.8; margin-top: 5px; }
	</style>
</head>
<body>
	<div class="header">
		<h1>Section Objdump Analysis</h1>
		<div class="subtitle">Section Index: %d</div>
	</div>
	<div class="content">%s</div>
</body>
</html>`, sectionIndex, sectionIndex, htmlEscape(content))

	// Write the complete HTML to the popup.
	popup.Get("document").Call("write", htmlContent)
	popup.Get("document").Call("close")
}

func AnalyzeWrapper(this js.Value, args []js.Value, fileBytes []byte, pe_file *pe.File) any {

	//fileBytes := make([]byte, args[0].Get("length").Int()).
	js.CopyBytesToGo(fileBytes, args[0])

	// Try to analyze the PE file, but handle errors for packed files.
	result := ""
	defer func() {
		if r := recover(); r != nil {
			// If we panic during analysis, provide basic info.
			result = "[!] Error during PE analysis: " + fmt.Sprintf("%v\n", r) + "\n"
			result += "[!] File may be packed or obfuscated.\n\n"
			result += AnalyzeBasicInfo(fileBytes)
		}
	}()

	result = peAnalyze(fileBytes, pe_file)
	return js.ValueOf(result)

}

// AnalyzeBasicInfo provides basic information for packed or obfuscated PE files
// that cannot be fully parsed by the PE library
func AnalyzeBasicInfo(fileBytes []byte) string {
	result := "[+] Basic PE Information (Packed File)\n\n"

	// File hashes.
	md5_h := md5.Sum(fileBytes)
	sha1_h := sha1.Sum(fileBytes)
	sha256_h := sha256.Sum256(fileBytes)
	result += fmt.Sprintf("[*] MD5: %s\n", hex.EncodeToString(md5_h[:]))
	result += fmt.Sprintf("[*] SHA1: %s\n", hex.EncodeToString(sha1_h[:]))
	result += fmt.Sprintf("[*] SHA256: %s\n\n", hex.EncodeToString(sha256_h[:]))

	// File size.
	result += fmt.Sprintf("[*] File Size: %d bytes\n", len(fileBytes))

	// Entropy calculation for the entire file.
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

	result += fmt.Sprintf("[*] File entropy: %.4f\n", entropy)
	if entropy > 7.0 {
		result += "[!] High entropy suggests the file may be packed or encrypted.\n"
	} else if entropy > 6.0 {
		result += "[*] Medium entropy suggests possible packing or compression.\n"
	}

	// Try to detect specific packer.
	packer := detectPacker(fileBytes)
	if packer != "" {
		result += fmt.Sprintf("\n[+] Packer detected: %s\n", packer)
	}

	// Try to parse the PE file to extract basic information even for packed files.
	reader := bytes.NewReader(fileBytes)
	pe_file, err := pe.NewFile(reader)
	if err != nil {
		// If we can't parse it at all, provide basic DOS header information.
		if len(fileBytes) >= 64 {
			result += "\n[+] DOS Header:\n"
			result += fmt.Sprintf("  Magic: 0x%X (%c%c)\n", uint16(fileBytes[0])|uint16(fileBytes[1])<<8, fileBytes[0], fileBytes[1])

			// DOS header e_lfanew (PE header offset).
			peOffset := uint32(fileBytes[0x3C]) | (uint32(fileBytes[0x3D]) << 8) |
				(uint32(fileBytes[0x3E]) << 16) | (uint32(fileBytes[0x3F]) << 24)
			result += fmt.Sprintf("  PE Header Offset: 0x%X\n", peOffset)

			// Check if PE header is within file bounds.
			if uint32(len(fileBytes)) > peOffset+4 {
				peSignature := fileBytes[peOffset : peOffset+4]
				result += fmt.Sprintf("  PE Signature: %c%c\\x%02X\\x%02X\n", peSignature[0], peSignature[1], peSignature[2], peSignature[3])
			}
		}
	} else {
		// If we can parse it, extract as much information as possible.
		defer pe_file.Close()

		// File header information.
		result += "\n[+] File Header:\n"
		result += fmt.Sprintf("  Machine: 0x%X\n", pe_file.FileHeader.Machine)
		result += fmt.Sprintf("  Number of sections: %d\n", pe_file.FileHeader.NumberOfSections)
		result += fmt.Sprintf("  TimeDateStamp: %s\n", time.Unix(int64(pe_file.FileHeader.TimeDateStamp), 0).Format("2006-01-02 15:04:05"))

		// Section information (like pedump).
		result += "\n=== SECTIONS ===\n"
		result += "  NAME          RVA      VSZ   RAW_SZ  RAW_PTR  nREL  REL_PTR nLINE LINE_PTR     FLAGS\n"
		for _, section := range pe_file.Sections {
			name := strings.Trim(string(section.Name[:]), "\x00")
			result += fmt.Sprintf("  %-12s  %04x  %8x  %8x  %08x     0        0     0        0  %08x",
				name, section.VirtualAddress, section.VirtualSize, section.Size, section.Offset, section.Characteristics)

			// Decode section characteristics.
			flags := decodeSectionFlags(section.Characteristics)
			if len(flags) > 0 {
				result += fmt.Sprintf("  %s", strings.Join(flags, " "))
			}
			result += "\n"
		}

		// Try to extract import information (like pedump).
		result += "\n=== IMPORTS ===\n"
		result += "\nMODULE_NAME      HINT   ORD  FUNCTION_NAME\n"
		iat, _, _, err := pe_file.ImportDirectoryTable()
		if err == nil {
			for _, imp := range iat {
				result += fmt.Sprintf("%s\n", imp.DllName)
				result += "  (Import functions require full unpacking for packed files)\n"
			}
		} else {
			result += "  [!] Could not parse import table\n"
		}
	}

	result += "\n[!] This file appears to be packed or obfuscated.\n"
	result += "[!] For full analysis, unpack the file first using appropriate tools.\n"

	return result
}

// detectPacker tries to identify the packer used on a PE file.
func detectPacker(fileBytes []byte) string {
	// Convert file bytes to string for searching.
	fileStr := string(fileBytes)

	// Comprehensive packer signatures with their names.
	packerSignatures := map[string]string{
		// UPX - The Ultimate Packer for eXecutables.
		"UPX!": "UPX - The Ultimate Packer for eXecutables",
		"UPX0": "UPX - The Ultimate Packer for eXecutables",
		"UPX1": "UPX - The Ultimate Packer for eXecutables",
		"UPX2": "UPX - The Ultimate Packer for eXecutables",

		// ASPack - A highly compressed packer for Win32 executables.
		"ASPack": "ASPack - Highly compressed packer for Win32 executables",

		// PECompact - Compression tool for Win32 applications.
		"PECompact": "PECompact - Compression tool for Win32 applications",

		// Petite - Early executable compressor, known for its small footprint.
		"Petite": "Petite - Early executable compressor",

		// FSG - Fast and Simple Packer, often used in malware.
		"FSG!": "FSG - Fast and Simple Packer (often used in malware)",

		// MEW - Morphing Executable Wrapper, popular in the early 2000s.
		"MEW!": "MEW - Morphing Executable Wrapper",

		// NsPack - Lightweight packer, commonly seen in older malware.
		"NsPack": "NsPack - Lightweight packer (commonly seen in older malware)",

		// RLPack - Rare packer, sometimes associated with adware or trojans.
		"RLPack": "RLPack - Rare packer (sometimes associated with adware/trojans)",

		// yoda's Protector - A manual API call protector and packer used in cracks.
		"yoda's Protector": "yoda's Protector - Manual API call protector and packer",

		// yoda's Crypter - Variant of yoda's tools focused on obfuscation.
		"yoda's Crypter": "yoda's Crypter - Obfuscation-focused variant of yoda's tools",

		// tElock - Popular freeware executable protector with API hashing.
		"tElock": "tElock - Freeware executable protector with API hashing",

		// PELock - Professional PE file locker and protector.
		"PELock NT": "PELock - Professional PE file locker and protector",
		"PELock":    "PELock - Professional PE file locker and protector",

		// WinUpack - A strong, open-source crypter popular in packing cracked software.
		"WinUpack": "WinUpack - Open-source crypter (popular in cracked software)",

		// EPack - Executable packer with compression and basic protection.
		"!EPack": "EPack - Executable packer with compression and basic protection",

		// mPress - Strong compressor and protector with encryption features.
		"mPress": "mPress - Strong compressor and protector with encryption",

		// Armadillo - Commercial protection system with anti-debug and anti-reverse features.
		"Armadillo": "Armadillo - Commercial protection system with anti-debug features",

		// Themida - Advanced commercial protector with anti-reverse engineering techniques.
		"Themida": "Themida - Advanced commercial protector with anti-reverse engineering",

		// Obsidium - Software protection system for Windows applications.
		"Obsidium": "Obsidium - Software protection system for Windows applications",

		// Enigma Protector - Virtualization and encryption-based protector.
		"Enigma Protector": "Enigma Protector - Virtualization and encryption-based protector",

		// Packetyzer - Network-aware packer often used in trojans.
		"Packetyzer": "Packetyzer - Network-aware packer (often used in trojans)",

		// StarForce - Primarily a DRM system, sometimes exhibits packing behavior.
		"StarForce": "StarForce - DRM system with packing behavior",

		// Gigapack - Series of packers developed by the "Giga" team.
		"GigaPack": "GigaPack - Packer developed by the Giga team",

		// NSIS (Nullsoft Scriptable Install System) - Often used to package malware installers.
		"Nullsoft Installer": "NSIS - Nullsoft Scriptable Install System (often used for malware installers)",
		"NSIS_":              "NSIS - Nullsoft Scriptable Install System (often used for malware installers)",

		// UPack - Packer commonly used in older malware (not to be confused with UPX)
		"UPack": "UPack - Packer commonly used in older malware",

		// Algodom - Less common packer, sometimes seen in niche malware
		"AlgoDom": "AlgoDom - Less common packer (sometimes seen in niche malware)",

		// Bite/PEtite variant - Obfuscation and compression packer.
		"bitArithmetic": "bitArithmetic - Obfuscation and compression packer",

		// SUE - Simple Universal Encrypter, used in small malware samples
		"SUE": "SUE - Simple Universal Encrypter (used in small malware samples)",

		// Additional common packers.
		"VMProtect":        "VMProtect - Code virtualization protector",
		"Code Virtualizer": "Code Virtualizer - Code virtualization protector",
		"WinLicense":       "WinLicense - Commercial software protection system",
		"EXECryptor":       "EXECryptor - Executable protector and packer",
		"ASProtect":        "ASProtect - Anti-reverse engineering protector",
		"ACProtect":        "ACProtect - Anti-cracking protector",
		"NeoLite":          "NeoLite - Executable compressor",
		"kkrunchy":         "kkrunchy - Executable compressor",
		"Crinkler":         "Crinkler - Executable compressor",
		"Morphine":         "Morphine - Polymorphic packer",
		"SVKP":             "SVKP - Simple packer",
		"PEBundle":         "PEBundle - PE file bundler",
		"MPRMMGVA":         "MPRMMGVA - Obfuscation packer",
	}

	// Check for each packer signature.
	for signature, packerName := range packerSignatures {
		if strings.Contains(fileStr, signature) {
			return packerName
		}
	}

	return ""
}

// decodeSectionFlags converts section characteristics flags to readable strings.
func decodeSectionFlags(characteristics uint32) []string {
	var flags []string

	// Common section flags.
	// IMAGE_SCN_MEM_EXECUTE
	if characteristics&0x20000000 != 0 {
		flags = append(flags, "EXEC")
	}
	// IMAGE_SCN_MEM_READ
	if characteristics&0x40000000 != 0 {
		flags = append(flags, "READ")
	}
	// IMAGE_SCN_MEM_WRITE
	if characteristics&0x80000000 != 0 {
		flags = append(flags, "WRITE")
	}
	// IMAGE_SCN_CNT_CODE
	if characteristics&0x00000020 != 0 {
		flags = append(flags, "CODE")
	}
	// IMAGE_SCN_CNT_INITIALIZED_DATA
	if characteristics&0x00000040 != 0 {
		flags = append(flags, "IDATA")
	}
	// IMAGE_SCN_CNT_UNINITIALIZED_DATA
	if characteristics&0x00000080 != 0 {
		flags = append(flags, "UDATA")
	}

	return flags
}

// queryTeamCymruHash provides nslookup commands for Team Cymru's Malware Hash Registry.
func queryTeamCymruHash(hash string) MalwareHashResult {
	result := MalwareHashResult{
		Hash: hash,
	}

	// Instead of making actual DNS queries, provide the commands to run.
	result.IsKnownMalware = false
	result.Timestamp = time.Now().Unix()

	return result
}

// formatMalwareHashResult formats the malware hash lookup result for display.
func formatMalwareHashResult(result MalwareHashResult) string {
	if result.Error != "" {
		return fmt.Sprintf("[!] Malware Hash Lookup Error: %s\n", result.Error)
	}

	output := "[+] Team Cymru Malware Hash Registry Lookup Commands:\n"
	output += fmt.Sprintf("  [*] Hash: %s\n", result.Hash)
	output += "\n  [*] Windows Command:\n"
	output += fmt.Sprintf("      nslookup %s.hash.cymru.com\n", result.Hash)
	output += "\n  [*] Linux/Mac Command:\n"
	output += fmt.Sprintf("      nslookup %s.hash.cymru.com\n", result.Hash)
	output += fmt.Sprintf("      # Alternative: dig +short %s.hash.cymru.com A\n", result.Hash)
	output += "\n  [*] Expected Results:\n"
	output += "      - If hash is MALWARE: Returns 127.0.0.2\n"
	output += "      - If hash is CLEAN/UNKNOWN: Returns NXDOMAIN (not found)\n"
	output += "\n  [!] NOTE: Run these commands manually in your terminal/command prompt\n"

	return output + "\n"
}
