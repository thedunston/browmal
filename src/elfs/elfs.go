package elfs

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"syscall/js"

	"github.com/glaslos/ssdeep"
	"github.com/yalue/elf_reader"
)

/** Code adopted from https://github.com/yalue/elf_reader/tree/master/elf_view */

/**
 * elfAnalyze is a function that takes a file as a byte array and an ELFFile object,
 * and returns the results of the analysis as a string.
 */
func elfAnalyze(fileBytes []byte, elf elf_reader.ELFFile) string {

	result := "[+] ELF Detected\n\n"

	// File hashes.
	md5_h := md5.Sum(fileBytes)
	sha1_h := sha1.Sum(fileBytes)
	sha256_h := sha256.Sum256(fileBytes)
	result += fmt.Sprintf("[*] MD5: %s\n", hex.EncodeToString(md5_h[:]))
	result += fmt.Sprintf("[*] SHA1: %s\n", hex.EncodeToString(sha1_h[:]))
	result += fmt.Sprintf("[*] SHA256: %s\n", hex.EncodeToString(sha256_h[:]))

	// SSDeep fuzzy hash
	ssdeep_h, err := ssdeep.FuzzyBytes(fileBytes)
	if err != nil {
		result += fmt.Sprintf("[*] SSDeep: Error calculating fuzzy hash: %v\n\n", err)
	} else {
		result += fmt.Sprintf("[*] SSDeep: %s\n\n", ssdeep_h)
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

	result += fmt.Sprintf("[*] File entropy: %.4f\n\n", entropy)

	result += fmt.Sprintf("[+] Sections: %s\n", printSections(elf))
	result += fmt.Sprintf("[+] Symbols: %s\n\n", printSymbols(elf))
	result += fmt.Sprintf("[+] Strings: %s\n\n", printStrings(elf))
	result += fmt.Sprintf("[+] Segments: %s\n\n", printSegments(elf))
	result += fmt.Sprintf("[+] Program Headers Offsets: %s\n\n", printProgramHeaderOffsets(elf))
	result += fmt.Sprintf("[+] Relocations: %s\n\n", printRelocations(elf))
	result += fmt.Sprintf("[+] Dynamic Linking Table: %s\n\n", printDynamicLinkingTable(elf))

	return result

}

/**
 * printDynamicLinkingTable prints the dynamic linking table of an ELF file.
 */
func printDynamicLinkingTable(f elf_reader.ELFFile) string {

	var sectionIndex uint16
	var e error
	var result string

	count := f.GetSectionCount()

	for i := uint16(0); i < count; i++ {

		if !f.IsDynamicSection(uint16(i)) {

			continue

		}

		sectionIndex = uint16(i)
		break

	}
	if sectionIndex == 0 {

		result += fmt.Sprintf("No dynamic linking table was found.\n")

		return result

	}
	name, e := f.GetSectionName(sectionIndex)
	if e != nil {

		return fmt.Sprintf("Failed getting dynamic table section name: %s", e)

	}

	entries, e := f.DynamicEntries(sectionIndex)
	if e != nil {

		return fmt.Sprintf("Failed parsing the dynamic section: %s", e)

	}

	log.Printf("Dynamic linking table in section %s:\n", name)
	header, e := f.GetSectionHeader(sectionIndex)
	if e != nil {

		return fmt.Sprintf("Failed getting .dynamic section header: %s", e)

	}

	stringContent, e := f.GetSectionContent(uint16(header.GetLinkedIndex()))
	if e != nil {

		return fmt.Sprintf("Failed getting strings for dynamic section: %s", e)

	}

	var stringValue []byte
	for i := range entries {

		entry := entries[i]

		// If the tag indicates a string value, we'll print the string instead
		// of the default format.
		switch entry.GetTag().GetValue() {
		case 1, 14, 15:

			stringValue, e = elf_reader.ReadStringAtOffset(

				uint32(entry.GetValue()), stringContent)

			if e != nil {

				return fmt.Sprintf("Failed getting string value for tag %s: %s",

					entry.GetTag(), e)

			}

			result += fmt.Sprintf("  %d. %s: %s\n", i, entry.GetTag(), stringValue)

		default:

			result += fmt.Sprintf("  %d. %s\n", i, entry)

		}
		if entry.GetTag().GetValue() == 0 {

			break

		}

	}
	return result

}

/**
 * printRelocations prints the relocations of an ELF file.
 */
func printRelocations(f elf_reader.ELFFile) string {

	count := f.GetSectionCount()
	var result string

	for i := uint16(0); i < count; i++ {

		if !f.IsRelocationTable(uint16(i)) {

			continue

		}

		name, e := f.GetSectionName(uint16(i))
		if e != nil {

			return fmt.Sprintf("Error getting relocation table name: %s", e)
		}

		relocations, e := f.GetRelocations(uint16(i))
		if e != nil {

			return fmt.Sprintf("Couldn't read relocation table: %s", e)

		}

		result += fmt.Sprintf("%d relocations in section %s:\n", len(relocations), name)
		for j, r := range relocations {

			result += fmt.Sprintf("  %d. %s\n", j, r)

		}

		return result

	}

	return ""

}

/**
 * printSymbols prints the symbols of an ELF file.
 */
func printSymbols(f elf_reader.ELFFile) string {

	var result string
	count := f.GetSectionCount()

	for i := uint16(0); i < count; i++ {

		if !f.IsSymbolTable(uint16(i)) {

			continue

		}

		name, e := f.GetSectionName(uint16(i))
		if e != nil {

			return fmt.Sprintf("Couldn't read section name: %s", e)

		}

		symbols, names, e := f.GetSymbols(uint16(i))
		if e != nil {

			return fmt.Sprintf("Couldn't read symbol table: %s", e)

		}

		result += fmt.Sprintf("%d function calls in section %s:\n", len(symbols), name)
		for j := range symbols {

			result += fmt.Sprintf("  %d. %s: %s\n", j, names[j], symbols[j])

		}

		return result

	}

	return ""
}

/**
 * printStrings prints the strings of an ELF file.
 */
func printStrings(f elf_reader.ELFFile) string {
	count := f.GetSectionCount()

	var result string

	for i := uint16(0); i < count; i++ {

		if !f.IsStringTable(uint16(i)) {

			continue

		}

		name, e := f.GetSectionName(uint16(i))
		if e != nil {

			return fmt.Sprintf("Error getting string table name: %s", e)

		}

		splitStrings, e := f.GetStringTable(uint16(i))
		if e != nil {

			return fmt.Sprintf("Couldn't read string table: %s", e)

		}

		result += fmt.Sprintf("%d strings in section %s:\n", len(splitStrings), name)
		for j, s := range splitStrings {

			result += fmt.Sprintf("  %d. %s\n", j, s)

		}

		return result

	}

	return ""

}

/**
 * printSegments prints the segments of an ELF file.
 */
func printSegments(f elf_reader.ELFFile) string {

	count := f.GetSegmentCount()

	var result string

	for i := uint16(0); i < count; i++ {

		header, e := f.GetProgramHeader(i)
		if e != nil {

			return fmt.Sprintf("Error getting segment %d header: %s", i, e)

		}

		result += fmt.Sprintf("%d. %s\n", i, header)

	}

	return result

}

/**
 * printProgramHeaderOffsets prints the program header offsets of an ELF file.
 */
func printProgramHeaderOffsets(f elf_reader.ELFFile) string {

	var offset uint64
	var headerSize uint64
	count := f.GetSegmentCount()
	var result string

	elf32File, ok := f.(*elf_reader.ELF32File)
	if ok {

		headerSize = uint64(elf32File.Header.ProgramHeaderEntrySize)
		offset = uint64(elf32File.Header.ProgramHeaderOffset)

	} else {

		elf64File := f.(*elf_reader.ELF64File)
		headerSize = uint64(elf64File.Header.ProgramHeaderEntrySize)
		offset = uint64(elf64File.Header.ProgramHeaderOffset)
	}

	for i := 0; i < int(count); i++ {

		result += fmt.Sprintf("Program header %d's offset in file: 0x%x\n", i, offset)
		offset += headerSize

	}

	return result

}

/**
 * printSections prints the sections of an ELF file.
 */
func printSections(elf elf_reader.ELFFile) string {

	var name string
	var err error
	var result string

	count := elf.GetSectionCount()

	//var i uint16
	for i := uint16(0); i < count; i++ {

		if i != 0 {

			name, err = elf.GetSectionName(uint16(i))

		} else {

			name, err = "<null section>", nil

		}
		if err != nil {

			result := fmt.Sprintf("Error getting section %d name: %s", i, err)
			return result
		}

		header, err := elf.GetSectionHeader(i)
		if err != nil {

			result := fmt.Sprintf("Error getting section %d header: %s", i, err)

			return result

		}
		result += fmt.Sprintf("  [%d] %s: %s\n", i, name, header)

	}

	return result
}

/**
 * AnalyzeWrapper is a wrapper function that takes a file as a byte array and an ELFFile object,
 * and returns the results of the analysis as a string.
 */
func AnalyzeWrapper(this js.Value, args []js.Value, elf elf_reader.ELFFile) any {
	// Extract file bytes from JavaScript arguments
	fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	result := elfAnalyze(fileBytes, elf)
	return js.ValueOf(result)

}
