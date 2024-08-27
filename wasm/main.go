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
	"syscall/js"

	"github.com/gabriel-vasile/mimetype"

	"github.com/Binject/debug/pe"
	"github.com/yalue/elf_reader"
)

// Check if a file is a PE file.
func checkPefile(fileBytes []byte) (bool, *pe.File) {

	result := false
	reader := bytes.NewReader(fileBytes)
	pe_file, err := pe.NewFile(reader)
	if err != nil {

		result = false

		return result, nil

	} else {

		result = true

	}
	defer pe_file.Close()

	return result, pe_file

}

// Check if it is an elf file.
func checkElffile(fileBytes []byte) (elf_reader.ELFFile, error) {
	return elf_reader.ParseELFFile(fileBytes)
}

func checkOfficeDocumentType(fileBytes []byte) bool {

	result := false

	// Detect MIME type from the file data.
	mtype := mimetype.Detect(fileBytes)

	// Check for specific Office document types.
	if mtype.Is("application/vnd.openxmlformats-officedocument.wordprocessingml.document") || mtype.Is("application/msword") || mtype.Is("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") || mtype.Is("application/vnd.ms-excel") || mtype.Is("application/vnd.openxmlformats-officedocument.presentationml.presentation") || mtype.Is("application/vnd.ms-powerpoint") {

		result = true

	} else {

		result = false

	}

	return result

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

		return js.ValueOf(pes.AnalyzeWrapper(this, args, fileBytes, pe_file))

	} else if isOffice {

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

	select {}

}
