package main

import (
	"debug/pe"
	"fmt"
	"strings"
	"syscall/js"

	//kingpin "github.com/alecthomas/kingpin/v2"
	"www.velocidex.com/golang/oleparse"
)

/**var (
	app  = kingpin.New("oleparse", "Parse Office files.")
	file = app.Arg("file", "File to load").Required().Strings()
)*/

func docAnalyze() string {

	var result string
	for _, f := range *file {
		// Parse the macros from the file
		macros, err := oleparse.ParseFile(f)
		if err != nil {
			return fmt.Sprintf("While parsing %v: %w", f, err)
		}

		// Process and print each VBA module as standard text
		for _, module := range macros {
			// Replace the JSON-style escape sequences with actual newlines and quotes
			formattedCode := strings.ReplaceAll(module.Code, `\r\n`, "\n")
			formattedCode = strings.ReplaceAll(formattedCode, `\"`, `"`)

			// Print the formatted VBA module content
			result += fmt.Sprintf("Module Name: %s\nStream Name: %s\nType: %s\nCode:\n%s\n---\n",
				module.ModuleName, module.StreamName, module.Type, formattedCode)
		}

		result += fmt.Sprintf("---\n")
	}

	return ""
}

//func main() {

func AnalyzeWrapper(this js.Value, args []js.Value, fileBytes []byte, pe_file *pe.File) any {

	//fileBytes := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(fileBytes, args[0])

	result := docAnalyze(fileBytes, pe_file)
	return js.ValueOf(result)

	//}
	/**app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate).DefaultEnvars()
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Call the doParse function
	err := doParse()
	kingpin.FatalIfError(err, "Parsing")
	*/
}
