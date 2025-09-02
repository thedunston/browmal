package officedoc

import (
	"fmt"
	"os"
	"strings"
)

var (
	OLE_DEBUG *bool
)

/**
 * DebugPrintf is a debug print function that prints a formatted string to the console.
 * It is only enabled if the OLE_DEBUG environment variable is set to 1.
 */
func DebugPrintf(fmt_str string, args ...interface{}) {
	if OLE_DEBUG == nil {
		value := false
		OLE_DEBUG = &value

		for _, x := range os.Environ() {
			if strings.HasPrefix(x, "OLE_DEBUG=1") {
				value = true
				break
			}
		}

	}

	if *OLE_DEBUG {
		if !strings.HasSuffix(fmt_str, "\n") {
			fmt_str += "\n"
		}
		fmt.Printf(fmt_str, args...)
	}
}
