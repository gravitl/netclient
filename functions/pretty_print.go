package functions

import (
	"encoding/json"
	"fmt"

	"github.com/gravitl/netmaker/logger"
)

// PrettyPrint - print JSON with indentation
func PrettyPrint(data any) {
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Log(0, "Error parsing to JSON: ", err.Error())
	}
	fmt.Println(string(body))
}
