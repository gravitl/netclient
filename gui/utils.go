package gui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Opens the user's browser with the given URL
func OpenUrlInBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	return err
}

// GetFileAsBytes returns the byte array form files
// It can be used to return the app icon
func GetFileAsBytes(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	return b
}
