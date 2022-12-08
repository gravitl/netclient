//go:build headless
// +build headless

package main

import (
	"fmt"
)

func init() {
	guiFunc = func() {
		fmt.Println("I regret to inform you, this netclient is headless")
	}
}
