//go:build !headless
// +build !headless

package assets

import "embed"

//go:embed all:dist
var Assets embed.FS
