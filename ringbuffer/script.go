// Script for Frida injections
package main

import (
	"embed"
	"log"
)

//go:embed scripts/xshmcreateimage.js
var XShmCreateImageScriptFS embed.FS

// XShmCreateImageScript is the script that will be injected to hook XShmCreateImage
var XShmCreateImageScript string

func init() {
	// Load the script from the embedded file system
	script, err := XShmCreateImageScriptFS.ReadFile("scripts/xshmcreateimage.js")
	if err != nil {
		log.Fatalf("Failed to load script: %v", err)
	}
	XShmCreateImageScript = string(script)
}
