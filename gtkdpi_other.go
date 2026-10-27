//go:build !linux || !cgo

package main

// fixGTKDPI is the non-Linux stub: the GTK DPI workaround only exists on
// Linux, where the app is built with cgo against gtk+-3.0.
func fixGTKDPI() {}
