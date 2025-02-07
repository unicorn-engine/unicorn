//go:build !static

package unicorn

// #cgo LDFLAGS: -lunicorn
import "C"
