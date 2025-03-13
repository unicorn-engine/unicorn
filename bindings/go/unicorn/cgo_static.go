//go:build static

package unicorn

// #cgo !darwin LDFLAGS: -lunicorn -lpthread -lm -latomic
// #cgo  darwin LDFLAGS: -lunicorn.o
import "C"
