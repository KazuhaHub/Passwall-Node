//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "installation acceptance requires a disposable GitHub-hosted Ubuntu 24.04 runner")
	os.Exit(1)
}
