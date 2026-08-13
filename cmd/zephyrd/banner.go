package main

import (
	"fmt"
	"os"

	version "zephyr.vox/server/ce"
)

// banner is printed on stdout before any startup log. It deliberately does
// not go through the logger: terminal art must stay raw (no timestamp, no
// colors, no file sink), and it should appear even when config loading fails.
const banner = `
 ______          _             __      __
 |___ /         | |            \ \    / /
   / / ___ _ __ | |__  _   _ _ _\ \  / /____  __
  / / / _ \ '_ \| '_ \| | | | '__\ \/ / _ \ \/ /
 / /_|  __/ |_) | | | | |_| | |   \  / (_) >  <
/_____\___| .__/|_| |_|\__, |_|    \/ \___/_/\_\
         | |           __/ |
         |_|          |___/
`

// printBanner prints the ASCII banner followed by the embedded version on
// stdout, before any startup log. Like the art itself, the version line is
// raw output: no timestamp, no colors, no file sink.
func printBanner() {
	fmt.Fprint(os.Stdout, banner)
	fmt.Fprintf(os.Stdout, "v%s\n", version.Version)
}
