// Command cra-evidence-check runs machine-checkable CRA engineering evidence
// checks. All behavior lives in internal/cli so it can be tested end to end.
package main

import (
	"context"
	"os"

	"github.com/moveeeax/cra-evidence-check/internal/cli"
)

func main() {
	os.Exit(cli.Main(context.Background(), os.Args[1:], cli.Options{}))
}
