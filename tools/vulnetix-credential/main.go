// Command vulnetix-credential renders the credential the Vulnetix CLI is
// currently authenticated with, as an Authorization header value.
//
// INTERNAL USE ONLY.
//
// This is a bridge between one vendor's CLI and this suite, and it is useless
// to anybody testing a different provider. Nothing in the conformance suite
// depends on it, no test imports it, and deleting it would not change a single
// result.
//
// # Why it is a separate module
//
// It imports github.com/vulnetix/cli/v3/pkg/auth, and this directory carries
// its own go.mod so that dependency stays out of the suite's. A vendor-neutral
// conformance tool should not have a vendor's CLI in its build graph, and the
// suite's binary must stay buildable by anyone who has never heard of Vulnetix.
// Go ignores a directory with its own go.mod, so `go build ./...` at the root
// never sees this.
//
// # Why it is not a shell script
//
// The Vulnetix CLI resolves credentials from six sources in precedence order —
// two token environment pairs, a SigV4 pair, a project dotfile, a home dotfile
// and a netrc entry — and any of the file-backed ones may keep the secret in
// the OS keychain rather than on disk. It then renders three different header
// shapes from them. Reimplementing that in a justfile would be a copy that
// drifts, and the failure mode of a drifted copy is a 401 that looks like the
// provider's fault. Asking the CLI's own package is the only version of this
// that stays correct.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func main() {
	var (
		export  = flag.Bool("export", false, "print a shell `export` statement instead of the bare value")
		varName = flag.String("var", "TEA_VULNETIX_CREDENTIAL", "environment variable `name` to export")
		verbose = flag.Bool("v", false, "describe the credential on stderr")
	)
	flag.Parse()

	creds, err := auth.LoadCredentials()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulnetix-credential: %v\n", err)
		os.Exit(1)
	}

	header := auth.GetAuthHeader(creds)
	if header == "" {
		fmt.Fprintf(os.Stderr,
			"vulnetix-credential: the CLI is authenticated with method %q, which renders no "+
				"Authorization header\n", creds.Method)
		os.Exit(1)
	}

	if *verbose {
		// The value itself never goes to stderr: this command is meant to be
		// used inside a command substitution, and a log line is the one place a
		// secret escapes into a scrollback buffer nobody was watching.
		fmt.Fprintf(os.Stderr, "vulnetix-credential: %s credential for org %s from %s\n",
			creds.Method, orDash(creds.OrgID), auth.CredentialSource())
	}

	if *export {
		// Single-quoted with any embedded quote escaped, so the line is safe to
		// eval whatever the credential contains.
		fmt.Printf("export %s='%s'\n", *varName, strings.ReplaceAll(header, `'`, `'\''`))
		return
	}
	fmt.Println(header)
}

func orDash(s string) string {
	if s == "" {
		return "(resolved server-side)"
	}
	return s
}
