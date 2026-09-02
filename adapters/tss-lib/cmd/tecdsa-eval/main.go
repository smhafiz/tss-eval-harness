// tecdsa-eval runs one (n, t) keygen+signing scenario against bnb-chain/tss-lib
// and writes one schema-conformant JSON result file — the tss-lib counterpart to
// the TR-ECDSA repo's `trecdsa-eval` (apps/eval/main.cpp). See
// ../../../schema/result_schema.json for the schema and ../../../schema/SCHEMA.md
// for the non-comparability caveats between the two adapters.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"tss-eval-harness/tsslib-adapter/internal"
)

func main() {
	n := flag.Int("n", 0, "party count (required)")
	t := flag.Int("t", 0, "threshold (required)")
	mode := flag.String("mode", "live", "keygen mode: fixtures|live (fixtures only supports n=5,t=2)")
	preParamsTimeout := flag.Duration("pre-params-timeout", 3*time.Minute, "timeout for live Paillier/safe-prime pre-param generation, per party")
	signTrials := flag.Int("sign-trials", 8, "number of repeated signing trials")
	out := flag.String("out", "", "output JSON path (default: stdout)")
	gitCommit := flag.String("git-commit", "unknown", "short git SHA of the tss-lib checkout under test")
	flag.Parse()

	if *n <= 0 || *t < 0 || *t >= *n {
		fmt.Fprintln(os.Stderr, "usage: tecdsa-eval -n=<int> -t=<int> [-mode=fixtures|live] [-sign-trials=N] [-out=<path>] [-git-commit=<sha>]")
		os.Exit(1)
	}

	kr, err := internal.RunKeygen(*n, *t, *mode, *preParamsTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		os.Exit(1)
	}

	signers := *t + 1
	sr, err := internal.RunSigning(kr, signers, *signTrials)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		os.Exit(1)
	}

	obj, err := internal.ComputeObjectSizes(kr, sr.SignatureBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "object size sampling failed: %v\n", err)
		os.Exit(1)
	}

	result := internal.BuildResult(*gitCommit, kr, sr, obj)

	bz, err := result.MarshalPretty()
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshaling result: %v\n", err)
		os.Exit(1)
	}
	bz = append(bz, '\n')

	if *out == "" {
		os.Stdout.Write(bz)
	} else if err := os.WriteFile(*out, bz, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", *out, err)
		os.Exit(1)
	}

	if !sr.AllValid {
		fmt.Fprintln(os.Stderr, "CORRECTNESS FAILURE: not all signatures verified")
		os.Exit(1)
	}
}
