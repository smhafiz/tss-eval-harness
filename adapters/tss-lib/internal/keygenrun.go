package internal

import (
	"fmt"
	"sort"
	"time"

	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

// fixtureN and fixtureT are the only (n,t) tss-lib ships precomputed keygen
// fixtures for (test.TestParticipants / TestThreshold upstream). Asking for
// mode=fixtures at any other (n,t) is an error rather than a silent fallback —
// silently running live would turn a "fast" grid row into a multi-minute one
// with no indication in the output.
const (
	fixtureN = 5
	fixtureT = 2
)

// KeygenResult carries everything the signing and reporting stages need out of
// key generation, plus the timing of the two phases the schema separates.
//
// SetupStats/KeygenStats are nil in fixtures mode — deliberately nil rather than
// zero-valued, so BuildResult can serialize JSON null and a skipped measurement
// can never be averaged in as an instant one (SCHEMA.md caveat 8).
type KeygenResult struct {
	N, T     int
	Mode     string
	PartyIDs tss.SortedPartyIDs
	SaveData []keygen.LocalPartySaveData

	SetupStats   *Stats // per-party Paillier pre-param generation
	KeygenStats  *Stats // the interactive DKG protocol itself
	SetupTrials  int    // == N in live mode (one pre-param set per party)
	KeygenTrials int    // == 1 in live mode: the protocol runs once
}

// RunKeygen produces n key shares with threshold t, either by loading tss-lib's
// bundled fixtures or by running the real protocol.
func RunKeygen(n, t int, mode string, preParamsTimeout time.Duration) (*KeygenResult, error) {
	switch mode {
	case "fixtures":
		return loadFixtures(n, t)
	case "live":
		return runLiveKeygen(n, t, preParamsTimeout)
	default:
		return nil, fmt.Errorf("unknown keygen mode %q: want fixtures or live", mode)
	}
}

func loadFixtures(n, t int) (*KeygenResult, error) {
	if n != fixtureN || t != fixtureT {
		return nil, fmt.Errorf(
			"mode=fixtures only supports n=%d,t=%d (the single (n,t) tss-lib ships fixtures for); got n=%d,t=%d — use -mode=live",
			fixtureN, fixtureT, n, t)
	}
	keys, pids, err := keygen.LoadKeygenTestFixtures(n)
	if err != nil {
		return nil, fmt.Errorf("loading tss-lib keygen fixtures: %w", err)
	}
	return &KeygenResult{
		N:        n,
		T:        t,
		Mode:     "fixtures",
		PartyIDs: pids,
		SaveData: keys,
		// Both nil: fixtures bypass pre-params and the interactive protocol
		// entirely, so there is no timing to report for either.
	}, nil
}

func runLiveKeygen(n, t int, preParamsTimeout time.Duration) (*KeygenResult, error) {
	// --- setup phase: one Paillier safe-prime pre-param set per party -------
	//
	// Generated serially and timed individually so the per-party spread is
	// visible in min/max/stddev. This is the dominant cost of a live cell, and
	// hiding it inside "keygen" would misattribute seconds of factoring work to
	// the DKG protocol (SCHEMA.md caveats 6 and 7).
	preParams := make([]keygen.LocalPreParams, n)
	setupSeconds := make([]float64, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		pp, err := keygen.GeneratePreParams(preParamsTimeout)
		if err != nil {
			return nil, fmt.Errorf("generating pre-params for party %d (timeout %s): %w", i, preParamsTimeout, err)
		}
		setupSeconds[i] = time.Since(t0).Seconds()
		preParams[i] = *pp
	}
	setupStats := ComputeStats(setupSeconds)

	// --- the DKG protocol itself -------------------------------------------
	// tss-lib's own keygen tests build their party set this way; reusing the
	// same helper keeps the ShareIDs consistent with what SortPartyIDs expects.
	pids := tss.GenerateTestPartyIDs(n)
	p2pCtx := tss.NewPeerContext(pids)

	parties := make([]tss.Party, n)
	outCh := make(chan tss.Message, n*n)
	endCh := make(chan *keygen.LocalPartySaveData, n)
	errCh := make(chan *tss.Error, n)

	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pids[i], n, t)
		// Note what is NOT called here: params.SetNoProofMod() and
		// params.SetNoProofFac(). tss-lib's own tests disable those ZK proofs
		// for speed; leaving them enabled is what makes these numbers
		// production-representative. Do not "optimize" this — SCHEMA.md
		// caveat 10.
		parties[i] = keygen.NewLocalParty(params, outCh, endCh, preParams[i])
	}

	saveData := make([]keygen.LocalPartySaveData, 0, n)

	t0 := time.Now()
	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}
	err := RunMessageLoop(parties, outCh, endCh, errCh, n,
		func(save *keygen.LocalPartySaveData) { saveData = append(saveData, *save) },
		nil) // keygen bandwidth is not part of the schema; only signing is measured
	if err != nil {
		return nil, fmt.Errorf("keygen protocol: %w", err)
	}
	keygenStats := ComputeStats([]float64{time.Since(t0).Seconds()})

	// Parties finish in nondeterministic order, but RunSigning takes the first
	// `signers` entries of SaveData alongside the first `signers` PartyIDs — so
	// the two slices have to agree. Sorting save data by ShareID puts it in the
	// same order tss.SortPartyIDs put the IDs in.
	sort.Slice(saveData, func(i, j int) bool {
		return saveData[i].ShareID.Cmp(saveData[j].ShareID) == -1
	})

	return &KeygenResult{
		N:            n,
		T:            t,
		Mode:         "live",
		PartyIDs:     pids,
		SaveData:     saveData,
		SetupStats:   &setupStats,
		KeygenStats:  &keygenStats,
		SetupTrials:  n,
		KeygenTrials: 1,
	}, nil
}
