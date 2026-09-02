package internal

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

// RoundBandwidth is one entry of bandwidth_bytes.per_round in the schema.
type RoundBandwidth struct {
	Label     string
	Bytes     int64
	Exactness string
}

// signRoundRe extracts the round number from tss-lib's signing message type
// names. Type() returns the fully-qualified protobuf message name (e.g.
// "binance.tsslib.ecdsa.signing.SignRound3Message", "...SignRound1Message1"),
// so this matches the SignRoundN prefix anywhere in the string. Best-effort
// bucketing over Type() strings, not a protocol-level round boundary — see
// SCHEMA.md caveat 1.
var signRoundRe = regexp.MustCompile(`SignRound(\d+)`)

// SignResult holds the outcome of RunSigning: timing over signTrials repeated
// signings (fresh message each trial, same fixed signer subset), bandwidth from
// one representative trial (mirrors TR-ECDSA's last_bandwidth() semantics —
// see apps/eval in the TR-ECDSA repo), and an isolated verify-timing pass.
type SignResult struct {
	SignStats   Stats
	VerifyStats Stats
	TotalBytes  int64
	PerRound    []RoundBandwidth
	AllValid       bool
	SignerCount    int
	SignTrials     int
	SignatureBytes int // len(sig.Signature) = R||S from the last trial
}

// RunSigning selects the first `signers` of kr's n parties as a fixed signer
// subset (their relative performance is protocol-symmetric, so — unlike
// TR-ECDSA's bench, which re-randomizes the subset every trial — a single fixed
// subset reused across trials is a reasonable simplification; see keygenrun.go).
func RunSigning(kr *KeygenResult, signers, signTrials int) (*SignResult, error) {
	if signers > len(kr.PartyIDs) {
		return nil, fmt.Errorf("requested %d signers but only %d parties available", signers, len(kr.PartyIDs))
	}
	signPIDs := kr.PartyIDs[:signers]
	signSaveData := kr.SaveData[:signers]
	p2pCtx := tss.NewPeerContext(signPIDs)
	curveOrder := tss.S256().Params().N

	signTimes := make([]float64, 0, signTrials)
	allValid := true
	var lastTotalBytes int64
	var lastPerRound []RoundBandwidth
	var lastSig *common.SignatureData
	var lastMsg []byte

	for trial := 0; trial < signTrials; trial++ {
		msgInt, err := rand.Int(rand.Reader, curveOrder)
		if err != nil {
			return nil, fmt.Errorf("generating random message: %w", err)
		}

		parties := make([]tss.Party, signers)
		partyPtrs := make([]*signing.LocalParty, signers)
		outCh := make(chan tss.Message, signers*signers)
		endCh := make(chan *common.SignatureData, signers)
		errCh := make(chan *tss.Error, signers)

		for i := 0; i < signers; i++ {
			params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], signers, kr.T)
			p := signing.NewLocalParty(msgInt, params, signSaveData[i], outCh, endCh).(*signing.LocalParty)
			parties[i] = p
			partyPtrs[i] = p
		}

		roundBytes := map[string]int64{}
		var totalBytes int64
		onMessage := func(msg tss.Message, n int) {
			totalBytes += int64(n)
			label := "unmatched"
			if m := signRoundRe.FindStringSubmatch(msg.Type()); m != nil {
				label = "round" + m[1]
			}
			roundBytes[label] += int64(n)
		}

		t0 := time.Now()
		for _, p := range partyPtrs {
			p := p
			go func() {
				if err := p.Start(); err != nil {
					errCh <- err
				}
			}()
		}
		var sig *common.SignatureData
		err = RunMessageLoop(parties, outCh, endCh, errCh, signers, func(s *common.SignatureData) {
			sig = s
		}, onMessage)
		if err != nil {
			return nil, fmt.Errorf("signing trial %d: %w", trial, err)
		}
		signTimes = append(signTimes, time.Since(t0).Seconds())

		lastTotalBytes = totalBytes
		lastPerRound = lastPerRound[:0]
		for label, b := range roundBytes {
			lastPerRound = append(lastPerRound, RoundBandwidth{Label: label, Bytes: b, Exactness: "exact"})
		}
		lastSig = sig
		lastMsg = sig.M

		pub := kr.SaveData[0].ECDSAPub.ToECDSAPubKey()
		r := new(big.Int).SetBytes(sig.R)
		s := new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(pub, sig.M, r, s) {
			allValid = false
		}
	}

	// Isolated verify pass, matching TR-ECDSA's convention of timing Verify
	// separately from Sign (reusing one already-produced signature).
	verifyTimes := make([]float64, signTrials)
	pub := kr.SaveData[0].ECDSAPub.ToECDSAPubKey()
	r := new(big.Int).SetBytes(lastSig.R)
	s := new(big.Int).SetBytes(lastSig.S)
	for i := 0; i < signTrials; i++ {
		t0 := time.Now()
		_ = ecdsa.Verify(pub, lastMsg, r, s)
		verifyTimes[i] = time.Since(t0).Seconds()
	}

	return &SignResult{
		SignStats:      ComputeStats(signTimes),
		VerifyStats:    ComputeStats(verifyTimes),
		TotalBytes:     lastTotalBytes,
		PerRound:       lastPerRound,
		AllValid:       allValid,
		SignerCount:    signers,
		SignTrials:     signTrials,
		SignatureBytes: len(lastSig.Signature),
	}, nil
}
