package internal

import (
	"encoding/json"
	"runtime"
)

// Result is the on-disk shape defined by schema/result_schema.json. The schema
// sets additionalProperties:false everywhere, so every field here must exist
// there and vice versa — field tags are the contract, not decoration.
type Result struct {
	SchemaVersion  int    `json:"schema_version"`
	Implementation string `json:"implementation"`
	ProtocolName   string `json:"protocol_name"`
	GitCommit      string `json:"git_commit"`

	Security struct {
		Label     string `json:"label"`
		EncScheme string `json:"enc_scheme"`
		// Pointer so Paillier's 2048 and CL-HSM's "not applicable" are
		// distinguishable in JSON; tss-lib always sets it.
		EncModulusBits *int `json:"enc_modulus_bits"`
	} `json:"security"`

	Params struct {
		N       int `json:"n"`
		T       int `json:"t"`
		Signers int `json:"signers"`
	} `json:"params"`

	Trials struct {
		SetupTrials int `json:"setup_trials"`
		DkgTrials   int `json:"dkg_trials"`
		SignTrials  int `json:"sign_trials"`
	} `json:"trials"`

	// Pointers throughout: a skipped phase must serialize as JSON null, never
	// as a zero-valued stats object that would be indistinguishable from an
	// instantaneous one (SCHEMA.md caveat 8).
	TimingMS struct {
		Setup       *Stats `json:"setup"`
		DkgOrKeygen *Stats `json:"dkg_or_keygen"`
		Sign        *Stats `json:"sign"`
		Verify      *Stats `json:"verify"`
	} `json:"timing_ms"`

	ThroughputSigPerSec float64 `json:"throughput_sig_per_sec"`

	BandwidthBytes struct {
		Total      int64       `json:"total"`
		PerParty   float64     `json:"per_party"`
		PerRound   []roundJSON `json:"per_round"`
		Comparable bool        `json:"per_round_comparable_across_impl"`
	} `json:"bandwidth_bytes"`

	ObjectSizesBytes struct {
		Signature     int `json:"signature"`
		ECPublicKey   int `json:"ec_public_key"`
		ECKeyShare    int `json:"ec_key_share"`
		EncPublicKey  int `json:"enc_public_key"`
		EncKeyShare   int `json:"enc_key_share"`
		EncCiphertext int `json:"enc_ciphertext"`
	} `json:"object_sizes_bytes"`

	Correctness struct {
		AllSignaturesValid bool `json:"all_signatures_valid"`
	} `json:"correctness"`

	Environment struct {
		OS           string `json:"os"`
		ImplLanguage string `json:"impl_language"`
	} `json:"environment"`

	Notes string `json:"notes"`
}

type roundJSON struct {
	RoundLabel string `json:"round_label"`
	Bytes      int64  `json:"bytes"`
	Exactness  string `json:"exactness"`
}

const paillierModulusBits = 2048

// BuildResult assembles the schema object from the three measurement stages.
func BuildResult(gitCommit string, kr *KeygenResult, sr *SignResult, obj *ObjectSizes) *Result {
	r := &Result{
		SchemaVersion:  1,
		Implementation: "tss-lib",
		ProtocolName:   "GG18 (9-round, Paillier)",
		GitCommit:      gitCommit,
	}

	encBits := paillierModulusBits
	// tss-lib has no security-level knob — it is hardwired to secp256k1 — so the
	// label reports the curve. That is a name, not a strength: the aggregator
	// derives the real 112-bit figure from the Paillier modulus (SCHEMA.md
	// caveats 4 and 5).
	r.Security.Label = "secp256k1"
	r.Security.EncScheme = "Paillier"
	r.Security.EncModulusBits = &encBits

	r.Params.N = kr.N
	r.Params.T = kr.T
	r.Params.Signers = sr.SignerCount

	r.Trials.SetupTrials = kr.SetupTrials
	r.Trials.DkgTrials = kr.KeygenTrials
	r.Trials.SignTrials = sr.SignTrials

	r.TimingMS.Setup = kr.SetupStats        // nil in fixtures mode -> null
	r.TimingMS.DkgOrKeygen = kr.KeygenStats // nil in fixtures mode -> null
	signStats := sr.SignStats
	verifyStats := sr.VerifyStats
	r.TimingMS.Sign = &signStats
	r.TimingMS.Verify = &verifyStats

	if signStats.Mean > 0 {
		r.ThroughputSigPerSec = 1000 / signStats.Mean
	}

	r.BandwidthBytes.Total = sr.TotalBytes
	if sr.SignerCount > 0 {
		r.BandwidthBytes.PerParty = float64(sr.TotalBytes) / float64(sr.SignerCount)
	}
	r.BandwidthBytes.PerRound = make([]roundJSON, 0, len(sr.PerRound))
	for _, rb := range sr.PerRound {
		r.BandwidthBytes.PerRound = append(r.BandwidthBytes.PerRound, roundJSON{
			RoundLabel: rb.Label,
			Bytes:      rb.Bytes,
			Exactness:  rb.Exactness,
		})
	}
	// Always false: the round labels come from regex-matching tss-lib message
	// type names, which is not TR-ECDSA's native round boundary (caveat 1).
	r.BandwidthBytes.Comparable = false

	r.ObjectSizesBytes.Signature = obj.Signature
	r.ObjectSizesBytes.ECPublicKey = obj.ECPublicKey
	r.ObjectSizesBytes.ECKeyShare = obj.ECKeyShare
	r.ObjectSizesBytes.EncPublicKey = obj.EncPublicKey
	r.ObjectSizesBytes.EncKeyShare = obj.EncKeyShare
	r.ObjectSizesBytes.EncCiphertext = obj.EncCiphertext

	r.Correctness.AllSignaturesValid = sr.AllValid

	r.Environment.OS = runtime.GOOS
	r.Environment.ImplLanguage = "go" + goMinorVersion()

	if kr.Mode == "fixtures" {
		r.Notes = "setup and keygen timing skipped: precomputed fixtures used (see SCHEMA.md caveat 8)"
	}

	return r
}

// MarshalPretty renders the result as indented JSON, the form the results/ tree
// stores so a diff between two runs is readable line by line.
func (r *Result) MarshalPretty() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// goMinorVersion turns "go1.23.4" into "1.23" — impl_language records the
// language toolchain family that built the measured code, not the exact patch
// release, so cells built on different patch versions stay comparable.
func goMinorVersion() string {
	v := runtime.Version() // e.g. "go1.23.4"
	v = v[len("go"):]
	dots := 0
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			dots++
			if dots == 2 {
				return v[:i]
			}
		}
	}
	return v
}
