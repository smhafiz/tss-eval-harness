package internal

import (
	"crypto/elliptic"
	"errors"

	"github.com/bnb-chain/tss-lib/v3/tss"
)

// ObjectSizes mirrors the schema's object_sizes_bytes block. Sizes are of a
// single serialized object sampled from the completed run, not of anything
// aggregated.
type ObjectSizes struct {
	Signature     int
	ECPublicKey   int
	ECKeyShare    int
	EncPublicKey  int
	EncKeyShare   int
	EncCiphertext int
}

// ComputeObjectSizes samples one of each object out of party 0's save data.
//
// The two enc_* key fields are the ones to be careful with: GG18 does not
// threshold-ize Paillier at all — each party holds its own complete, independent
// Paillier keypair used only for local MtA — so "public key" here is one party's
// own key and "key share" is really a whole secret key. The schema uses these
// names for cross-implementation uniformity; SCHEMA.md caveats 2 and 3 spell out
// that TR-ECDSA's identically-named fields describe a genuinely shared CL secret.
func ComputeObjectSizes(kr *KeygenResult, signatureBytes int) (*ObjectSizes, error) {
	if len(kr.SaveData) == 0 {
		return nil, errors.New("no key shares available to sample object sizes from")
	}
	save := kr.SaveData[0]

	if save.ECDSAPub == nil {
		return nil, errors.New("save data has no ECDSA public key")
	}
	if save.Xi == nil {
		return nil, errors.New("save data has no secret key share")
	}
	if save.PaillierSK == nil || save.PaillierSK.N == nil {
		return nil, errors.New("save data has no Paillier key")
	}

	// Compressed point encoding (33 bytes on secp256k1) — the form an
	// implementation would actually store or transmit, matching TR-ECDSA's
	// compressed-point convention.
	pubKey := elliptic.MarshalCompressed(tss.S256(), save.ECDSAPub.X(), save.ECDSAPub.Y())

	// Fixed-width field-element encoding: Xi.Bytes() alone would report a short
	// length whenever the share happens to have leading zero bytes, which would
	// show up as a spurious size difference between otherwise identical cells.
	shareBytes := (tss.S256().Params().N.BitLen() + 7) / 8

	// Paillier: public key is the modulus N; a ciphertext lives mod N², so it is
	// twice as wide. The "share" is the party's own secret key material, sized
	// by lambda(N), which is the same width as N.
	nBytes := len(save.PaillierSK.N.Bytes())

	return &ObjectSizes{
		Signature:     signatureBytes,
		ECPublicKey:   len(pubKey),
		ECKeyShare:    shareBytes,
		EncPublicKey:  nBytes,
		EncKeyShare:   nBytes,
		EncCiphertext: nBytes * 2,
	}, nil
}
