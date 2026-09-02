package internal

import (
	"fmt"

	"github.com/bnb-chain/tss-lib/v3/test"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

// RunMessageLoop drives an already-started set of tss-lib parties to completion,
// reusing tss-lib's own test.SharedPartyUpdater goroutine/channel dispatch
// pattern (see the _test.go files in ecdsa/keygen and ecdsa/signing upstream) —
// there is no public non-test driver in the library, and reimplementing the
// routing rules would be a way to measure a protocol the library doesn't
// actually run.
//
// It is generic over the end-channel payload E so one loop drives both party
// types: keygen ends with *keygen.LocalPartySaveData, signing with
// *common.SignatureData.
//
// onMessage, if non-nil, is called for every outgoing message with its
// serialized wire length — this is where bandwidth accounting hooks in. It runs
// on the loop's own goroutine, so it needs no locking, but it must not block.
//
// The loop returns once `want` parties have reported completion, or on the first
// party error.
func RunMessageLoop[E any](
	parties []tss.Party,
	outCh chan tss.Message,
	endCh chan E,
	errCh chan *tss.Error,
	want int,
	onEnd func(E),
	onMessage func(msg tss.Message, wireBytes int),
) error {
	done := 0
	for {
		select {
		case err := <-errCh:
			return fmt.Errorf("party error: %w", err.Cause())

		case msg := <-outCh:
			// Count the bytes that would actually cross a network, once per
			// message emitted. Done here rather than inside the per-recipient
			// dispatch below so a broadcast is counted once, matching how
			// TR-ECDSA's eval app accounts for its own broadcasts. (SCHEMA.md
			// caveat 11: these bytes are counted, never actually transmitted.)
			if onMessage != nil {
				bz, _, err := msg.WireBytes()
				if err != nil {
					return fmt.Errorf("serializing outgoing message for byte count: %w", err)
				}
				onMessage(msg, len(bz))
			}

			dest := msg.GetTo()
			if dest == nil { // broadcast
				for _, p := range parties {
					if p.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go test.SharedPartyUpdater(p, msg, errCh)
				}
				continue
			}
			if dest[0].Index == msg.GetFrom().Index {
				return fmt.Errorf("party %d tried to send a point-to-point message to itself", dest[0].Index)
			}
			go test.SharedPartyUpdater(parties[dest[0].Index], msg, errCh)

		case end := <-endCh:
			if onEnd != nil {
				onEnd(end)
			}
			done++
			if done >= want {
				return nil
			}
		}
	}
}
