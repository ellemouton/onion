package onion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
)

// HopData couples the payload we want to send to the peer we want to send it
// to.
type HopData struct {
	PubKey  *btcec.PublicKey
	Payload []byte
}

// HopPayload is the actual hop payload we will send to a hop in the onion.
// It contains the general payload along with which pubkey it should forward
// the reset of the onion to.
type HopPayload struct {
	// Payload is the payload for this hop.
	Payload []byte

	// FwdTo is the pub key of the node to which the packet should be
	// forwarded to.
	FwdTo *btcec.PublicKey
}

// Serialize the HopPayload. Since this is just an example, let's use a very
// basic encoding:
//  	- 2 byte len field for payload len
// 	- payload
// 	- 33 byte for FwdTo pub key. Set to all zeros for final hop.
func (h *HopPayload) Serialize() []byte {
	b := make([]byte, 2+len(h.Payload)+33)

	payloadLen := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLen, uint16(len(h.Payload)))

	copy(b[:2], payloadLen)
	copy(b[2:2+len(h.Payload)], h.Payload)

	if h.FwdTo != nil {
		copy(b[2+len(h.Payload):], h.FwdTo.SerializeCompressed())
	} else {
		var empty [33]byte
		copy(b[2+len(h.Payload):], empty[:])
	}

	return b
}

func DeserializeHopPayload(b []byte) (*HopPayload, error) {
	if len(b) < 2+33 {
		return nil, fmt.Errorf("insufficient length")
	}

	payloadLen := binary.BigEndian.Uint16(b[:2])

	payload := make([]byte, payloadLen)
	copy(payload[:], b[2:2+payloadLen])

	pubkey := b[2+payloadLen:]
	var (
		temp [33]byte
		pk   *btcec.PublicKey
		err  error
	)
	if !bytes.Equal(pubkey, temp[:]) {
		pk, err = btcec.ParsePubKey(pubkey)
		if err != nil {
			return nil, err
		}
	}

	return &HopPayload{
		FwdTo:   pk,
		Payload: payload,
	}, nil
}
