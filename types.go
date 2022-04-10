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

type BlindedPath struct {
	EntryNodeID               *btcec.PublicKey
	BlindedNodeIDs            []*btcec.PublicKey
	EncryptedData             [][]byte
	FirstBlindingEphemeralKey *btcec.PublicKey
}

func (b *BlindedPath) String() string {
	str := fmt.Sprintf("Entry Node: %x\n",
		b.EntryNodeID.SerializeCompressed())

	str += "Blinded Node IDs:\n"
	for _, b := range b.BlindedNodeIDs {
		str += fmt.Sprintf(" - %x\n", b.SerializeCompressed())
	}

	str += "Encrypted Data:\n"
	for _, b := range b.EncryptedData {
		str += fmt.Sprintf(" - %x\n", b)
	}

	str += fmt.Sprintf("First Blinding Ephemeral Key: %x\n",
		b.FirstBlindingEphemeralKey.SerializeCompressed())

	str += fmt.Sprintf("Encoded: %x\n", b.Encode())

	return str
}

func (b *BlindedPath) Encode() []byte {
	/*
		33 byte -> entry node pub key
		2 byte (numBlind) -> num of blinded keys
		33 * numBlind -> blinded keys
		numBlind + 1{
			2 byte len -> len of encrypted data
			encrypted data
		}
		33 byte -> first ephemeral key
	*/
	totalLen := 33 + 2 + (33 * len(b.BlindedNodeIDs)) + 33
	for _, data := range b.EncryptedData {
		totalLen += 2 + len(data)
	}

	payload := make([]byte, totalLen)
	copy(payload[:33], b.EntryNodeID.SerializeCompressed())
	binary.BigEndian.PutUint16(
		payload[33:35], uint16(len(b.BlindedNodeIDs)),
	)
	offset := 35
	for _, b := range b.BlindedNodeIDs {
		copy(
			payload[offset:offset+33],
			b.SerializeCompressed(),
		)
		offset += 33
	}

	for _, b := range b.EncryptedData {
		binary.BigEndian.PutUint16(payload[offset:offset+2],
			uint16(len(b)))
		offset += 2
		copy(payload[offset:offset+len(b)], b)
		offset += len(b)
	}

	copy(payload[offset:], b.FirstBlindingEphemeralKey.SerializeCompressed())

	return payload
}

func DecodeBlindedPath(b []byte) (*BlindedPath, error) {
	/*
		33 byte -> entry node pub key
		2 byte (numBlind) -> num of blinded keys
		33 * numBlind -> blinded keys
		numBlind + 1{
			2 byte len -> len of encrypted data
			encrypted data
		}
		33 byte -> first ephemeral key
	*/
	entryNode, err := btcec.ParsePubKey(b[:33])
	if err != nil {
		return nil, err
	}

	numBlinded := binary.BigEndian.Uint16(b[33:35])
	blindedPoints := make([]*btcec.PublicKey, numBlinded)

	offset := 35
	for i := 0; i < int(numBlinded); i++ {
		point, err := btcec.ParsePubKey(b[offset : offset+33])
		if err != nil {
			return nil, err
		}

		blindedPoints[i] = point
		offset += 33
	}

	encryptedData := make([][]byte, numBlinded+1)
	for i := 0; i < int(numBlinded)+1; i++ {
		l := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2

		data := make([]byte, l)
		copy(data[:], b[offset:offset+int(l)])
		offset += int(l)

		encryptedData[i] = data
	}

	point, err := btcec.ParsePubKey(b[offset:])
	if err != nil {
		return nil, err
	}

	return &BlindedPath{
		EntryNodeID:               entryNode,
		BlindedNodeIDs:            blindedPoints,
		EncryptedData:             encryptedData,
		FirstBlindingEphemeralKey: point,
	}, nil
}
