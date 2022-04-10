package onion

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSerializeDeserializeHopPayload(t *testing.T) {
	pk, _ := btcec.NewPrivateKey()

	hopPayload := &HopPayload{
		Payload: []byte("a message for you"),
		FwdTo:   pk.PubKey(),
	}

	b := hopPayload.Serialize()

	hp2, err := DeserializeHopPayload(b)
	require.NoError(t, err)

	require.True(t, bytes.Equal(hopPayload.Payload[:], hp2.Payload[:]))
	require.True(t, hp2.FwdTo.IsEqual(hopPayload.FwdTo))

	// Also test empty FwdTo:
	hopPayload = &HopPayload{
		Payload: []byte("a message for you"),
	}

	b = hopPayload.Serialize()

	hp2, err = DeserializeHopPayload(b)
	require.NoError(t, err)

	require.True(t, bytes.Equal(hopPayload.Payload[:], hp2.Payload[:]))
	require.Nil(t, hp2.FwdTo)
}

func TestBlindedPathEncodeDecode(t *testing.T) {
	pk1, _ := btcec.NewPrivateKey()
	pk2, _ := btcec.NewPrivateKey()
	pk3, _ := btcec.NewPrivateKey()
	pk4, _ := btcec.NewPrivateKey()

	bp := &BlindedPath{
		EntryNodeID: pk1.PubKey(),
		BlindedNodeIDs: []*btcec.PublicKey{
			pk2.PubKey(),
			pk3.PubKey(),
		},
		EncryptedData: [][]byte{
			[]byte("boop"),
			[]byte("beep"),
			[]byte("baap"),
		},
		FirstBlindingEphemeralKey: pk4.PubKey(),
	}

	b := bp.Encode()

	bp2, err := DecodeBlindedPath(b)
	require.NoError(t, err)

	require.Equal(t, bp, bp2)
}
