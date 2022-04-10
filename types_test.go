package onion

import (
	"bytes"
	"encoding/hex"
	"fmt"
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

func TestBlindedPathEncodeDecode2(t *testing.T) {
	entryB, _ := hex.DecodeString("02b206d58012315e12414d339667c985108780408cf55a6d2d5b2a198d14127d86")
	entry, _ := btcec.ParsePubKey(entryB)

	node1B, _ := hex.DecodeString("022fe0175b3219bf919b5235c03bc18c948b34ed5f77202eece192fc154b0e5e0c")
	node1, _ := btcec.ParsePubKey(node1B)

	node2B, _ := hex.DecodeString("033316570e8e06daf4312808203c4c67c783cdbda48f3a7929ee3eaf761a383d53")
	node2, _ := btcec.ParsePubKey(node2B)

	ephB, _ := hex.DecodeString("0374f41e150c3315b3de62477fdeb9a6ce403e659e27fcb5ae1d04d1b6e664eb0e")
	eph, _ := btcec.ParsePubKey(ephB)

	data1, _ := hex.DecodeString("d9dc5fd6f6ec1e90602d")
	data2, _ := hex.DecodeString("6a5af8a7a743f6d9")
	data3, _ := hex.DecodeString("08eb17a57fbd")

	bp := &BlindedPath{
		EntryNodeID: entry,
		BlindedNodeIDs: []*btcec.PublicKey{
			node1, node2,
		},
		EncryptedData: [][]byte{
			data1, data2, data3,
		},
		FirstBlindingEphemeralKey: eph,
	}

	b := bp.Encode()

	bp2, err := DecodeBlindedPath(b)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(bp2.Encode()),
		"02b206d58012315e12414d339667c985108780408cf55a6d2d5b2a198d14127d860002022fe0175b3219bf919b5235c03bc18c948b34ed5f77202eece192fc154b0e5e0c033316570e8e06daf4312808203c4c67c783cdbda48f3a7929ee3eaf761a383d53000ad9dc5fd6f6ec1e90602d00086a5af8a7a743f6d9000608eb17a57fbd0374f41e150c3315b3de62477fdeb9a6ce403e659e27fcb5ae1d04d1b6e664eb0e")
}

func TestEncodeDecodeHopDataPayload(t *testing.T) {
	pk1, _ := btcec.NewPrivateKey()

	tests := []*HopData{
		{
			ClearData: []byte("clear data"),
		},
		{
			ClearData:     []byte("clear data"),
			EncryptedData: []byte("encrypted data"),
		},
		{
			ClearData:     []byte("clear data"),
			EncryptedData: []byte("encrypted data"),
			EphemeralKey:  pk1.PubKey(),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			b := test.EncodePayload()
			hd, err := DecodeHopDataPayload(b)
			require.NoError(t, err)

			require.True(t, bytes.Equal(test.EncryptedData, hd.EncryptedData))
			require.True(t, bytes.Equal(test.ClearData, hd.ClearData))
			if test.EphemeralKey == nil {
				require.Nil(t, hd.EphemeralKey)
			} else {
				require.True(t, test.EphemeralKey.IsEqual(hd.EphemeralKey))
			}
		})
	}
}
