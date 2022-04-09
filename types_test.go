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
