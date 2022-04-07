package onion

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestSharedSecret(t *testing.T) {
	priv1, _ := btcec.NewPrivateKey()
	priv2, _ := btcec.NewPrivateKey()

	ss1 := sharedSecret(priv1, priv2.PubKey())
	ss2 := sharedSecret(priv2, priv1.PubKey())

	require.True(t, bytes.Equal(ss1[:], ss2[:]))
}
