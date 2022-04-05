package onion

import "github.com/btcsuite/btcd/btcec/v2"

type HopData struct {
	PubKey  *btcec.PublicKey
	Payload []byte
}
