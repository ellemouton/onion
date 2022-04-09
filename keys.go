package onion

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	// rhoType is used for generating the pseudo-random byte stream that is
	// used to obfuscate the per-hop info.
	rhoType = []byte{0x72, 0x68, 0x6F}

	// muType is used during the HMAC generation.
	muType = []byte{0x6d, 0x75}

	// umType is used during error reporting.
	umType = []byte{0x75, 0x6d}

	// padType is used to generate random filler bytes for the starting
	// mix-header packet.
	padType = []byte{0x70, 0x61, 0x64}
)

type Hop struct {
	// E is _our_ ephemeral priv key for this node.
	E *btcec.PrivateKey

	// P is the Node's Public key.
	P *btcec.PublicKey

	// SS is the shared secred we have with this node and it is derived
	// from the above E and P.
	SS [32]byte

	// BF is the blinding factor to be used to get from the ephemeral key
	// used for this hop to the next hop.
	BF [32]byte

	// The following keys are all derived from the SS key above.
	Rho [32]byte
	Mu  [32]byte
	Um  [32]byte
	Pad [32]byte

	// Payload is the payload we want to send to this hop.
	Payload []byte
}

func NewHop(p *btcec.PublicKey, e *btcec.PrivateKey, payload []byte) *Hop {
	ss := sharedSecret(e, p)

	rho := genKey(ss, rhoType)
	um := genKey(ss, umType)
	mu := genKey(ss, muType)
	pad := genKey(ss, padType)
	bf := blindingFactor(ss, p)

	return &Hop{
		E:       e,
		P:       p,
		BF:      bf,
		SS:      ss,
		Rho:     rho,
		Mu:      um,
		Um:      mu,
		Pad:     pad,
		Payload: payload,
	}
}

func (h *Hop) TotalSize() int {
	return 2 + len(h.Payload) + 32
}

// genKey generates a key using HMAC256 with the given key type and using a
// 32 byte s
func genKey(ss [32]byte, hmacKey []byte) [32]byte {
	hash := hmac.New(sha256.New, hmacKey)
	_, err := hash.Write(ss[:])
	if err != nil {
		panic(err)
	}

	var key [32]byte
	copy(key[:], hash.Sum(nil))

	return key
}

func sharedSecret(e *btcec.PrivateKey, p *btcec.PublicKey) [32]byte {
	var pubJ btcec.JacobianPoint
	p.AsJacobian(&pubJ)

	var ecdhPoint btcec.JacobianPoint
	btcec.ScalarMultNonConst(&e.Key, &pubJ, &ecdhPoint)

	ecdhPoint.ToAffine()
	ecdhPubKey := btcec.NewPublicKey(&ecdhPoint.X, &ecdhPoint.Y)

	return sha256.Sum256(ecdhPubKey.SerializeCompressed())
}

func blindingFactor(ss [32]byte, p *btcec.PublicKey) [32]byte {
	hash := sha256.New()

	_, err := hash.Write(append(p.SerializeCompressed(), ss[:]...))
	if err != nil {
		panic(err)
	}

	var key [32]byte
	copy(key[:], hash.Sum(nil))

	return key
}

func blindPriv(bf [32]byte, p *btcec.PrivateKey) *btcec.PrivateKey {
	scalar := &btcec.ModNScalar{}
	scalar.SetByteSlice(bf[:])

	return btcec.PrivKeyFromScalar(p.Key.Mul(scalar))
}
