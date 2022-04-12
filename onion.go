package onion

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/aead/chacha20"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Onion struct {
	Version     [1]byte
	PubKey      [33]byte
	HopPayloads [1300]byte
	HMAC        [32]byte

	// EphemeralKey is the key that should be passed onto the next hop in
	// addition to the onion packet.
	EphemeralKey *btcec.PublicKey
}

func (o *Onion) Serialize() []byte {
	var packet = [1366]byte{}
	copy(packet[:1], o.Version[:])
	copy(packet[1:34], o.PubKey[:])
	copy(packet[34:1334], o.HopPayloads[:])
	copy(packet[1334:], o.HMAC[:])
	return packet[:]
}

func DeserializeOnion(b []byte) (*Onion, error) {
	if len(b) != 1366 {
		return nil, errors.New("onion must be 1364 bytes")
	}

	onion := &Onion{}
	copy(onion.Version[:], b[:1])
	copy(onion.PubKey[:], b[1:34])
	copy(onion.HopPayloads[:], b[34:1334])
	copy(onion.HMAC[:], b[1334:])

	return onion, nil
}

func BuildOnion(sessionKey *btcec.PrivateKey, hopsData []*HopData) (*Onion, error) {
	finalSessionKey := sessionKey.PubKey()

	fmt.Printf("My session key is: %x\n",
		sessionKey.PubKey().SerializeCompressed())

	ephemeralKey := sessionKey
	hops := make([]*Hop, len(hopsData))
	blindedRoute := false
	for i, hop := range hopsData {
		if hop.EncryptedData != nil {
			blindedRoute = true
		}

		payload := &HopPayload{
			Payload: hop.EncodePayload(),
		}

		if i != len(hopsData)-1 && !blindedRoute {
			payload.FwdTo = hopsData[i+1].PubKey
		}

		hops[i] = NewHop(hop.PubKey, ephemeralKey, payload.Serialize())

		//fmt.Printf("Preparing %s hop: \n"+
		//	" - payload: %s\n - ephemeral key: %x\n",
		//	UserIndex[string(hop.PubKey.SerializeCompressed())],
		//	string(payload.Payload),
		//	ephemeralKey.PubKey().SerializeCompressed())

		ephemeralKey = blindPriv(hops[i].BF, ephemeralKey)
	}

	filler := genFiller(hops)

	packet := genPadding(sessionKey)

	var nextHmac [32]byte
	for i := len(hops) - 1; i >= 0; i-- {
		hop := hops[i]

		hmac := nextHmac

		payload := make([]byte, hop.TotalSize())

		binary.BigEndian.PutUint16(
			payload[:2], uint16(len(hop.Payload)),
		)
		copy(payload[2:2+len(hop.Payload)], hop.Payload)
		copy(payload[2+len(hop.Payload):], hmac[:])

		rightShift(packet[:], hop.TotalSize())
		copy(packet[:hop.TotalSize()], payload)

		stream := pSByteStream(hop.Rho[:], 1300)

		xor(packet[:], packet[:], stream[:])

		// If this is the "last" hop, then we'll override the tail of
		// the hop data.
		if i == len(hops)-1 {
			copy(packet[len(packet)-len(filler):], filler)
		}

		nextHmac = calcMac(hop.Mu, packet)
	}

	var pubKey [33]byte
	copy(pubKey[:], finalSessionKey.SerializeCompressed())

	var finalPacket [1300]byte
	copy(finalPacket[:], packet)

	return &Onion{
		Version:     [1]byte{0x00},
		PubKey:      pubKey,
		HopPayloads: finalPacket,
		HMAC:        nextHmac,
	}, nil
}

func Peel(user *User, onion *Onion) (*HopPayload, *Onion, error) {
	if onion.Version[0] != 0 {
		return nil, nil, fmt.Errorf("must use version 0")
	}

	peerPubKey, err := btcec.ParsePubKey(onion.PubKey[:])
	if err != nil {
		return nil, nil, err
	}

	privKey := user.privKey

	var rhoR [32]byte
	var nextEphemeral *btcec.PublicKey
	if onion.EphemeralKey != nil {
		// Tweak our priv key with the blinding factor
		ssR := sharedSecret(user.privKey, onion.EphemeralKey)
		bfR := genKey(ssR, []byte("blinded_node_id"))
		rhoR = genKey(ssR, rhoType)

		privKey = blindPriv(bfR, user.privKey)

		// SHA256(E(i) || ss(i)) * e(i)
		bf := blindingFactor(ssR, onion.EphemeralKey)
		nextEphemeral = blindPub(bf, onion.EphemeralKey)
	}

	ss := sharedSecret(privKey, peerPubKey)
	bf := blindingFactor(ss, peerPubKey)
	mu := genKey(ss, muType)
	rho := genKey(ss, rhoType)

	var packet [1300]byte
	copy(packet[:], onion.HopPayloads[:])

	// Validate the HMAC.
	calculatedHmac := calcMac(mu, packet[:])
	if !hmac.Equal(onion.HMAC[:], calculatedHmac[:]) {
		return nil, nil, fmt.Errorf("invalid HMAC")
	}

	// First we pad the packet with 1300 zero bytes.
	var paddedPacket [2600]byte
	copy(paddedPacket[:], packet[:])

	// Now we go ahead and de-obfuscate the packet.
	stream := pSByteStream(rho[:], 2600)
	xor(paddedPacket[:], paddedPacket[:], stream)

	// We should now be able to read our packet. (len + payload + hmac)
	payloadLen := binary.BigEndian.Uint16(paddedPacket[:2])
	//if payloadLen > 65 { // 1300/20=65
	//	return nil, nil, fmt.Errorf("payload len too large")
	//}

	payload := make([]byte, payloadLen)
	copy(payload[:], paddedPacket[2:2+payloadLen])

	hopPayload, err := DeserializeHopPayload(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("cant deserilize payload: %v", err)
	}

	hopPayloadData, err := DecodeHopDataPayload(hopPayload.Payload)
	if err != nil {
		return nil, nil, err
	}

	if hopPayloadData.EphemeralKey != nil {
		// Tweak our priv key with the blinding factor
		ssR := sharedSecret(user.privKey, hopPayloadData.EphemeralKey)
		bfR := genKey(ssR, []byte("blinded_node_id"))
		rhoR = genKey(ssR, rhoType)

		privKey = blindPriv(bfR, user.privKey)

		// SHA256(E(i) || ss(i)) * e(i)
		bf := blindingFactor(ssR, hopPayloadData.EphemeralKey)
		nextEphemeral = blindPub(bf, hopPayloadData.EphemeralKey)
	}

	if len(hopPayloadData.EncryptedData) != 0 {
		stream := pSByteStream(rhoR[:], len(hopPayloadData.EncryptedData))
		decrypted := make([]byte, len(hopPayloadData.EncryptedData))

		xor(decrypted[:], hopPayloadData.EncryptedData[:], stream)

		loadFromRecipient, err := DeserializeHopPayload(decrypted)
		if err != nil {
			return nil, nil, err
		}

		hopPayload.FwdTo = loadFromRecipient.FwdTo
	}

	var nextHmac [32]byte
	copy(nextHmac[:], paddedPacket[2+payloadLen:2+payloadLen+32])

	var finalPacket [1300]byte
	copy(finalPacket[:], paddedPacket[2+payloadLen+32:])

	// Blind the given ephemeral pub key to get the next one.
	nextPubKey := blindPub(bf, peerPubKey)
	var nextPubKeyBytes [33]byte
	copy(nextPubKeyBytes[:], nextPubKey.SerializeCompressed())

	return hopPayload, &Onion{
		Version:      onion.Version,
		PubKey:       nextPubKeyBytes,
		HopPayloads:  finalPacket,
		HMAC:         nextHmac,
		EphemeralKey: nextEphemeral,
	}, nil
}

func BuildBlindedPath(sessionKey *btcec.PrivateKey,
	hopsData []*HopData) (*BlindedPath, error) {

	if len(hopsData) < 2 {
		return nil, fmt.Errorf("need at least 2 nodes for a blinded " +
			"path")
	}

	firstBlindingEphemeral := sessionKey.PubKey()
	entryNode := hopsData[0].PubKey

	blindedNodeIds := make([]*btcec.PublicKey, len(hopsData))
	encryptedData := make([][]byte, len(hopsData))

	ephemeral := sessionKey
	for i := 0; i < len(hopsData); i++ {
		ss := sharedSecret(ephemeral, hopsData[i].PubKey)
		bf := genKey(ss, []byte("blinded_node_id"))
		rho := genKey(ss, rhoType)

		blindedNodeIds[i] = blindPub(bf, hopsData[i].PubKey)

		var fwdTo *btcec.PublicKey
		if i != len(hopsData)-1 {
			fwdTo = hopsData[i+1].PubKey
		}

		payload := &HopPayload{
			Payload: hopsData[i].ClearData,
			FwdTo:   fwdTo,
		}
		payloadSer := payload.Serialize()

		stream := pSByteStream(rho[:], len(payloadSer))
		xor(payloadSer[:], payloadSer[:], stream)

		encryptedData[i] = payloadSer

		ephemeral = blindPriv(blindingFactor(ss, ephemeral.PubKey()), ephemeral)
	}

	return &BlindedPath{
		EntryNodeID:               entryNode,
		BlindedNodeIDs:            blindedNodeIds[1:],
		EncryptedData:             encryptedData,
		FirstBlindingEphemeralKey: firstBlindingEphemeral,
	}, nil
}

// calcMac calculates HMAC-SHA-256 over the message using the passed secret key
// as input to the HMAC.
func calcMac(key [32]byte, msg []byte) [32]byte {
	hmac := hmac.New(sha256.New, key[:])
	hmac.Write(msg)
	h := hmac.Sum(nil)

	var mac [32]byte
	copy(mac[:], h[:32])

	return mac
}

// rightShift shifts the byte-slice by the given number of bytes to the right
// and 0-fill the resulting gap.
func rightShift(slice []byte, num int) {
	for i := len(slice) - num - 1; i >= 0; i-- {
		slice[num+i] = slice[i]
	}

	for i := 0; i < num; i++ {
		slice[i] = 0
	}
}

func genFiller(hops []*Hop) []byte {
	numHops := len(hops)

	// We have to generate a filler that matches all but the last hop (the
	// last hop won't generate an HMAC)
	fillerSize := 0
	for i := 0; i < numHops-1; i++ {
		fillerSize += hops[i].TotalSize()
	}
	filler := make([]byte, fillerSize)

	for i := 0; i < numHops-1; i++ {
		// Sum up how many frames were used by prior hops.
		fillerStart := 1300
		for _, h := range hops[:i] {
			fillerStart -= h.TotalSize()
		}

		// The filler is the part dangling off of the end of the
		// routingInfo, so offset it from there, and use the current
		// hop's frame count as its size.
		fillerEnd := 1300 + hops[i].TotalSize()

		streamKey := genKey(hops[i].SS, rhoType)
		streamBytes := pSByteStream(streamKey[:], 2600)

		xor(filler, filler, streamBytes[fillerStart:fillerEnd])
	}

	return filler
}

func genPadding(sessionKey *btcec.PrivateKey) []byte {
	var sessionKeyBytes [32]byte
	copy(sessionKeyBytes[:], sessionKey.Serialize())

	paddingKey := genKey(sessionKeyBytes, padType)

	// Now that we have our target key, we'll use chacha20 to generate a
	// series of random bytes directly into the passed mixHeader packet.
	var nonce [8]byte
	padCipher, err := chacha20.NewCipher(nonce[:], paddingKey[:])
	if err != nil {
		panic(err)
	}

	var res [1300]byte
	padCipher.XORKeyStream(res[:], res[:])

	return res[:]
}

// pSByteStream generates a pseudo-random byte stream by initialising Chacha20
// with one of the shared secret keys and a 96-bit zero nonce. A zero byte
// stream of the required length is then encrypted to produce the final stream.
func pSByteStream(key []byte, len int) []byte {
	// 96-bit zero nonce
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	cipher, err := chacha20.NewCipher(nonce, key)
	if err != nil {
		panic(err)
	}

	output := make([]byte, len)
	cipher.XORKeyStream(output, output)

	return output
}

func xor(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
