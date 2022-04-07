package onion

import "errors"

type Onion struct {
	Version     [1]byte
	PubKey      [33]byte
	HopPayloads [1300]byte
	HMAC        [32]byte
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

func BuildOnion(hopsData []*HopData) (*Onion, error) {
	return &Onion{
		Version: [1]byte{0x00},
	}, nil
}
