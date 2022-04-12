package onion

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSerializeDeserialiseOnion(t *testing.T) {
	onion := "0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a710f8eaf9ccc768f66bb5dec1f7827f33c43fe2ddd05614c8283aa78e9e7573f87c50f7d61ab590531cf08000178a333a347f8b4072e1cea42da7552402b10765adae3f581408f35ff0a71a34b78b1d8ecae77df96c6404bae9a8e8d7178977d7094a1ae549f89338c0777551f874159eb42d3a59fb9285ad4e24883f27de23942ec966611e99bee1cee503455be9e8e642cef6cef7b9864130f692283f8a973d47a8f1c1726b6e59969385975c766e35737c8d76388b64f748ee7943ffb0e2ee45c57a1abc40762ae598723d21bd184e2b338f68ebff47219357bd19cd7e01e2337b806ef4d717888e129e59cd3dc31e6201ccb2fd6d7499836f37a993262468bcb3a4dcd03a22818aca49c6b7b9b8e9e870045631d8e039b066ff86e0d1b7291f71cefa7264c70404a8e538b566c17ccc5feab231401e6c08a01bd5edfc1aa8e3e533b96e82d1f91118d508924b923531929aea889fcdf057f5995d9731c4bf796fb0e41c885d488dcbc68eb742e27f44310b276edc6f652658149e7e9ced4edde5d38c9b8f92e16f6b4ab13d710ee5c193921909bdd75db331cd9d7581a39fca50814ed8d9d402b86e7f8f6ac2f3bca8e6fe47eb45fbdd3be21a8a8d200797eae3c9a0497132f92410d804977408494dff49dd3d8bce248e0b74fd9e6f0f7102c25ddfa02bd9ad9f746abbfa3379834bc2380d58e9d23237821475a1874484783a15d68f47d3dc339f38d9bf925655d5c946778680fd6d1f062f84128895aff09d35d6c92cca63d3f95a9ee8f2a84f383b4d6a087533e65de12fc8dcaf85777736a2088ff4b22462265028695b37e70963c10df8ef2458756c73007dc3e544340927f9e9f5ea4816a9fd9832c311d122e9512739a6b4714bba590e31caa143ce83cb84b36c738c60c3190ff70cd9ac286a9fd2ab619399b68f1f7447be376ce884b5913c8496d01cbf7a44a60b6e6747513f69dc538f340bc1388e0fde5d0c1db50a4dcb9cc0576e0e2474e4853af9623212578d502757ffb2e0e749695ed70f61c116560d0d4154b64dcf3cbf3c91d89fb6dd004dc19588e3479fcc63c394a4f9e8a3b8b961fce8a532304f1337f1a697a1bb14b94d2953f39b73b6a3125d24f27fcd4f60437881185370bde68a5454d816e7a70d4cea582effab9a4f1b730437e35f7a5c4b769c7b72f0346887c1e63576b2f1e2b3706142586883f8cf3a23595cc8e35a52ad290afd8d2f8bcd5b4c1b891583a4159af7110ecde092079209c6ec46d2bda60b04c519bb8bc6dffb5c87f310814ef2f3003671b3c90ddf5d0173a70504c2280d31f17c061f4bb12a978122c8a2a618bb7d1edcf14f84bf0fa181798b826a254fca8b6d7c81e0beb01bd77f6461be3c8647301d02b04753b0771105986aa0cbc13f7718d64e1b3437e8eef1d319359914a7932548c91570ef3ea741083ca5be5ff43c6d9444d29df06f76ec3dc936e3d180f4b6d0fbc495487c7d44d7c8fe4a70d5ff1461d0d9593f3f898c919c363fa18341ce9dae54f898ccf3fe792136682272941563387263c51b2a2f32363b804672cc158c9230472b554090a661aa81525d11876eefdcc45442249e61e07284592f1606491de5c0324d3af4be035d7ede75b957e879e9770cdde2e1bbc1ef75d45fe555f1ff6ac296a2f648eeee59c7c08260226ea333c285bcf37a9bbfa57ba2ab8083c4be6fc2ebe279537d22da96a07392908cf22b233337a74fe5c603b51712b43c3ee55010ee3d44dd9ba82bba3145ec358f863e04bbfa53799a7a9216718fd5859da2f0deb77b8e315ad6868fdec9400f45a48e6dc8ddbaeb3"
	onionBytes, err := hex.DecodeString(onion)
	require.NoError(t, err)

	o, err := DeserializeOnion(onionBytes)
	require.NoError(t, err)

	onion2 := o.Serialize()
	require.True(t, bytes.Equal(onionBytes, onion2))
}

func TestBuildAndPeelOnion(t *testing.T) {
	pk1, _ := btcec.NewPrivateKey()

	tests := []struct {
		name       string
		sessionKey *btcec.PrivateKey
		hopsData   []*HopData
		hopUsers   []string
	}{
		{
			name:       "normal onion A -> B -> C -> D",
			sessionKey: pk1,
			hopsData: []*HopData{
				{
					PubKey:    Users[Bob].PubKey,
					ClearData: []byte("Hi Bob"),
				},
				{
					PubKey:    Users[Charlie].PubKey,
					ClearData: []byte("Hi Charlie"),
				},
				{
					PubKey:    Users[Dave].PubKey,
					ClearData: []byte("Hi Dave"),
				},
			},
			hopUsers: []string{Bob, Charlie, Dave},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			onion, err := BuildOnion(test.sessionKey, test.hopsData)
			require.NoError(t, err)

			var payload *HopPayload
			for i, u := range test.hopUsers {
				user := Users[u]
				payload, onion, err = Peel(user, onion)
				require.NoError(t, err)

				pl, err := DecodeHopDataPayload(payload.Payload)
				require.NoError(t, err)

				require.True(
					t,
					bytes.Equal(
						test.hopsData[i].ClearData,
						pl.ClearData,
					),
				)
			}
		})
	}
}

func TestBuildAndPeelBlindedOnion(t *testing.T) {
	// A -> B -> C -> B(D) -> B(E)

	// First, Eve builds blinded path C -> D -> E
	eveSessionKey, _ := btcec.NewPrivateKey()

	blindedHopData := []*HopData{
		{
			PubKey:    Users[Charlie].PubKey,
			ClearData: []byte("Hi Charlie, from Eve"),
		},
		{
			PubKey:    Users[Dave].PubKey,
			ClearData: []byte("Hi Dave, from Eve"),
		},
		{
			PubKey:    Users[Eve].PubKey,
			ClearData: []byte("Hi Me, from Me"),
		},
	}

	bp, err := BuildBlindedPath(eveSessionKey, blindedHopData)
	require.NoError(t, err)

	// Now, Alice builds the onion.
	aliceSessionKey, _ := btcec.NewPrivateKey()

	hopsData := []*HopData{
		{
			PubKey:    Users[Bob].PubKey,
			ClearData: []byte("Hi Bob, from Alice"),
		},
		{
			PubKey:        Users[Charlie].PubKey,
			ClearData:     []byte("Hi Charlie, from Alice"),
			EncryptedData: bp.EncryptedData[0],
			EphemeralKey:  bp.FirstBlindingEphemeralKey,
		},
		{
			PubKey:        bp.BlindedNodeIDs[0],
			ClearData:     []byte("Hi B(D), from Alice"),
			EncryptedData: bp.EncryptedData[1],
		},
		{
			PubKey:        bp.BlindedNodeIDs[1],
			ClearData:     []byte("Hi B(E), from Alice"),
			EncryptedData: bp.EncryptedData[2],
		},
	}

	onion, err := BuildOnion(aliceSessionKey, hopsData)
	require.NoError(t, err)

	// Give onion to Bob:
	_, onion, err = Peel(Users[Bob], onion)
	require.NoError(t, err)

	// Give onion to Charlie:
	_, onion, err = Peel(Users[Charlie], onion)
	require.NoError(t, err)

	// Give onion to Dave:
	_, onion, err = Peel(Users[Dave], onion)
	require.NoError(t, err)

	// Give onion to Eve:
	_, onion, err = Peel(Users[Eve], onion)
	require.NoError(t, err)
}
