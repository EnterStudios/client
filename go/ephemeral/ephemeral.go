package libkb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

const EphemeralSeedSize = 32

func makeNewRandomSeed() (seed [EphemeralSeedSize]byte, err error) {
	bs, err := libkb.RandBytes(32)
	if err != nil {
		return seed, err
	}
	return libkb.MakeByte32(bs), nil
}

type DeviceEphemeralSeed [EphemeralSeedSize]byte

func newDeviceEphemeralSeed() (seed DeviceEphemeralSeed, err error) {
	randomSeed, err := makeNewRandomSeed()
	if err != nil {
		return seed, err
	}
	return DeviceEphemeralSeed(randomSeed), nil
}

func (s *DeviceEphemeralSeed) DeriveDHKey() (key *libkb.NaclDHKeyPair, err error) {
	derived, err := libkb.DeriveFromSecret(*s, libkb.DeriveReasonDeviceEKEncryption)
	if err != nil {
		return nil, err
	}
	keypair, err := libkb.MakeNaclDHKeyPairFromSecret(derived)
	return &keypair, err
}

func postNewDeviceEK(ctx context.Context, g *libkb.GlobalContext, sig string) error {
	apiArg := libkb.APIArg{
		Endpoint:    "user/device_ek",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args: libkb.HTTPArgs{
			"sig":       libkb.S{Val: sig},
			"device_id": libkb.S{Val: string(g.Env.GetDeviceID())},
		},
	}
	_, err := g.GetAPI().Post(apiArg)
	return err
}

func PublishNewDeviceEK(ctx context.Context, g *libkb.GlobalContext) (data keybase1.DeviceEkMetadata, err error) {
	merkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	if err != nil {
		return data, err
	}

	// TODO: Read the actual generation from the deviceEK store.
	generation := 1

	seed, err := newDeviceEphemeralSeed()
	if err != nil {
		return data, err
	}

	// TODO: Store the key.

	dhKeypair, err := seed.DeriveDHKey()
	if err != nil {
		return data, err
	}
	metadata := keybase1.DeviceEkMetadata{
		Kid:        dhKeypair.GetKID(),
		Generation: generation,
		HashMeta:   merkleRoot.HashMeta(),
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return data, err
	}

	// Sign the metadata blob with the device's long term signing key.
	signingKey, err := g.ActiveDevice.SigningKey()
	if err != nil {
		return data, err
	}
	signedPacket, _, err := signingKey.SignToString(metadataJSON)

	err = postNewDeviceEK(ctx, g, signedPacket)
	if err != nil {
		return data, err
	}

	return metadata, nil
}

type DeviceEKResponseElement struct {
	MerklePayload string `json:"merkle_payload"`
	Sig           string `json:"sig"`
}

type DeviceEKsResponse struct {
	Results []DeviceEKResponseElement `json:"results"`
}

func GetOwnDeviceEKs(ctx context.Context, g *libkb.GlobalContext) ([]keybase1.DeviceEkMetadata, error) {
	apiArg := libkb.APIArg{
		Endpoint:    "user/device_eks",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args:        libkb.HTTPArgs{},
	}
	res, err := g.GetAPI().Get(apiArg)
	if err != nil {
		return nil, err
	}

	parsedResponse := DeviceEKsResponse{}
	err = res.Body.UnmarshalAgain(&parsedResponse)
	if err != nil {
		return nil, err
	}

	// The client now needs to verify several things about these blobs its
	// received:
	// 1) Each is validly signed.
	// 2) The signing key belongs to one of the current user's devices.
	// 3) The key hasn't expired. That is, the Merkle root it was delegated
	//    with is within one week of the current root. The server deliberately
	//    avoids doing this filtering for us, and finding expired keys in the
	//    results here is expected. We silently drop them.
	prunedDevices := []keybase1.DeviceEkMetadata{}
	merkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	for _, element := range parsedResponse.Results {
		key, payload, _, err := libkb.NaclVerifyAndExtract(element.Sig)
		if err != nil {
			return nil, err
		}
		fmt.Printf("key: %#v\npayload: %#v\nmerkleRoot: %#v", key, string(payload), merkleRoot)
	}

	return prunedDevices, nil
}
