package libkb

import (
	"context"
	"fmt"
	"testing"

	"github.com/keybase/client/go/kbtest"
	"github.com/keybase/client/go/libkb"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceEK(t *testing.T) {
	tc := libkb.SetupTest(t, "ephemeral", 2)
	defer tc.Cleanup()

	_, err := kbtest.CreateAndSignupFakeUser("t", tc.G)
	require.NoError(t, err)

	metadata, err := PublishNewDeviceEK(context.Background(), tc.G)
	require.NoError(t, err)

	fetchedDevices, err := GetOwnDeviceEKs(context.Background(), tc.G)
	require.NoError(t, err)

	fmt.Println(metadata, fetchedDevices)
}
