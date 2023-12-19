// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spio_test

import (
	"crypto/aes"
	"testing"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/spio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeAuthMac(t *testing.T) {
	//IA1 := xtest.MustParseIA("1-ff00:0:111")
	//IA2 := xtest.MustParseIA("1-ff00:0:112")
	authKey := drkey.Key{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	//ts := uint32(0x030201)

	testCases := map[string]struct {
		optionParameter slayers.PathInfoOptionParams
		rawMACInput     []byte
		assertErr       assert.ErrorAssertionFunc
	}{
		"valid": {
			optionParameter: slayers.PathInfoOptionParams{
				SPI:         	slayers.PathInfoSPI(0x1),
				PMI:			0x04,
				PTI:    		0x03,
				HBH_Opts:		0x02,
				E2E_Opts: 		0x01,
				ISD_1:			0x0606,
				AS_1: 			0x060000000001,
				ISD_2:      	0x0605,
				AS_2:			0x060000000000,
				Algorithm:   	slayers.PathInfoCMAC,
				TimestampSN:	0x060504030201,
				Auth:        	make([]byte, 16),
			},
			rawMACInput: []byte{
				0x4, 0x3, 0x2, 0x1, // PMI | PTI | HBH_Opts | E2E_Opts
				0x6, 0x6, // ISD1
				0x6, 0x0, 0x0, 0x0, 0x0, 0x1, // AS1
				0x6, 0x5, // ISD2
				0x6, 0x0, 0x0, 0x0, 0x0, 0x0, // AS2
				0x0, 0x0, // Algorithm | RSV
				0x6, 0x5, 0x4, 0x3, 0x2, 0x1, // Timestamp / Sequence Number
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			optAuth, err := slayers.NewPathInfoOption(tc.optionParameter)
			assert.NoError(t, err)

			buf := make([]byte, spio.MACBufferSize)
			inpLen, err := spio.SerializeAuthenticatedData(
				buf,
				optAuth,
			)
			require.NoError(t, err)
			require.Equal(t, tc.rawMACInput, buf[:inpLen])

			mac, err := spio.SpioComputeAuthCMAC(
				spio.SpioMACInput{
					authKey[:],
					optAuth,
				},
				make([]byte, spio.MACBufferSize),
				optAuth.Authenticator(),
			)
			tc.assertErr(t, err)
			if err != nil {
				return
			}

			block, err := aes.NewCipher(authKey[:])
			require.NoError(t, err)
			macFunc, err := cmac.New(block)
			require.NoError(t, err)

			macFunc.Write(tc.rawMACInput)
			expectedMac := macFunc.Sum(nil)
			assert.Equal(t, expectedMac, mac)

		})
	}

}
