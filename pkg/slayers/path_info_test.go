// Copyright 2023 ETH Zurich
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

package slayers_test

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	spio_algo       = slayers.PathInfoCMAC
	spio_ts         = uint64(0x060504030201)
	spio_optAuthMAC = []byte("16byte_mac_foooo")
)

var spio_rawE2EOptAuth = append(
	[]byte{
		0x11, 0xc, 0x3, 0x30,
		0x0, 0x1, 0x0, 0x1,
		0x4, 0x3, 0x2, 0x1, // PMI | PTI | HBH_Opts | E2E_Opts
		0x6, 0x6, // ISD1
	    0x6, 0x0, 0x0, 0x0, 0x0, 0x1, // AS1
		0x6, 0x5, // ISD2
		0x6, 0x0, 0x0, 0x0, 0x0, 0x0, // AS2
		0x0, 0x0, // Algorithm | RSV
		0x6, 0x5, 0x4, 0x3, 0x2, 0x1, // Timestamp / Sequence Number
	},
	optAuthMAC...,
)

func TestPathInfoOptSerialize(t *testing.T) {
	cases := []struct {
		name      string
		spiFunc   func(t *testing.T) slayers.PathInfoSPI
		algo      slayers.PathInfoAlg
		ts        uint64
		optAuth   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		{
			name:      "correct",
			spiFunc:   SpioinitSPI,
			algo:      spio_algo,
			ts:        spio_ts,
			optAuth:   spio_optAuthMAC,
			errorFunc: assert.NoError,
		},
		{
			name:      "bad_ts",
			spiFunc:   SpioinitSPI,
			algo:      spio_algo,
			ts:        uint64(1 << 48),
			optAuth:   spio_optAuthMAC,
			errorFunc: assert.Error,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			spio, err := slayers.NewPathInfoOption(slayers.PathInfoOptionParams{
				SPI:         	c.spiFunc(t),
				PMI:			0x04,
				PTI:    		0x03,
				HBH_Opts:		0x02,
				E2E_Opts: 		0x01,
				ISD_1:			0x0606,
				AS_1: 			0x060000000001,
				ISD_2:      	0x0605,
				AS_2:			0x060000000000,
				Algorithm:   	c.algo,
				TimestampSN:	c.ts,
				Auth:        	c.optAuth,
			})
			c.errorFunc(t, err)
			if err != nil {
				return
			}

			e2e := slayers.EndToEndExtn{}
			e2e.NextHdr = slayers.L4UDP
			e2e.Options = []*slayers.EndToEndOption{spio.EndToEndOption}

			b := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")
			assert.Equal(t, spio_rawE2EOptAuth, b.Bytes(), "Raw Buffer")
		})
	}
}

func TestPathInfoOptDeserialize(t *testing.T) {
	e2e := slayers.EndToEndExtn{}

	_, err := e2e.FindOption(slayers.OptTypePathInfo)
	assert.Error(t, err)

	assert.NoError(t, e2e.DecodeFromBytes(spio_rawE2EOptAuth, gopacket.NilDecodeFeedback))
	assert.Equal(t, slayers.L4UDP, e2e.NextHdr, "NextHeader")
	optAuth, err := e2e.FindOption(slayers.OptTypePathInfo)
	require.NoError(t, err, "FindOption")
	auth, err := slayers.ParsePathInfoOption(optAuth)
	require.NoError(t, err, "ParsePathInfoOption")
	assert.Equal(t, SpioinitSPI(t), auth.SPI(), "SPI")
	assert.Equal(t, slayers.PathInfoASHost, auth.SPI().Type())
	assert.Equal(t, slayers.PathInfoReceiverSide, auth.SPI().Direction())
	assert.Equal(t, true, auth.SPI().IsDRKey())
	assert.Equal(t, spio_algo, auth.Algorithm(), "Algorithm Type")
	assert.Equal(t, spio_ts, auth.TimestampSN(), "TimestampSN")
	assert.Equal(t, spio_optAuthMAC, auth.Authenticator(), "Authenticator data (MAC)")

	assert.Equal(t, uint8(0x04), auth.PMI(), "PMI")
	assert.Equal(t, uint8(0x03), auth.PTI(), "PTI")
	assert.Equal(t, uint8(0x02), auth.HBHOpts(), "HBH_Opts")
	assert.Equal(t, uint8(0x01), auth.E2EOpts(), "E2E_Opts")
	assert.Equal(t, uint16(0x0606), auth.ISD1(), "ISD_1")
	assert.Equal(t, uint64(0x060000000001), auth.AS1(), "AS_1")
	assert.Equal(t, uint16(0x0605), auth.ISD2(), "ISD_2")
	assert.Equal(t, uint64(0x060000000000), auth.AS2(), "AS_2")
}

func TestMakePathInfoSPIDrkey(t *testing.T) {
	spi := initSPI(t)
	assert.EqualValues(t, binary.BigEndian.Uint32([]byte{0, 1, 0, 1}), spi)
}

func TestPathInfoOptAuthenticatorDeserializeCorrupt(t *testing.T) {
	optAuthCorrupt := slayers.EndToEndOption{
		OptType: slayers.OptTypePathInfo,
		OptData: []byte{},
	}
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = slayers.L4UDP
	e2e.Options = []*slayers.EndToEndOption{&optAuthCorrupt}

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")

	assert.NoError(t, e2e.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	optAuth, err := e2e.FindOption(slayers.OptTypePathInfo)
	require.NoError(t, err, "FindOption")
	_, err = slayers.ParsePacketAuthOption(optAuth)
	require.Error(t, err, "ParsePacketAuthOption should fail")
}

func SpioinitSPI(t *testing.T) slayers.PathInfoSPI {
	spi, err := slayers.MakePathInfoSPIDRKey(
		1,
		slayers.PathInfoASHost,
		slayers.PathInfoReceiverSide)
	require.NoError(t, err)
	return spi
}