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

package spio

import (
	"crypto/aes"
	"encoding/binary"
	"hash"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const (
	// FixAuthDataInputLen is the unvariable fields length for the
	// authenticated data. It consists of the Path Information Metadata length 
	fixAuthDataInputLen = slayers.PathInfoOptionMetadataLen - 4

	// MACBufferSize sets an upperBound to the authenticated data length . 
	// This is:
	// 1. Path Information Option Meta without SPI ????
	// We round this up to 28 (Path Information option meta - 4) 
	MACBufferSize = 28
)

type SpioMACInput struct {
	Key        []byte
	Header     slayers.PathInfoOption
}

// ComputeAuthCMAC computes the authenticator tag for the AES-CMAC algorithm.
// The key should correspond to the SPI defined in opt.SPI.
//
// The aux buffer is used as a temporary buffer for the MAC computation.
// It must be at least MACBufferSize long.
// The resulting MAC is written to outBuffer (appending, if necessary),
// and returned as a slice of length 16.
func SpioComputeAuthCMAC(
	input SpioMACInput,
	auxBuffer []byte,
	outBuffer []byte,
) ([]byte, error) {

	cmac, err := initCMAC(input.Key)
	if err != nil {
		return nil, err
	}

	inputLen, err := serializeAuthenticatedData(
		auxBuffer,
		input.Header,
	)
	if err != nil {
		return nil, err
	}
	
	cmac.Write(auxBuffer[:inputLen])

	return cmac.Sum(outBuffer[:0]), nil
}

func initCMAC(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize AES cipher", err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.WrapStr("unable to initialize Mac", err)
	}
	return mac, nil
}

func serializeAuthenticatedData(
	buf []byte,
	opt slayers.PathInfoOption,
) (int, error) {

	_ = buf[MACBufferSize-1]

	//binary.BigEndian.PutUint32(buf[:4], uint32(opt.SPI())) // SPI not in MAC computatuon !!!
	buf[0] = byte(opt.PMI())
	buf[1] = byte(opt.PTI())
	buf[2] = byte(opt.HBHOpts())
	buf[3] = byte(opt.E2EOpts())
	binary.BigEndian.PutUint16(buf[4:6], opt.ISD1())
	PathInfobigEndianPutUint48(buf[6:12], opt.AS1())
	binary.BigEndian.PutUint16(buf[12:14], opt.ISD2())
	PathInfobigEndianPutUint48(buf[14:20], opt.AS2())
	buf[20] = byte(opt.Algorithm())
	buf[21] = byte(0)
	PathInfobigEndianPutUint48(buf[22:], opt.TimestampSN())

	offset := fixAuthDataInputLen

	return offset, nil
}

func PathInfobigEndianPutUint48(b []byte, v uint64) {
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	binary.BigEndian.PutUint32(b[2:6], uint32(v))
}