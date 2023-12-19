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

// This file includes the SPAO header implementation as specified
// in https://docs.scion.org/en/latest/protocols/authenticator-option.html

// The Path Information option format is as follows:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   NextHdr=UDP |     ExtLen    |  OptType=3    |  OptDataLen   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Security Parameter Index                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      PMI      |      PTI      |  HBH Options  |  E2E Options  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              ISD1             |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+							   |
// |                              AS1                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              ISD2             |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+							   |
// |                              AS2                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Algorithm  |      RSV      |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+							   |
// |                   Timestamp / Sequence Number                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                        16-octet MAC data                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

package slayers

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	PathInfoASHost uint8 = iota
	PathInfoHostHost
)

const (
	PathInfoSenderSide uint8 = iota
	PathInfoReceiverSide
)

const (
	// PathInfoOptionMetadataLen is the size of the SPIO Metadata and
	// corresponds the minimum size of the SPIO OptData.
	// The SPIO header contains the following fixed-length fields:
	// SPI (4 Bytes), PMI (3 Bits), RSV (5 Bits), PTI (1 Byte),
	// HBH Options (1 Byte), E2E Options (1 Byte),
	// ISD1 (2 Bytes), AS1 (6 Bytes), ISD2 (2 Bytes), AS2 (6 Bytes)
	// Algorithm (1 Byte), RSV (1 Byte) and
	// Timestamp / Sequence Number (6 Bytes).
	PathInfoOptionMetadataLen = 32
)

// PathInfoSPI (Security Parameter Index) is the identifier for the key
// used for the Path Information option. DRKey values are in the 
// range [1, 2^21-1].
type PathInfoSPI uint32

func (p PathInfoSPI) Type() uint8 {
	if p&(1<<17) == 0 {
		return PathInfoASHost
	}
	return PathInfoHostHost
}

func (p PathInfoSPI) Direction() uint8 {
	if p&(1<<16) == 0 {
		return PathInfoSenderSide
	}
	return PathInfoReceiverSide
}

func (p PathInfoSPI) DRKeyProto() uint16 {
	return uint16(p)
}

func (p PathInfoSPI) IsDRKey() bool {
	return p > 0 && p < (1<<21)
}

func MakePathInfoSPIDRKey(
	proto uint16,
	drkeyType uint8,
	dir uint8,
) (PathInfoSPI, error) {

	if proto < 1 {
		return 0, serrors.New("Invalid proto identifier value")
	}
	if drkeyType > 1 {
		return 0, serrors.New("Invalid DRKeyType value")
	}
	if dir > 1 {
		return 0, serrors.New("Invalid DRKeyDirection value")
	}
	spi := uint32((drkeyType & 0x1)) << 17
	spi |= uint32((dir & 0x1)) << 16
	spi |= uint32(proto)

	return PathInfoSPI(spi), nil
}

// PathInfoAlg is the enumerator for authenticator algorithm types in the
// Path Information option.
type PathInfoAlg uint8

const (
	PathInfoCMAC PathInfoAlg = iota
	PathInfoSHA1_AES_CBC
)

type PathInfoOptionParams struct {
	SPI         PathInfoSPI
	PMI			uint8
	PTI    		uint8
	HBH_Opts	uint8
	E2E_Opts 	uint8
	ISD_1		uint16
	AS_1 		uint64
	ISD_2       uint16
	AS_2		uint64
	Algorithm   PathInfoAlg
	TimestampSN uint64
	Auth        []byte
}

// PathInfoOption wraps an EndToEndOption of OptTypePathInfo.
// This can be used to serialize and parse the internal structure of the Path Information
// option.
type PathInfoOption struct {
	*EndToEndOption
}

// NewPathInfoOption creates a new EndToEndOption of
// OptTypePathInfo, initialized with the given SPIO data.
func NewPathInfoOption(
	p PathInfoOptionParams,
) (PathInfoOption, error) {

	o := PathInfoOption{EndToEndOption: new(EndToEndOption)}
	err := o.Reset(p)
	return o, err
}

// ParsePathInfoOption parses o as a Path Information option.
// Performs minimal checks to ensure that SPI, algorithm, timestamp, RSV, sequence number,
// PMI, PTI, HBH_Opts, E2E_Opts, ISD_1, AS_1, ISD_2 and AS_1 are set.
// Checking the size and content of the Authenticator data must be done by the
// caller.
func ParsePathInfoOption(o *EndToEndOption) (PathInfoOption, error) {
	if o.OptType != OptTypePathInfo {
		return PathInfoOption{},
			serrors.New("wrong option type", "expected", OptTypePathInfo, "actual", o.OptType)
	}
	if len(o.OptData) < PathInfoOptionMetadataLen {
		return PathInfoOption{},
			serrors.New("buffer too short", "expected at least", 32, "actual", len(o.OptData))
	}
	return PathInfoOption{o}, nil
}

// Reset reinitializes the underlying EndToEndOption with the SPIO data.
// Reuses the OptData buffer if it is of sufficient capacity.
func (o PathInfoOption) Reset(
	p PathInfoOptionParams,
) error {

	if p.TimestampSN >= (1 << 48) {
		return serrors.New("Timestamp value should be smaller than 2^48")
	}

	if p.AS_1 >= (1 << 48) {
		return serrors.New("AS_1 value should be smaller than 2^48")
	}

	if p.AS_2 >= (1 << 48) {
		return serrors.New("AS_2 value should be smaller than 2^48")
	}

	o.OptType = OptTypePathInfo

	n := PathInfoOptionMetadataLen + len(p.Auth)
	if n <= cap(o.OptData) {
		o.OptData = o.OptData[:n]
	} else {
		o.OptData = make([]byte, n)
	}
	binary.BigEndian.PutUint32(o.OptData[:4], uint32(p.SPI))
	o.OptData[4] = byte(p.PMI)
	o.OptData[5] = byte(p.PTI)
	o.OptData[6] = byte(p.HBH_Opts)
	o.OptData[7] = byte(p.E2E_Opts)
	binary.BigEndian.PutUint16(o.OptData[8:10], p.ISD_1)
	PathInfobigEndianPutUint48(o.OptData[10:16], p.AS_1)
	binary.BigEndian.PutUint16(o.OptData[16:18], p.ISD_2)
	PathInfobigEndianPutUint48(o.OptData[18:24], p.AS_2)
	o.OptData[24] = byte(p.Algorithm)
	o.OptData[25] = byte(0)
	PathInfobigEndianPutUint48(o.OptData[26:32], p.TimestampSN)
	copy(o.OptData[32:], p.Auth)

	o.OptAlign = [2]uint8{4, 2}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
	return nil
}

// SPI returns the value set in the Security Parameter Index in the extension.
func (o PathInfoOption) SPI() PathInfoSPI {
	return PathInfoSPI(binary.BigEndian.Uint32(o.OptData[:4]))
}

// PMI returns the value set in the PMI field in the extension.
func (o PathInfoOption) PMI() uint8 {
	return uint8(o.OptData[4])
}

// PTI returns the value set in the PTI field in the extension.
func (o PathInfoOption) PTI() uint8 {
	return uint8(o.OptData[5])
}

// HBHOpts returns the value set in the HBH_Opts field in the extension.
func (o PathInfoOption) HBHOpts() uint8 {
	return uint8(o.OptData[6])
}

// E2EOpts returns the value set in the E2_Opts field in the extension.
func (o PathInfoOption) E2EOpts() uint8 {
	return uint8(o.OptData[7])
}

// ISD1 returns the value set in the ISD_1 field in the extension.
func (o PathInfoOption) ISD1() uint16 {
	return binary.BigEndian.Uint16(o.OptData[8:10])
}

// AS1 returns the value set in the AS_1 field in the extension.
func (o PathInfoOption) AS1() uint64 {
	return PathInfobigEndianUint48(o.OptData[10:16])
}

// ISD2 returns the value set in the ISD_2 field in the extension.
func (o PathInfoOption) ISD2() uint16 {
	return binary.BigEndian.Uint16(o.OptData[16:18])
}

// AS2 returns the value set in the AS_2 field in the extension.
func (o PathInfoOption) AS2() uint64 {
	return PathInfobigEndianUint48(o.OptData[18:24])
}

// Algorithm returns the algorithm type stored in the data buffer.
func (o PathInfoOption) Algorithm() PathInfoAlg {
	return PathInfoAlg(o.OptData[24])
}

// Timestamp returns the value set in the homonym field in the extension.
func (o PathInfoOption) TimestampSN() uint64 {
	return PathInfobigEndianUint48(o.OptData[26:32])
}

// Authenticator returns slice of the underlying auth buffer.
// Changes to this slice will be reflected on the wire when
// the extension is serialized.
func (o PathInfoOption) Authenticator() []byte {
	return o.OptData[32:]
}

func PathInfobigEndianUint48(b []byte) uint64 {
	return uint64(b[0])<<40 + uint64(b[1])<<32 +
		uint64(binary.BigEndian.Uint32(b[2:6]))
}

func PathInfobigEndianPutUint48(b []byte, v uint64) {
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	binary.BigEndian.PutUint32(b[2:6], uint32(v))
}
