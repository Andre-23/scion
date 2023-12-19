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

package spio_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/spio"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/stretchr/testify/assert"
)


func TestTimestamp(t *testing.T) {
	now := time.Now()
	testCases := map[string]struct {
		currentTime time.Time
		epoch       drkey.Epoch
		assertErr   assert.ErrorAssertionFunc
	}{
		"valid": {
			currentTime: now,
			epoch:       getEpoch(now),
			assertErr:   assert.NoError,
		},
		"invalid": {
			currentTime: now,
			epoch:       getEpoch(now.Add(-4 * 24 * time.Hour)),
			assertErr:   assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			rt, err := spio.RelativeTimestamp(tc.epoch, tc.currentTime)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			recoveredTime := spio.AbsoluteTimestamp(tc.epoch, rt)
			
			assert.True(t, tc.currentTime.Equal(recoveredTime))
		})
	}
}

func getEpoch(t time.Time) drkey.Epoch {
	epochDuration := drkeyutil.LoadEpochDuration()
	duration := int64(epochDuration / time.Second)
	idx := t.Unix() / duration
	begin := uint32(idx * duration)
	end := begin + uint32(duration)
	return drkey.NewEpoch(begin, end)
}