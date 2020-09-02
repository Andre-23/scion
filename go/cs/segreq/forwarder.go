// Copyright 2020 ETH Zurich
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

package segreq

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// ForwardingLookup handles path segment lookup requests in a non-core AS. If
// segments are missing, the request is forwarded to the respective core ASes.
// It should only be used in a non-core AS.
type ForwardingLookup struct {
	LocalIA     addr.IA
	CoreChecker CoreChecker
	Fetcher     *segfetcher.Fetcher
	Expander    WildcardExpander
}

// LookupSegments looks up the segments for the given request
//
//  - requests for up segment are answered directly, from the local DB
//  - down and core segments are forwarded to the responsible core ASes,
//    and results are cached
func (f ForwardingLookup) LookupSegments(ctx context.Context, src,
	dst addr.IA) (segfetcher.Segments, error) {

	segType, err := f.classify(ctx, src, dst)
	if err != nil {
		return nil, err
	}

	reqs, err := f.Expander.ExpandSrcWildcard(ctx,
		segfetcher.Request{
			Src:     src,
			Dst:     dst,
			SegType: segType,
		},
	)
	if err != nil {
		return nil, serrors.WrapStr("expanding wildcard request", err)
	}
	return f.Fetcher.Fetch(ctx, reqs, false)
}

// classify validates the request and determines the segment type for the request
func (f ForwardingLookup) classify(ctx context.Context,
	src, dst addr.IA) (proto.PathSegType, error) {

	unset := proto.PathSegType_unset // shorthand
	if src.I == 0 || dst.I == 0 {
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "zero ISD src or dst")
	}
	if dst == f.LocalIA {
		// this could be an otherwise valid request, but probably the requester switched Src and Dst
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "dst is local AS, confusion?")
	}
	srcCore, err := f.CoreChecker.IsCore(ctx, src)
	if err != nil {
		return proto.PathSegType_unset, err
	}
	dstCore, err := f.CoreChecker.IsCore(ctx, dst)
	if err != nil {
		return proto.PathSegType_unset, err
	}
	switch {
	case srcCore && dstCore:
		// core
		if src.I != f.LocalIA.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "core segment request src ISD not local ISD")
		}
		return proto.PathSegType_core, nil
	case srcCore:
		// down
		if src.I != dst.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "down segment request src/dst in different ISD")
		}
		return proto.PathSegType_down, nil
	case dstCore:
		// up
		if src != f.LocalIA {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "up segment request src not local AS")
		}
		if dst.I != f.LocalIA.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "up segment request dst in different ISD")
		}
		return proto.PathSegType_up, nil
	default:
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "non-core src & dst")
	}
}
