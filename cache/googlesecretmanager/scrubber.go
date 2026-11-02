package googlesecretmanager

import (
	"fmt"

	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	"github.com/runsecure/hkdfguard-go"
)

// receiveBufferScrubber is gRPC's protobuf codec, except that it zeroes the buffers a response
// message was received into once it has decoded them - the Go counterpart of the .NET
// ReceiveBufferScrubber. grpc-go reads each message into buffers from its buffer pool (a frame over
// 1 KiB) or the heap, decodes it, and returns them to the pool uncleared, so a secret payload would
// otherwise stay in a pooled buffer that the next message on any connection is read into, or in
// garbage the collector frees without clearing. proto.Unmarshal copies every bytes field out of its
// input (it never aliases it unless asked to), so the payload is already in the response's own slice
// - which the cache zeroes - when the buffers are cleared, and clearing them loses nothing.
//
// It is used per call, with grpc.ForceCodecV2 through gax.WithGRPCOptions, so the application's
// client - and every other call it makes - is left as it is. Over REST the option is ignored.
//
// What it can't reach: a compressed response's received bytes (gRPC frees them itself once
// decompressed, and decompresses only when a compressor such as grpc/encoding/gzip is registered in
// the process), the connection's read buffer and TLS's decryption buffers, all below the codec.
// gRPC's binary logging (GRPC_BINARY_LOG_FILTER), were it turned on, would record the zeroed
// buffer, not the payload.
type receiveBufferScrubber struct{}

// Name is empty, so the call keeps the default content type, application/grpc: gRPC names a forced
// codec's content subtype after it, and Google's front end answers application/grpc+proto - what
// the name "proto" would send - with an HTTP 404.
func (receiveBufferScrubber) Name() string { return "" }

// Marshal encodes a request; requests hold nothing secret.
func (receiveBufferScrubber) Marshal(v any) (mem.BufferSlice, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("googlesecretmanager: can't marshal a %T: it isn't a proto.Message", v)
	}
	encoded, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return mem.BufferSlice{mem.SliceBuffer(encoded)}, nil
}

// Unmarshal decodes a response from data, then zeroes data - and, when the message arrived in more
// than one buffer, the copy it was joined into - whether or not decoding succeeded. gRPC frees data
// once this returns, so the cleared buffers go back to the pool.
func (receiveBufferScrubber) Unmarshal(data mem.BufferSlice, v any) error {
	defer scrub(data)
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("googlesecretmanager: can't unmarshal into a %T: it isn't a proto.Message", v)
	}
	if len(data) == 1 {
		return proto.Unmarshal(data[0].ReadOnlyData(), m)
	}
	joined := data.Materialize()
	defer hkdfguard.Wipe(joined)
	return proto.Unmarshal(joined, m)
}

// scrub zeroes every buffer in data. They are read-only by gRPC's contract to stop a codec
// changing what another reader sees; here nothing reads them again before they are freed.
func scrub(data mem.BufferSlice) {
	for _, buffer := range data {
		hkdfguard.Wipe(buffer.ReadOnlyData())
	}
}
