package googlesecretmanager

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/experimental"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	"github.com/runsecure/hkdfguard-go"
)

func encodedResponse(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&secretmanagerpb.AccessSecretVersionResponse{
		Name:    "projects/1/secrets/item/versions/1",
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTheScrubber_DecodesAResponse_ThenZeroesTheBufferItWasReceivedInto(t *testing.T) {
	received := encodedResponse(t, []byte("s3cret"))
	response := &secretmanagerpb.AccessSecretVersionResponse{}

	if err := (receiveBufferScrubber{}).Unmarshal(mem.BufferSlice{mem.SliceBuffer(received)}, response); err != nil {
		t.Fatal(err)
	}
	if got := string(response.GetPayload().GetData()); got != "s3cret" {
		t.Fatalf("got %q; the payload must be copied out before the buffer is zeroed", got)
	}
	if !hkdfguard.IsZero(received) {
		t.Error("the receive buffer wasn't zeroed")
	}
}

func TestTheScrubber_ZeroesEveryBuffer_OfAMessageReceivedInPieces(t *testing.T) {
	encoded := encodedResponse(t, []byte("a payload received across three buffers"))
	pieces := [][]byte{bytes.Clone(encoded[:7]), bytes.Clone(encoded[7:20]), bytes.Clone(encoded[20:])}
	data := mem.BufferSlice{mem.SliceBuffer(pieces[0]), mem.SliceBuffer(pieces[1]), mem.SliceBuffer(pieces[2])}
	response := &secretmanagerpb.AccessSecretVersionResponse{}

	if err := (receiveBufferScrubber{}).Unmarshal(data, response); err != nil {
		t.Fatal(err)
	}
	if got := string(response.GetPayload().GetData()); got != "a payload received across three buffers" {
		t.Fatalf("got %q", got)
	}
	for i, piece := range pieces {
		if !hkdfguard.IsZero(piece) {
			t.Errorf("buffer %d wasn't zeroed", i)
		}
	}
}

func TestTheScrubber_ZeroesTheBuffer_EvenWhenTheMessageDoesNotDecode(t *testing.T) {
	received := append(encodedResponse(t, []byte("s3cret")), 0xff) // a truncated field
	if err := (receiveBufferScrubber{}).Unmarshal(mem.BufferSlice{mem.SliceBuffer(received)}, &secretmanagerpb.AccessSecretVersionResponse{}); err == nil {
		t.Fatal("decoded a malformed message")
	}
	if !hkdfguard.IsZero(received) {
		t.Error("the receive buffer wasn't zeroed")
	}

	received = encodedResponse(t, []byte("s3cret"))
	if err := (receiveBufferScrubber{}).Unmarshal(mem.BufferSlice{mem.SliceBuffer(received)}, "not a message"); err == nil {
		t.Fatal("decoded into a string")
	}
	if !hkdfguard.IsZero(received) {
		t.Error("the receive buffer wasn't zeroed")
	}
}

func TestTheScrubber_EncodesRequestsAsTheProtoCodecDoes(t *testing.T) {
	codec := receiveBufferScrubber{}
	request := &secretmanagerpb.AccessSecretVersionRequest{Name: "projects/p/secrets/s/versions/latest"}
	data, err := codec.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &secretmanagerpb.AccessSecretVersionRequest{}
	if err := proto.Unmarshal(data.Materialize(), decoded); err != nil || !proto.Equal(decoded, request) {
		t.Fatalf("%v, %v", decoded, err)
	}
	if _, err := codec.Marshal("not a message"); err == nil {
		t.Error("encoded a string")
	}
}

// recordingPool is the client's gRPC buffer pool: it hands out fresh buffers, and records, as each
// comes back, whether it still holds the marker.
type recordingPool struct {
	marker []byte

	mu       sync.Mutex
	returned int
	holding  int
}

func (p *recordingPool) Get(length int) *[]byte {
	buffer := make([]byte, length)
	return &buffer
}

func (p *recordingPool) Put(buffer *[]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.returned++
	if bytes.Contains((*buffer)[:cap(*buffer)], p.marker) {
		p.holding++
	}
}

func (p *recordingPool) counts() (returned, holding int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.returned, p.holding
}

func markedSecret(length int) (secret string, marker []byte) {
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	marker = []byte("marker-" + hex.EncodeToString(random))
	return strings.Repeat(string(marker), length/len(marker)+1)[:length], marker
}

// Through the real gRPC client: a payload over 1 KiB is received into buffers from the pool, which
// gRPC returns uncleared - unless the cache's call option scrubs them. 4 KiB arrives in one frame,
// 40 KiB across several.
func TestOverGRPC_TheBuffersTheResponseWasReceivedInto_GoBackToThePoolZeroed(t *testing.T) {
	for _, length := range []int{4 * 1024, 40 * 1024} {
		fake := newFakeSecretManager().serve(t)
		secret, marker := markedSecret(length)
		fake.setString("item", secret)
		pool := &recordingPool{marker: marker}
		client := fake.client(t, option.WithGRPCDialOption(experimental.WithBufferPool(pool)))

		// Without the cache's codec, the secret goes back to the pool: the problem being solved.
		if _, err := client.AccessSecretVersion(t.Context(), &secretmanagerpb.AccessSecretVersionRequest{
			Name: "projects/" + testProjectID + "/secrets/item/versions/latest",
		}); err != nil {
			t.Fatal(err)
		}
		if returned, holding := pool.counts(); returned == 0 || holding == 0 {
			t.Fatalf("%d bytes: %d buffers returned, %d holding the secret; the test can't see the problem it checks for", length, returned, holding)
		}

		pool.mu.Lock()
		pool.returned, pool.holding = 0, 0
		pool.mu.Unlock()
		c := newCacheOver(t, client, Options{})
		if got := decryptString(t, c, "item"); got != secret {
			t.Fatalf("%d bytes: got %d bytes", length, len(got))
		}
		if returned, holding := pool.counts(); returned == 0 || holding != 0 {
			t.Errorf("%d bytes: %d buffers returned, %d still holding the secret; want none", length, returned, holding)
		}

		// Google's front end refuses application/grpc+proto: the codec must leave the content type be.
		fake.mu.Lock()
		contentTypes := fake.contentTypes
		fake.mu.Unlock()
		for _, contentType := range contentTypes {
			if contentType != "application/grpc" {
				t.Errorf("content type %q; want application/grpc", contentType)
			}
		}
	}
}
