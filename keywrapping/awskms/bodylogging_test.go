package awskms

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// optionsRecorder is a fakeKMS that applies each call's options to a client logging everything, and
// records the log mode the call would have run with.
type optionsRecorder struct {
	*fakeKMS
	modes []aws.ClientLogMode
}

const logEverything = aws.LogRequestWithBody | aws.LogResponseWithBody | aws.LogRetries

func (r *optionsRecorder) record(optFns []func(*kms.Options)) {
	options := kms.Options{ClientLogMode: logEverything}
	for _, fn := range optFns {
		fn(&options)
	}
	r.modes = append(r.modes, options.ClientLogMode)
}

func (r *optionsRecorder) Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	r.record(optFns)
	return r.fakeKMS.Encrypt(ctx, in)
}

func (r *optionsRecorder) Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	r.record(optFns)
	return r.fakeKMS.Decrypt(ctx, in)
}

func (r *optionsRecorder) GenerateDataKeyWithoutPlaintext(ctx context.Context, in *kms.GenerateDataKeyWithoutPlaintextInput,
	optFns ...func(*kms.Options)) (*kms.GenerateDataKeyWithoutPlaintextOutput, error) {
	r.record(optFns)
	return r.fakeKMS.GenerateDataKeyWithoutPlaintext(ctx, in)
}

func TestEveryCall_TurnsBodyLoggingOff_UnlessSensitiveLoggingIsOn(t *testing.T) {
	original := diagnostics.KeyWrapping.SensitiveLoggingEnabled()
	t.Cleanup(func() { diagnostics.KeyWrapping.SetSensitiveLogging(original) })

	for _, sensitive := range []bool{false, true} {
		diagnostics.KeyWrapping.SetSensitiveLogging(sensitive)
		recorder := &optionsRecorder{fakeKMS: newFakeKMS(t)}
		wrapper := newWrapper(t, recorder)

		wrapped := make([]byte, 1024)
		n, err := wrapper.Wrap(t.Context(), random(32), wrapped)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wrapper.Unwrap(t.Context(), wrapped[:n], make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := wrapper.GenerateAndWrap(t.Context(), make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}

		if len(recorder.modes) != 3 {
			t.Fatalf("sensitive=%v: %d calls recorded", sensitive, len(recorder.modes))
		}
		want := logEverything
		if !sensitive {
			want = aws.LogRetries // every other mode the client chose is kept
		}
		for i, mode := range recorder.modes {
			if mode != want {
				t.Errorf("sensitive=%v: call %d ran with log mode %b; want %b", sensitive, i, mode, want)
			}
		}
	}
}
