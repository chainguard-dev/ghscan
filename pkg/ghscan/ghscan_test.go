package ghscan_test

import (
	"encoding/json"
	"reflect"
	"testing"

	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/google/go-github/v86/github"
)

func TestResult_IsEmpty(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		r    ghscan.Result
		want bool
	}{
		{
			name: "empty result is empty",
			r:    ghscan.Result{Repository: "o/r"},
			want: true,
		},
		{
			name: "Base64Data only is non-empty",
			r:    ghscan.Result{Repository: "o/r", Base64Data: "x"},
			want: false,
		},
		{
			name: "DecodedData only is non-empty",
			r:    ghscan.Result{Repository: "o/r", DecodedData: "x"},
			want: false,
		},
		{
			name: "LineData only is non-empty",
			r:    ghscan.Result{Repository: "o/r", LineData: "x"},
			want: false,
		},
		{
			name: "all populated is non-empty",
			r:    ghscan.Result{Base64Data: "a", DecodedData: "b", LineData: "c"},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.r.IsEmpty(); got != tc.want {
				t.Fatalf("IsEmpty=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestResult_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	in := ghscan.Result{
		Repository:       "o/r",
		WorkflowFileName: "ci.yml",
		WorkflowURL:      "https://example.invalid/wf",
		WorkflowRunURL:   "https://example.invalid/run",
		Base64Data:       "ZGF0YQ==",
		DecodedData:      "data",
		LineData:         "ioc found here",
	}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ghscan.Result
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestCache_OmitemptyResults(t *testing.T) {
	t.Parallel()

	c := ghscan.Cache{}
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// `results` carries omitempty, so an empty cache must not embed
	// a `"results":[]` envelope.
	if got := string(blob); got != "{}" {
		t.Fatalf("empty cache json = %q, want {}", got)
	}
}

func TestResultsDirIsStable(t *testing.T) {
	t.Parallel()

	if ghscan.ResultsDir == "" {
		t.Fatal("ResultsDir must not be empty -- callers depend on it")
	}
}

// TestRequest_AccessorsReturnInjectedClients verifies the accessor
// methods are wired to the unexported fields populated by
// NewRequest. The accessors are the only supported way for consumers
// outside the package to reach the embedded clients.
func TestRequest_AccessorsReturnInjectedClients(t *testing.T) {
	t.Parallel()

	gh := github.NewClient(nil)
	hc := httpclient.New()

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Client:     gh,
		HTTPClient: hc,
	})

	if got := req.Client(); got != gh {
		t.Fatalf("Client() = %p, want %p", got, gh)
	}
	if got := req.HTTPClient(); got != hc {
		t.Fatalf("HTTPClient() = %p, want %p", got, hc)
	}
}

// TestRequest_NilSafeAccessors documents the zero-value contract: a
// freshly declared Request returns nil from both accessors instead of
// panicking, so test helpers and configuration code that build a
// Request progressively are not forced to populate every client up
// front.
func TestRequest_NilSafeAccessors(t *testing.T) {
	t.Parallel()

	var req ghscan.Request
	if got := req.Client(); got != nil {
		t.Fatalf("Client() = %v, want nil", got)
	}
	if got := req.HTTPClient(); got != nil {
		t.Fatalf("HTTPClient() = %v, want nil", got)
	}
}
