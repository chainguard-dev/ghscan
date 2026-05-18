package httpclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"golang.org/x/time/rate"
)

// ExampleNew demonstrates the canonical Client construction and a
// single GET against a local httptest server. Production code points
// the Client at api.github.com; the example uses an httptest server
// so the doc snippet is hermetic and deterministic.
func ExampleNew() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	client := httpclient.New(
		httpclient.WithHTTPClient(&http.Client{
			Timeout:       2 * time.Second,
			Transport:     srv.Client().Transport,
			CheckRedirect: nil,
		}),
		httpclient.WithRateLimit(rate.Inf, 5),
	)

	body, resp, err := client.Get(context.Background(), srv.URL+"/users/octocat") //nolint:bodyclose // httpclient drains body and assigns http.NoBody.
	if err != nil {
		fmt.Println("get:", err)
		return
	}
	fmt.Println(resp.StatusCode, string(body))
	// Output:
	// 200 {"login":"octocat"}
}
