package file_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/file"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

// ExampleWriteCache shows the streaming intermediate-cache writer.
// Concurrent calls against the same path are serialized internally so
// readers always observe a complete file.
func ExampleWriteCache() {
	dir, err := os.MkdirTemp("", "ghscan-example-*")
	if err != nil {
		fmt.Println("tempdir:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	cachePath := filepath.Join(dir, "cache.json")
	logger := clog.New(slog.Default().Handler())

	results := []ghscan.Result{
		{Repository: "octocat/Hello-World", LineData: "ioc seen at line 12"},
	}
	file.WriteCache(context.Background(), logger, cachePath, results)

	blob, err := os.ReadFile(cachePath) // #nosec G304 -- example with controlled path
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	var c ghscan.Cache
	if err := json.Unmarshal(blob, &c); err != nil {
		fmt.Println("unmarshal:", err)
		return
	}
	fmt.Println(len(c.Results), c.Results[0].LineData)
	// Output:
	// 1 ioc seen at line 12
}
