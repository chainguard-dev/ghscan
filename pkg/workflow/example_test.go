package workflow_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/chainguard-dev/ghscan/pkg/workflow"
)

// ExampleExtractLogs demonstrates decoding the zip archive that the
// GitHub run-logs API returns. Production callers pass the response
// body directly; the example builds an equivalent in-memory archive.
func ExampleExtractLogs() {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("0_job.txt")
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	if w == nil {
		fmt.Println("nil writer")
		return
	}
	_, _ = w.Write([]byte("step started\nstep finished\n"))
	_ = zw.Close()

	logs, err := workflow.ExtractLogs(bytes.NewReader(buf.Bytes()))
	if err != nil {
		fmt.Println("extract:", err)
		return
	}
	fmt.Println(strings.Contains(logs, "step started"))
	fmt.Println(strings.Contains(logs, "step finished"))
	// Output:
	// true
	// true
}

// ExampleParseLogs demonstrates the per-line IOC scan: a custom IOC
// is constructed, the log text is scanned, and the resulting Finding
// reports the matched line with timestamps stripped.
func ExampleParseLogs() {
	customIOC, _ := ioc.NewIOC(&ioc.Config{
		Name:    "demo",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	logger := clog.New(slog.Default().Handler())

	logText := "2025-01-01T00:00:00.000Z hello world\n" +
		"2025-01-01T00:00:01.000Z DROP_THIS_TOKEN was here\n"
	findings, ok := workflow.ParseLogs(logger, logText, 1, customIOC)
	if len(findings) == 0 {
		fmt.Println(ok, 0, false)
		return
	}
	fmt.Println(ok, len(findings), strings.Contains(findings[0].LineData, "DROP_THIS_TOKEN"))
	// Output:
	// true 1 true
}
