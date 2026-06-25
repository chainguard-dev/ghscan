package ghscan_test

import (
	"fmt"

	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

// ExampleResult_IsEmpty shows the canonical Result shape and how the
// IsEmpty helper distinguishes "no extracted data" findings (skipped
// in CSV output) from real hits.
func ExampleResult_IsEmpty() {
	hit := ghscan.Result{
		Repository:       "octocat/Hello-World",
		WorkflowFileName: "ci.yml",
		LineData:         "ioc found here",
	}
	empty := ghscan.Result{
		Repository: "octocat/Hello-World",
	}

	fmt.Println(hit.IsEmpty())
	fmt.Println(empty.IsEmpty())
	// Output:
	// false
	// true
}
