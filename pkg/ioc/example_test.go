package ioc_test

import (
	"fmt"

	"github.com/chainguard-dev/ghscan/pkg/ioc"
)

// ExampleNewMatcher demonstrates the primary matcher entry point: the
// caller supplies a literal IOC corpus, and Match returns one Hit per
// occurrence in the scanned log.
func ExampleNewMatcher() {
	m, err := ioc.NewMatcher([]string{"BAD_TOKEN"})
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	if m == nil {
		fmt.Println("nil matcher")
		return
	}

	log := []byte("normal log line\nfound BAD_TOKEN here\n")
	hits := m.Match(log)
	if len(hits) == 0 {
		fmt.Println("no hits")
		return
	}

	fmt.Println(len(hits), hits[0].IOC)
	// Output:
	// 1 BAD_TOKEN
}

// ExampleMatcher_MatchAnyString is the allocation-free yes/no path
// used by per-line scanners that already hold the line as a string.
func ExampleMatcher_MatchAnyString() {
	m, _ := ioc.NewMatcher([]string{"BAD_TOKEN"})
	if m == nil {
		fmt.Println("nil matcher")
		return
	}

	fmt.Println(m.MatchAnyString("nothing suspicious"))
	fmt.Println(m.MatchAnyString("contains BAD_TOKEN inline"))
	// Output:
	// false
	// true
}

// ExampleLoadEmbeddedCorpus demonstrates loading the corpus baked into
// the binary and turning a single entry into a scannable IOC.
func ExampleLoadEmbeddedCorpus() {
	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	entry := c.FindEntry("tj-actions/changed-files")
	if entry == nil {
		fmt.Println("missing")
		return
	}
	built, err := entry.BuildIOC()
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Println(built.GetMatcher().MatchAnyString("uses: tj-actions/changed-files@v36"))
	// Output: true
}
