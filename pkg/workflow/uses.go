package workflow

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxYAMLBytes caps any workflow YAML accepted by the parser. A workflow
// file larger than 1 MiB is pathological and likely a denial-of-service
// attempt rather than a real GHA definition.
const maxYAMLBytes = 1 << 20

// UsesEdge represents a single uses: occurrence in a workflow file.
// Each edge captures the verbatim coordinate, parsed action+ref, the
// classified ref form, source location, and any secrets reachable
// from the step (or job, for reusable workflow calls).
type UsesEdge struct {
	Uses       string
	Action     string
	Ref        string
	RefForm    string
	JobName    string
	StepName   string
	LineNumber int
	Secrets    []string
}

var (
	hex40RE     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	hex7RE      = regexp.MustCompile(`^[0-9a-fA-F]{7}$`)
	semverRE    = regexp.MustCompile(`^v?\d+(\.\d+){0,2}([-+][A-Za-z0-9.\-]+)?$`)
	secretRefRE = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
)

// ClassifyRef returns the ref-form label for ref: "commit-sha" for a
// 40-char hex string, "short-sha" for a 7-char hex string, "tag" for a
// v-prefixed or numeric semver-like form, "branch" for anything else,
// and "unspecified" when ref is empty.
func ClassifyRef(ref string) string {
	if ref == "" {
		return "unspecified"
	}
	if hex40RE.MatchString(ref) {
		return "commit-sha"
	}
	if hex7RE.MatchString(ref) {
		return "short-sha"
	}
	if semverRE.MatchString(ref) {
		return "tag"
	}
	return "branch"
}

// ParseUsesEdges walks a workflow YAML document and returns every
// uses: edge it contains. It handles step-level uses (action calls)
// and job-level uses (reusable workflow calls). The parser uses
// yaml.v3's Node API so each edge carries its source line for
// downstream attribution. Input larger than 1 MiB is rejected.
func ParseUsesEdges(data []byte) ([]UsesEdge, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) > maxYAMLBytes {
		return nil, fmt.Errorf("workflow YAML exceeds maximum size (%d > %d bytes)", len(data), maxYAMLBytes)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing workflow YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, nil
	}

	jobs := mappingValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}

	var edges []UsesEdge
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobKey := jobs.Content[i]
		jobVal := jobs.Content[i+1]
		if jobVal.Kind != yaml.MappingNode {
			continue
		}
		jobName := jobKey.Value

		jobEnvSecrets := collectSecretsFromNode(mappingValue(jobVal, "env"))

		if jobUses := mappingValue(jobVal, "uses"); jobUses != nil && jobUses.Kind == yaml.ScalarNode {
			edges = append(edges, buildEdge(jobUses.Value, jobName, "", jobUses.Line, jobEnvSecrets))
		}

		steps := mappingValue(jobVal, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			usesNode := mappingValue(step, "uses")
			if usesNode == nil || usesNode.Kind != yaml.ScalarNode {
				continue
			}
			stepName := ""
			if n := mappingValue(step, "name"); n != nil && n.Kind == yaml.ScalarNode {
				stepName = n.Value
			}

			secrets := dedupSecrets(
				jobEnvSecrets,
				collectSecretsFromNode(mappingValue(step, "env")),
				collectSecretsFromNode(mappingValue(step, "with")),
			)
			edges = append(edges, buildEdge(usesNode.Value, jobName, stepName, usesNode.Line, secrets))
		}
	}

	return edges, nil
}

func buildEdge(usesRaw, jobName, stepName string, line int, secrets []string) UsesEdge {
	uses := strings.TrimSpace(usesRaw)
	action, ref := splitUses(uses)
	return UsesEdge{
		Uses:       uses,
		Action:     action,
		Ref:        ref,
		RefForm:    ClassifyRef(ref),
		JobName:    jobName,
		StepName:   stepName,
		LineNumber: line,
		Secrets:    secrets,
	}
}

// splitUses parses a uses: value into (action, ref). The verbatim value
// from yaml.v3 already has surrounding quotes stripped and inline
// comments excluded; we only need to handle the @ split and any
// stray trailing whitespace.
func splitUses(s string) (string, string) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s, ""
	}
	return s[:at], s[at+1:]
}

// mappingValue returns the value node for key inside a mapping node, or
// nil when the key is absent or the parent is not a mapping.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// collectSecretsFromNode walks a scalar/sequence/mapping node and
// returns every secrets.NAME reference it carries. The walk is shallow
// for sequences (we look at scalar leaves) but recurses through
// mappings so env: NAME: ${{ secrets.X }} works.
func collectSecretsFromNode(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil {
			return
		}
		switch node.Kind {
		case yaml.ScalarNode:
			for _, m := range secretRefRE.FindAllStringSubmatch(node.Value, -1) {
				if len(m) > 1 {
					out = append(out, m[1])
				}
			}
		case yaml.SequenceNode, yaml.MappingNode, yaml.DocumentNode:
			for _, c := range node.Content {
				walk(c)
			}
		case yaml.AliasNode:
			// aliases would induce billion-laughs cycles; skip.
		}
	}
	walk(n)
	return dedupSecrets(out)
}

// dedupSecrets merges every input slice into a single deduped list,
// preserving first-seen order so test assertions remain deterministic.
func dedupSecrets(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
