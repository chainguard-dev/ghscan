package workflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/google/go-github/v86/github"
)

// workflowsDir is the only directory whose YAML files the YAML scanner
// will fetch. Anything outside this prefix is rejected before any
// network call so a malicious workflow path cannot be used to pivot
// reads to arbitrary repo content.
const workflowsDir = ".github/workflows"

// ListWorkflowFilePaths returns every .yml/.yaml file under
// .github/workflows for the given ref. A 404 from the contents API
// (directory does not exist) is normalized to an empty slice.
func ListWorkflowFilePaths(ctx context.Context, gh *github.Client, owner, repo, ref string) ([]string, error) {
	if gh == nil {
		return nil, fmt.Errorf("github client must not be nil")
	}
	opts := &github.RepositoryContentGetOptions{Ref: ref}
	_, dirContents, resp, err := gh.Repositories.GetContents(ctx, owner, repo, workflowsDir, opts)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return nil, nil
		}
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil &&
			(ghErr.Response.StatusCode == http.StatusNotFound || ghErr.Response.StatusCode == http.StatusGone) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing %s: %w", workflowsDir, err)
	}

	out := make([]string, 0, len(dirContents))
	for _, c := range dirContents {
		if c == nil || c.GetType() != "file" {
			continue
		}
		name := c.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, c.GetPath())
	}
	return out, nil
}

// FetchWorkflowYAML returns the raw YAML bytes for a single workflow
// file under .github/workflows. Paths outside that prefix are rejected
// before any network call. The returned bytes are capped at 1 MiB; a
// larger file is treated as pathological.
func FetchWorkflowYAML(ctx context.Context, gh *github.Client, owner, repo, wfPath, ref string) ([]byte, error) {
	body, _, err := FetchWorkflowYAMLWithSHA(ctx, gh, owner, repo, wfPath, ref)
	return body, err
}

// FetchWorkflowYAMLWithSHA mirrors [FetchWorkflowYAML] but also returns
// the blob SHA so callers can attribute findings back to the exact
// revision they were detected against.
func FetchWorkflowYAMLWithSHA(ctx context.Context, gh *github.Client, owner, repo, wfPath, ref string) ([]byte, string, error) {
	if gh == nil {
		return nil, "", fmt.Errorf("github client must not be nil")
	}
	if err := validateWorkflowPath(wfPath); err != nil {
		return nil, "", err
	}

	opts := &github.RepositoryContentGetOptions{Ref: ref}
	fileContent, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, wfPath, opts)
	if err != nil {
		return nil, "", fmt.Errorf("fetching %s: %w", wfPath, err)
	}
	if fileContent == nil {
		return nil, "", fmt.Errorf("fetching %s: API returned no file content", wfPath)
	}
	if size := fileContent.GetSize(); size > maxYAMLBytes {
		return nil, "", fmt.Errorf("workflow %s exceeds maximum size (%d > %d bytes)", wfPath, size, maxYAMLBytes)
	}

	body, err := fileContent.GetContent()
	if err != nil {
		return nil, "", fmt.Errorf("decoding %s: %w", wfPath, err)
	}
	if len(body) > maxYAMLBytes {
		return nil, "", fmt.Errorf("workflow %s exceeds maximum size (%d > %d bytes)", wfPath, len(body), maxYAMLBytes)
	}
	return []byte(body), fileContent.GetSHA(), nil
}

// validateWorkflowPath enforces that wfPath sits under .github/workflows
// and points at a yml/yaml file. Path cleaning collapses ../ segments
// so a malicious caller cannot escape the prefix.
func validateWorkflowPath(wfPath string) error {
	if wfPath == "" {
		return fmt.Errorf("workflow path must not be empty")
	}
	clean := path.Clean(wfPath)
	if clean != wfPath {
		return fmt.Errorf("workflow path %q is not in canonical form", wfPath)
	}
	if !strings.HasPrefix(clean, workflowsDir+"/") {
		return fmt.Errorf("workflow path %q is outside %s/", wfPath, workflowsDir)
	}
	if !strings.HasSuffix(clean, ".yml") && !strings.HasSuffix(clean, ".yaml") {
		return fmt.Errorf("workflow path %q is not a .yml or .yaml file", wfPath)
	}
	return nil
}
