package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestResolveExitCode covers the binary's exit-code contract:
//
//	0 — clean run (no errors, zero findings)
//	2 — at least one IOC finding (no errors)
//	3 — any pipeline error, regardless of findings count
func TestResolveExitCode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		scanErr  error
		writeErr error
		findings int
		want     int
	}{
		{name: "clean run", findings: 0, want: exitClean},
		{name: "findings only", findings: 1, want: exitFindings},
		{name: "many findings", findings: 17, want: exitFindings},
		{name: "scan error supersedes findings", scanErr: errors.New("boom"), findings: 5, want: exitScanFailed},
		{name: "write error supersedes findings", writeErr: errors.New("disk full"), findings: 5, want: exitScanFailed},
		{name: "both errors", scanErr: errors.New("a"), writeErr: errors.New("b"), findings: 0, want: exitScanFailed},
		{name: "scan error alone, zero findings", scanErr: errors.New("boom"), want: exitScanFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveExitCode(tc.scanErr, tc.writeErr, tc.findings)
			if got != tc.want {
				t.Fatalf("resolveExitCode(%v, %v, %d) = %d, want %d",
					tc.scanErr, tc.writeErr, tc.findings, got, tc.want)
			}
		})
	}
}

// The main function in this package is a thin orchestration wrapper:
// flag parsing -> viper config -> oauth2 token source -> action.Scan
// -> file.WriteResults. Every constituent piece is covered by its
// package-level tests; the integration suite (build tag `integration`)
// in internal/action/integration_test.go covers main end-to-end.
//
// This file exercises setDefaults, the helper that seeds viper before
// ReadInConfig runs. The defaults must be sane on their own so a fresh
// checkout with no config.yaml does not blow up on
// time.ParseDuration("") or errgroup.SetLimit(0).

func TestSetDefaults_PopulatesMissingKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		key     string
		wantStr string
		wantInt int
	}{
		{name: "global_timeout falls back to 3h", key: "global_timeout", wantStr: "3h"},
		{name: "operation_timeout falls back to 30s", key: "operation_timeout", wantStr: "30s"},
		{name: "ioc name falls back to tj-actions", key: "ioc.name", wantStr: "tj-actions/changed-files"},
		{name: "max_retries falls back to 3", key: "max_retries", wantInt: 3},
		{name: "max_concurrency falls back to 32 to keep errgroup bounded", key: "max_concurrency", wantInt: 32},
		{name: "workflow_fetch_budget falls back to 60s", key: "workflow_fetch_budget", wantStr: "60s"},
		{name: "run_scan_budget falls back to 30s", key: "run_scan_budget", wantStr: "30s"},
		{name: "repo_enum_budget falls back to 150s", key: "repo_enum_budget", wantStr: "150s"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := viper.New()
			setDefaults(v)

			if tc.wantStr != "" {
				got := v.GetString(tc.key)
				if got != tc.wantStr {
					t.Fatalf("GetString(%q)=%q, want %q", tc.key, got, tc.wantStr)
				}
				return
			}
			got := v.GetInt(tc.key)
			if got != tc.wantInt {
				t.Fatalf("GetInt(%q)=%d, want %d", tc.key, got, tc.wantInt)
			}
		})
	}
}

// TestSetDefaults_DoesNotOverrideExplicitValues asserts the negative
// case: setDefaults must never overwrite a value the caller has
// already set via flag, env, or config file. This is the contract
// viper.SetDefault advertises but is worth pinning so a future refactor
// to viper.Set cannot silently regress.
func TestSetDefaults_DoesNotOverrideExplicitValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		key     string
		preset  any
		wantStr string
		wantInt int
	}{
		{name: "explicit global_timeout wins", key: "global_timeout", preset: "1h", wantStr: "1h"},
		{name: "explicit max_retries wins", key: "max_retries", preset: 7, wantInt: 7},
		{name: "explicit max_concurrency wins", key: "max_concurrency", preset: 64, wantInt: 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := viper.New()
			v.Set(tc.key, tc.preset)
			setDefaults(v)

			if tc.wantStr != "" {
				if got := v.GetString(tc.key); got != tc.wantStr {
					t.Fatalf("GetString(%q)=%q, want %q", tc.key, got, tc.wantStr)
				}
				return
			}
			if got := v.GetInt(tc.key); got != tc.wantInt {
				t.Fatalf("GetInt(%q)=%d, want %d", tc.key, got, tc.wantInt)
			}
		})
	}
}

// TestSetDefaults_ScanFlagsDefaultTrue asserts both scan paths are on
// by default so existing users observe no behavior change.
func TestSetDefaults_ScanFlagsDefaultTrue(t *testing.T) {
	t.Parallel()
	v := viper.New()
	setDefaults(v)
	if !v.GetBool("scan_yaml") {
		t.Fatal("scan_yaml default=false, want true")
	}
	if !v.GetBool("scan_logs") {
		t.Fatal("scan_logs default=false, want true")
	}
}

// TestSetDefaults_IocFile asserts the ioc_file key exists and defaults
// to empty so the binary falls back to the embedded corpus when no
// override is supplied.
func TestSetDefaults_IocFile(t *testing.T) {
	t.Parallel()
	v := viper.New()
	setDefaults(v)
	if got := v.GetString("ioc_file"); got != "" {
		t.Fatalf("ioc_file default=%q, want empty", got)
	}
	if !v.IsSet("ioc_file") {
		t.Fatal("ioc_file should be registered as a viper key")
	}
}

// TestSetDefaults_GlobalTimeoutParsesAsDuration ties the default
// straight to the consumer's parse step. main calls
// time.ParseDuration(viper.GetString("global_timeout")) and dies on
// error, so the default literal must round-trip cleanly.
func TestSetDefaults_GlobalTimeoutParsesAsDuration(t *testing.T) {
	t.Parallel()

	v := viper.New()
	setDefaults(v)

	for _, key := range []string{
		"global_timeout",
		"operation_timeout",
		"workflow_fetch_budget",
		"run_scan_budget",
		"repo_enum_budget",
	} {
		s := v.GetString(key)
		if s == "" {
			t.Fatalf("%s default is empty; time.ParseDuration would fail", key)
		}
		if _, err := time.ParseDuration(s); err != nil {
			t.Fatalf("time.ParseDuration(%q for %s): %v", s, key, err)
		}
	}
}

// TestResolveGitHubToken_ExplicitValueWins asserts that when viper
// already holds a non-empty token (env, flag, or config), the helper
// returns it verbatim and does not shell out to gh.
func TestResolveGitHubToken_ExplicitValueWins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake gh shim is a unix shell script")
	}
	// Point PATH at a temp dir with a gh that would FAIL the test if
	// invoked; the helper must not invoke it when viper has a value.
	dir := t.TempDir()
	ghPath := filepath.Join(dir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\necho FAKE_GH_INVOKED\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", dir)

	v := viper.New()
	v.Set("token", "ghp_explicit_value")

	got, err := resolveGitHubToken(context.Background(), v)
	if err != nil {
		t.Fatalf("resolveGitHubToken: %v", err)
	}
	if got != "ghp_explicit_value" {
		t.Fatalf("token=%q, want ghp_explicit_value", got)
	}
}

// TestResolveGitHubToken_FallsBackToGhAuthToken asserts that when viper
// is empty, the helper invokes gh and returns its trimmed stdout.
func TestResolveGitHubToken_FallsBackToGhAuthToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake gh shim is a unix shell script")
	}
	const sentinel = "ghp_from_gh_cli"
	dir := t.TempDir()
	ghPath := filepath.Join(dir, "gh")
	// Trailing newline must be trimmed by the helper.
	script := "#!/bin/sh\nprintf '" + sentinel + "\\n'\n"
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", dir)

	v := viper.New()
	v.Set("token", "")

	got, err := resolveGitHubToken(context.Background(), v)
	if err != nil {
		t.Fatalf("resolveGitHubToken: %v", err)
	}
	if got != sentinel {
		t.Fatalf("token=%q, want %q", got, sentinel)
	}
}

// TestResolveGitHubToken_GhFailureWraps asserts that when gh exits
// non-zero, the helper returns a wrapped error and does not panic.
func TestResolveGitHubToken_GhFailureWraps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake gh shim is a unix shell script")
	}
	dir := t.TempDir()
	ghPath := filepath.Join(dir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", dir)

	v := viper.New()
	v.Set("token", "")

	got, err := resolveGitHubToken(context.Background(), v)
	if err == nil {
		t.Fatalf("expected error when gh fails, got token=%q", got)
	}
	if got != "" {
		t.Fatalf("token=%q, want empty on failure", got)
	}
	if !strings.Contains(err.Error(), "gh auth token") {
		t.Fatalf("error %q does not mention gh auth token", err.Error())
	}
}

// TestResolveGitHubToken_GhMissingWraps asserts that when gh is not on
// PATH, the helper returns a wrapped error mentioning the failure.
func TestResolveGitHubToken_GhMissingWraps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake gh shim is a unix shell script")
	}
	// Empty PATH guarantees gh cannot be found.
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	v := viper.New()
	v.Set("token", "")

	got, err := resolveGitHubToken(context.Background(), v)
	if err == nil {
		t.Fatalf("expected error when gh is missing, got token=%q", got)
	}
	if got != "" {
		t.Fatalf("token=%q, want empty on missing gh", got)
	}
	if !strings.Contains(err.Error(), "gh auth token") {
		t.Fatalf("error %q does not mention gh auth token", err.Error())
	}
}
