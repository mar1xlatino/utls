// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/refraction-networking/utls/testenv"
)

// Tests that the linker is able to remove references to the Client or Server if unused.
// This is an integration test that requires subprocess compilation.
func TestLinkerGC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode: requires subprocess compilation")
	}
	t.Parallel()
	goBin := testenv.GoToolPath(t)
	testenv.MustHaveGoBuild(t)

	tests := []struct {
		name    string
		program string
		want    []string
		bad     []string
	}{
		{
			name: "empty_import",
			program: `package main
import _ "crypto/tls"
func main() {}
`,
			bad: []string{
				"tls.(*Conn)",
				"type:crypto/tls.clientHandshakeState",
				"type:crypto/tls.serverHandshakeState",
			},
		},
		{
			name: "client_and_server",
			program: `package main
import "crypto/tls"
func main() {
  tls.Dial("", "", nil)
  tls.Server(nil, nil)
}
`,
			want: []string{
				"crypto/tls.(*Conn).clientHandshake",
				"crypto/tls.(*Conn).serverHandshake",
			},
		},
		{
			name: "only_client",
			program: `package main
import "crypto/tls"
func main() { tls.Dial("", "", nil) }
`,
			want: []string{
				"crypto/tls.(*Conn).clientHandshake",
			},
			bad: []string{
				"crypto/tls.(*Conn).serverHandshake",
			},
		},
		// TODO: add only_server like func main() { tls.Server(nil, nil) }
		// That currently brings in the client via Conn.handleRenegotiation.

	}
	for _, tt := range tests {
		tt := tt // capture range variable for parallel execution
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // run subtests in parallel for faster execution

			// Each subtest gets its own temp directory for parallel safety
			tmpDir := t.TempDir()
			goFile := filepath.Join(tmpDir, "x.go")
			exeFile := filepath.Join(tmpDir, "x.exe")

			if err := os.WriteFile(goFile, []byte(tt.program), 0644); err != nil {
				t.Fatal(err)
			}

			// Use optimized build flags:
			// -trimpath removes file system paths for reproducible builds and better cache hits
			// CGO_ENABLED=0 forces pure Go build which is faster
			// Note: cannot use -ldflags="-s -w" as we need symbols for nm inspection
			cmd := exec.Command(goBin, "build", "-trimpath", "-o", exeFile, goFile)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compile: %v, %s", err, out)
			}

			cmd = exec.Command(goBin, "tool", "nm", exeFile)
			nm, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nm: %v, %s", err, nm)
			}
			for _, sym := range tt.want {
				if !bytes.Contains(nm, []byte(sym)) {
					t.Errorf("expected symbol %q not found", sym)
				}
			}
			for _, sym := range tt.bad {
				if bytes.Contains(nm, []byte(sym)) {
					t.Errorf("unexpected symbol %q found", sym)
				}
			}
		})
	}
}
