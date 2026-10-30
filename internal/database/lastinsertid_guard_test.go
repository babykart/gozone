package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoRawLastInsertIdInTestSeeds locks the dialect-matrix portability rule:
// test seeds must retrieve generated ids via DB.ExecReturnID (or the
// insertReturnID helper), never via sql.Result.LastInsertId — lib/pq does
// not implement it, so a raw call breaks every seed on the PostgreSQL matrix
// job (and silently yields id 0 where the error is ignored). Production code
// is exempt: database.ExecReturnID uses LastInsertId as the MySQL fallback
// behind the SupportsInsertReturning switch.
func TestNoRawLastInsertIdInTestSeeds(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The guard's own source contains the forbidden call as a string
		// literal — it can never be a seed.
		if filepath.Base(path) == "lastinsertid_guard_test.go" {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- path is constructed from the fixed root above
		if err != nil {
			return err
		}
		if strings.Contains(string(data), ".LastInsertId(") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(offenders) > 0 {
		t.Errorf("test seeds must use ExecReturnID, not sql.Result.LastInsertId (lib/pq does not implement it):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
