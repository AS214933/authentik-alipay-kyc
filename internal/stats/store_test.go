package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistsCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.IncrementTotal(); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrementSuccess(); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrementFailure(); err != nil {
		t.Fatal(err)
	}

	got, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 || got.Success != 1 || got.Failure != 1 || got.UpdatedAt == "" {
		t.Fatalf("unexpected counters: %+v", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Counters
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != got {
		t.Fatalf("persisted counters = %+v, want %+v", persisted, got)
	}
}
