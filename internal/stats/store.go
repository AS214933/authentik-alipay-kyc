package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Counters struct {
	Total     int64  `json:"total"`
	Success   int64  `json:"success"`
	Failure   int64  `json:"failure"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("stats file path is required")
	}
	store := &Store{path: path}
	if _, err := store.Snapshot(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Snapshot() (Counters, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked()
}

func (s *Store) IncrementTotal() error {
	return s.increment(func(c *Counters) {
		c.Total++
	})
}

func (s *Store) IncrementSuccess() error {
	return s.increment(func(c *Counters) {
		c.Success++
	})
}

func (s *Store) IncrementFailure() error {
	return s.increment(func(c *Counters) {
		c.Failure++
	})
}

func (s *Store) increment(update func(*Counters)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	counters, err := s.readLocked()
	if err != nil {
		return err
	}
	update(&counters)
	counters.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return s.writeLocked(counters)
}

func (s *Store) readLocked() (Counters, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			counters := Counters{}
			return counters, s.writeLocked(counters)
		}
		return Counters{}, fmt.Errorf("read stats file: %w", err)
	}
	if len(data) == 0 {
		return Counters{}, nil
	}
	var counters Counters
	if err := json.Unmarshal(data, &counters); err != nil {
		return Counters{}, fmt.Errorf("decode stats file: %w", err)
	}
	return counters, nil
}

func (s *Store) writeLocked(counters Counters) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create stats directory: %w", err)
	}
	data, err := json.MarshalIndent(counters, "", "  ")
	if err != nil {
		return fmt.Errorf("encode stats file: %w", err)
	}
	data = append(data, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write stats temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace stats file: %w", err)
	}
	return nil
}
