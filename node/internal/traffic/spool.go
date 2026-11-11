// SPDX-License-Identifier: MPL-2.0
//
// Ported from cedar2025/Xboard-Node, patches/xboard-node-v1.13/0002-reliable-traffic.patch
// (internal/controlplane/nanmonee_spool.go). The algorithm is unchanged: immutable
// batches, an atomic single-file checkpoint, and ownership transferred only after
// a successful rename.

package traffic

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"nanmonee/node/internal/panel"
)

// maxSpoolBytes bounds the checkpoint file. A full spool keeps its pending
// batches and refuses new samples instead of dropping either.
const maxSpoolBytes = 8 << 20

var (
	// ErrSpoolFull means the checkpoint cannot grow; pending batches are retained.
	ErrSpoolFull = errors.New("traffic spool full; pending batches retained")
	// ErrSampleInvalid means the sample cannot be described faithfully on the wire.
	ErrSampleInvalid = errors.New("measured traffic cannot be reported")
)

// batchSize is the panel's per-report member limit.
const batchSize = panel.MaxBatchEntries

// ReportError distinguishes traffic already owned by the on-disk spool from
// traffic that is still only in memory.
type ReportError struct {
	Err       error
	Persisted bool
}

func (e *ReportError) Error() string { return e.Err.Error() }
func (e *ReportError) Unwrap() error { return e.Err }

// Persisted reports whether the spool owns the traffic described by err.
func Persisted(err error) bool {
	var report *ReportError
	return errors.As(err, &report) && report.Persisted
}

type spoolState struct {
	Version   int                  `json:"version"`
	Identity  string               `json:"identity"`
	RuntimeID string               `json:"runtime_id"`
	SampledTo int64                `json:"sampled_to"`
	Cursor    map[int][2]int64     `json:"cursor"`
	Pending   []panel.TrafficBatch `json:"pending"`
}

// Spool is the durable owner of reported traffic for one node identity.
type Spool struct {
	mu      sync.Mutex
	drainMu sync.Mutex
	dir     string
	lock    *os.File
	state   spoolState
	syncDir func() error
}

// Open locks and loads the spool for identity under base.
func Open(base, identity, runtimeID string) (*Spool, error) {
	if base == "" {
		return nil, errors.New("the traffic spool requires a data directory")
	}
	if identity == "" || runtimeID == "" {
		return nil, errors.New("the traffic spool requires an identity and runtime ID")
	}
	hash := sha256.Sum256([]byte(identity))
	dir := filepath.Join(base, "nanmonee-traffic-v1", hex.EncodeToString(hash[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create traffic spool: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open traffic spool lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("traffic spool already in use: %w", err)
	}
	spool := &Spool{
		dir:  dir,
		lock: lock,
		state: spoolState{
			Version:   1,
			Identity:  identity,
			RuntimeID: runtimeID,
			SampledTo: time.Now().Unix(),
			Cursor:    map[int][2]int64{},
		},
	}
	spool.syncDir = func() error {
		handle, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer handle.Close()
		return handle.Sync()
	}
	if err := spool.load(identity); err != nil {
		spool.closeFiles()
		return nil, err
	}
	return spool, nil
}

func (s *Spool) load(identity string) error {
	data, err := os.ReadFile(filepath.Join(s.dir, "pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		_, err = s.save(s.state)
		return err
	}
	if err != nil {
		return fmt.Errorf("read traffic spool: %w", err)
	}
	if len(data) > maxSpoolBytes {
		return errors.New("traffic spool exceeds the size limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("parse traffic spool: %w", err)
	}
	for _, field := range []string{"version", "identity", "runtime_id", "sampled_to", "cursor", "pending"} {
		if _, present := fields[field]; !present {
			return errors.New("traffic spool checkpoint is incomplete")
		}
	}
	var state spoolState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse traffic spool: %w", err)
	}
	if state.Version != 1 || state.Identity != identity {
		return errors.New("traffic spool identity or version mismatch")
	}
	if state.SampledTo < 0 || state.SampledTo > 253402300799 || state.RuntimeID == "" || state.Cursor == nil {
		return errors.New("traffic spool checkpoint is invalid or incomplete")
	}
	for memberID, pair := range state.Cursor {
		if memberID <= 0 || pair[0] < 0 || pair[1] < 0 {
			return errors.New("traffic spool checkpoint has invalid counters")
		}
	}
	seen := make(map[string]bool, len(state.Pending))
	for _, batch := range state.Pending {
		if err := validateBatch(batch); err != nil {
			return err
		}
		if seen[batch.BatchID] {
			return errors.New("duplicate batch in traffic spool")
		}
		seen[batch.BatchID] = true
	}
	s.state = state
	// A previous process owns those counters. Never subtract its checkpoint from
	// ours, or the first sample after a restart would replay its whole history.
	s.state.Cursor = map[int][2]int64{}
	s.state.RuntimeID = ""
	return nil
}

// Close releases the single-writer lock. The checkpoint stays on disk.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *Spool) closeFiles() {
	if s.lock != nil {
		_ = s.lock.Close()
		s.lock = nil
	}
}

// Pending returns how many batches are waiting for confirmation.
func (s *Spool) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.state.Pending)
}

// Total returns the total pending members across all batches.
func (s *Spool) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, batch := range s.state.Pending {
		total += len(batch.Traffic)
	}
	return total
}

// save returns ownership after the rename, even when the directory fsync after
// it fails. That is the crash-safe ordering: the new checkpoint is already
// visible, so the traffic it describes must not be re-queued.
func (s *Spool) save(state spoolState) (bool, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	if len(data) > maxSpoolBytes {
		return false, ErrSpoolFull
	}
	file, err := os.CreateTemp(s.dir, ".pending-")
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	if err := os.Rename(file.Name(), filepath.Join(s.dir, "pending.json")); err != nil {
		return false, err
	}
	return true, s.syncDir()
}

// Report takes ownership of a fresh sample and then tries to drain the queue.
//
// measured must be the process-lifetime counters for runtimeID. The caller keeps
// ownership of the sample only when Persisted(err) is false, in which case the
// same delta must be offered again on the next call.
func (s *Spool) Report(measured map[int][2]int64, runtimeID string, send func(panel.TrafficBatch) error) error {
	err := s.Sample(measured, runtimeID)
	switch {
	case err == nil:
		// The sample is durable; draining is best effort.
	case errors.Is(err, ErrSampleInvalid):
		return &ReportError{Err: err}
	default:
		persistErr := fmt.Errorf("persist traffic: %w", err)
		if errors.Is(err, ErrSpoolFull) {
			// Free capacity using sealed batches; the caller still owns the sample.
			if drainErr := s.drain(send); drainErr != nil {
				persistErr = errors.Join(persistErr, fmt.Errorf("drain pending: %w", drainErr))
			} else {
				// Seal the waiting sample before returning, including at shutdown.
				return s.Sample(measured, runtimeID)
			}
		}
		return &ReportError{Err: persistErr, Persisted: Persisted(err)}
	}
	if drainErr := s.drain(send); drainErr != nil {
		return &ReportError{Err: drainErr, Persisted: true}
	}
	return nil
}

// Sample persists counters without sending; the worker reports on a separate tick.
func (s *Spool) Sample(measured map[int][2]int64, runtimeID string) error {
	committed, err := s.record(measured, runtimeID)
	if err != nil {
		return &ReportError{Err: err, Persisted: committed}
	}
	return nil
}

// record seals one sample into the checkpoint and releases the lock before any
// network work. The panel round trip must never hold s.mu: status queries read
// the same lock, so a slow panel would otherwise make the control plane look
// hung exactly when an operator is investigating the outage.
func (s *Spool) record(measured map[int][2]int64, runtimeID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.state
	state.Pending = append([]panel.TrafficBatch(nil), state.Pending...)

	// A different runtime means a different counter origin: reset the baseline
	// instead of computing a negative delta against the previous process.
	if state.RuntimeID != runtimeID {
		state.RuntimeID = runtimeID
		state.Cursor = map[int][2]int64{}
	}
	if state.Cursor == nil {
		state.Cursor = map[int][2]int64{}
	}

	deltas := make(map[int][2]int64, len(measured))
	nextCursor := make(map[int][2]int64, len(measured))
	ids := make([]int, 0, len(measured))
	for memberID, counters := range measured {
		if memberID <= 0 || counters[0] < 0 || counters[1] < 0 {
			return false, fmt.Errorf("%w: invalid counters for member %d", ErrSampleInvalid, memberID)
		}
		previous := state.Cursor[memberID]
		delta := [2]int64{counters[0] - previous[0], counters[1] - previous[1]}
		if delta[0] < 0 || delta[1] < 0 {
			// Counters never decrease within one runtime; treat it as a fault
			// rather than silently reporting a negative amount.
			return false, fmt.Errorf("%w: counters regressed for member %d", ErrSampleInvalid, memberID)
		}
		nextCursor[memberID] = counters
		if delta[0] > 0 || delta[1] > 0 {
			deltas[memberID] = delta
			ids = append(ids, memberID)
		}
	}
	// Members that vanished from the snapshot keep their cursor: they may return
	// after a reconnect, and their counters continue where they left off.
	for memberID, counters := range state.Cursor {
		if _, present := nextCursor[memberID]; !present {
			nextCursor[memberID] = counters
		}
	}

	sort.Ints(ids)
	end := max(time.Now().Unix(), state.SampledTo)
	for offset := 0; offset < len(ids); offset += batchSize {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return false, err
		}
		batch := panel.TrafficBatch{
			Protocol:    panel.TrafficProtocol,
			BatchID:     hex.EncodeToString(random[:]),
			SampledFrom: state.SampledTo,
			SampledTo:   end,
			Traffic:     make(map[int][2]int64),
		}
		for _, memberID := range ids[offset:min(offset+batchSize, len(ids))] {
			batch.Traffic[memberID] = deltas[memberID]
		}
		state.Pending = append(state.Pending, batch)
	}
	state.SampledTo = end
	state.Cursor = nextCursor

	committed, err := s.save(state)
	if committed {
		// Even when the directory fsync failed, the rename already published this
		// checkpoint; keeping it prevents a second batch for the same bytes.
		s.state = state
	}
	return committed, err
}

// drain sends sealed batches oldest first. One cycle is bounded so a slow panel
// cannot stall sampling; the next tick continues with the same IDs.
//
// The state lock is only held around bookkeeping, never across send: a batch is
// confirmed on the panel first and removed from disk afterwards, so a crash in
// between replays the same batch_id, which the panel already treats as idempotent.
func (s *Spool) drain(send func(panel.TrafficBatch) error) error {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()

	for count := 0; count < 16; count++ {
		s.mu.Lock()
		if len(s.state.Pending) == 0 {
			s.mu.Unlock()
			return nil
		}
		batch := s.state.Pending[0]
		s.mu.Unlock()

		if err := send(batch); err != nil {
			// A permanently rejected batch would otherwise stay at the head of the
			// queue forever and stop every later batch, so it is dropped once and
			// reported loudly; other failures keep the batch for a retry.
			if !errors.Is(err, panel.ErrBatchRejected) {
				return err
			}
			log.Printf("dropping traffic batch %s after the panel refused it permanently: %v", batch.BatchID, err)
		}

		s.mu.Lock()
		state := s.state
		if len(state.Pending) == 0 || state.Pending[0].BatchID != batch.BatchID {
			// Already confirmed elsewhere; never remove a different batch.
			s.mu.Unlock()
			return nil
		}
		state.Pending = append([]panel.TrafficBatch(nil), state.Pending[1:]...)
		committed, err := s.save(state)
		if committed {
			s.state = state
		}
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("persist confirmation: %w", err)
		}
	}
	return nil
}

func validateBatch(batch panel.TrafficBatch) error {
	id, err := hex.DecodeString(batch.BatchID)
	if err != nil || len(id) != 16 || batch.BatchID != hex.EncodeToString(id) {
		return errors.New("invalid traffic batch ID")
	}
	if batch.Protocol != panel.TrafficProtocol || batch.SampledFrom < 0 || batch.SampledTo < batch.SampledFrom || batch.SampledTo > 253402300799 {
		return errors.New("invalid traffic batch metadata")
	}
	if len(batch.Traffic) == 0 || len(batch.Traffic) > batchSize {
		return errors.New("invalid traffic batch size")
	}
	for memberID, pair := range batch.Traffic {
		if memberID <= 0 || pair[0] < 0 || pair[1] < 0 || (pair[0] == 0 && pair[1] == 0) {
			return errors.New("invalid traffic batch counters")
		}
	}
	return nil
}
