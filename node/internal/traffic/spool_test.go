// SPDX-License-Identifier: MPL-2.0

package traffic

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"nanmonee/node/internal/panel"
)

const testIdentity = "https://panel.example.com|7|vless"

func openTest(t *testing.T, dir, runtimeID string) *Spool {
	t.Helper()
	spool, err := Open(dir, testIdentity, runtimeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

func TestBatchesStayImmutableAcrossConfirmationFailuresAndRestart(t *testing.T) {
	dir := t.TempDir()
	spool := openTest(t, dir, "rt-1")

	var attempts []panel.TrafficBatch
	send := func(batch panel.TrafficBatch) error {
		attempts = append(attempts, batch)
		return errors.New("confirmation lost")
	}
	if err := spool.Report(map[int][2]int64{2: {7, 9}}, "rt-1", send); !Persisted(err) {
		t.Fatalf("traffic was not owned after persist: %v", err)
	}
	first := spool.state.Pending[0]
	if err := spool.Report(map[int][2]int64{2: {11, 13}}, "rt-1", send); !Persisted(err) {
		t.Fatal(err)
	}
	if len(spool.state.Pending) != 2 {
		t.Fatalf("expected two pending batches, got %d", len(spool.state.Pending))
	}
	if !reflect.DeepEqual(first, spool.state.Pending[0]) || first.BatchID == spool.state.Pending[1].BatchID {
		t.Fatal("retry mutated or merged a sealed batch")
	}
	if spool.state.Pending[1].Traffic[2] != [2]int64{4, 4} {
		t.Fatalf("delta was not computed against the checkpoint: %+v", spool.state.Pending[1].Traffic)
	}

	info, err := os.Stat(filepath.Join(spool.dir, "pending.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint is not private: %v", err)
	}
	_ = spool.Close()

	reopened := openTest(t, dir, "rt-2")
	var replayed []panel.TrafficBatch
	if err := reopened.Report(nil, "rt-2", func(batch panel.TrafficBatch) error {
		replayed = append(replayed, batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 2 || !reflect.DeepEqual(replayed[0], first) {
		t.Fatalf("restart did not replay the original batches: %+v", replayed)
	}
	if reopened.Pending() != 0 {
		t.Fatal("acknowledged batches were retained")
	}
}

func TestPersistenceFailureKeepsCallerOwnershipAndSendsNothing(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	original := spool.dir
	if err := os.Rename(original, original+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(original)
		_ = os.Rename(original+"-saved", original)
	})

	sent := false
	err := spool.Report(map[int][2]int64{1: {7, 9}}, "rt-1", func(panel.TrafficBatch) error {
		sent = true
		return nil
	})
	if err == nil || Persisted(err) || sent || len(spool.state.Pending) != 0 {
		t.Fatalf("failed persistence lost ownership: %v", err)
	}
}

func TestDirectorySyncFailureAfterRenameKeepsTheSameIDWithoutSending(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	original := spool.syncDir
	spool.syncDir = func() error { return errors.New("sync failed") }

	sent := false
	err := spool.Report(map[int][2]int64{1: {7, 9}}, "rt-1", func(panel.TrafficBatch) error {
		sent = true
		return nil
	})
	if err == nil || !Persisted(err) || sent || len(spool.state.Pending) != 1 {
		t.Fatalf("ambiguous rename was not retained: %v", err)
	}
	identifier := spool.state.Pending[0].BatchID
	spool.syncDir = original
	if err := spool.Report(nil, "rt-1", func(batch panel.TrafficBatch) error {
		if batch.BatchID != identifier {
			t.Fatal("batch ID changed on retry")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedConfirmationPersistRetriesTheSameID(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	original := spool.dir
	var accepted string
	err := spool.Report(map[int][2]int64{1: {7, 9}}, "rt-1", func(batch panel.TrafficBatch) error {
		accepted = batch.BatchID
		if err := os.Rename(original, original+"-saved"); err != nil {
			t.Fatal(err)
		}
		return os.WriteFile(original, []byte("blocked"), 0o600)
	})
	if err == nil || !Persisted(err) || len(spool.state.Pending) != 1 {
		t.Fatalf("confirmation write failure dropped the batch: %v", err)
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original+"-saved", original); err != nil {
		t.Fatal(err)
	}
	if err := spool.Report(nil, "rt-1", func(batch panel.TrafficBatch) error {
		if batch.BatchID != accepted {
			t.Fatal("acknowledged batch changed identity on retry")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPermanentlyRejectedBatchIsDroppedAndTheQueueKeepsDraining(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	var first string
	if err := spool.Report(map[int][2]int64{1: {7, 9}}, "rt-1", func(batch panel.TrafficBatch) error {
		first = batch.BatchID
		return errors.New("confirmation lost")
	}); !Persisted(err) {
		t.Fatal(err)
	}
	var sent []string
	if err := spool.Report(map[int][2]int64{1: {20, 30}}, "rt-1", func(batch panel.TrafficBatch) error {
		sent = append(sent, batch.BatchID)
		if batch.BatchID == first {
			return &panel.BatchRejectedError{StatusCode: 409}
		}
		return nil
	}); err != nil {
		t.Fatalf("a permanently rejected batch stopped the queue: %v", err)
	}
	if len(sent) != 2 || sent[0] != first || spool.Pending() != 0 {
		t.Fatalf("the rejected batch was not dropped behind the queue: sent=%v pending=%d", sent, spool.Pending())
	}
}

func TestCorruptionIsRejectedWithoutDeletingIt(t *testing.T) {
	dir := t.TempDir()
	spool := openTest(t, dir, "rt-1")
	path := filepath.Join(spool.dir, "pending.json")
	_ = spool.Close()

	broken := []byte(`{"version":1,"identity":"wrong"}`)
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir, testIdentity, "rt-1"); err == nil {
		_ = reopened.Close()
		t.Fatal("corrupt checkpoint was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(got, broken) {
		t.Fatal("corrupt checkpoint was overwritten")
	}
}

func TestIncompleteCheckpointsAreRejectedWithoutOverwritingThem(t *testing.T) {
	for _, document := range []string{`{}`, `null`, `{"version":1,"identity":"` + testIdentity + `"}`} {
		t.Run(document, func(t *testing.T) {
			dir := t.TempDir()
			spool := openTest(t, dir, "rt-1")
			path := filepath.Join(spool.dir, "pending.json")
			_ = spool.Close()
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(dir, testIdentity, "rt-2"); err == nil {
				_ = reopened.Close()
				t.Fatal("incomplete checkpoint was silently accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != document {
				t.Fatal("incomplete checkpoint was overwritten")
			}
		})
	}
}

func TestSecondWriterIsRefused(t *testing.T) {
	dir := t.TempDir()
	first := openTest(t, dir, "rt-1")
	second, err := Open(dir, testIdentity, "rt-1")
	if err == nil {
		_ = second.Close()
		_ = first.Close()
		t.Fatal("a second writer acquired the spool")
	}
}

func TestLargeSamplesSplitWithoutChangingAmounts(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	measured := make(map[int][2]int64, 2500)
	for index := 1; index <= 2500; index++ {
		measured[index] = [2]int64{int64(index), int64(index * 2)}
	}
	seen := make(map[int][2]int64, 2500)
	err := spool.Report(measured, "rt-1", func(batch panel.TrafficBatch) error {
		if len(batch.Traffic) > 1000 {
			t.Fatalf("batch exceeded the entry limit: %d", len(batch.Traffic))
		}
		for memberID, pair := range batch.Traffic {
			if _, duplicate := seen[memberID]; duplicate {
				t.Fatalf("member %d appeared twice", memberID)
			}
			seen[memberID] = pair
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(measured) {
		t.Fatalf("split lost members: %d of %d", len(seen), len(measured))
	}
	for memberID, pair := range measured {
		if seen[memberID] != pair {
			t.Fatalf("member %d amount changed: %+v", memberID, seen[memberID])
		}
	}
}

func TestNewRuntimeNeverSubtractsThePreviousCheckpoint(t *testing.T) {
	dir := t.TempDir()
	spool := openTest(t, dir, "rt-1")
	received := map[int][2]int64{}
	if err := spool.Report(map[int][2]int64{5: {100, 200}}, "rt-1", func(batch panel.TrafficBatch) error {
		for memberID, pair := range batch.Traffic {
			previous := received[memberID]
			received[memberID] = [2]int64{previous[0] + pair[0], previous[1] + pair[1]}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = spool.Close()

	// A restarted process reports counters that restart from zero.
	restarted := openTest(t, dir, "rt-2")
	if err := restarted.Report(map[int][2]int64{5: {7, 9}}, "rt-2", func(batch panel.TrafficBatch) error {
		for memberID, pair := range batch.Traffic {
			previous := received[memberID]
			received[memberID] = [2]int64{previous[0] + pair[0], previous[1] + pair[1]}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if received[5] != [2]int64{107, 209} {
		t.Fatalf("restart double counted or dropped bytes: %+v", received[5])
	}
}

func TestCounterRegressionIsRefusedRatherThanReportedNegative(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	if err := spool.Report(map[int][2]int64{3: {10, 10}}, "rt-1", func(panel.TrafficBatch) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err := spool.Report(map[int][2]int64{3: {4, 10}}, "rt-1", func(panel.TrafficBatch) error { return nil })
	if !errors.Is(err, ErrSampleInvalid) {
		t.Fatalf("regression was not refused: %v", err)
	}
}

func TestVanishedMembersKeepTheirCursor(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	if err := spool.Report(map[int][2]int64{1: {5, 5}, 2: {8, 8}}, "rt-1", func(panel.TrafficBatch) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// Member 2 is temporarily unauthorized and stops appearing.
	if err := spool.Report(map[int][2]int64{1: {6, 6}}, "rt-1", func(panel.TrafficBatch) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// It returns with counters that continue from 8 rather than 0.
	var reported map[int][2]int64
	if err := spool.Report(map[int][2]int64{1: {6, 6}, 2: {9, 11}}, "rt-1", func(batch panel.TrafficBatch) error {
		reported = batch.Traffic
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if reported[2] != [2]int64{1, 3} {
		t.Fatalf("cursor for a returning member was lost: %+v", reported)
	}
}

func TestFullSpoolKeepsPendingBatchesAndRefusesTheNewSample(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")

	// Build sealed batches until one marshalled checkpoint exceeds the limit.
	// The growth is measured with a few round trips, not one per batch.
	state := spool.state
	next := func(count int) spoolState {
		built := spoolState{Version: state.Version, Identity: state.Identity, SampledTo: state.SampledTo}
		for index := 0; index < count; index++ {
			traffic := make(map[int][2]int64, 1000)
			for memberID := 1; memberID <= 1000; memberID++ {
				traffic[memberID] = [2]int64{1, 1}
			}
			built.Pending = append(built.Pending, panel.TrafficBatch{
				Protocol:    panel.TrafficProtocol,
				BatchID:     fmt.Sprintf("%032x", index),
				SampledFrom: 1,
				SampledTo:   2,
				Traffic:     traffic,
			})
		}
		return built
	}
	count := 1
	oversized := next(count)
	for {
		encoded, err := json.Marshal(oversized)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > maxSpoolBytes {
			break
		}
		count *= 2
		if count > 4096 {
			t.Fatal("could not fill the spool")
		}
		oversized = next(count)
	}

	if _, err := spool.save(oversized); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("an oversized checkpoint was persisted: %v", err)
	}
	// The refused write must not have replaced the on-disk checkpoint.
	if spool.Pending() != 0 {
		t.Fatal("a refused write mutated in-memory state")
	}
	if err := spool.Report(map[int][2]int64{1: {1, 1}}, "rt-1", func(panel.TrafficBatch) error { return nil }); err != nil {
		t.Fatalf("a sample that fits was refused: %v", err)
	}
}

func TestFullSpoolDrainsWithoutLosingRejectionsOrTheWaitingSample(t *testing.T) {
	spool := openTest(t, t.TempDir(), "rt-1")
	large := make(map[int][2]int64, batchSize)
	for id := 1; id <= batchSize; id++ {
		large[id] = [2]int64{math.MaxInt64, math.MaxInt64}
	}
	batch := panel.TrafficBatch{Protocol: panel.TrafficProtocol, BatchID: fmt.Sprintf("%032x", 0), SampledFrom: 1, SampledTo: 2, Traffic: large}
	encodedBatch, _ := json.Marshal(batch)
	emptyState, _ := json.Marshal(spool.state)
	state := spool.state
	for i := 0; i < (maxSpoolBytes-len(emptyState))/(len(encodedBatch)+1)-1; i++ {
		batch.BatchID = fmt.Sprintf("%032x", i)
		state.Pending = append(state.Pending, batch)
	}
	if committed, err := spool.save(state); !committed || err != nil {
		t.Fatalf("could not persist the nearly full spool: %v", err)
	}
	spool.state = state
	before := spool.Pending()
	measured := make(map[int][2]int64, batchSize)
	for id := batchSize + 1; id <= 2*batchSize; id++ {
		measured[id] = [2]int64{math.MaxInt64, math.MaxInt64}
	}
	err := spool.Report(measured, "rt-1", func(panel.TrafficBatch) error {
		return &panel.RejectedError{StatusCode: 403}
	})
	if !errors.Is(err, ErrSpoolFull) || !errors.Is(err, panel.ErrRejected) || Persisted(err) || spool.Pending() != before {
		t.Fatalf("a full spool lost the rejection or the caller's sample: %v", err)
	}
	sent := 0
	err = spool.Report(measured, "rt-1", func(panel.TrafficBatch) error {
		sent++
		return nil
	})
	if err != nil || sent != 16 || !reflect.DeepEqual(spool.state.Cursor, measured) {
		t.Fatalf("full spool did not free capacity and persist the waiting sample: %v, sent=%d", err, sent)
	}
	if err := spool.Sample(measured, "rt-1"); err != nil {
		t.Fatalf("the same cumulative sample could not be retried: %v", err)
	}
	if spool.Pending() != before-16+1 || !reflect.DeepEqual(spool.state.Pending[len(spool.state.Pending)-1].Traffic, measured) {
		t.Fatal("retry dropped or duplicated the unpersisted counters")
	}
}

func TestStatusStaysResponsiveWhileAPanelReportIsStalled(t *testing.T) {
	dir := t.TempDir()
	spool := openTest(t, dir, "rt-1")

	// A dead panel keeps the report call inside send for a long time. The status
	// helpers read the same spool, so they must not block behind the network.
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- spool.Report(map[int][2]int64{1: {10, 20}}, "rt-1", func(panel.TrafficBatch) error {
			close(entered)
			<-release
			return errors.New("panel unreachable")
		})
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the report never reached the panel")
	}

	read := make(chan int, 1)
	go func() {
		read <- spool.Pending()
	}()

	select {
	case pending := <-read:
		if pending != 1 {
			t.Fatalf("pending = %d, want 1", pending)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reading the spool blocked behind a stalled panel report")
	}

	close(release)
	if err := <-done; !Persisted(err) {
		t.Fatalf("a stalled report must keep ownership: %v", err)
	}
	if spool.Pending() != 1 {
		t.Fatalf("pending = %d, want the batch retained", spool.Pending())
	}
}
