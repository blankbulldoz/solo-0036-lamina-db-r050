package engine

import (
	"fmt"
	"lamina/internal/catalog"
	"lamina/internal/index"
	"lamina/internal/journal"
	"lamina/internal/snapshot"
	"lamina/internal/versions"
	"os"
	"path/filepath"
	"sync"
)

type DB struct {
	mu           sync.RWMutex
	dir          string
	catalog      *catalog.Catalog
	store        *versions.Store
	indexes      *index.Registry
	wal          *journal.WAL
	sequence     uint64
	horizon      uint64
	transactions map[string]*Transaction
	closed       bool
	commits      uint64
	conflicts    uint64
	queries      uint64
	recovery     RecoveryReport
}

// Open replays the verified checkpoint prefix and every journal frame after it.
// It publishes a DB only when the complete verified range is readable: the
// checkpoint image is valid, every replayed record applies in order, and the
// recovered constraints hold. Otherwise it returns a *StartupError carrying the
// evidence gathered so far. A torn final frame is quarantined and truncated; a
// complete but damaged frame is never truncated and never partially applied.
func Open(dir string, options journal.Options) (*DB, error) {
	options, err := journal.NormalizeOptions(options)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	checkpointPath := filepath.Join(absolute, "checkpoint.lmi")
	image, digest, err := snapshot.ReadWithDigest(checkpointPath)
	missing := os.IsNotExist(err)
	if err != nil && !missing {
		return nil, &StartupError{Report: RecoveryReport{State: "failed", Evidence: options.Evidence, EvidenceLimit: options.EvidenceLimit}, Err: fmt.Errorf("checkpoint: %w", err)}
	}
	if !missing {
		if _, err = os.Stat(filepath.Join(absolute, "journal.lmw")); err != nil {
			return nil, &StartupError{Report: RecoveryReport{State: "failed", Evidence: options.Evidence, EvidenceLimit: options.EvidenceLimit, Checkpoint: checkpointEvidence(missing, image, digest, checkpointPath)}, Err: fmt.Errorf("checkpoint without journal; use validated restore")}
		}
	}
	options.ReplayAfter = image.Sequence
	w, err := journal.Open(absolute, image.Sequence, options)
	if err != nil {
		var corruption *journal.RecoveryError
		if asRecovery(err, &corruption) {
			report := corruptionReport(corruption, options)
			report.Checkpoint = checkpointEvidence(missing, image, digest, checkpointPath)
			report.State = "failed"
			return nil, &StartupError{Report: report, Err: err}
		}
		return nil, &StartupError{Report: RecoveryReport{State: "failed", Checkpoint: checkpointEvidence(missing, image, digest, checkpointPath), Evidence: options.Evidence, EvidenceLimit: options.EvidenceLimit}, Err: err}
	}
	d := &DB{dir: absolute, catalog: catalog.New(), store: versions.New(), wal: w, transactions: map[string]*Transaction{}}
	if !missing {
		d.catalog = image.Catalog
		d.store = image.Store
		d.sequence = image.Sequence
		d.horizon = image.Horizon
	}
	report := reportFromJournal(w.Base, w.Recovery, options)
	report.Checkpoint = checkpointEvidence(missing, image, digest, checkpointPath)
	verified := w.VerifiedThrough()
	if d.sequence > verified {
		w.Close()
		// The image claims more than the journal proves. Its prefix is not
		// readable, so nothing after the journal header base is claimed; the
		// frames are left untouched for inspection.
		report.VerifiedThrough = w.Base
		report.Sequence = w.Base
		report.VerifiedRecords = 0
		report.State = "failed"
		report.Corruption = &CorruptionEvidence{
			Class:            "checkpoint",
			Detail:           fmt.Sprintf("checkpoint claims sequence %d but the journal only proves %d; the image cannot own this journal prefix", d.sequence, verified),
			ExpectedSequence: verified + 1,
			VerifiedThrough:  w.Base,
			Source:           filepath.Join(absolute, "journal.lmw"),
			SourcePreserved:  true,
			Sample:           report.Sample,
			SampleTotal:      report.SampleTotal,
			Kinds:            report.Kinds,
		}
		return nil, &StartupError{Report: report, Err: fmt.Errorf("checkpoint ahead of journal: checkpoint %d, journal verified through %d", d.sequence, verified)}
	}
	for _, r := range w.Records {
		if r.Sequence <= d.sequence {
			continue
		}
		if err = d.apply(r); err != nil {
			w.Close()
			report.VerifiedRecords = appliedRecords(w, d.sequence)
			report.Corruption = &CorruptionEvidence{
				Class:            "apply",
				Detail:           err.Error(),
				Offset:           report.OffsetOf(r.Sequence),
				ExpectedSequence: r.Sequence,
				VerifiedThrough:  d.sequence,
				Source:           filepath.Join(absolute, "journal.lmw"),
				SourcePreserved:  true,
				Sample:           report.Sample,
				SampleTotal:      report.SampleTotal,
				Kinds:            report.Kinds,
			}
			report.VerifiedThrough = d.sequence
			report.Sequence = d.sequence
			report.State = "failed"
			return nil, &StartupError{Report: report, Err: fmt.Errorf("replay sequence %d: %w", r.Sequence, err)}
		}
	}
	d.indexes = index.Build(d.catalog, d.store)
	for _, relation := range d.catalog.List() {
		if err = d.unique(relation.Name, nil); err != nil {
			w.Close()
			report.State = "failed"
			report.VerifiedRecords = appliedRecords(w, d.sequence)
			report.VerifiedThrough = d.sequence
			report.Sequence = d.sequence
			report.Corruption = &CorruptionEvidence{Class: "constraint", Detail: err.Error(), VerifiedThrough: d.sequence, Source: filepath.Join(absolute, "journal.lmw"), SourcePreserved: true, Sample: report.Sample, SampleTotal: report.SampleTotal, Kinds: report.Kinds}
			return nil, &StartupError{Report: report, Err: fmt.Errorf("recovered constraints: %w", err)}
		}
	}
	report = readyReport(report, d.sequence)
	report.VerifiedThrough = d.sequence
	d.recovery = report
	return d, nil
}

func checkpointEvidence(missing bool, image snapshot.Image, digest, path string) *CheckpointEvidence {
	if missing {
		return &CheckpointEvidence{Present: false, Path: path}
	}
	return &CheckpointEvidence{Present: true, Sequence: image.Sequence, Horizon: image.Horizon, Digest: digest, Path: path}
}

// appliedRecords counts journal frames whose sequence was verified and lies at
// or below the last applied sequence, i.e. records whose state is now readable.
func appliedRecords(w *journal.WAL, applied uint64) int {
	n := 0
	for _, r := range w.Records {
		if r.Sequence <= applied {
			n++
		}
	}
	return n
}

func asRecovery(err error, target **journal.RecoveryError) bool {
	for err != nil {
		if typed, ok := err.(*journal.RecoveryError); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// verifiedThrough is the last sequence that is both durably framed and applied
// in memory. A frame is appended before it is applied, so during a publish the
// journal may be one ahead of the readable state; that frame is not yet a fact a
// reader or change consumer may rely on. Callers must hold at least a read lock.
func (d *DB) verifiedThrough() uint64 {
	verified := d.wal.VerifiedThrough()
	if d.sequence < verified {
		return d.sequence
	}
	return verified
}

// RecoveryReport returns the startup account for this instance. It is a frozen
// snapshot of the read that opened the database: the verified boundary it names
// is derived from the same journal prefix the change feed serves. Later commits
// extend the live boundary, which /health and /stats report.
func (d *DB) RecoveryReport() RecoveryReport {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.recovery
}

func (d *DB) usable() error {
	if d.closed {
		return fault("unavailable", "database closed")
	}
	if d.wal.Poisoned {
		return fault("unavailable", "journal write outcome uncertain; restart required")
	}
	return nil
}
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.transactions = map[string]*Transaction{}
	return d.wal.Close()
}
func (d *DB) publish(r journal.Record) error {
	r.Sequence = d.sequence + 1
	r.Format = 1
	if err := d.wal.Append(r); err != nil {
		return fault("unavailable", "durable commit failed: %s", err)
	}
	if err := d.apply(r); err != nil {
		d.wal.Poisoned = true
		return fault("unavailable", "durable record cannot be applied: %s", err)
	}
	if len(r.Writes) > 0 {
		d.indexes.Apply(d.catalog, r.Writes)
	}
	return nil
}
func (d *DB) Relations() ([]catalog.Relation, []catalog.Index, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.usable(); err != nil {
		return nil, nil, err
	}
	return d.catalog.List(), d.catalog.IndexList(), nil
}
