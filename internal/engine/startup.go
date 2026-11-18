package engine

import (
	"fmt"
	"lamina/internal/journal"
	"time"
)

// RecoveryReport is the operator-facing account of one startup. It is frozen
// when Open returns. It keeps three claims separate, because an operator must
// not confuse them:
//
//   - Verified: every sequence from HistoryBase+1 through VerifiedThrough was
//     completely framed, checksummed, decoded and (unless already covered by the
//     checkpoint) applied in order. Queries and the change feed may serve
//     exactly this range.
//   - Unconfirmed: the final frame was incomplete. It was never decoded, so its
//     commit may or may not have reached stable storage. It is preserved,
//     excluded from the verified range, and truncated away.
//   - Corrupt: a complete frame failed a length, checksum, decode, ordering or
//     apply check. Startup fails closed: nothing is truncated, nothing is
//     published, and the source journal is left untouched for inspection.
type RecoveryReport struct {
	State           string                   `json:"state"`
	QueryReady      bool                     `json:"query_ready"`
	ReadyAt         string                   `json:"ready_at,omitempty"`
	Checkpoint      *CheckpointEvidence      `json:"checkpoint"`
	HistoryBase     uint64                   `json:"history_base"`
	VerifiedThrough uint64                   `json:"verified_through"`
	Sequence        uint64                   `json:"sequence"`
	VerifiedRecords int                      `json:"verified_records"`
	Replayed        int                      `json:"replayed_records"`
	ReplayedBytes   int64                    `json:"replayed_bytes"`
	Skipped         int                      `json:"checkpoint_skipped_records"`
	SkippedBytes    int64                    `json:"checkpoint_skipped_bytes"`
	Evidence        journal.EvidenceLevel    `json:"evidence"`
	EvidenceLimit   int                      `json:"evidence_limit,omitempty"`
	Sample          []journal.RecordEvidence `json:"sample,omitempty"`
	SampleTotal     int                      `json:"sample_total,omitempty"`
	Kinds           map[string]int           `json:"kinds,omitempty"`
	Tail            journal.TailEvidence     `json:"tail"`
	Corruption      *CorruptionEvidence      `json:"corruption,omitempty"`
}

// CheckpointEvidence states which image, if any, was the replay starting point.
type CheckpointEvidence struct {
	Present  bool   `json:"present"`
	Sequence uint64 `json:"sequence,omitempty"`
	Horizon  uint64 `json:"horizon,omitempty"`
	Digest   string `json:"sha256,omitempty"`
	Path     string `json:"path,omitempty"`
}

// CorruptionEvidence is attached to a failed startup. It reports the last
// verified sequence so an operator can tell "commits through N are proven"
// from "the frame at N+1 is broken" — a state that is not a torn tail.
type CorruptionEvidence struct {
	Class              string                   `json:"class"`
	Detail             string                   `json:"detail"`
	Offset             int64                    `json:"offset,omitempty"`
	ExpectedSequence   uint64                   `json:"expected_sequence,omitempty"`
	VerifiedThrough    uint64                   `json:"verified_through"`
	FrameBytes         int64                    `json:"frame_bytes,omitempty"`
	DeclaredFrameBytes uint32                   `json:"declared_frame_bytes,omitempty"`
	PayloadSHA256      string                   `json:"payload_sha256,omitempty"`
	Source             string                   `json:"source"`
	SourcePreserved    bool                     `json:"source_preserved"`
	Sample             []journal.RecordEvidence `json:"sample,omitempty"`
	SampleTotal        int                      `json:"sample_total,omitempty"`
	Kinds              map[string]int           `json:"kinds,omitempty"`
}

// StartupError carries the full report for a startup that refused to publish.
type StartupError struct {
	Report RecoveryReport
	Err    error
}

func (e *StartupError) Error() string { return e.Err.Error() }
func (e *StartupError) Unwrap() error { return e.Err }

func reportFromJournal(base uint64, r journal.Recovery, opts journal.Options) RecoveryReport {
	return RecoveryReport{
		HistoryBase:     base,
		VerifiedThrough: base + uint64(r.Records),
		Sequence:        base + uint64(r.Records),
		Evidence:        opts.Evidence,
		EvidenceLimit:   opts.EvidenceLimit,
		Sample:          r.Sample,
		SampleTotal:     r.SampleTotal,
		Kinds:           r.Kinds,
		Tail:            r.Tail,
		VerifiedRecords: r.Records,
		Replayed:        r.Replayed,
		ReplayedBytes:   r.ReplayedBytes,
		Skipped:         r.Skipped,
		SkippedBytes:    r.SkippedBytes,
	}
}

func corruptionReport(e *journal.RecoveryError, opts journal.Options) RecoveryReport {
	return RecoveryReport{
		HistoryBase:     e.HistoryBase,
		VerifiedThrough: e.VerifiedThrough,
		Sequence:        e.VerifiedThrough,
		Evidence:        opts.Evidence,
		EvidenceLimit:   opts.EvidenceLimit,
		Sample:          e.Sample,
		SampleTotal:     e.SampleTotal,
		Kinds:           e.Kinds,
		VerifiedRecords: e.SampleTotal,
		Corruption: &CorruptionEvidence{
			Class:              e.Class,
			Detail:             e.Detail,
			Offset:             e.Offset,
			ExpectedSequence:   e.ExpectedSequence,
			VerifiedThrough:    e.VerifiedThrough,
			FrameBytes:         e.FrameBytes,
			DeclaredFrameBytes: e.DeclaredFrameBytes,
			PayloadSHA256:      e.PayloadSHA256,
			Source:             e.Path,
			SourcePreserved:    e.SourcePreserved,
			Sample:             e.Sample,
			SampleTotal:        e.SampleTotal,
			Kinds:              e.Kinds,
		},
	}
}

// OffsetOf locates a sequence in the bounded sample, when that sequence was
// sampled. A missing value means "not in the retained evidence", never "absent
// from the journal".
func (r RecoveryReport) OffsetOf(sequence uint64) int64 {
	for _, e := range r.Sample {
		if e.Sequence == sequence {
			return e.Offset
		}
	}
	return 0
}

func readyReport(report RecoveryReport, sequence uint64) RecoveryReport {
	report.State = "ready"
	report.QueryReady = true
	report.Sequence = sequence
	report.ReadyAt = time.Now().UTC().Format(time.RFC3339Nano)
	return report
}

// Describe is a one-line operator summary that names only the verified range.
func (r RecoveryReport) Describe() string {
	if r.Corruption != nil && r.Corruption.Class == "base" {
		return fmt.Sprintf("no verified prefix: the checkpoint image covering base %d is missing or stale; journal records after it are preserved but unclaimed", r.HistoryBase)
	}
	if r.Corruption != nil && r.Corruption.Class == "checkpoint" {
		return "not ready: the checkpoint and the journal prefix disagree; neither the image nor its suffix is claimed as readable"
	}
	base := fmt.Sprintf("verified sequences %d..%d", r.HistoryBase+1, r.VerifiedThrough)
	if r.VerifiedThrough == r.HistoryBase {
		base = fmt.Sprintf("verified prefix is empty after base %d", r.HistoryBase)
	}
	if r.Tail.Present {
		base += fmt.Sprintf("; %d unconfirmed tail bytes preserved at %s", r.Tail.Bytes, r.Tail.Preserved)
	}
	if r.Corruption != nil {
		base += fmt.Sprintf("; corruption (%s) at sequence %d", r.Corruption.Class, r.Corruption.ExpectedSequence)
	}
	return base
}
