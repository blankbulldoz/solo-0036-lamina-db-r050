package journal

import "fmt"

// EvidenceLevel selects how much per-record material a startup recovery
// report keeps. Every level is bounded: "bounded" retains a fixed-size sample
// of verified frames so an operator can explain the boundary without walking a
// long journal twice or retaining diagnostic space proportional to the log.
type EvidenceLevel string

const (
	// EvidenceMinimal reports only verified-range counts and the tail/corruption boundary.
	EvidenceMinimal EvidenceLevel = "minimal"
	// EvidenceSummary adds per-kind counts for the verified prefix; no per-record locations.
	EvidenceSummary EvidenceLevel = "summary"
	// EvidenceBounded adds at most EvidenceLimit per-record locations drawn from the
	// start and end of the verified prefix.
	EvidenceBounded EvidenceLevel = "bounded"
)

const (
	DefaultEvidenceLevel = EvidenceBounded
	DefaultEvidenceLimit = 16
	MaxEvidenceLimit     = 256
)

// Options configures recovery evidence collection and the split point used to
// count how much of the verified prefix a checkpoint image already covers.
type Options struct {
	Evidence      EvidenceLevel
	EvidenceLimit int
	// ReplayAfter is the sequence already contained in the checkpoint image.
	// Frames at or below it are verified and located but not replayed.
	ReplayAfter uint64
}

// NormalizeOptions validates an evidence selection and applies defaults.
func NormalizeOptions(opts Options) (Options, error) {
	switch opts.Evidence {
	case "":
		opts.Evidence = DefaultEvidenceLevel
	case EvidenceMinimal, EvidenceSummary, EvidenceBounded:
	default:
		return opts, fmt.Errorf("unknown recovery evidence level %q (want minimal, summary or bounded)", opts.Evidence)
	}
	if opts.EvidenceLimit == 0 {
		opts.EvidenceLimit = DefaultEvidenceLimit
	}
	if opts.EvidenceLimit < 1 || opts.EvidenceLimit > MaxEvidenceLimit {
		return opts, fmt.Errorf("recovery evidence limit must be 1..%d", MaxEvidenceLimit)
	}
	if opts.Evidence != EvidenceBounded {
		opts.EvidenceLimit = 0
	}
	return opts, nil
}

// RecordEvidence is a bounded description of one verified frame. Offset is the
// byte position of the frame header in the journal, so a sampled record can be
// located in the preserved source file without retaining its payload here.
type RecordEvidence struct {
	Sequence    uint64 `json:"sequence"`
	Kind        string `json:"kind"`
	Offset      int64  `json:"offset"`
	Bytes       int64  `json:"frame_bytes"`
	Transaction string `json:"transaction,omitempty"`
	Writes      int    `json:"writes,omitempty"`
}

// TailEvidence describes an incomplete final frame found after the last
// verified frame. Such a frame is not corrupt; it was never confirmed as
// complete, so it is quarantined before the journal is truncated. Its last write
// may or may not have reached stable storage, so it is reported as unconfirmed.
type TailEvidence struct {
	Present             bool   `json:"present"`
	Offset              int64  `json:"offset,omitempty"`
	Bytes               int64  `json:"bytes,omitempty"`
	FrameHeaderComplete bool   `json:"frame_header_complete"`
	DeclaredFrameBytes  uint32 `json:"declared_frame_bytes,omitempty"`
	NextSequence        uint64 `json:"next_sequence,omitempty"`
	SHA256              string `json:"sha256,omitempty"`
	Preserved           string `json:"preserved,omitempty"`
}

// Recovery is the bounded evidence gathered while reading the journal.
// Records always holds every verified record because the change feed needs the
// complete prefix; Sample only holds the bounded subset selected for diagnostics.
type Recovery struct {
	HeaderBytes   int64            `json:"header_bytes"`
	Records       int              `json:"records"`
	Bytes         int64            `json:"verified_bytes"`
	Replayed      int              `json:"replayed_records"`
	ReplayedBytes int64            `json:"replayed_bytes"`
	Skipped       int              `json:"checkpoint_skipped_records"`
	SkippedBytes  int64            `json:"checkpoint_skipped_bytes"`
	Sample        []RecordEvidence `json:"sample,omitempty"`
	SampleTotal   int              `json:"sample_total,omitempty"`
	Kinds         map[string]int   `json:"kinds,omitempty"`
	Evidence      EvidenceLevel    `json:"evidence"`
	EvidenceLimit int              `json:"evidence_limit,omitempty"`
	Tail          TailEvidence     `json:"tail"`
}

// RecoveryError classifies a journal that cannot be opened. Corruption is
// always fatal: unlike an incomplete final frame it is never truncated or
// treated as an ordinary tail. VerifiedThrough is the last sequence that was
// completely framed, checksummed, decoded and ordered before the fault.
type RecoveryError struct {
	Class              string
	Detail             string
	Offset             int64
	ExpectedSequence   uint64
	VerifiedThrough    uint64
	FrameBytes         int64
	DeclaredFrameBytes uint32
	PayloadSHA256      string
	HistoryBase        uint64
	Path               string
	SourcePreserved    bool
	Sample             []RecordEvidence
	SampleTotal        int
	Kinds              map[string]int
	Evidence           EvidenceLevel
	EvidenceLimit      int
}

func (e *RecoveryError) Error() string {
	message := fmt.Sprintf("journal corruption (%s) at offset %d: %s; verified through %d", e.Class, e.Offset, e.Detail, e.VerifiedThrough)
	if e.ExpectedSequence != 0 {
		message += fmt.Sprintf("; sequence %d is unconfirmed (not a torn tail)", e.ExpectedSequence)
	}
	return message
}

type evidenceCollector struct {
	level        EvidenceLevel
	limit        int
	replayAfter  uint64
	first        []RecordEvidence
	last         []RecordEvidence
	lastNext     int
	total        int
	replayed     int
	replayBytes  int64
	skipped      int
	skippedBytes int64
	kinds        map[string]int
}

func newEvidenceCollector(opts Options) *evidenceCollector {
	c := &evidenceCollector{level: opts.Evidence, limit: opts.EvidenceLimit, replayAfter: opts.ReplayAfter}
	if opts.Evidence != EvidenceMinimal {
		c.kinds = map[string]int{}
	}
	return c
}

func (c *evidenceCollector) add(e RecordEvidence) {
	c.total++
	if c.kinds != nil {
		c.kinds[e.Kind]++
	}
	if e.Sequence <= c.replayAfter {
		c.skipped++
		c.skippedBytes += e.Bytes
	} else {
		c.replayed++
		c.replayBytes += e.Bytes
	}
	if c.level != EvidenceBounded {
		return
	}
	head := c.limit / 2
	tail := c.limit - head
	if len(c.first) < head {
		c.first = append(c.first, e)
		return
	}
	if tail == 0 {
		return
	}
	if len(c.last) < tail {
		c.last = append(c.last, e)
		return
	}
	c.last[c.lastNext] = e
	c.lastNext = (c.lastNext + 1) % tail
}

func (c *evidenceCollector) sample() []RecordEvidence {
	if c.level != EvidenceBounded {
		return nil
	}
	out := make([]RecordEvidence, 0, len(c.first)+len(c.last))
	out = append(out, c.first...)
	for i := 0; i < len(c.last); i++ {
		out = append(out, c.last[(c.lastNext+i)%len(c.last)])
	}
	return out
}
