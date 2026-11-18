package engine

import (
	"sort"

	"lamina/internal/journal"
)

type Stats struct {
	Sequence        uint64                `json:"sequence"`
	Horizon         uint64                `json:"horizon"`
	VerifiedThrough uint64                `json:"verified_through"`
	HistoryBase     uint64                `json:"history_base"`
	Active          []Transaction         `json:"active"`
	Keys            int                   `json:"keys"`
	Versions        int                   `json:"versions"`
	IndexEntries    map[string]int        `json:"index_entries"`
	JournalRecords  int                   `json:"journal_records"`
	RecoveredTail   int64                 `json:"recovered_tail_bytes"`
	Tail            journal.TailEvidence  `json:"recovery_tail"`
	Evidence        journal.EvidenceLevel `json:"recovery_evidence"`
	Commits         uint64                `json:"commits_since_open"`
	Conflicts       uint64                `json:"conflicts_since_open"`
	Queries         uint64                `json:"queries_since_open"`
}

func (d *DB) Stats() (Stats, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.usable(); err != nil {
		return Stats{}, err
	}
	keys, versions := d.store.Count()
	s := Stats{Sequence: d.sequence, Horizon: d.horizon, VerifiedThrough: d.verifiedThrough(), Keys: keys, Versions: versions, Active: []Transaction{}, IndexEntries: map[string]int{}, JournalRecords: len(d.wal.Records), HistoryBase: d.wal.Base, RecoveredTail: d.wal.RecoveredTail, Tail: d.wal.Recovery.Tail, Evidence: d.recovery.Evidence, Commits: d.commits, Conflicts: d.conflicts, Queries: d.queries}
	for _, tx := range d.transactions {
		copy := *tx
		copy.writes = nil
		s.Active = append(s.Active, copy)
	}
	sort.Slice(s.Active, func(i, j int) bool { return s.Active[i].ID < s.Active[j].ID })
	for name, t := range d.indexes.Trees {
		s.IndexEntries[name] = t.Size()
	}
	return s, nil
}
