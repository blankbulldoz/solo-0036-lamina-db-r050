package engine

import "lamina/internal/journal"

type ChangePage struct {
	Records     []journal.Record `json:"records"`
	Cursor      uint64           `json:"cursor"`
	Head        uint64           `json:"head"`
	HistoryBase uint64           `json:"history_base"`
	More        bool             `json:"more"`
}

// Changes serves the same verified range startup recovery proved. Head is the
// highest sequence whose complete commit record is present and applied; a
// cursor beyond it is rejected rather than silently clamped. A torn tail and a
// corrupt frame are both excluded here: only completely verified records are
// ever published to consumers.
func (d *DB) Changes(after uint64, limit int) (ChangePage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	verified := d.verifiedThrough()
	out := ChangePage{Records: []journal.Record{}, Cursor: after, Head: verified, HistoryBase: d.wal.Base}
	if err := d.usable(); err != nil {
		return out, err
	}
	if after < d.wal.Base {
		return out, fault("snapshot", "change history begins at %d", d.wal.Base)
	}
	if after > verified || limit < 1 || limit > 1000 {
		return out, fault("invalid", "invalid change cursor or limit; verified head is %d", verified)
	}
	for _, r := range d.wal.Records {
		if r.Sequence <= after {
			continue
		}
		if r.Sequence > verified {
			break
		}
		if len(out.Records) >= limit {
			out.More = true
			break
		}
		out.Records = append(out.Records, r)
		out.Cursor = r.Sequence
	}
	return out, nil
}
