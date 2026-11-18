package journal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const MaxFrame = 16 << 20

// WAL owns the verified commit prefix. Base is the first sequence the journal
// file can describe; Records holds every frame that was completely framed,
// checksummed, decoded and ordered. No caller may claim a sequence above
// VerifiedThrough.
type WAL struct {
	Base          uint64
	file          *os.File
	lock          *os.File
	dir           string
	Records       []Record
	RecoveredTail int64
	Poisoned      bool
	Recovery      Recovery
	options       Options
}

func Open(dir string, base uint64, options Options) (*WAL, error) {
	options, err := NormalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lamina.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("data directory already open: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "journal.lmw"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		lock.Close()
		return nil, err
	}
	w := &WAL{file: f, lock: lock, dir: dir, Base: base, options: options}
	info, err := f.Stat()
	if err != nil {
		w.Close()
		return nil, err
	}
	if info.Size() == 0 {
		header := make([]byte, 16)
		copy(header[:4], "LMW1")
		binary.BigEndian.PutUint64(header[4:12], base)
		binary.BigEndian.PutUint32(header[12:], crc32.ChecksumIEEE(header[:12]))
		if _, err = f.Write(header); err == nil {
			err = f.Sync()
		}
		if err != nil {
			w.Close()
			return nil, err
		}
	}
	directory, syncErr := os.Open(dir)
	if syncErr != nil {
		w.Close()
		return nil, syncErr
	}
	syncErr = directory.Sync()
	directory.Close()
	if syncErr != nil {
		w.Close()
		return nil, syncErr
	}
	if _, err = f.Seek(0, 0); err != nil {
		w.Close()
		return nil, err
	}
	// Re-stat after the header write so a fresh journal is measured correctly.
	if info, err = f.Stat(); err != nil {
		w.Close()
		return nil, err
	}
	if err = w.recover(info.Size()); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// VerifiedThrough is the highest sequence the journal can prove: every frame
// from Base+1 through it was complete, checksummed, decodable and contiguous.
// Startup recovery and the change feed share this one range.
func (w *WAL) VerifiedThrough() uint64 { return w.Base + uint64(len(w.Records)) }

func (w *WAL) recover(fileSize int64) error {
	w.Recovery = Recovery{HeaderBytes: 16, Evidence: w.options.Evidence, EvidenceLimit: w.options.EvidenceLimit}
	collector := newEvidenceCollector(w.options)
	var header [16]byte
	if _, err := io.ReadFull(w.file, header[:]); err != nil {
		return fmt.Errorf("journal header: %w", err)
	}
	if string(header[:4]) != "LMW1" || crc32.ChecksumIEEE(header[:12]) != binary.BigEndian.Uint32(header[12:]) {
		return &RecoveryError{Class: "header", Detail: "invalid journal header", Offset: 0, VerifiedThrough: w.Base, Evidence: w.options.Evidence, EvidenceLimit: w.options.EvidenceLimit, HistoryBase: w.Base, Path: filepath.Join(w.dir, "journal.lmw")}
	}
	actualBase := binary.BigEndian.Uint64(header[4:12])
	if actualBase > w.Base {
		return w.corrupt(collector, RecoveryError{
			Class:           "base",
			Detail:          fmt.Sprintf("journal requires a checkpoint covering sequence %d, but none is installed; the image that owns this prefix is missing", actualBase),
			Offset:          4,
			VerifiedThrough: actualBase,
			HistoryBase:     actualBase,
			Path:            filepath.Join(w.dir, "journal.lmw"),
			SourcePreserved: true,
		})
	}
	w.Base = actualBase
	offset := int64(16)
	last := w.Base
	for {
		frameOffset := offset
		var head [8]byte
		n, err := io.ReadFull(w.file, head[:])
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			return w.preserveTail(collector, fileSize, frameOffset, last, false, 0)
		}
		if err != nil {
			return fmt.Errorf("journal read at %d: %w", frameOffset, err)
		}
		length := binary.BigEndian.Uint32(head[:4])
		if length == 0 || length > MaxFrame {
			return w.corrupt(collector, RecoveryError{
				Class:              "length",
				Detail:             "frame length outside 1..16MiB",
				Offset:             frameOffset,
				ExpectedSequence:   last + 1,
				VerifiedThrough:    last,
				FrameBytes:         int64(n),
				DeclaredFrameBytes: length,
			})
		}
		payload := make([]byte, length)
		n, err = io.ReadFull(w.file, payload)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return w.preserveTail(collector, fileSize, frameOffset, last, true, length)
		}
		if err != nil {
			return fmt.Errorf("journal read at %d: %w", frameOffset, err)
		}
		frameBytes := int64(8 + length)
		if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(head[4:]) {
			return w.corrupt(collector, RecoveryError{
				Class:              "checksum",
				Detail:             "complete frame checksum mismatch",
				Offset:             frameOffset,
				ExpectedSequence:   last + 1,
				VerifiedThrough:    last,
				FrameBytes:         frameBytes,
				DeclaredFrameBytes: length,
				PayloadSHA256:      digest(payload),
			})
		}
		var r Record
		if err = json.Unmarshal(payload, &r); err != nil {
			return w.corrupt(collector, RecoveryError{
				Class:              "decode",
				Detail:             "complete frame is not a valid record: " + err.Error(),
				Offset:             frameOffset,
				ExpectedSequence:   last + 1,
				VerifiedThrough:    last,
				FrameBytes:         frameBytes,
				DeclaredFrameBytes: length,
				PayloadSHA256:      digest(payload),
			})
		}
		if r.Format != 1 || r.Sequence != last+1 {
			return w.corrupt(collector, RecoveryError{
				Class:              "sequence",
				Detail:             "record sequence or format is not contiguous",
				Offset:             frameOffset,
				ExpectedSequence:   last + 1,
				VerifiedThrough:    last,
				FrameBytes:         frameBytes,
				DeclaredFrameBytes: length,
				PayloadSHA256:      digest(payload),
			})
		}
		w.Records = append(w.Records, r)
		collector.add(RecordEvidence{Sequence: r.Sequence, Kind: r.Kind, Offset: frameOffset, Bytes: frameBytes, Transaction: r.Transaction, Writes: len(r.Writes)})
		last = r.Sequence
		offset += frameBytes
	}
	w.finishEvidence(collector, offset)
	_, err := w.file.Seek(0, io.SeekEnd)
	return err
}

// preserveTail keeps an incomplete final frame as source material before the
// journal is truncated. The frame is unconfirmed, not corrupt: it is never
// decoded, never counted, and never reported as a failed commit.
func (w *WAL) preserveTail(collector *evidenceCollector, fileSize, frameOffset int64, last uint64, headerComplete bool, declared uint32) error {
	w.finishEvidence(collector, frameOffset)
	tailBytes := fileSize - frameOffset
	if tailBytes <= 0 {
		return fmt.Errorf("journal tail at %d has no bytes; refusing to truncate", frameOffset)
	}
	tail := make([]byte, tailBytes)
	if _, err := w.file.ReadAt(tail, frameOffset); err != nil {
		return fmt.Errorf("journal tail at %d cannot be read for preservation: %w", frameOffset, err)
	}
	path, err := w.quarantine(frameOffset, tail)
	if err != nil {
		return fmt.Errorf("journal tail at %d cannot be preserved; refusing to truncate: %w", frameOffset, err)
	}
	if err = w.file.Truncate(frameOffset); err != nil {
		return err
	}
	if err = w.file.Sync(); err != nil {
		return err
	}
	w.RecoveredTail = tailBytes
	w.Recovery.Tail = TailEvidence{
		Present:             true,
		Offset:              frameOffset,
		Bytes:               tailBytes,
		FrameHeaderComplete: headerComplete,
		DeclaredFrameBytes:  declared,
		NextSequence:        last + 1,
		SHA256:              digest(tail),
		Preserved:           path,
	}
	_, err = w.file.Seek(0, io.SeekEnd)
	return err
}

func (w *WAL) quarantine(offset int64, tail []byte) (string, error) {
	dir := filepath.Join(w.dir, "recovery")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	sum := digest(tail)
	name := fmt.Sprintf("torn-%d-%d-%s.bin", offset, len(tail), sum[:12])
	path := filepath.Join(dir, name)
	if existing, err := os.ReadFile(path); err == nil {
		if digest(existing) == sum {
			return filepath.Join("recovery", name), nil
		}
		return "", fmt.Errorf("quarantine file %s already holds different bytes", name)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err = f.Write(tail); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	d, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return "", err
	}
	return filepath.Join("recovery", name), nil
}

func (w *WAL) corrupt(collector *evidenceCollector, e RecoveryError) error {
	w.finishEvidence(collector, e.Offset)
	e.Sample = w.Recovery.Sample
	e.SampleTotal = w.Recovery.SampleTotal
	e.Kinds = w.Recovery.Kinds
	e.Evidence = w.options.Evidence
	e.EvidenceLimit = w.options.EvidenceLimit
	if e.HistoryBase == 0 {
		e.HistoryBase = w.Base
	}
	e.SourcePreserved = true
	e.Path = filepath.Join(w.dir, "journal.lmw")
	return &e
}

func (w *WAL) finishEvidence(collector *evidenceCollector, verifiedOffset int64) {
	w.Recovery.Records = len(w.Records)
	w.Recovery.Bytes = verifiedOffset - w.Recovery.HeaderBytes
	w.Recovery.Replayed = collector.replayed
	w.Recovery.ReplayedBytes = collector.replayBytes
	w.Recovery.Skipped = collector.skipped
	w.Recovery.SkippedBytes = collector.skippedBytes
	w.Recovery.Sample = collector.sample()
	w.Recovery.SampleTotal = collector.total
	w.Recovery.Kinds = collector.kinds
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Append encodes, writes and fsyncs exactly one complete frame. The record
// joins the verified range only after Sync returns; a failure poisons the
// journal because the caller cannot know whether the frame reached disk.
func (w *WAL) Append(r Record) error {
	if w.Poisoned {
		return fmt.Errorf("journal is unavailable; restart required")
	}
	if r.Sequence != w.Base+uint64(len(w.Records))+1 {
		return fmt.Errorf("noncontiguous journal sequence")
	}
	r.Format = 1
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrame {
		return fmt.Errorf("commit exceeds journal frame limit")
	}
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], crc32.ChecksumIEEE(payload))
	copy(frame[8:], payload)
	if _, err = w.file.Write(frame); err != nil {
		w.Poisoned = true
		return err
	}
	if err = w.file.Sync(); err != nil {
		w.Poisoned = true
		return err
	}
	w.Records = append(w.Records, r)
	w.Recovery.Records = len(w.Records)
	w.Recovery.Bytes += int64(len(frame))
	return nil
}

func (w *WAL) Close() error {
	err := w.file.Close()
	w.lock.Close()
	return err
}
