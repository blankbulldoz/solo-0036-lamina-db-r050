package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"lamina/internal/engine"
	"lamina/internal/journal"
	"lamina/internal/snapshot"
	"lamina/internal/transport"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("lamina stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	dir := flag.String("data", "var/lamina", "data directory exclusively owned by this process")
	addr := flag.String("listen", "127.0.0.1:7386", "HTTP bind address")
	restore := flag.String("restore", "", "validated backup to install into a new data directory before serving")
	evidence := flag.String("recovery-evidence", string(journal.DefaultEvidenceLevel), "startup recovery evidence: minimal, summary or bounded")
	evidenceLimit := flag.Int("recovery-evidence-limit", journal.DefaultEvidenceLimit, "per-record evidence entries kept when evidence is bounded (1..256, split across start and end of the verified prefix)")
	reportPath := flag.String("recovery-report", "", "optional path to write the bounded startup recovery report as JSON")
	flag.Parse()
	options, err := journal.NormalizeOptions(journal.Options{Evidence: journal.EvidenceLevel(*evidence), EvidenceLimit: *evidenceLimit})
	if err != nil {
		return err
	}
	if *restore != "" {
		info, err := os.Stat(*restore)
		if err != nil {
			return err
		}
		if info.Size() > snapshot.MaxImage {
			return fmt.Errorf("backup exceeds limit")
		}
		b, err := os.ReadFile(*restore)
		if err != nil {
			return err
		}
		if err = engine.Restore(*dir, b); err != nil {
			return err
		}
	}
	db, err := engine.Open(*dir, options)
	if err != nil {
		var startup *engine.StartupError
		if errors.As(err, &startup) {
			startup.Report.State = "failed"
			emitReport(*reportPath, startup.Report)
			slog.Error("recovery refused", "report", startup.Report.Describe())
			return fmt.Errorf("%w; no query service started and no records were published", err)
		}
		return err
	}
	defer db.Close()
	report := db.RecoveryReport()
	emitReport(*reportPath, report)
	slog.Info("recovery complete", "report", report.Describe(), "verified_through", report.VerifiedThrough, "sequence", report.Sequence, "query_ready", report.QueryReady)
	server := &http.Server{Addr: *addr, Handler: transport.New(db), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 32 << 10}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopped)
	finished := make(chan error, 1)
	go func() { slog.Info("lamina ready", "address", *addr); finished <- server.ListenAndServe() }()
	select {
	case err = <-finished:
		if err != http.ErrServerClosed {
			return err
		}
	case <-stopped:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = server.Shutdown(ctx); err != nil {
			server.Close()
			return err
		}
	}
	return nil
}

// emitReport writes the same bounded report that was logged, so an operator
// can keep it beside the preserved journal without scraping stderr.
func emitReport(path string, report engine.RecoveryReport) {
	if path == "" {
		return
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		err = os.WriteFile(path, append(b, '\n'), 0600)
	}
	if err != nil {
		slog.Warn("recovery report not written", "path", path, "error", err)
	}
}
