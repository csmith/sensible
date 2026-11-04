package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// CertRecordsDir holds the paths each certificate has been written to, in
// <name>/record.json.
const CertRecordsDir = "/var/lib/sensible/certs"

// CertRecord adds a certificate's paths to its record. It's listed ahead of
// the files, so a failed run can't leave a private key nothing knows about.
// Certificates can be written anywhere, including directories sensible
// doesn't otherwise own, so only the recorded files can be cleaned up.
type CertRecord struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

// CertRecords removes the recorded files that no File in the same run
// declared, along with the records of certificates that are gone. It's
// skipped if anything on the host failed.
type CertRecords struct{}

func (r CertRecord) ID() string { return "cert-record:" + r.Name }

func (r CertRecords) ID() string { return "cert-records" }

func (r CertRecord) Check(_ context.Context, sys Sys) (Change, error) {
	rec, err := readCertRecord(sys, r.Name)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, path := range r.Paths {
		if !slices.Contains(rec.Paths, path) {
			diff.WriteString("record " + path + "\n")
		}
	}
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r CertRecord) Apply(_ context.Context, sys Sys) error {
	rec, err := readCertRecord(sys, r.Name)
	if err != nil {
		return err
	}
	rec.Paths = append(rec.Paths, r.Paths...)
	slices.Sort(rec.Paths)
	rec.Paths = slices.Compact(rec.Paths)
	return writeCertRecord(sys, r.Name, rec)
}

func (r CertRecords) Check(ctx context.Context, sys Sys) (Change, error) {
	cleanups, err := r.cleanups(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, c := range cleanups {
		for _, path := range c.stale {
			diff.WriteString("remove " + path + "\n")
		}
		if !c.declared {
			diff.WriteString("forget certificate " + c.name + "\n")
		}
	}
	return Change{InSync: len(cleanups) == 0, Diff: diff.String()}, nil
}

func (r CertRecords) Apply(ctx context.Context, sys Sys) error {
	cleanups, err := r.cleanups(ctx, sys)
	if err != nil {
		return err
	}
	declared := state(ctx).declared
	for _, c := range cleanups {
		for _, path := range c.stale {
			if err := sys.RemoveAll(path); err != nil {
				return err
			}
			if err := removeIfEmpty(sys, filepath.Dir(path), declared); err != nil {
				return err
			}
		}
		if !c.declared {
			if err := sys.RemoveAll(filepath.Join(CertRecordsDir, c.name)); err != nil {
				return err
			}
			continue
		}
		if err := writeCertRecord(sys, c.name, certRecord{Paths: c.kept}); err != nil {
			return err
		}
	}
	return nil
}

// certCleanup is what's left to do for a record.
type certCleanup struct {
	name string
	// declared is whether the certificate is still on the host.
	declared bool
	stale    []string
	kept     []string
}

func (r CertRecords) cleanups(ctx context.Context, sys Sys) ([]certCleanup, error) {
	names, err := sys.ReadDir(CertRecordsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	declared := state(ctx).declared
	var out []certCleanup
	for _, name := range names {
		rec, err := readCertRecord(sys, name)
		if err != nil {
			return nil, err
		}
		c := certCleanup{name: name, declared: declared[filepath.Join(CertRecordsDir, name)]}
		for _, path := range rec.Paths {
			// Another certificate may have taken over a path this one left.
			if declared[path] {
				c.kept = append(c.kept, path)
			} else {
				c.stale = append(c.stale, path)
			}
		}
		if len(c.stale) > 0 || !c.declared {
			out = append(out, c)
		}
	}
	return out, nil
}

// removeIfEmpty removes a directory a certificate has left, unless something
// else is using it.
func removeIfEmpty(sys Sys, dir string, declared map[string]bool) error {
	if declared[dir] {
		return nil
	}
	names, err := sys.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(names) > 0) {
		return nil
	}
	if err != nil {
		return err
	}
	return sys.RemoveAll(dir)
}

type certRecord struct {
	Paths []string `json:"paths"`
}

func certRecordPath(name string) string {
	return filepath.Join(CertRecordsDir, name, "record.json")
}

func readCertRecord(sys Sys, name string) (certRecord, error) {
	data, err := sys.ReadFile(certRecordPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return certRecord{}, nil
	}
	if err != nil {
		return certRecord{}, err
	}
	var rec certRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return certRecord{}, fmt.Errorf("parsing %s: %w", certRecordPath(name), err)
	}
	return rec, nil
}

func writeCertRecord(sys Sys, name string, rec certRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := certRecordPath(name)
	if err := sys.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return sys.WriteFile(path, append(data, '\n'), WriteOptions{UID: -1, GID: -1, Mode: 0o600})
}
