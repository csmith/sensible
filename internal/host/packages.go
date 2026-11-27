package host

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"chameth.com/x/text"
)

const (
	familyArch   = "arch"
	familyDebian = "debian"
)

// OSFamilies are the values Facts.OSFamily can take.
var OSFamilies = []string{familyArch, familyDebian}

func (r Package) Check(ctx context.Context, sys Sys) (Change, error) {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if family == familyArch {
		return r.checkPacman(ctx, sys)
	}
	return r.checkApt(ctx, sys)
}

func (r Package) Apply(ctx context.Context, sys Sys) error {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return err
	}
	if r.Absent {
		if err := removePackage(ctx, sys, family, r.Name); err != nil {
			return err
		}
		return forgetPackage(sys, r.Name)
	}
	if !r.Record {
		return r.install(ctx, sys, family)
	}
	installed, err := packageInstalled(ctx, sys, family, r.Name)
	if err != nil {
		return err
	}
	if err := r.install(ctx, sys, family); err != nil || installed {
		return err
	}
	return recordPackage(sys, r.Name)
}

func (r Package) install(ctx context.Context, sys Sys, family string) error {
	if family == familyArch {
		res, err := runPacman(ctx, sys, argv("pacman", "-S", "--needed", "--noconfirm", r.Name))
		return explainStaleSyncDB(res, err)
	}
	if err := refreshAptIndex(ctx, sys); err != nil {
		return err
	}
	target := r.Name
	if r.Deb != "" {
		target = r.Deb
	}
	_, err := runOK(
		ctx,
		sys,
		aptGet("install", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", target),
	)
	return err
}

func (r Package) checkPacman(ctx context.Context, sys Sys) (Change, error) {
	if r.Deb != "" {
		return Change{}, errors.New("local .deb packages can only be installed on Debian")
	}
	db, err := pacman(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	switch {
	case r.Absent && db.installed[r.Name]:
		return drift("remove package\n"), nil
	case !r.Absent && !db.satisfied[r.Name]:
		return r.checkPacmanSync(ctx, sys)
	default:
		return Change{InSync: true}, nil
	}
}

// checkPacmanSync looks for the package, or a group or package providing
// it, in pacman's sync database.
func (r Package) checkPacmanSync(ctx context.Context, sys Sys) (Change, error) {
	res, err := runOK(ctx, sys, argv("pacman", "-Sp", "--noconfirm", "--print-format", "%n", r.Name))
	if err != nil && strings.Contains(res.Stderr, "target not found") {
		if pacmanSyncChanged(state(ctx)) {
			return Change{}, fmt.Errorf("%s isn't in pacman's sync database: %w", r.Name, ErrNotYetCheckable)
		}
		return Change{}, fmt.Errorf(
			"%s isn't in pacman's sync database; if it's a new package, run pacman -Syu on the host, "+
				"or apply with --update-packages",
			r.Name,
		)
	}
	if err != nil {
		return Change{}, err
	}
	return drift("install package\n"), nil
}

// pacmanSyncChanged reports whether a sync database was refreshed earlier in
// the run, or would be, so a package missing from it may be found after.
func pacmanSyncChanged(st *runState) bool {
	for id, modified := range st.modified {
		if modified && (id == PackageUpdate{}.ID() || strings.HasPrefix(id, "pacman-repo:")) {
			return true
		}
	}
	return false
}

func (r Package) checkApt(ctx context.Context, sys Sys) (Change, error) {
	installed, err := dpkg(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	current, isInstalled := installed[r.Name]

	switch {
	case r.Absent && isInstalled:
		return drift("remove package\n"), nil
	case r.Absent:
		return Change{InSync: true}, nil
	case r.Deb != "":
		return r.checkDeb(ctx, sys, current.version)
	case isInstalled:
		return Change{InSync: true}, nil
	}

	res, err := runOK(ctx, sys, argv("apt-cache", "policy", r.Name))
	if err != nil {
		return Change{}, err
	}
	for line := range strings.Lines(res.Stdout) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok && strings.TrimSpace(v) != "(none)" {
			return drift(fmt.Sprintf("install package (%s)\n", strings.TrimSpace(v))), nil
		}
	}
	stale, err := aptIndexStale(sys)
	if err != nil {
		return Change{}, err
	}
	if stale || state(ctx).aptSourcesChanged {
		return drift("install package, after refreshing the package index\n"), nil
	}
	return Change{}, fmt.Errorf("%s isn't in any configured repository: %w", r.Name, ErrNotYetCheckable)
}

func (r Package) checkDeb(ctx context.Context, sys Sys, installed string) (Change, error) {
	if _, err := sys.Stat(r.Deb); errors.Is(err, fs.ErrNotExist) {
		return Change{}, fmt.Errorf("%s doesn't exist yet: %w", r.Deb, ErrNotYetCheckable)
	} else if err != nil {
		return Change{}, err
	}
	res, err := runOK(ctx, sys, argv("dpkg-deb", "--field", r.Deb, "Version"))
	if err != nil {
		return Change{}, err
	}
	version := strings.TrimSpace(res.Stdout)
	switch installed {
	case version:
		return Change{InSync: true}, nil
	case "":
		return drift(fmt.Sprintf("install %s (%s)\n", r.Deb, version)), nil
	default:
		return drift(fmt.Sprintf("install %s (%s → %s)\n", r.Deb, installed, version)), nil
	}
}

// lockTimeout is how long to wait for another package manager, such as
// unattended-upgrades on a freshly booted host, to finish.
const lockTimeout = 5 * time.Minute

func aptGet(args ...string) Cmd {
	return Cmd{
		Argv: append(
			[]string{"apt-get", "-y", "-q", "-o", fmt.Sprintf("DPkg::Lock::Timeout=%d", int(lockTimeout.Seconds()))},
			args...,
		),
		Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"},
	}
}

// aptUpdate runs apt-get update, which doesn't wait for the lists lock
// as other commands wait for dpkg's, so it retries until the lock is free.
func aptUpdate(ctx context.Context, sys Sys) error {
	deadline := sys.Now().Add(lockTimeout)
	for {
		res, err := runOK(ctx, sys, aptGet("update"))
		if err == nil || !strings.Contains(output(res), "Could not get lock") || !sys.Now().Before(deadline) {
			return err
		}
		if err := sys.Sleep(ctx, lockPoll); err != nil {
			return err
		}
	}
}

const lockPoll = 5 * time.Second

// runPacman runs a command that locks pacman's database once no other
// pacman holds it. A lock left by a pacman that's no longer running is
// pacman's to report.
func runPacman(ctx context.Context, sys Sys, cmd Cmd) (Result, error) {
	deadline := sys.Now().Add(lockTimeout)
	for {
		held, err := pacmanLockHeld(sys)
		if err != nil {
			return Result{}, err
		}
		if !held {
			return runOK(ctx, sys, cmd)
		}
		if !sys.Now().Before(deadline) {
			return Result{}, fmt.Errorf("another pacman still holds %s after %s", pacmanLock, lockTimeout)
		}
		if err := sys.Sleep(ctx, lockPoll); err != nil {
			return Result{}, err
		}
	}
}

const pacmanLock = "/var/lib/pacman/db.lck"

func pacmanLockHeld(sys Sys) (bool, error) {
	if _, err := sys.Stat(pacmanLock); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	comms, err := sys.Glob("/proc/[0-9]*/comm")
	if err != nil {
		return false, err
	}
	for _, path := range comms {
		// Processes can exit between listing and reading.
		if comm, err := sys.ReadFile(path); err == nil && strings.TrimSpace(string(comm)) == "pacman" {
			return true, nil
		}
	}
	return false, nil
}

// refreshAptIndex runs apt-get update if the index is over an hour old, or
// a source changed earlier in the run.
func refreshAptIndex(ctx context.Context, sys Sys) error {
	st := state(ctx)
	stale := false
	if !st.aptUpdated {
		var err error
		if stale, err = aptIndexStale(sys); err != nil {
			return err
		}
	}
	if !stale && !st.aptSourcesChanged {
		return nil
	}
	if err := aptUpdate(ctx, sys); err != nil {
		return err
	}
	st.aptUpdated, st.aptSourcesChanged = true, false
	return nil
}

// aptIndexStale reports whether the index is missing, over an hour old, or
// older than a source, as when a run added a repository then failed before
// updating.
func aptIndexStale(sys Sys) (bool, error) {
	if fetched, err := aptListsFetched(sys); err != nil || !fetched {
		return !fetched, err
	}
	for _, path := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists"} {
		info, err := sys.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if sys.Now().Sub(info.ModTime) > time.Hour {
			return true, nil
		}
		sources, err := aptSourcesModified(sys)
		if err != nil {
			return false, err
		}
		return sources.After(info.ModTime), nil
	}
	return true, nil
}

// aptListsFetched reports whether apt-get update has fetched any repository.
// The lists directory's own age doesn't show that: images often empty it,
// leaving it newer than an hour with nothing in it.
func aptListsFetched(sys Sys) (bool, error) {
	names, err := sys.ReadDir("/var/lib/apt/lists")
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if strings.HasSuffix(name, "Release") {
			return true, nil
		}
	}
	return false, nil
}

// aptSourcesModified returns when an apt source file last changed.
func aptSourcesModified(sys Sys) (time.Time, error) {
	paths, err := aptSourcePaths(sys)
	if err != nil {
		return time.Time{}, err
	}
	var latest time.Time
	for _, p := range paths {
		info, err := sys.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return time.Time{}, err
		}
		if info.ModTime.After(latest) {
			latest = info.ModTime
		}
	}
	return latest, nil
}

// aptSourcePaths lists sources.list and the entries in AptSourcesDir.
func aptSourcePaths(sys Sys) ([]string, error) {
	paths := []string{AptSourcesList}
	names, err := sys.ReadDir(AptSourcesDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, n := range names {
		paths = append(paths, AptSourcesDir+"/"+n)
	}
	return paths, nil
}

type dpkgPackage struct {
	version string
	base    bool
	// depends names what the package depends or pre-depends on, including
	// every alternative.
	depends  []string
	provides []string
}

// dpkg returns the installed packages, reading dpkg's status file once per
// run until something changes.
func dpkg(ctx context.Context, sys Sys) (map[string]dpkgPackage, error) {
	st := state(ctx)
	if st.dpkg != nil {
		return st.dpkg, nil
	}
	data, err := sys.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}

	installed := map[string]dpkgPackage{}
	for _, fields := range controlStanzas(string(data)) {
		if status := strings.Fields(fields["Status"]); len(status) == 3 && status[2] == "installed" {
			installed[fields["Package"]] = dpkgPackage{
				version: fields["Version"],
				base: fields["Essential"] == "yes" ||
					fields["Priority"] == "required" ||
					fields["Priority"] == "important",
				depends:  dpkgRelationNames(fields["Depends"] + "," + fields["Pre-Depends"]),
				provides: dpkgRelationNames(fields["Provides"]),
			}
		}
	}
	st.dpkg = installed
	return installed, nil
}

// dpkgRelationNames returns the package names in a relationship field such
// as "libc6 (>= 2.34), foo:any | bar", leaving out versions and
// architectures.
func dpkgRelationNames(field string) []string {
	var names []string
	for rel := range strings.FieldsFuncSeq(field, func(r rune) bool { return r == ',' || r == '|' }) {
		if fields := strings.Fields(rel); len(fields) > 0 {
			name, _, _ := strings.Cut(fields[0], ":")
			name, _, _ = strings.Cut(name, "(")
			names = append(names, name)
		}
	}
	return names
}

// controlStanzas splits a file of dpkg control stanzas, such as dpkg's
// status file, into the fields of each. Continuation lines are skipped.
func controlStanzas(data string) []map[string]string {
	var stanzas []map[string]string
	for stanza := range strings.SplitSeq(data, "\n\n") {
		fields := map[string]string{}
		for line := range strings.Lines(stanza) {
			if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, " ") {
				fields[k] = strings.TrimSpace(v)
			}
		}
		stanzas = append(stanzas, fields)
	}
	return stanzas
}

type pacmanDB struct {
	installed map[string]bool
	// satisfied includes what installed packages provide.
	satisfied map[string]bool
	// explicit holds what each package installed explicitly, rather than
	// as a dependency, provides, including its own name.
	explicit map[string][]string
	// depended holds what installed packages depend on.
	depended map[string]bool
}

const pacmanLocalDB = "/var/lib/pacman/local"

// pacman reads pacman's local database once per run until something
// changes.
func pacman(ctx context.Context, sys Sys) (*pacmanDB, error) {
	st := state(ctx)
	if st.pacman != nil {
		return st.pacman, nil
	}
	entries, err := sys.ReadDir(pacmanLocalDB)
	if err != nil {
		return nil, err
	}

	db := &pacmanDB{
		installed: map[string]bool{},
		satisfied: map[string]bool{},
		explicit:  map[string][]string{},
		depended:  map[string]bool{},
	}
	for _, entry := range entries {
		desc, err := sys.ReadFile(filepath.Join(pacmanLocalDB, entry, "desc"))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		section, pkg, dependency := "", "", false
		var provides []string
		scanner := bufio.NewScanner(strings.NewReader(string(desc)))
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
				section = line
			case line == "":
				section = ""
			case section == "%NAME%":
				pkg = line
				db.installed[line] = true
				db.satisfied[line] = true
			case section == "%PROVIDES%":
				name, _, _ := strings.Cut(line, "=")
				db.satisfied[name] = true
				provides = append(provides, name)
			case section == "%DEPENDS%":
				if i := strings.IndexAny(line, "<>="); i >= 0 {
					line = line[:i]
				}
				db.depended[line] = true
			case section == "%REASON%":
				dependency = line == "1"
			}
		}
		if pkg != "" && !dependency {
			db.explicit[pkg] = append([]string{pkg}, provides...)
		}
	}
	st.pacman = db
	return db, nil
}

const (
	AptSourcesList = "/etc/apt/sources.list"
	AptSourcesDir  = "/etc/apt/sources.list.d"
	AptKeyringsDir = "/etc/apt/keyrings"
)

func (r AptRepo) Check(ctx context.Context, sys Sys) (Change, error) {
	key, keyPath, err := r.key(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	if r.SigningKey == "" {
		// The key's path is only known once it's downloaded.
		state(ctx).declared[keyPath] = true
		if current, err := sys.ReadFile(keyPath); errors.Is(err, fs.ErrNotExist) {
			diff.WriteString("add signing key " + keyPath + "\n")
		} else if err != nil {
			return Change{}, err
		} else if string(current) != string(key) {
			diff.WriteString("replace signing key " + keyPath + "\n")
		}
	}

	current, err := sys.ReadFile(r.sourcesPath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Change{}, err
	}
	diff.WriteString(text.UnifiedDiff(string(current), r.sources(keyPath), 3))
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r AptRepo) Apply(ctx context.Context, sys Sys) error {
	key, keyPath, err := r.key(ctx, sys)
	if err != nil {
		return err
	}
	unowned := ownership{uid: -1, gid: -1}
	if r.SigningKey == "" {
		if err := sys.MkdirAll(filepath.Dir(keyPath), defaultDirMode); err != nil {
			return err
		}
		if err := sys.WriteFile(keyPath, key, unowned.writeOptions(sys, keyPath, defaultFileMode)); err != nil {
			return err
		}
	}
	if err := sys.MkdirAll(AptSourcesDir, defaultDirMode); err != nil {
		return err
	}
	opts := unowned.writeOptions(sys, r.sourcesPath(), defaultFileMode)
	if err := sys.WriteFile(r.sourcesPath(), []byte(r.sources(keyPath)), opts); err != nil {
		return err
	}
	state(ctx).aptSourcesChanged = true
	return nil
}

func (r AptRepo) sourcesPath() string {
	return AptSourcesDir + "/" + r.Name + ".sources"
}

func (r AptRepo) sources(keyPath string) string {
	return fmt.Sprintf(
		"Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n",
		strings.Join(r.URIs, " "),
		strings.Join(r.Suites, " "),
		strings.Join(r.Components, " "),
		keyPath,
	)
}

// key downloads the signing key, returning it and the path it belongs at,
// which depends on whether it's armored. A local keyring is returned as its
// path alone.
func (r AptRepo) key(ctx context.Context, sys Sys) ([]byte, string, error) {
	if r.SigningKey != "" {
		return nil, r.SigningKey, nil
	}
	key, err := sys.Fetch(ctx, r.SigningKeyURL)
	if err != nil {
		return nil, "", err
	}
	ext := "gpg"
	if strings.HasPrefix(strings.TrimSpace(string(key)), "-----BEGIN PGP") {
		ext = "asc"
	}
	return key, AptKeyringsDir + "/" + r.Name + "." + ext, nil
}

func (r DisownedAptSources) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	return leftoverWarning(ctx, r.ID(), extra, "no apt repo declares these"), err
}

func (r DisownedAptSources) Apply(context.Context, Sys) error { return nil }

func (r DisownedAptSources) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	declared := state(ctx).declared
	sources, err := undeclaredIn(sys, declared, AptSourcesDir, false)
	if err != nil {
		return nil, err
	}
	keys, err := undeclaredIn(sys, declared, AptKeyringsDir, false)
	if err != nil {
		return nil, err
	}
	if r.SourcesList {
		listed, err := listsRepos(sys, AptSourcesList)
		if err != nil {
			return nil, err
		}
		if listed {
			sources = append([]string{AptSourcesList}, sources...)
		}
	}
	// Removing a key that a source still refers to would break the source.
	paths, err := aptSourcePaths(sys)
	if err != nil {
		return nil, err
	}
	var referenced strings.Builder
	for _, path := range paths {
		info, err := sys.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsRegular() {
			continue
		}
		content, err := sys.ReadFile(path)
		if err != nil {
			return nil, err
		}
		referenced.Write(content)
		referenced.WriteByte('\n')
	}
	for _, key := range keys {
		if !strings.Contains(referenced.String(), key) {
			sources = append(sources, key)
		}
	}
	return sources, nil
}

func (r DisownedAptSources) Prune(_ context.Context, sys Sys, item string) error {
	return sys.RemoveAll(item)
}

// listsRepos reports whether the one-line-style sources file at path has
// any deb or deb-src lines that aren't commented out.
func listsRepos(sys Sys, path string) (bool, error) {
	data, err := sys.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for line := range strings.Lines(string(data)) {
		if fields := strings.Fields(line); len(fields) > 0 && (fields[0] == "deb" || fields[0] == "deb-src") {
			return true, nil
		}
	}
	return false, nil
}

const (
	PacmanConf     = "/etc/pacman.conf"
	PacmanReposDir = "/etc/pacman.d/sensible"
	pacmanKeyring  = "/etc/pacman.d/gnupg"
	pacmanSyncDir  = "/var/lib/pacman/sync"
)

func (r PacmanRepo) Check(ctx context.Context, sys Sys) (Change, error) {
	var diff strings.Builder
	if r.SigningKeyURL != "" {
		key, err := sys.Fetch(ctx, r.SigningKeyURL)
		if err != nil {
			return Change{}, err
		}
		keyDiff, err := r.keyDiff(ctx, sys, key)
		if err != nil {
			return Change{}, err
		}
		diff.WriteString(keyDiff)
	}
	current, err := readOptional(sys, r.confPath())
	if err != nil {
		return Change{}, err
	}
	diff.WriteString(text.UnifiedDiff(current, r.conf(), 3))
	synced, err := r.synced(sys)
	if err != nil {
		return Change{}, err
	}
	if current != r.conf() || !synced {
		diff.WriteString("refresh " + r.Name + "'s sync database\n")
	}
	conf, _, err := readForEdit(sys, PacmanConf)
	if err != nil {
		return Change{}, err
	}
	included, err := r.include().edit(conf)
	if err != nil {
		return Change{}, err
	}
	diff.WriteString(text.UnifiedDiff(conf, included, 3))
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

// Apply trusts the key before the repo's database is fetched, which needs
// it, and only adds the repo to pacman.conf once its database is fetched,
// so a repo that can't be reached doesn't break pacman.
func (r PacmanRepo) Apply(ctx context.Context, sys Sys) error {
	if r.SigningKeyURL != "" {
		if err := r.trustKey(ctx, sys); err != nil {
			return err
		}
	}
	if err := r.sync(ctx, sys); err != nil {
		return err
	}
	conf, info, err := readForEdit(sys, PacmanConf)
	if err != nil {
		return err
	}
	included, err := r.include().edit(conf)
	if err != nil || included == conf {
		return err
	}
	return writeEdited(sys, PacmanConf, included, info)
}

// trustKey saves the signing key and has pacman trust it, unless that's
// already done.
func (r PacmanRepo) trustKey(ctx context.Context, sys Sys) error {
	key, err := sys.Fetch(ctx, r.SigningKeyURL)
	if err != nil {
		return err
	}
	keyDiff, err := r.keyDiff(ctx, sys, key)
	if err != nil || keyDiff == "" {
		return err
	}
	if err := sys.MkdirAll(PacmanReposDir, defaultDirMode); err != nil {
		return err
	}
	unowned := ownership{uid: -1, gid: -1}
	if err := sys.WriteFile(r.keyPath(), key, unowned.writeOptions(sys, r.keyPath(), defaultFileMode)); err != nil {
		return err
	}
	// Locally signing needs pacman's own key, which hosts made from some
	// images, such as Arch's for Docker, don't have yet. --init only makes
	// one if it's missing.
	for _, args := range [][]string{
		{"--init"},
		{"--add", r.keyPath()},
		{"--lsign-key", r.SigningKeyID},
	} {
		if _, err := runOK(ctx, sys, argv(append([]string{"pacman-key"}, args...)...)); err != nil {
			return err
		}
	}
	return nil
}

// sync refreshes the repo's sync database if its section changed or it was
// never fetched, then writes the section.
func (r PacmanRepo) sync(ctx context.Context, sys Sys) error {
	current, err := readOptional(sys, r.confPath())
	if err != nil {
		return err
	}
	synced, err := r.synced(sys)
	if err != nil {
		return err
	}
	if current != r.conf() || !synced {
		// The section alone is the config, so no other repo is refreshed.
		// It's read from stdin, so the file is only written once it works.
		_, err := runPacman(
			ctx,
			sys,
			Cmd{
				Argv:  []string{"pacman", "--config", "/dev/stdin", "--arch", "auto", "-Sy", "--noconfirm"},
				Stdin: r.conf(),
			},
		)
		if err != nil {
			return err
		}
	}
	if current == r.conf() {
		return nil
	}
	if err := sys.MkdirAll(PacmanReposDir, defaultDirMode); err != nil {
		return err
	}
	opts := ownership{uid: -1, gid: -1}.writeOptions(sys, r.confPath(), defaultFileMode)
	return sys.WriteFile(r.confPath(), []byte(r.conf()), opts)
}

func (r PacmanRepo) confPath() string { return PacmanReposDir + "/" + r.Name + ".conf" }

func (r PacmanRepo) keyPath() string { return PacmanReposDir + "/" + r.Name + ".key" }

func (r PacmanRepo) conf() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\nSigLevel = %s\n", r.Name, r.SigLevel)
	for _, server := range r.Servers {
		fmt.Fprintf(&b, "Server = %s\n", server)
	}
	return b.String()
}

// include is the line in pacman.conf that adds the repo. Appended, it comes
// after the distribution's repos, so theirs win when both have a package.
func (r PacmanRepo) include() LineInFile {
	return pacmanInclude(r.confPath())
}

func pacmanInclude(path string) LineInFile {
	return LineInFile{
		Path:   PacmanConf,
		Regexp: `^\s*Include\s*=\s*` + regexp.QuoteMeta(path) + `\s*$`,
		Line:   "Include = " + path,
	}
}

// readOptional reads a file that may not exist yet as empty.
func readOptional(sys Sys, path string) (string, error) {
	data, err := sys.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return string(data), err
}

// synced reports whether the repo's sync database has been fetched.
func (r PacmanRepo) synced(sys Sys) (bool, error) {
	_, err := sys.Stat(pacmanSyncDir + "/" + r.Name + ".db")
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// keyDiff describes how the saved key differs from key, or that pacman
// doesn't trust it yet.
func (r PacmanRepo) keyDiff(ctx context.Context, sys Sys, key []byte) (string, error) {
	current, err := sys.ReadFile(r.keyPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "add signing key " + r.keyPath() + "\n", nil
	case err != nil:
		return "", err
	case string(current) != string(key):
		return "replace signing key " + r.keyPath() + "\n", nil
	}
	trusted, err := pacmanKeyTrusted(ctx, sys, r.SigningKeyID)
	if err != nil || trusted {
		return "", err
	}
	return "trust signing key " + r.SigningKeyID + "\n", nil
}

func pacmanGPG(args ...string) Cmd {
	return argv(
		slices.Concat(
			[]string{"gpg", "--homedir", pacmanKeyring, "--no-permission-warning", "--batch", "--with-colons"},
			args,
		)...,
	)
}

// pacmanKeyTrusted reports whether pacman's keyring has a key matching id
// with full or ultimate validity, as a key locally signed by pacman's own
// key has.
func pacmanKeyTrusted(ctx context.Context, sys Sys, id string) (bool, error) {
	res, err := sys.Run(ctx, pacmanGPG("--list-keys", id))
	if err != nil {
		return false, err
	}
	if res.Code != 0 {
		return false, nil
	}
	for line := range strings.Lines(res.Stdout) {
		if fields := strings.Split(line, ":"); len(fields) > 1 &&
			fields[0] == "pub" &&
			(fields[1] == "f" || fields[1] == "u") {
			return true, nil
		}
	}
	return false, nil
}

func (r DisownedPacmanRepos) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	return leftoverWarning(ctx, r.ID(), extra, "no pacman repo declares these"), err
}

func (r DisownedPacmanRepos) Apply(context.Context, Sys) error { return nil }

func (r DisownedPacmanRepos) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	return undeclaredIn(sys, state(ctx).declared, PacmanReposDir, false)
}

func (r DisownedPacmanRepos) Prune(ctx context.Context, sys Sys, item string) error {
	if name, ok := strings.CutSuffix(filepath.Base(item), ".conf"); ok {
		if err := unincludePacmanRepo(sys, item); err != nil {
			return err
		}
		for _, ext := range []string{".db", ".db.sig", ".files", ".files.sig"} {
			if err := sys.RemoveAll(pacmanSyncDir + "/" + name + ext); err != nil {
				return err
			}
		}
	}
	if strings.HasSuffix(item, ".key") {
		if err := untrustPacmanKey(ctx, sys, item); err != nil {
			return err
		}
	}
	return sys.RemoveAll(item)
}

// unincludePacmanRepo removes the line including the repo section at path
// from pacman.conf.
func unincludePacmanRepo(sys Sys, path string) error {
	conf, info, err := readForEdit(sys, PacmanConf)
	if errors.Is(err, ErrNotYetCheckable) {
		return nil
	}
	if err != nil {
		return err
	}
	include := pacmanInclude(path)
	include.Absent = true
	edited, err := include.edit(conf)
	if err != nil || edited == conf {
		return err
	}
	return writeEdited(sys, PacmanConf, edited, info)
}

// untrustPacmanKey removes the keys in the file at path from pacman's
// keyring, other than those another key file in PacmanReposDir holds, as
// repos can share a key.
func untrustPacmanKey(ctx context.Context, sys Sys, path string) error {
	removing, err := pacmanKeyFingerprints(ctx, sys, path)
	if err != nil {
		return err
	}
	others, err := sys.Glob(PacmanReposDir + "/*.key")
	if err != nil {
		return err
	}
	for _, other := range others {
		if other == path {
			continue
		}
		kept, err := pacmanKeyFingerprints(ctx, sys, other)
		if err != nil {
			return err
		}
		removing = slices.DeleteFunc(removing, func(fpr string) bool { return slices.Contains(kept, fpr) })
	}
	for _, fpr := range removing {
		res, err := sys.Run(ctx, pacmanGPG("--list-keys", fpr))
		if err != nil {
			return err
		}
		if res.Code != 0 {
			continue
		}
		if _, err := runOK(ctx, sys, argv("pacman-key", "--delete", fpr)); err != nil {
			return err
		}
	}
	return nil
}

// pacmanKeyFingerprints lists the primary keys in the key file at path.
func pacmanKeyFingerprints(ctx context.Context, sys Sys, path string) ([]string, error) {
	res, err := runOK(ctx, sys, pacmanGPG("--show-keys", path))
	if err != nil {
		return nil, err
	}
	var fprs []string
	primary := false
	for line := range strings.Lines(res.Stdout) {
		fields := strings.Split(strings.TrimSuffix(line, "\n"), ":")
		switch {
		case fields[0] == "pub":
			primary = true
		case fields[0] == "fpr" && primary && len(fields) > 9:
			fprs = append(fprs, fields[9])
			primary = false
		case fields[0] != "fpr":
			primary = false
		}
	}
	return fprs, nil
}

func (r AURPackage) Check(ctx context.Context, sys Sys) (Change, error) {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if family != familyArch {
		return Change{}, errors.New("the AUR is only available on Arch Linux")
	}
	db, err := pacman(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if db.satisfied[r.Name] {
		return Change{InSync: true}, nil
	}
	if _, err := sys.LookupUser(r.BuildUser); errors.Is(err, fs.ErrNotExist) {
		return Change{}, fmt.Errorf("build user %s doesn't exist yet: %w", r.BuildUser, ErrNotYetCheckable)
	} else if err != nil {
		return Change{}, err
	}
	return drift("install package from the AUR\n"), nil
}

func (r AURPackage) Apply(ctx context.Context, sys Sys) error {
	installed := false
	if r.Record {
		db, err := pacman(ctx, sys)
		if err != nil {
			return err
		}
		installed = db.installed[r.Name]
	}
	res, err := runPacman(
		ctx,
		sys,
		Cmd{
			Argv: []string{"paru", "-S", "--needed", "--noconfirm", "--skipreview", "--removemake", r.Name},
			User: r.BuildUser,
		},
	)
	if err := explainStaleSyncDB(res, err); err != nil {
		return err
	}
	if r.Record && !installed {
		return recordPackage(sys, r.Name)
	}
	return nil
}

// explainStaleSyncDB advises a pacman -Syu after a 404 from the mirrors.
func explainStaleSyncDB(res Result, err error) error {
	// Mirrors only keep current versions, so a stale sync database names
	// files they've deleted.
	if out := output(res); err != nil &&
		strings.Contains(out, "failed retrieving file") &&
		strings.Contains(out, "404") {
		return fmt.Errorf("%w\n%s", err, staleSyncDBAdvice)
	}
	return err
}

const staleSyncDBAdvice = "pacman's sync database is out of date; run pacman -Syu on the host, " +
	"or apply with --update-packages"

func (r PackageUpdate) Check(ctx context.Context, sys Sys) (Change, error) {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	if family == familyArch {
		return drift("update all packages with pacman -Syu\n"), nil
	}
	return drift("update all packages with apt-get full-upgrade\n"), nil
}

func (r PackageUpdate) Apply(ctx context.Context, sys Sys) error {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return err
	}
	if family == familyArch {
		_, err := runPacman(ctx, sys, argv("pacman", "-Syu", "--noconfirm"))
		return err
	}
	st := state(ctx)
	if err := aptUpdate(ctx, sys); err != nil {
		return err
	}
	st.aptUpdated = true
	_, err = runOK(
		ctx,
		sys,
		aptGet("full-upgrade", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"),
	)
	return err
}

// appliedWarning says when the running kernel isn't the newest installed
// one of its flavour, or isn't installed at all any more, as after Arch
// upgrades it.
func (r PackageUpdate) appliedWarning(ctx context.Context, sys Sys) string {
	warning, err := rebootWarning(ctx, sys)
	if err != nil {
		return "couldn't tell whether the host needs a reboot: " + err.Error() + "\n"
	}
	return warning
}

func rebootWarning(ctx context.Context, sys Sys) (string, error) {
	res, err := runOK(ctx, sys, argv("uname", "-r"))
	if err != nil {
		return "", err
	}
	running := strings.TrimSpace(res.Stdout)
	installed, err := installedKernels(sys)
	if err != nil {
		return "", err
	}
	newest := ""
	for _, k := range installed {
		if kernelFlavour(k) == kernelFlavour(running) && (newest == "" || compareVersions(k, newest) > 0) {
			newest = k
		}
	}
	switch {
	case len(installed) == 0:
		// A container's kernel belongs to its host.
		return "", nil
	case newest != "" && compareVersions(newest, running) > 0:
		return fmt.Sprintf(
			"the host needs a reboot to run its newest kernel, %s, instead of %s\n",
			newest,
			running,
		), nil
	case !slices.Contains(installed, running):
		return fmt.Sprintf("the host needs a reboot, as its running kernel, %s, is no longer installed\n", running), nil
	default:
		return "", nil
	}
}

// installedKernels are the releases with modules in /lib/modules. A release
// whose package has gone can leave behind files it didn't own, but not its
// kernel directory.
func installedKernels(sys Sys) ([]string, error) {
	names, err := sys.ReadDir("/lib/modules")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var kernels []string
	for _, name := range names {
		if info, err := sys.Stat(filepath.Join("/lib/modules", name, "kernel")); err == nil && info.Mode.IsDir() {
			kernels = append(kernels, name)
		}
	}
	return kernels, nil
}

// kernelFlavour is what follows a release's last hyphen, e.g. "amd64".
func kernelFlavour(release string) string {
	return release[strings.LastIndex(release, "-")+1:]
}

// compareVersions compares a and b with runs of digits compared as numbers.
func compareVersions(a, b string) int {
	for a != "" && b != "" {
		da, db := leadingDigits(a), leadingDigits(b)
		switch {
		case da != "" && db != "":
			na, nb := strings.TrimLeft(da, "0"), strings.TrimLeft(db, "0")
			if c := cmp.Compare(len(na), len(nb)); c != 0 {
				return c
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
			a, b = a[len(da):], b[len(db):]
		case a[0] != b[0]:
			return cmp.Compare(a[0], b[0])
		default:
			a, b = a[1:], b[1:]
		}
	}
	return cmp.Compare(len(a), len(b))
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func (r DisownedPackages) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.Leftovers(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	change := leftoverWarning(ctx, r.ID(), extra, "nothing declares these")
	gone, err := r.goneRecords(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	for _, name := range gone {
		change.InSync = false
		change.Diff += "forget record of package " + name + "\n"
	}
	return change, nil
}

// Apply forgets the records of packages that have been removed since they
// were installed. It never removes the packages themselves.
func (r DisownedPackages) Apply(ctx context.Context, sys Sys) error {
	gone, err := r.goneRecords(ctx, sys)
	if err != nil {
		return err
	}
	for _, name := range gone {
		if err := forgetPackage(sys, name); err != nil {
			return err
		}
	}
	return nil
}

// Leftovers lists each undeclared package that's installed and either
// recorded or installed by hand, as "package <name>".
func (r DisownedPackages) Leftovers(ctx context.Context, sys Sys) ([]string, error) {
	var extra []string
	err := eachRecorded(
		ctx,
		sys,
		func(name string, installed bool) {
			if installed {
				extra = append(extra, "package "+name)
			}
		},
	)
	if err != nil {
		return nil, err
	}
	manual, err := manualPackages(ctx, sys)
	if err != nil {
		return nil, err
	}
	for _, name := range manual {
		if item := "package " + name; !slices.Contains(extra, item) {
			extra = append(extra, item)
		}
	}
	return extra, nil
}

// manualPackages lists the installed packages that nothing earlier in the
// run declares, that were installed explicitly rather than as a dependency,
// and that no installed package depends on: those `pacman -Qqet` lists, or
// the Debian equivalent. A package that provides a depended-on name counts
// as depended on and, on Arch, one that provides a declared name counts as
// declared. On Debian, the base system is left out too, as images mark much
// of it manually installed.
func manualPackages(ctx context.Context, sys Sys) ([]string, error) {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return nil, err
	}
	declared := state(ctx).packages
	var manual []string
	if family == familyArch {
		db, err := pacman(ctx, sys)
		if err != nil {
			return nil, err
		}
		for name, provides := range db.explicit {
			if !slices.ContainsFunc(provides, func(p string) bool { return declared[p] || db.depended[p] }) {
				manual = append(manual, name)
			}
		}
		slices.Sort(manual)
		return manual, nil
	}
	installed, err := dpkg(ctx, sys)
	if err != nil {
		return nil, err
	}
	auto, err := aptAutoInstalled(sys)
	if err != nil {
		return nil, err
	}
	depended := map[string]bool{}
	for _, pkg := range installed {
		for _, dep := range pkg.depends {
			depended[dep] = true
		}
	}
	for name, pkg := range installed {
		needed := depended[name] || slices.ContainsFunc(pkg.provides, func(p string) bool { return depended[p] })
		if !declared[name] && !auto[name] && !pkg.base && !needed {
			manual = append(manual, name)
		}
	}
	slices.Sort(manual)
	return manual, nil
}

// aptAutoInstalled returns the packages apt marks as installed
// automatically, as dependencies.
func aptAutoInstalled(sys Sys) (map[string]bool, error) {
	data, err := sys.ReadFile("/var/lib/apt/extended_states")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	auto := map[string]bool{}
	for _, fields := range controlStanzas(string(data)) {
		if fields["Auto-Installed"] == "1" {
			auto[fields["Package"]] = true
		}
	}
	return auto, nil
}

func (r DisownedPackages) Prune(ctx context.Context, sys Sys, item string) error {
	name, ok := strings.CutPrefix(item, "package ")
	if !ok || name == "" {
		return fmt.Errorf("%q isn't a package", item)
	}
	family, err := osFamily(ctx, sys)
	if err != nil {
		return err
	}
	if err := removePackage(ctx, sys, family, name); err != nil {
		return err
	}
	return forgetPackage(sys, name)
}

// goneRecords lists the undeclared packages that are recorded but no longer
// installed.
func (r DisownedPackages) goneRecords(ctx context.Context, sys Sys) ([]string, error) {
	var gone []string
	err := eachRecorded(
		ctx,
		sys,
		func(name string, installed bool) {
			if !installed {
				gone = append(gone, name)
			}
		},
	)
	return gone, err
}

// eachRecorded calls fn for each recorded package that nothing earlier in
// the run declares.
func eachRecorded(ctx context.Context, sys Sys, fn func(name string, installed bool)) error {
	names, err := sys.ReadDir(InstalledDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	family, err := osFamily(ctx, sys)
	if err != nil {
		return err
	}
	declared := state(ctx).packages
	for _, name := range names {
		if declared[name] {
			continue
		}
		installed, err := packageInstalled(ctx, sys, family, name)
		if err != nil {
			return err
		}
		fn(name, installed)
	}
	return nil
}

// InstalledDir holds a record of each package a Package or AURPackage with
// Record installed.
const InstalledDir = "/var/lib/sensible/packages"

func packageRecordPath(name string) string {
	return filepath.Join(InstalledDir, name)
}

func recordPackage(sys Sys, name string) error {
	if err := sys.MkdirAll(InstalledDir, 0o700); err != nil {
		return err
	}
	return sys.WriteFile(packageRecordPath(name), nil, WriteOptions{UID: -1, GID: -1, Mode: 0o600})
}

func forgetPackage(sys Sys, name string) error {
	if err := sys.RemoveAll(packageRecordPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func packageInstalled(ctx context.Context, sys Sys, family, name string) (bool, error) {
	if family == familyArch {
		db, err := pacman(ctx, sys)
		if err != nil {
			return false, err
		}
		return db.installed[name], nil
	}
	installed, err := dpkg(ctx, sys)
	if err != nil {
		return false, err
	}
	_, ok := installed[name]
	return ok, nil
}

func installedPackages(ctx context.Context, sys Sys) ([]string, error) {
	family, err := osFamily(ctx, sys)
	if err != nil {
		return nil, err
	}
	if family == familyArch {
		db, err := pacman(ctx, sys)
		if err != nil {
			return nil, err
		}
		return slices.Collect(maps.Keys(db.installed)), nil
	}
	installed, err := dpkg(ctx, sys)
	if err != nil {
		return nil, err
	}
	return slices.Collect(maps.Keys(installed)), nil
}

func removePackage(ctx context.Context, sys Sys, family, name string) error {
	if family == familyArch {
		_, err := runPacman(ctx, sys, argv("pacman", "-R", "--noconfirm", name))
		return err
	}
	_, err := runOK(ctx, sys, aptGet("remove", name))
	return err
}

// osFamily reads /etc/os-release once per run.
func osFamily(ctx context.Context, sys Sys) (string, error) {
	st := state(ctx)
	if st.osFamily != "" {
		return st.osFamily, nil
	}
	data, err := sys.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	facts, err := parseOSRelease(string(data))
	if err != nil {
		return "", err
	}
	st.osFamily = facts.OSFamily
	return facts.OSFamily, nil
}

// parseOSRelease returns the facts that come from os-release.
func parseOSRelease(data string) (Facts, error) {
	fields := map[string]string{}
	for line := range strings.Lines(data) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		fields[k] = strings.Trim(v, `"'`)
	}
	for _, id := range append([]string{fields["ID"]}, strings.Fields(fields["ID_LIKE"])...) {
		switch id {
		case familyArch:
			return Facts{OSFamily: familyArch, Distro: fields["ID"]}, nil
		case familyDebian:
			return Facts{OSFamily: familyDebian, Distro: fields["ID"], Release: fields["VERSION_CODENAME"]}, nil
		}
	}
	return Facts{}, fmt.Errorf("unsupported OS %q", fields["ID"])
}
