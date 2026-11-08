package host

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
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
		res, err := runOK(ctx, sys, argv("pacman", "-S", "--needed", "--noconfirm", r.Name))
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
		aptGet(
			"install",
			"-o",
			"Dpkg::Options::=--force-confdef",
			"-o",
			"Dpkg::Options::=--force-confold",
			target,
		),
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
		if state(ctx).modified[PackageUpdate{}.ID()] {
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

func aptGet(args ...string) Cmd {
	return Cmd{
		Argv: append([]string{"apt-get", "-y", "-q"}, args...),
		Env:  map[string]string{"DEBIAN_FRONTEND": "noninteractive"},
	}
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
	if _, err := runOK(ctx, sys, aptGet("update")); err != nil {
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
	paths := []string{"/etc/apt/sources.list"}
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
			}
		}
	}
	st.dpkg = installed
	return installed, nil
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

	db := &pacmanDB{installed: map[string]bool{}, satisfied: map[string]bool{}, explicit: map[string][]string{}}
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
	AptSourcesDir  = "/etc/apt/sources.list.d"
	AptKeyringsDir = "/etc/apt/keyrings"
)

func (r AptRepo) Check(ctx context.Context, sys Sys) (Change, error) {
	key, keyPath, err := r.key(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	// The key's path is only known once it's downloaded.
	state(ctx).declared[keyPath] = true
	var diff strings.Builder
	if current, err := sys.ReadFile(keyPath); errors.Is(err, fs.ErrNotExist) {
		diff.WriteString("add signing key " + keyPath + "\n")
	} else if err != nil {
		return Change{}, err
	} else if string(current) != string(key) {
		diff.WriteString("replace signing key " + keyPath + "\n")
	}

	current, err := sys.ReadFile(r.sourcesPath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Change{}, err
	}
	diff.WriteString(unifiedDiff(string(current), r.sources(keyPath)))
	return Change{InSync: diff.Len() == 0, Diff: diff.String()}, nil
}

func (r AptRepo) Apply(ctx context.Context, sys Sys) error {
	key, keyPath, err := r.key(ctx, sys)
	if err != nil {
		return err
	}
	unowned := ownership{uid: -1, gid: -1}
	if err := sys.MkdirAll(filepath.Dir(keyPath), defaultDirMode); err != nil {
		return err
	}
	if err := sys.WriteFile(keyPath, key, unowned.writeOptions(sys, keyPath, defaultFileMode)); err != nil {
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
// which depends on whether it's armored.
func (r AptRepo) key(ctx context.Context, sys Sys) ([]byte, string, error) {
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
	res, err := runOK(
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
	if out := output(res); err != nil && strings.Contains(out, "failed retrieving file") && strings.Contains(out, "404") {
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
		_, err := runOK(ctx, sys, argv("pacman", "-Syu", "--noconfirm"))
		return err
	}
	st := state(ctx)
	if _, err := runOK(ctx, sys, aptGet("update")); err != nil {
		return err
	}
	st.aptUpdated = true
	_, err = runOK(
		ctx,
		sys,
		aptGet(
			"full-upgrade",
			"-o",
			"Dpkg::Options::=--force-confdef",
			"-o",
			"Dpkg::Options::=--force-confold",
		),
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
		return fmt.Sprintf("the host needs a reboot to run its newest kernel, %s, instead of %s\n", newest, running), nil
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
// run declares, and that were installed explicitly rather than as a
// dependency: those `apt-mark showmanual` or `pacman -Qqe` list. On Arch, a
// package that provides a declared name counts as declared. On Debian, the
// base system is left out, as images mark much of it manually installed.
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
			if !slices.ContainsFunc(provides, func(p string) bool { return declared[p] }) {
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
	for name, pkg := range installed {
		if !declared[name] && !auto[name] && !pkg.base {
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

func removePackage(ctx context.Context, sys Sys, family, name string) error {
	if family == familyArch {
		_, err := runOK(ctx, sys, argv("pacman", "-R", "--noconfirm", name))
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
