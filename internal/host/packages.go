package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
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
	if family == familyArch {
		if r.Absent {
			_, err = runOK(ctx, sys, argv("pacman", "-R", "--noconfirm", r.Name))
			return err
		}
		res, err := runOK(ctx, sys, argv("pacman", "-S", "--needed", "--noconfirm", r.Name))
		// Mirrors only keep current versions, so a stale sync database
		// names files they've deleted.
		if out := output(res); err != nil && strings.Contains(out, "failed retrieving file") && strings.Contains(out, "404") {
			return fmt.Errorf("%w\npacman's sync database is out of date; run pacman -Syu on the host", err)
		}
		return err
	}

	if r.Absent {
		_, err = runOK(ctx, sys, aptGet("remove", r.Name))
		return err
	}
	if err := refreshAptIndex(ctx, sys); err != nil {
		return err
	}
	target := r.Name
	if r.Deb != "" {
		target = r.Deb
	}
	_, err = runOK(
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
		return Change{}, fmt.Errorf(
			"%s isn't in pacman's sync database; if it's a new package, run pacman -Syu on the host",
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

// aptIndexStale reports whether the index is over an hour old, or older than
// a source, as when a run added a repository then failed before updating.
func aptIndexStale(sys Sys) (bool, error) {
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

// aptSourcesModified returns when an apt source file last changed.
func aptSourcesModified(sys Sys) (time.Time, error) {
	paths := []string{"/etc/apt/sources.list"}
	names, err := sys.ReadDir("/etc/apt/sources.list.d")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, err
	}
	for _, n := range names {
		paths = append(paths, "/etc/apt/sources.list.d/"+n)
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

type dpkgPackage struct {
	version string
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
	for stanza := range strings.SplitSeq(string(data), "\n\n") {
		fields := map[string]string{}
		for line := range strings.Lines(stanza) {
			if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, " ") {
				fields[k] = strings.TrimSpace(v)
			}
		}
		if status := strings.Fields(fields["Status"]); len(status) == 3 && status[2] == "installed" {
			installed[fields["Package"]] = dpkgPackage{version: fields["Version"]}
		}
	}
	st.dpkg = installed
	return installed, nil
}

type pacmanDB struct {
	installed map[string]bool
	// satisfied includes what installed packages provide.
	satisfied map[string]bool
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

	db := &pacmanDB{installed: map[string]bool{}, satisfied: map[string]bool{}}
	for _, entry := range entries {
		desc, err := sys.ReadFile(filepath.Join(pacmanLocalDB, entry, "desc"))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		section := ""
		scanner := bufio.NewScanner(strings.NewReader(string(desc)))
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
				section = line
			case line == "":
				section = ""
			case section == "%NAME%":
				db.installed[line] = true
				db.satisfied[line] = true
			case section == "%PROVIDES%":
				name, _, _ := strings.Cut(line, "=")
				db.satisfied[name] = true
			}
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
	_, err := runOK(
		ctx,
		sys,
		Cmd{
			Argv: []string{"paru", "-S", "--needed", "--noconfirm", "--skipreview", "--removemake", r.Name},
			User: r.BuildUser,
		},
	)
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
