package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/csmith/envflag/v2"

	"chameth.com/sensible/internal/host"
	"chameth.com/sensible/internal/run"
)

var (
	configDir = flag.String("config", ".", "Configuration directory")
	sourceDir = flag.String("source", "", "Source checkout to build agents from (default: found automatically)")
	debug     = flag.Bool("debug", false, "Show debugging output")
)

const usage = `Usage: sensible [flags] <command> [args]

Commands:
  bootstrap <host> [--user root|chris] [--rotate] [--host-key SHA256:...]
  plan [hosts...] [--addr host=address]
  apply [hosts...] [--addr host=address] [--yes]
  facts <host> [--addr host=address]
  config <host> [--os family] [--addr host=address]
  secret encrypt
  secret show <file> <path>
  agent

Flags:
`

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}
	envflag.Parse(envflag.WithPrefix("SENSIBLE_"))
	run.Debug = *debug

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if args[0] == "agent" {
		if err := host.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "agent: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := command(context.Background(), args[0], args[1:]); err != nil {
		if !errors.Is(err, errUsage) {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func command(ctx context.Context, name string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	addrs := addrFlag{}
	user, rotate, yes, osFamily, hostKey := new(string), new(bool), new(bool), new(string), new(string)
	switch name {
	case "bootstrap":
		user = fs.String("user", "", "Account to set the host up through: root or chris")
		rotate = fs.Bool("rotate", false, "Replace existing credentials")
		hostKey = fs.String("host-key", "", "Expected SHA256 fingerprint of a new host's key, instead of asking")
	case "plan", "facts", "config":
		fs.Var(addrs, "addr", "Address to use for a host, as host=address (repeatable)")
	case "apply":
		fs.Var(addrs, "addr", "Address to use for a host, as host=address (repeatable)")
		yes = fs.Bool("yes", false, "Apply without asking")
	default:
	}
	if name == "config" {
		osFamily = fs.String("os", "", "OS family to merge config for, instead of asking the host")
	}
	args = parse(fs, args)

	switch {
	case name == "bootstrap" && len(args) == 1:
		return run.Bootstrap(
			ctx,
			run.BootstrapOptions{
				ConfigDir: *configDir,
				SourceDir: *sourceDir,
				Host:      args[0],
				User:      *user,
				Rotate:    *rotate,
				HostKey:   *hostKey,
			},
		)
	case name == "plan" || name == "apply":
		return run.Run(
			ctx,
			run.Options{
				ConfigDir: *configDir,
				SourceDir: *sourceDir,
				Hosts:     args,
				Addrs:     addrs,
				Apply:     name == "apply",
				Yes:       *yes,
			},
		)
	case name == "facts" && len(args) == 1:
		return run.Facts(ctx, *configDir, *sourceDir, args[0], addrs[args[0]], os.Stdout)
	case name == "config" && len(args) == 1:
		return run.ShowConfig(ctx, *configDir, *sourceDir, args[0], *osFamily, addrs[args[0]], os.Stdout)
	case name == "secret" && len(args) == 1 && args[0] == "encrypt":
		return run.EncryptSecret(*configDir, os.Stdin, os.Stdout)
	case name == "secret" && len(args) == 3 && args[0] == "show":
		return run.ShowSecret(*configDir, args[1], args[2], os.Stdout)
	default:
		return badUsage("invalid arguments for " + name)
	}
}

func badUsage(msg string) error {
	_, _ = fmt.Fprintln(os.Stderr, msg)
	flag.Usage()
	return errUsage
}

// parse parses fs's flags wherever they appear among args, returning the
// other arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	envflag.Parse(envflag.WithFlagSet(fs), envflag.WithArguments(flags), envflag.WithPrefix("SENSIBLE_"))
	return positional
}

type addrFlag map[string]string

func (a addrFlag) String() string {
	parts := make([]string, 0, len(a))
	for name, addr := range a {
		parts = append(parts, name+"="+addr)
	}
	return strings.Join(parts, ",")
}

func (a addrFlag) Set(value string) error {
	name, addr, ok := strings.Cut(value, "=")
	if !ok || name == "" || addr == "" {
		return errors.New("must be host=address")
	}
	a[name] = addr
	return nil
}
