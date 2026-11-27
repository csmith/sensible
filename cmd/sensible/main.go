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
	debug     = flag.Bool("debug", false, "Show debugging output")
)

const usage = `Usage: sensible [flags] <command> [args]

Commands:
  bootstrap <host> [--user account | --bootstrap-key] [--rotate] [--host-key SHA256:...]
  bootstrap-binary -o <file> [--arch amd64|arm64]
  apply [hosts...] [--yes] [--update-packages]
  prune [hosts...]
  facts [hosts...]
  render [hosts...] [--facts file] [--json]
  secret encrypt [--raw]
  secret show <file>          List a file's !age paths, or decrypt a .age file
  secret show <file> <path>   Decrypt the !age value at path
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
	if len(args) == 0 && run.IsBootstrapBinary() {
		if err := run.SetUpForBootstrapKey(context.Background(), os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
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
	user, rotate, yes, hostKey, raw := new(string), new(bool), new(bool), new(string), new(bool)
	updatePackages := new(bool)
	facts, asJSON := new(string), new(bool)
	bootstrapKey, output, arch := new(bool), new(string), new(string)
	switch name {
	case "bootstrap":
		user = fs.String("user", "", "Account to set a remote host up through: root, or one with sudo")
		rotate = fs.Bool("rotate", false, "Replace existing credentials")
		hostKey = fs.String("host-key", "", "Expected SHA256 fingerprint of a new host's key, instead of asking")
		bootstrapKey = fs.Bool(
			"bootstrap-key",
			false,
			"Connect with the bootstrap key, for a host set up by a bootstrap binary",
		)
	case "bootstrap-binary":
		output = fs.String("o", "", "Write the binary to this `file`")
		arch = fs.String("arch", "amd64", "Architecture to build for: amd64 or arm64")
	case "apply":
		yes = fs.Bool("yes", false, "Apply without asking")
		updatePackages = fs.Bool("update-packages", false, "Bring each host's packages up to date first")
	case "render":
		facts = fs.String("facts", "", "Read facts from this `file`, as the facts command prints them")
		asJSON = fs.Bool("json", false, "Print JSON")
	case "secret":
		raw = fs.Bool(
			"raw",
			false,
			"Print an armored age file, e.g. for a stack's .age file, and keep piped input exactly",
		)
	default:
	}
	args = parse(fs, args)

	switch {
	case name == "bootstrap" && len(args) == 1:
		return run.Bootstrap(
			ctx,
			run.BootstrapOptions{
				ConfigDir: *configDir,
				Host:      args[0],
				User:      *user,
				Rotate:    *rotate,
				HostKey:   *hostKey,

				BootstrapKey: *bootstrapKey,
			},
		)
	case name == "bootstrap-binary" && len(args) == 0 && *output != "":
		return run.BootstrapBinary(
			ctx,
			run.BootstrapBinaryOptions{ConfigDir: *configDir, Output: *output, Arch: *arch},
		)
	case name == "apply":
		return run.Run(
			ctx,
			run.Options{
				ConfigDir: *configDir,
				Hosts:     args,
				Yes:       *yes,

				UpdatePackages: *updatePackages,
			},
		)
	case name == "prune":
		return run.Prune(ctx, run.PruneOptions{ConfigDir: *configDir, Hosts: args})
	case name == "facts":
		return run.Facts(ctx, *configDir, args, os.Stdout)
	case name == "render":
		return run.Render(
			ctx,
			run.RenderOptions{
				ConfigDir: *configDir,
				Hosts:     args,
				FactsFile: *facts,
				JSON:      *asJSON,
			},
			os.Stdout,
		)
	case name == "secret" && len(args) == 1 && args[0] == "encrypt":
		return run.EncryptSecret(*configDir, *raw, os.Stdin, os.Stdout)
	case name == "secret" && len(args) == 2 && args[0] == "show":
		return run.ShowSecret(*configDir, args[1], "", os.Stdout)
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
