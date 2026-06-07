package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	envdassets "github.com/envd/envd/internal/assets"
)

const version = "0.1.0-dev"

type app struct {
	stdout io.Writer
	stderr io.Writer
	root   string
}

type gatewayConfig struct {
	BindIP       string
	SOCKSPort    int
	HTTPHostPort int
	SOCKSInner   int
	HTTPInner    int
	ServerIP     string
	ServerPort   string
	Raw          map[string]string
}

const (
	devImage           = "sshdev:24.04"
	sidecarImage       = "devnet-sidecar:1"
	gatewayNet         = "vpn-gateway_inside"
	remoteXrayVersion  = "26.2.6"
	containerAssetsDir = "internal/assets/containers"
)

type assetSpec struct {
	Name        string
	Image       string
	ContextDir  string
	EmbeddedDir string
}

type runOptions struct {
	Name            string
	Network         string
	Storage         string
	Profile         string
	NetworkExplicit bool
	StorageExplicit bool
	ProfileExplicit bool
}

type projectManifest struct {
	Network string
	Storage string
	Profile string
}

type hostingCatalog struct {
	Version   int               `json:"version"`
	Providers []hostingProvider `json:"providers"`
}

type hostingProvider struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Homepage          string          `json:"homepage"`
	SignupURL         string          `json:"signup_url"`
	APIURL            *string         `json:"api_url"`
	CountriesSoldFrom []string        `json:"countries_sold_from"`
	Regions           []hostingRegion `json:"regions"`
	Payments          []string        `json:"payments"`
	MinPlan           hostingMinPlan  `json:"min_plan"`
	Notes             []string        `json:"notes"`
	Confidence        string          `json:"confidence"`
}

type hostingRegion struct {
	Code    string `json:"code"`
	Country string `json:"country"`
	City    string `json:"city"`
	ASN     string `json:"asn"`
}

type hostingMinPlan struct {
	CPU    int `json:"cpu"`
	RAMMB  int `json:"ram_mb"`
	DiskGB int `json:"disk_gb"`
}

type gatewayProvider interface {
	Name() string
	Render(app, gatewayConfig) ([]byte, error)
}

type xrayProvider struct{}

var runtimeAssets = []assetSpec{
	{Name: "dev image", Image: devImage, ContextDir: filepath.Join(containerAssetsDir, "sshdev"), EmbeddedDir: "containers/sshdev"},
	{Name: "net sidecar image", Image: sidecarImage, ContextDir: filepath.Join(containerAssetsDir, "net-sidecar"), EmbeddedDir: "containers/net-sidecar"},
}

const builtInHostingCatalogJSON = `{
  "version": 1,
  "providers": [
    {
      "id": "hetzner",
      "name": "Hetzner",
      "homepage": "https://www.hetzner.com",
      "signup_url": "https://accounts.hetzner.com/signUp",
      "api_url": "https://api.hetzner.cloud/v1/locations",
      "countries_sold_from": ["DE"],
      "regions": [
        { "code": "fsn1", "country": "DE", "city": "Falkenstein", "asn": "AS24940" },
        { "code": "hel1", "country": "FI", "city": "Helsinki", "asn": "AS24940" }
      ],
      "payments": ["card", "paypal"],
      "min_plan": { "cpu": 1, "ram_mb": 2048, "disk_gb": 20 },
      "notes": ["well-known provider", "useful baseline, not diversity by itself"],
      "confidence": "verified"
    },
    {
      "id": "ovhcloud",
      "name": "OVHcloud",
      "homepage": "https://www.ovhcloud.com",
      "signup_url": "https://www.ovhcloud.com/manager/",
      "api_url": "https://eu.api.ovh.com/1.0/",
      "countries_sold_from": ["FR"],
      "regions": [
        { "code": "gra", "country": "FR", "city": "Gravelines", "asn": "AS16276" },
        { "code": "waw", "country": "PL", "city": "Warsaw", "asn": "AS16276" }
      ],
      "payments": ["card", "paypal"],
      "min_plan": { "cpu": 1, "ram_mb": 2048, "disk_gb": 20 },
      "notes": ["large European provider", "different ASN from Hetzner"],
      "confidence": "verified"
    },
    {
      "id": "netcup",
      "name": "netcup",
      "homepage": "https://www.netcup.com",
      "signup_url": "https://www.netcup.com/en/server/",
      "api_url": null,
      "countries_sold_from": ["DE"],
      "regions": [
        { "code": "de", "country": "DE", "city": "Nuremberg", "asn": "AS197540" }
      ],
      "payments": ["card", "paypal", "bank-transfer"],
      "min_plan": { "cpu": 1, "ram_mb": 1024, "disk_gb": 20 },
      "notes": ["manual setup", "smaller ASN than the largest hyperscalers"],
      "confidence": "community"
    },
    {
      "id": "timeweb-cloud",
      "name": "Timeweb Cloud",
      "homepage": "https://timeweb.cloud",
      "signup_url": "https://timeweb.cloud/",
      "api_url": "https://api.timeweb.cloud/api/v1/",
      "countries_sold_from": ["RU"],
      "regions": [
        { "code": "nl", "country": "NL", "city": "Amsterdam", "asn": "unknown" },
        { "code": "pl", "country": "PL", "city": "Warsaw", "asn": "unknown" }
      ],
      "payments": ["local-card", "card"],
      "min_plan": { "cpu": 1, "ram_mb": 1024, "disk_gb": 15 },
      "notes": ["regional payment path", "verify current region availability before use"],
      "confidence": "community"
    }
  ]
}`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__unlock-agent" {
		if err := runUnlockAgentCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "__identity-agent" {
		if err := runStaticIdentityAgentCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
			os.Exit(1)
		}
		return
	}

	root, err := findRepoRoot()
	if err != nil {
		root, _ = os.Getwd()
	}

	a := app{stdout: os.Stdout, stderr: os.Stderr, root: root}
	if err := a.run(os.Args[1:]); err != nil {
		fmt.Fprintf(a.stderr, "ERROR: %s\n", redactSensitive(err.Error()))
		os.Exit(1)
	}
}

func (a app) run(args []string) error {
	if len(args) == 0 {
		a.printHelp()
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		if len(args) > 1 {
			return a.printCommandHelp(args[1:])
		}
		a.printHelp()
		return nil
	case "version", "--version":
		fmt.Fprintf(a.stdout, "envd %s\n", version)
		return nil
	case "init":
		return a.runInit(args[1:])
	case "unlock":
		return a.runUnlock(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "password":
		return a.runPassword(args[1:])
	case "reset-state":
		return a.runResetState(args[1:])
	default:
		if len(args) > 1 && isHelpArg(args[1]) {
			return a.printCommandHelp([]string{args[0]})
		}
	}

	switch args[0] {
	case "proxy":
		if len(args) > 1 && isHelpArg(args[1]) {
			return a.runProxy(args[1:], nil)
		}
		return a.withState(func(st *envdState) error { return a.runProxy(args[1:], st) })
	case "doctor":
		return a.withStateSaveOnError(func(st *envdState) error { return a.runDoctor(args[1:], st) })
	case "gateway":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.runGateway(args[1:], nil)
		}
		return a.withState(func(st *envdState) error { return a.runGateway(args[1:], st) })
	case "user":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"user"})
		}
		return a.withState(func(st *envdState) error { return a.runUser(args[1:], st) })
	case "internet":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"internet"})
		}
		return a.withState(func(st *envdState) error { return a.runInternet(args[1:], st) })
	case "hosting":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"hosting"})
		}
		return a.withState(func(st *envdState) error { return a.runHosting(args[1:], st) })
	case "identity":
		if len(args) > 1 && args[1] == "broker" {
			return a.runIdentityBroker(args[2:])
		}
		if len(args) > 1 && args[1] == "ssh-agent" {
			return a.runIdentitySSHAgent(args[2:])
		}
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"identity"})
		}
		return a.withState(func(st *envdState) error { return a.runIdentity(args[1:], st) })
	case "list":
		return a.withState(func(st *envdState) error { return a.listEnvs(args[1:], st) })
	case "inspect":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"inspect"})
		}
		return a.withState(func(st *envdState) error { return a.runInspect(args[1:], st) })
	case "start":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"start"})
		}
		return a.withState(func(st *envdState) error { return a.startOrCreateEnv(args[1:], st) })
	case "stop":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"stop"})
		}
		return a.withState(func(st *envdState) error { return a.stopEnv(args[1:], st) })
	case "rm":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"rm"})
		}
		return a.withState(func(st *envdState) error { return a.rmEnv(args[1:], st) })
	case "lock":
		return a.withState(func(st *envdState) error { return a.lockEnvd(args[1:], st) })
	case "shell":
		return a.runShell(args[1:])
	case "ssh-proxy":
		return a.runSSHProxy(args[1:])
	case "vscode-extensions":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"vscode-extensions"})
		}
		return a.runVSCodeExtensions(args[1:])
	case "network":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"network"})
		}
		return a.withStatePasswordSaveOnError(func(st *envdState, password []byte) error { return a.networkEnv(args[1:], st, password) })
	case "pkg":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"pkg"})
		}
		return a.withState(func(st *envdState) error { return a.runPkg(args[1:], st) })
	case "supervisor":
		return a.runSupervisor(args[1:])
	case "migrate":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"migrate"})
		}
		return a.withStatePasswordSaveOnError(func(st *envdState, password []byte) error { return a.runMigrate(args[1:], st, password) })
	case "events":
		return a.withState(func(st *envdState) error { return a.runEvents(args[1:], st) })
	case "why":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"why"})
		}
		return a.withState(func(st *envdState) error { return a.runWhy(args[1:], st) })
	default:
		return fmt.Errorf("unknown command %q\n\nRun envd help for available commands.", args[0])
	}
}

func isHelpArg(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "--help"
}

func (a app) runInit(args []string) error {
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(a.stdout, "Usage: envd init\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd init")
	}
	store, err := newStateStore()
	if err != nil {
		return err
	}
	path, err := store.init(a.stderr)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Initialized encrypted envd state: %s\n", path)
	return nil
}

func (a app) runUnlock(args []string) error {
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(a.stdout, "Usage: envd unlock\n\nRestores envd SSH targets/workloads after lock and caches the master password briefly.\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd unlock")
	}
	store, err := newStateStore()
	if err != nil {
		return err
	}
	st, ttl, cached, err := store.unlock(a.stderr)
	if err != nil {
		return err
	}
	_ = removeIdentityAgentSockets()
	restoreApp := a
	restoreApp.stdout = io.Discard
	restored, failed, restoreErr := restoreApp.restoreUnlockedEnvs()
	agents, agentErr := a.startUnlockedIdentityAgents(&st)
	_ = ttl
	_ = cached
	fmt.Fprintf(a.stdout, "Unlocked: %d envs\n", restored)
	if agents > 0 {
		fmt.Fprintf(a.stdout, "Identity: %d live\n", agents)
	}
	if failed > 0 {
		fmt.Fprintf(a.stdout, "Failed: %d\n", failed)
	}
	if restoreErr != nil {
		return restoreErr
	}
	if agentErr != nil {
		return agentErr
	}
	return nil
}

func (a app) runStatus(args []string) error {
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(a.stdout, "Usage: envd status\n\nShows non-secret runtime access state without opening encrypted state.\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd status")
	}
	access, err := loadRuntimeAccess()
	if err != nil {
		return err
	}
	accessState := "locked"
	if !access.Locked && len(access.Routes) > 0 {
		accessState = "unlocked"
	}
	cacheState := "expired"
	if _, ok := cachedMasterPassword(); ok {
		cacheState = "active"
	}
	gatewayState := dockerContainerStatus("vpn-gateway-xray-1")
	agentState := identityAgentRuntimeStatus(access)
	fmt.Fprintf(a.stdout, "Access:       %s\n", accessState)
	fmt.Fprintf(a.stdout, "SSH routes:   %d\n", len(access.Routes))
	fmt.Fprintf(a.stdout, "Master cache: %s\n", cacheState)
	if agentState != "" {
		fmt.Fprintf(a.stdout, "Identity:     %s\n", agentState)
	}
	fmt.Fprintf(a.stdout, "Gateway:      %s\n", gatewayState)
	if len(access.Routes) > 0 {
		names := make([]string, 0, len(access.Routes))
		for name := range access.Routes {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(a.stdout, "Envs:         %s\n", strings.Join(names, ", "))
	}
	return nil
}

func identityAgentRuntimeStatus(access runtimeAccessState) string {
	if len(access.Routes) == 0 {
		return ""
	}
	stale := []string{}
	live := 0
	for name := range access.Routes {
		socketPath, err := identityAgentSocketPath(name)
		if err != nil {
			continue
		}
		if _, err := os.Stat(socketPath); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if unixSocketAccepts(socketPath) {
			live++
			continue
		}
		stale = append(stale, name)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		return "stale for " + strings.Join(stale, ", ") + "; run envd unlock"
	}
	if live > 0 {
		return fmt.Sprintf("%d live", live)
	}
	return ""
}

func (a app) restoreUnlockedEnvs() (int, int, error) {
	restored := 0
	failed := 0
	var failures []string
	err := a.withState(func(st *envdState) error {
		for _, name := range sortedEnvNames(st) {
			ref, err := resolveEnvRef(st, name)
			if err != nil {
				continue
			}
			rec := st.Environments[name]
			if !envCanBeExposedAfterUnlock(ref, rec) {
				continue
			}
			if envNeedsStart(ref, rec.Network) {
				if err := a.startEnv([]string{name}, st); err != nil {
					failed++
					failures = append(failures, name+": "+redactSensitive(err.Error()))
					continue
				}
				restored++
				continue
			}
			if err := repairEnvSSHAccessForRef(ref); err != nil {
				failed++
				failures = append(failures, name+": "+redactSensitive(err.Error()))
				continue
			}
			touchEnvUsed(st, name, time.Now().UTC())
			restored++
		}
		return nil
	})
	if err != nil {
		return restored, failed, err
	}
	if failed > 0 {
		return restored, failed, fmt.Errorf("unlock restored %d environments; failed %d: %s", restored, failed, strings.Join(failures, "; "))
	}
	return restored, failed, nil
}

func envCanBeExposedAfterUnlock(ref envRef, rec envRecord) bool {
	if rec.Storage == "protected" {
		return true
	}
	return containerExists(ref.DevName) || containerExists(ref.NetName)
}

func (a app) runPassword(args []string) error {
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(a.stdout, `Usage: envd password change

Unlocks existing encrypted envd state with the current master password, asks for
a new master password twice, then re-encrypts the same state with the new
password.

The current password is requested explicitly even if the short-lived unlock
cache is active.

`)
		return nil
	}
	if len(args) != 1 || args[0] != "change" {
		return fmt.Errorf("usage: envd password change")
	}
	store, err := newStateStore()
	if err != nil {
		return err
	}
	if err := store.changePassword(a.stderr); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Changed envd master password")
	return nil
}

func (a app) runResetState(args []string) error {
	confirmed := false
	yes := false
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(a.stdout, `Usage: envd reset-state --delete --i-understand-this-deletes-envd-state --yes

Moves encrypted envd state to a timestamped backup and then prints the next
step. Docker containers and volumes are not deleted.

Requires typing: Remove envd state

`)
		return nil
	}
	for _, arg := range args {
		switch arg {
		case "--yes", "-y":
			yes = true
		case "--delete":
			confirmed = true
		case "--i-understand-this-deletes-envd-state":
			confirmed = true
		default:
			return fmt.Errorf("unknown reset-state option %q", arg)
		}
	}
	if !yes || !confirmed || !hasArg(args, "--delete") || !hasArg(args, "--i-understand-this-deletes-envd-state") {
		return fmt.Errorf("usage: envd reset-state --delete --i-understand-this-deletes-envd-state --yes")
	}
	if err := confirmResetState(a.stderr); err != nil {
		return err
	}
	store, err := newStateStore()
	if err != nil {
		return err
	}
	result, path, err := store.reset(time.Now().UTC())
	if err != nil {
		return err
	}
	switch result {
	case "missing":
		fmt.Fprintf(a.stdout, "No envd state found at: %s\n", store.dir)
	case "moved":
		fmt.Fprintf(a.stdout, "Moved envd state to backup: %s\n", path)
		fmt.Fprintln(a.stdout, "Next: envd init")
	default:
		return fmt.Errorf("unknown reset result %q", result)
	}
	return nil
}

func confirmResetState(stderr io.Writer) error {
	const phrase = "Remove envd state"
	if os.Getenv("ENVD_NONINTERACTIVE") == "1" {
		return nil
	}
	fmt.Fprintf(stderr, "This moves encrypted envd state to a backup and resets envd metadata.\n")
	fmt.Fprintf(stderr, "Docker containers and volumes are not deleted.\n")
	fmt.Fprintf(stderr, "Type %q to continue: ", phrase)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(line) != phrase {
		return errors.New("reset-state cancelled")
	}
	return nil
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func (a app) withState(fn func(*envdState) error) error {
	store, err := newStateStore()
	if err != nil {
		return err
	}
	return store.withState(a.stderr, func(st *envdState) error {
		st.ensureDefaults()
		return fn(st)
	})
}

func (a app) withStateSaveOnError(fn func(*envdState) error) error {
	store, err := newStateStore()
	if err != nil {
		return err
	}
	return store.withStateSaveOnError(a.stderr, func(st *envdState) error {
		st.ensureDefaults()
		return fn(st)
	})
}

func (a app) withStatePasswordSaveOnError(fn func(*envdState, []byte) error) error {
	store, err := newStateStore()
	if err != nil {
		return err
	}
	return store.withStatePasswordSaveOnError(a.stderr, func(st *envdState, password []byte) error {
		st.ensureDefaults()
		return fn(st, password)
	})
}

func (a app) printHelp() {
	fmt.Fprint(a.stdout, `envd - sealed development environments with a managed gateway

Usage:
  envd COMMAND [args]
  envd help COMMAND

Start:
  envd init
  envd gateway install ams1 --host 1.2.3.4 --user root --password --yes
  envd gateway use ams1
  envd start books
  envd shell books

Setup:
  init                 create encrypted state
  status               show lock/access/cache state
  lock                 stop envd-managed workloads
  unlock               restore access after lock
  password             change master password
  reset-state          reset forgotten-password state

Environment:
  start                create or start an environment
  shell                open a shell or run a command
  list                 list environments
  inspect              show environment details
  stop                 stop an environment
  rm                   remove an environment
  vscode-extensions    lock/unlock remote VS Code extensions

Gateway:
  gateway              install/use/list gateways
  proxy                show/test local proxy ports
  user                 print app import URIs

Diagnostics:
  doctor               diagnose what is broken
  why                  explain an environment state
  events               show encrypted event log
  internet             check direct/gateway reachability
  hosting              check hosting provider reachability

Advanced:
  network              change network mode
  pkg                  manage package profiles
  identity             manage encrypted identities
  migrate              adopt legacy envd containers
  supervisor           stop idle workloads
  version              print version
  help                 show help

Run envd help COMMAND for usage.

`)
}

func (a app) printCommandHelp(args []string) error {
	if len(args) == 0 {
		a.printHelp()
		return nil
	}
	switch args[0] {
	case "init":
		fmt.Fprint(a.stdout, "Usage: envd init\n\nCreates encrypted envd state and asks for the master password twice.\n")
	case "unlock":
		fmt.Fprint(a.stdout, "Usage: envd unlock\n\nRestores envd SSH targets/workloads after lock and caches the master password briefly.\n")
	case "status":
		fmt.Fprint(a.stdout, "Usage: envd status\n\nShows non-secret runtime access state without opening encrypted state.\n")
	case "password":
		fmt.Fprint(a.stdout, `Usage: envd password change

Changes the master password without deleting encrypted state.

Prompts:
  current master password
  new master password
  confirmation of new master password

The current password is requested explicitly even if the short-lived unlock
cache is active.

`)
	case "reset-state":
		fmt.Fprint(a.stdout, `Usage: envd reset-state --delete --i-understand-this-deletes-envd-state --yes

Moves encrypted envd state to a timestamped backup when the master password is
lost. Docker containers and volumes are not deleted.

Requires typing: Remove envd state
Next command: envd init

`)
	case "gateway":
		a.printGatewayHelp()
	case "proxy":
		a.printProxyHelp()
	case "start":
		a.printStartHelp()
	case "shell":
		fmt.Fprint(a.stdout, "Usage:\n  envd shell ENV\n  envd shell ENV COMMAND [args]\n")
	case "list":
		fmt.Fprint(a.stdout, "Usage: envd list\n")
	case "inspect":
		fmt.Fprint(a.stdout, "Usage: envd inspect ENV\n")
	case "stop":
		fmt.Fprint(a.stdout, "Usage: envd stop ENV\n")
	case "rm":
		fmt.Fprint(a.stdout, "Usage: envd rm ENV --yes\n")
	case "vscode-extensions":
		a.printVSCodeExtensionsHelp()
	case "lock":
		fmt.Fprint(a.stdout, "Usage: envd lock\n\nStops envd-managed workloads, hides envd SSH targets, and clears cached unlock.\n")
	case "doctor":
		a.printDoctorHelp()
	case "why":
		fmt.Fprint(a.stdout, "Usage: envd why ENV\n")
	case "events":
		fmt.Fprint(a.stdout, "Usage: envd events\n")
	case "internet":
		a.printInternetHelp()
	case "hosting":
		a.printHostingHelp()
	case "network":
		a.printNetworkHelp()
	case "pkg":
		a.printPkgHelp()
	case "ssh-proxy":
		fmt.Fprint(a.stdout, "Usage: envd ssh-proxy ENV\n")
	case "identity":
		a.printIdentityHelp()
	case "migrate":
		a.printMigrateHelp()
	case "supervisor":
		a.printSupervisorHelp()
	case "user":
		fmt.Fprint(a.stdout, "Usage: envd user uri GATEWAY\n")
	case "version":
		fmt.Fprint(a.stdout, "Usage: envd version\n")
	case "help":
		fmt.Fprint(a.stdout, "Usage:\n  envd help\n  envd help COMMAND\n")
	default:
		return fmt.Errorf("unknown help topic %q", args[0])
	}
	return nil
}

func (a app) runProxy(args []string, st *envdState) error {
	if len(args) > 0 {
		switch args[0] {
		case "test":
			return a.runProxyTest(args[1:], st)
		case "help", "-h", "--help":
			a.printProxyHelp()
			return nil
		default:
			return fmt.Errorf("unknown proxy subcommand %q", args[0])
		}
	}

	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}

	host := hostForClient(cfg.BindIP)
	fmt.Fprintf(a.stdout, "SOCKS: %s:%d\n", host, cfg.SOCKSPort)
	fmt.Fprintf(a.stdout, "HTTP:  %s:%d\n", host, cfg.HTTPHostPort)
	fmt.Fprintf(a.stdout, "Bind:  %s\n", cfg.BindIP)
	if cfg.ServerIP != "" {
		fmt.Fprintf(a.stdout, "Remote: %s:%s\n", cfg.ServerIP, cfg.ServerPort)
	}
	return nil
}

func (a app) runProxyTest(args []string, st *envdState) error {
	fs := flag.NewFlagSet("proxy test", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	target := fs.String("target", "api.ipify.org:443", "HTTPS target to test through proxies")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout per probe")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}

	host := hostForClient(cfg.BindIP)
	socksAddr := net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
	httpAddr := net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort))

	results := []probeResult{
		probeTCP("Host SOCKS TCP", socksAddr, *timeout),
		probeSOCKS("Host SOCKS", socksAddr, *target, *timeout),
		probeTCP("Host HTTP TCP", httpAddr, *timeout),
		probeHTTPProxy("Host HTTP", httpAddr, *target, *timeout),
	}

	ok := true
	for _, r := range results {
		if r.Err != nil {
			ok = false
			fmt.Fprintf(a.stdout, "%-16s FAIL %s\n", r.Name, redactSensitive(r.Err.Error()))
		} else {
			fmt.Fprintf(a.stdout, "%-16s OK   %s\n", r.Name, r.Detail)
		}
	}
	if !ok {
		return errors.New("proxy test failed")
	}
	return nil
}

func (a app) runDoctor(args []string, st *envdState) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	deep := fs.Bool("deep", false, "run real proxy traffic probes")
	identity := fs.Bool("identity", false, "check encrypted identity records")
	if err := fs.Parse(args); err != nil {
		return err
	}

	checks := []probeResult{}
	if !*identity || *deep {
		checks = append(checks, a.probeDocker())
		for _, asset := range runtimeAssets {
			checks = append(checks, a.probeRuntimeAsset(asset))
		}
		cfg, _, err := a.activeGatewayConfig(st)
		if err != nil {
			checks = append(checks, probeResult{Name: "Gateway config", Err: err})
		} else {
			host := hostForClient(cfg.BindIP)
			checks = append(checks,
				a.probeGatewayRender(cfg),
				a.probeGatewayRuntime(st),
				a.probeGatewayPortConflicts(cfg),
				a.probeGatewayPorts(cfg),
				probeTCP("Host SOCKS TCP", net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort)), 3*time.Second),
				probeTCP("Host HTTP TCP", net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort)), 3*time.Second),
			)
			checks = append(checks, a.probeEnvWorkloads(st)...)
			if *deep {
				checks = append(checks,
					probeSOCKS("Host SOCKS", net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort)), "api.ipify.org:443", 10*time.Second),
					probeHTTPProxy("Host HTTP", net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort)), "api.ipify.org:443", 10*time.Second),
				)
				checks = append(checks, a.probeSealedEnvTraffic(st))
			}
		}
	}
	if *identity {
		checks = append(checks, probeIdentityRecords(st)...)
	}

	ok := true
	currentFailures := map[string]string{}
	for _, c := range checks {
		if c.Err != nil {
			ok = false
			currentFailures[c.Name] = redactSensitive(c.Err.Error())
			fmt.Fprintf(a.stdout, "%-22s FAIL %s\n", c.Name, redactSensitive(c.Err.Error()))
			if next := nextActionForError(c.Err); next != "" {
				fmt.Fprintf(a.stdout, "%-22s      Next: %s\n", "", next)
			}
		} else {
			fmt.Fprintf(a.stdout, "%-22s OK   %s\n", c.Name, c.Detail)
		}
	}
	recordDoctorEvents(st, currentFailures)

	if !ok {
		return errors.New("doctor found failures")
	}
	return nil
}

func recordDoctorEvents(st *envdState, currentFailures map[string]string) {
	st.ensureDefaults()
	for name, message := range currentFailures {
		if st.DoctorFailures[name] != message {
			st.addEvent("doctor", name, "failure: "+message)
		}
	}
	for name, previous := range st.DoctorFailures {
		if _, stillFailing := currentFailures[name]; !stillFailing {
			st.addEvent("doctor", name, "recovered from: "+previous)
		}
	}
	st.DoctorFailures = currentFailures
}

func (a app) runGateway(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printGatewayHelp()
		return nil
	}
	switch args[0] {
	case "list", "ls":
		return a.runGatewayList(args[1:], st)
	case "status":
		return a.runGatewayStatus(st)
	case "inspect":
		return a.runGatewayInspect(st)
	case "render":
		return a.runGatewayRender(st)
	case "egress":
		return a.runGatewayEgress(st)
	case "share":
		return a.runGatewayShare(args[1:], st)
	case "shares":
		return a.runGatewayShares(args[1:], st)
	case "uri":
		return a.runGatewayURI(args[1:], st)
	case "revoke":
		return a.runGatewayRevoke(args[1:], st)
	case "risk":
		return a.runGatewayRisk(args[1:], st)
	case "install":
		return a.runGatewayInstall(args[1:], st)
	case "use":
		return a.runGatewayUse(args[1:], st)
	case "rollback":
		return a.runGatewayRollback(args[1:], st)
	case "chain":
		return a.runGatewayChain(args[1:], st)
	default:
		return fmt.Errorf("unknown gateway subcommand %q", args[0])
	}
}

func (a app) printGatewayHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd gateway COMMAND [args]

Start:
  envd gateway install NAME --host HOST --user USER --password --yes
  envd gateway install NAME --host HOST --user USER --password --probe --dry-run
  envd gateway use NAME

Manage:
  envd gateway list
  envd gateway status
  envd gateway inspect
  envd gateway rollback

App Access:
  envd gateway share NAME [LABEL]
  envd gateway uri NAME SHARE
  envd gateway shares NAME
  envd gateway revoke NAME SHARE

Diagnostics:
  envd gateway egress
  envd gateway render

`)
}

func (a app) printGatewayChainHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd gateway chain COMMAND [args]

Commands:
  create NAME --entry ENTRY --exit EXIT
  status NAME

`)
}

func (a app) printStartHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd start ENV [flags]

Flags:
  --network sealed|direct|offline
  --storage plain|protected
  --profile PROFILE

Default:
  sealed network, plain storage

`)
}

func (a app) printProxyHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd proxy
  envd proxy test

Commands:
  proxy        show local SOCKS/HTTP proxy endpoints
  proxy test   test local proxy handshakes

`)
}

func (a app) printDoctorHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd doctor
  envd doctor --deep

Checks:
  host Docker, embedded images, gateway runtime, proxy ports, and env repair

Deep:
  also runs real direct/gateway reachability probes

`)
}

func (a app) printVSCodeExtensionsHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd vscode-extensions lock ENV
  envd vscode-extensions unlock ENV

Default:
  extension storage is locked whenever envd creates or starts an env

`)
}

func (a app) printInternetHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd internet COMMAND

Commands:
  status       check direct and gateway reachability
  report       show recent reachability history

`)
}

func (a app) printHostingHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd hosting COMMAND [args]

Commands:
  check        test provider reachability from this machine
  shortlist    show reachable/diverse provider candidates
  update       install a signed provider catalog update

Update:
  envd hosting update --url PROVIDERS_JSON --sig SIG --key PUBKEY

`)
}

func (a app) printNetworkHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd network set ENV MODE

Modes:
  sealed       route through gateway and fail closed
  direct       use normal Docker networking
  offline      no outbound network

`)
}

func (a app) printPkgHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd pkg COMMAND [args]

Add:
  envd pkg add PROFILE apt:PACKAGE
  envd pkg add PROFILE npm:PACKAGE
  envd pkg add PROFILE tool:NAME

Promote:
  envd pkg suggest ENV
  envd pkg promote ENV --to PROFILE

`)
}

func (a app) printIdentityHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd identity COMMAND [args]

Manage:
  envd identity add NAME --ssh-key PATH
  envd identity add NAME --git-https --username USER --token-file PATH
  envd identity list

Rule:
  identities are usable from sealed envs only with a healthy gateway

`)
}

func (a app) printIdentityBrokerHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd identity broker COMMAND [args]

Commands:
  check ENV IDENTITY --class ssh
  serve

`)
}

func (a app) printMigrateHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd migrate COMMAND [args]

Commands:
  inspect              discover legacy envd containers/config
  adopt --yes          record legacy envs in envd state
  protected ENV --yes  move an env to protected storage

`)
}

func (a app) printSupervisorHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd supervisor COMMAND [args]

Commands:
  run [--idle 3h]      run the low-duty idle stopper loop
  tick [--idle 3h]     run one idle-stopper pass

`)
}

func (a app) runGatewayList(args []string, st *envdState) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(a.stdout, "Usage: envd gateway list\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd gateway list")
	}
	names := sortedGatewayNames(st)
	if len(names) == 0 {
		fmt.Fprintln(a.stdout, "No gateways. Add one with: envd gateway install NAME --host HOST --user root --password")
		return nil
	}
	fmt.Fprintf(a.stdout, "%-18s %-8s %-8s %-22s %-10s %-22s %s\n", "NAME", "ACTIVE", "TYPE", "REMOTE", "PROVIDER", "STRATEGY", "READY")
	for _, name := range names {
		active := ""
		switch name {
		case st.ActiveGateway:
			active = "active"
		case st.PreviousGateway:
			active = "previous"
		}
		typ := "local"
		remote := "-"
		provider := "xray"
		strategy := "-"
		ready := "yes"
		if chain, ok := st.GatewayChains[name]; ok {
			typ = "chain"
			remote = chain.Entry + "->" + chain.Exit
			provider = "chain"
			strategy = "fail-closed"
			ready = "no"
		} else if rec, ok := st.RemoteGateways[name]; ok {
			typ = "remote"
			remote = rec.Host
			provider = defaultString(rec.Provider, "xray")
			strategy = defaultString(rec.Strategy, "-")
			if _, ok := st.Gateways[name]; ok {
				ready = "yes"
			} else {
				ready = "no"
			}
		} else if rec, ok := st.Gateways[name]; ok {
			remote = rec.ServerIP + ":" + rec.ServerPort
			if rec.ImportedFromLocal {
				typ = "imported"
			}
		}
		fmt.Fprintf(a.stdout, "%-18s %-8s %-8s %-22s %-10s %-22s %s\n", name, active, typ, remote, provider, strategy, ready)
	}
	return nil
}

func (a app) listEnvs(args []string, st *envdState) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(a.stdout, "Usage: envd list\n")
		return nil
	}
	envs, err := listEnvContainers(st)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%-18s %-10s %-8s %-8s %-10s %-5s %-18s %-14s %-14s %s\n", "NAME", "STATE", "NET", "VPN", "STORAGE", "GEN", "EGRESS", "IMAGE", "IMAGE_ID", "ISSUE")
	seen := map[string]bool{}
	for _, env := range envs {
		seen[env.Name] = true
		netState := env.networkMode()
		vpn := env.netHealth()
		issue := env.issue(st.GatewayGeneration)
		fmt.Fprintf(a.stdout, "%-18s %-10s %-8s %-8s %-10s %-5d %-18s %-14s %-14s %s\n",
			env.Name, env.Dev.State.Status, netState, vpn, env.storageMode(st), st.GatewayGeneration, env.egressSummary(), shortImage(env.Dev.Config.Image), shortID(env.Dev.Image), issue)
	}
	for _, name := range sortedEnvNames(st) {
		if seen[name] {
			continue
		}
		rec := st.Environments[name]
		ref, err := resolveEnvRef(st, name)
		if err != nil {
			continue
		}
		fmt.Fprintf(a.stdout, "%-18s %-10s %-8s %-8s %-10s %-5d %-18s %-14s %-14s %s\n",
			name, "missing", networkOrSealed(rec.Network), "blocked", storageOrPlain(rec.Storage), st.GatewayGeneration, "-", shortImage(imageOrDefault(rec.Image)), "-", missingEnvIssue(ref))
	}
	return nil
}

func (a app) runInspect(args []string, st *envdState) error {
	if len(args) != 1 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, "Usage: envd inspect ENV\n")
		return nil
	}
	env, err := inspectEnv(st, args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Name:     %s\n", env.Name)
	fmt.Fprintf(a.stdout, "State:    %s\n", env.Dev.State.Status)
	fmt.Fprintf(a.stdout, "Network:  %s\n", env.networkMode())
	fmt.Fprintf(a.stdout, "VPN:      %s\n", env.netHealth())
	fmt.Fprintf(a.stdout, "Storage:  %s\n", env.storageMode(st))
	if env.storageMode(st) == "protected" {
		if rec, ok := st.Environments[args[0]]; ok {
			fmt.Fprintf(a.stdout, "Backend:  %s\n", rec.StorageBackend)
		}
	}
	fmt.Fprintf(a.stdout, "Gateway Generation: %d\n", st.GatewayGeneration)
	fmt.Fprintf(a.stdout, "Image:    %s\n", env.Dev.Config.Image)
	fmt.Fprintf(a.stdout, "Image ID: %s\n", env.Dev.Image)
	if env.BlockedReason != "" {
		fmt.Fprintf(a.stdout, "Blocked:  %s\n", env.BlockedReason)
	}
	if rec, ok := st.Environments[args[0]]; ok && rec.Profile != "" {
		fmt.Fprintf(a.stdout, "Profile:  %s generation %d\n", rec.Profile, rec.ProfileGeneration)
	}
	fmt.Fprintf(a.stdout, "Egress:   %s\n", env.egressSummary())
	if env.Legacy {
		fmt.Fprintf(a.stdout, "Legacy:   true\n")
	}
	if env.Net != nil {
		fmt.Fprintf(a.stdout, "Sidecar:  %s (%s)\n", env.Net.Name, env.Net.State.Status)
	}
	if issue := env.issue(st.GatewayGeneration); issue != "" {
		fmt.Fprintf(a.stdout, "Issue:    %s\n", issue)
	}
	return nil
}

func (a app) runVSCodeExtensions(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd vscode-extensions lock|unlock ENV")
	}
	action, name := args[0], args[1]
	route, err := runtimeRoute(name)
	if err != nil {
		return err
	}
	ref := envRef{Name: route.Name, ID: route.ID, UserName: route.UserName, DevName: route.DevName, Network: route.Network}
	if dockerContainerStatus(ref.DevName) != "running" {
		return fmt.Errorf("environment %q is not running; start it first with: envd start %s", name, name)
	}
	switch action {
	case "lock":
		if err := setVSCodeExtensionsLocked(ref, true); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "VS Code extensions: locked for %s\n", name)
		return nil
	case "unlock":
		if err := setVSCodeExtensionsLocked(ref, false); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "VS Code extensions: unlocked for %s\n", name)
		return nil
	default:
		return fmt.Errorf("usage: envd vscode-extensions lock|unlock ENV")
	}
}

func (a app) runEnv(args []string, st *envdState) error {
	opts, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	if err := applyProjectManifestDefaults(&opts); err != nil {
		return err
	}
	name, network, storage, profile := opts.Name, opts.Network, opts.Storage, opts.Profile
	if name == "" {
		return fmt.Errorf("usage: envd start ENV")
	}
	if err := validateEnvName(name); err != nil {
		return err
	}
	if !validNetworkMode(network) {
		return fmt.Errorf("invalid network mode %q: use sealed, direct, or offline", network)
	}
	if !validStorageMode(storage) {
		return fmt.Errorf("invalid storage mode %q: use plain or protected", storage)
	}
	image := devImage
	profileGeneration := 0
	if profile != "" {
		img, gen, err := a.ensureProfileImage(st, profile)
		if err != nil {
			return err
		}
		image = img
		profileGeneration = gen
	}
	if _, ok := st.Environments[name]; ok {
		return fmt.Errorf("environment %q already exists", name)
	}
	if containerExists(name) {
		return fmt.Errorf("environment %q already exists", name)
	}
	id, err := newOpaqueID(st)
	if err != nil {
		return err
	}
	devName := devContainerName(id)
	netName := netContainerName(id)
	if network == "sealed" && containerExists(netName) {
		return fmt.Errorf("sidecar %q already exists", netName)
	}

	if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
		return err
	}
	if network == "sealed" {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
			return err
		}
	}
	if network == "sealed" {
		if err := a.ensureActiveGatewayRuntime(st); err != nil {
			return err
		}
		if err := ensureDockerNetwork(gatewayNet); err != nil {
			return err
		}
	}

	homeVol := homeVolumeName(id)
	repoVol := repoVolumeName(id)
	homeSource := homeVol
	repoSource := repoVol
	protected := protectedStorageRecord{}
	created := []string{}
	protectedCreated := false
	cleanup := func() {
		for _, ref := range []string{devName, netName} {
			_ = exec.Command("docker", "rm", "-f", ref).Run()
		}
		for _, vol := range created {
			_ = exec.Command("docker", "volume", "rm", vol).Run()
		}
		if protectedCreated {
			_ = removeProtectedStorage(protected)
		}
	}
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

	if storage == "plain" {
		for _, vol := range []string{homeVol, repoVol} {
			if err := dockerRun("volume", "create", vol); err != nil {
				return err
			}
			created = append(created, vol)
		}
	} else {
		var err error
		protected, err = createProtectedStorage(id)
		if err != nil {
			return err
		}
		protectedCreated = true
		if err := detachProtectedStorage(protected); err != nil {
			return err
		}
		for _, vol := range []string{homeVol, repoVol} {
			if err := dockerRun("volume", "create", vol); err != nil {
				return err
			}
			created = append(created, vol)
		}
	}

	if network == "sealed" {
		if err := createSidecar(name, id, netName); err != nil {
			return err
		}
	}
	if err := a.createDevContainer(name, "dev", id, devName, netName, storage, homeSource, repoSource, network, image); err != nil {
		return err
	}
	if network == "sealed" {
		if err := verifySealedEnv(devName); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	st.Environments[name] = envRecord{
		ID:                id,
		Network:           network,
		Storage:           storage,
		StorageBackend:    protected.Backend,
		StorageImagePath:  protected.ImagePath,
		StorageMountPath:  protected.MountPath,
		StorageKey:        protected.Key,
		Image:             image,
		Profile:           profile,
		ProfileGeneration: profileGeneration,
		GatewayGeneration: st.GatewayGeneration,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastUsedAt:        now,
	}
	message := "created " + network + " " + storage + " environment"
	if profile != "" {
		message += " with profile " + profile + " generation " + strconv.Itoa(profileGeneration)
	}
	st.addEvent("env", name, message)
	ref := envRef{Name: name, ID: id, UserName: "dev", DevName: devName, NetName: netName, ProjectDockerName: projectDockerContainerName(id), Network: network}
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}

	ok = true
	fmt.Fprintf(a.stdout, "Created: %s\n", name)
	fmt.Fprintf(a.stdout, "Network: %s\n", network)
	fmt.Fprintf(a.stdout, "Storage: %s\n", storage)
	fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
	if storage == "protected" {
		fmt.Fprintf(a.stdout, "Storage backend: %s\n", protected.Backend)
	}
	if profile != "" {
		fmt.Fprintf(a.stdout, "Profile: %s generation %d\n", profile, profileGeneration)
	}
	return nil
}

func (a app) startOrCreateEnv(args []string, st *envdState) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: envd start ENV [--network sealed|direct|offline] [--storage plain|protected] [--profile PROFILE]")
	}
	name := args[0]
	if _, ok := st.Environments[name]; ok {
		if len(args) != 1 {
			return fmt.Errorf("environment %q already exists; usage: envd start %s", name, name)
		}
		return a.startEnv(args, st)
	}
	return a.runEnv(args, st)
}

func (a app) startEnv(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd start ENV")
	}
	name := args[0]
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	if rec, ok := st.Environments[name]; ok && rec.BlockedReason != "" {
		return fmt.Errorf("environment %q is blocked fail-closed: %s", name, rec.BlockedReason)
	}
	networkMode := ""
	env, err := inspectEnv(st, name)
	if err != nil {
		if rec, ok := st.Environments[name]; ok {
			networkMode = rec.Network
		}
		if networkMode == "" {
			networkMode = "sealed"
		}
		if ref.Storage != "protected" && !canRepairPlainEnv(ref) {
			if !ref.Legacy {
				return plainEnvDataMissingError(ref)
			}
			return err
		}
		if ref.Storage == "protected" && containerExists(ref.DevName) {
			return err
		}
	} else {
		networkMode = env.networkMode()
	}
	if networkMode == "" {
		networkMode = "sealed"
	}
	if ref.Storage == "protected" {
		if err := restoreProtectedVolumes(ref); err != nil {
			return err
		}
		if !containerExists(ref.DevName) {
			image := devImage
			if rec, ok := st.Environments[name]; ok && rec.Image != "" {
				image = rec.Image
			}
			if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
				return err
			}
			if networkMode == "sealed" {
				if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
					return err
				}
				if err := a.ensureActiveGatewayRuntime(st); err != nil {
					return err
				}
				if err := ensureDockerNetwork(gatewayNet); err != nil {
					return err
				}
				if !containerExists(ref.NetName) {
					if err := createSidecar(name, ref.ID, ref.NetName); err != nil {
						return err
					}
				} else {
					if err := dockerRun("start", ref.NetName); err != nil {
						return err
					}
					if err := waitForHealthy(ref.NetName, 60*time.Second); err != nil {
						return err
					}
				}
			}
			if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, networkMode, image); err != nil {
				return err
			}
			if networkMode == "sealed" {
				if err := verifySealedEnv(ref.DevName); err != nil {
					return err
				}
			}
			touchEnvUsed(st, name, time.Now().UTC())
			if err := repairEnvSSHAccessForRef(ref); err != nil {
				return err
			}
			if err := setVSCodeExtensionsLocked(ref, true); err != nil {
				return err
			}
			st.addEvent("env", name, "started from protected storage")
			fmt.Fprintf(a.stdout, "Started: %s\n", name)
			fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
			return nil
		}
	}
	if networkMode == "sealed" {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
			return err
		}
		if err := a.ensureActiveGatewayRuntime(st); err != nil {
			return err
		}
		if err := ensureDockerNetwork(gatewayNet); err != nil {
			return err
		}
		recreate, reason, err := sealedRuntimeRecreateStatus(ref)
		if err != nil {
			return err
		}
		if recreate {
			if err := a.recreateSealedRuntime(st, name, ref, reason); err != nil {
				if rec, ok := st.Environments[name]; ok {
					rec.BlockedReason = "sealed runtime recreate failed: " + redactSensitive(err.Error())
					rec.UpdatedAt = time.Now().UTC()
					st.Environments[name] = rec
				}
				st.addEvent("env", name, "sealed runtime recreate failed: "+redactSensitive(err.Error()))
				_ = stopEnvWorkload(ref)
				return err
			}
			touchEnvUsed(st, name, time.Now().UTC())
			if err := repairEnvSSHAccessForRef(ref); err != nil {
				return err
			}
			if err := setVSCodeExtensionsLocked(ref, true); err != nil {
				return err
			}
			st.addEvent("env", name, "recreated sealed runtime before start: "+reason)
			fmt.Fprintf(a.stdout, "Recreated sealed runtime: %s\n", reason)
			fmt.Fprintf(a.stdout, "Started: %s\n", name)
			fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
			return nil
		}
		if err := dockerRun("start", ref.NetName); err != nil {
			return err
		}
		if err := waitForHealthy(ref.NetName, 60*time.Second); err != nil {
			return err
		}
	} else if !containerExists(ref.DevName) {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
			return err
		}
		image := devImage
		if rec, ok := st.Environments[name]; ok && rec.Image != "" {
			image = rec.Image
		}
		if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, networkMode, image); err != nil {
			return err
		}
	} else if devContainerNeedsHostDockerSocketRepair(ref.DevName) {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
			return err
		}
		image := devImage
		if rec, ok := st.Environments[name]; ok && rec.Image != "" {
			image = rec.Image
		}
		_ = dockerRun("stop", ref.DevName)
		_ = dockerRun("rm", "-f", ref.DevName)
		if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, networkMode, image); err != nil {
			return err
		}
		st.addEvent("env", name, "recreated dev container to attach host Docker socket")
	}
	for _, cmd := range devStartCommandsForMode(networkMode, ref.DevName) {
		if err := dockerRun(cmd...); err != nil {
			return err
		}
	}
	touchEnvUsed(st, name, time.Now().UTC())
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	st.addEvent("env", name, "started")
	fmt.Fprintf(a.stdout, "Started: %s\n", name)
	fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
	return nil
}

func canRepairPlainEnv(ref envRef) bool {
	if ref.Legacy {
		return false
	}
	return volumeExists(ref.HomeVol) && volumeExists(ref.RepoVol)
}

func plainEnvDataMissingError(ref envRef) error {
	missing := []string{}
	for _, vol := range []string{ref.HomeVol, ref.RepoVol} {
		if !volumeExists(vol) {
			missing = append(missing, vol)
		}
	}
	if len(missing) == 0 {
		return fmt.Errorf("environment %q container is missing and could not be inspected", ref.Name)
	}
	return fmt.Errorf("environment %q data was deleted from Docker Desktop: missing volume(s): %s", ref.Name, strings.Join(missing, ", "))
}

func missingEnvIssue(ref envRef) string {
	if ref.Storage != "protected" && !canRepairPlainEnv(ref) {
		missing := []string{}
		for _, vol := range []string{ref.HomeVol, ref.RepoVol} {
			if !volumeExists(vol) {
				missing = append(missing, vol)
			}
		}
		if len(missing) > 0 {
			return "data deleted: " + strings.Join(missing, ",")
		}
	}
	return "container missing; run envd start " + ref.Name
}

func networkOrSealed(network string) string {
	if strings.TrimSpace(network) == "" {
		return "sealed"
	}
	return network
}

func imageOrDefault(image string) string {
	if strings.TrimSpace(image) == "" {
		return devImage
	}
	return image
}

func (a app) recreateSealedRuntime(st *envdState, name string, ref envRef, reason string) error {
	image := devImage
	if rec, ok := st.Environments[name]; ok && rec.Image != "" {
		image = rec.Image
	}
	if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
		return err
	}
	if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
		return err
	}
	_ = dockerRun("stop", ref.DevName)
	_ = dockerRun("rm", "-f", ref.DevName)
	_ = dockerRun("rm", "-f", ref.NetName)
	if err := createSidecar(name, ref.ID, ref.NetName); err != nil {
		return err
	}
	if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, "sealed", image); err != nil {
		return err
	}
	if err := verifySealedEnv(ref.DevName); err != nil {
		return err
	}
	if rec, ok := st.Environments[name]; ok {
		rec.Network = "sealed"
		rec.GatewayGeneration = st.GatewayGeneration
		rec.BlockedReason = ""
		rec.UpdatedAt = time.Now().UTC()
		st.Environments[name] = rec
	}
	_ = reason
	return nil
}

func devStartCommandsForMode(networkMode, devName string) [][]string {
	if networkMode == "sealed" {
		return [][]string{
			{"start", devName},
			{"restart", "-t", "1", devName},
		}
	}
	return [][]string{{"start", devName}}
}

func (a app) networkEnv(args []string, st *envdState, password []byte) error {
	if len(args) != 3 || args[0] != "set" {
		return fmt.Errorf("usage: envd network set ENV sealed|direct|offline")
	}
	name := args[1]
	mode := args[2]
	if !validNetworkMode(mode) {
		return fmt.Errorf("invalid network mode %q: use sealed, direct, or offline", mode)
	}
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	env, err := inspectEnv(st, name)
	if err != nil {
		return err
	}
	current := env.networkMode()
	if current == mode {
		fmt.Fprintf(a.stdout, "%s already uses %s networking\n", name, mode)
		return nil
	}
	if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
		return err
	}
	if mode == "sealed" {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
			return err
		}
		if err := ensureDockerNetwork(gatewayNet); err != nil {
			return err
		}
	}
	if err := createAutomaticRecoveryPoint(st, password, name, ref, "network change "+current+" -> "+mode); err != nil {
		return err
	}

	_ = dockerRun("stop", ref.DevName)
	_ = dockerRun("rm", "-f", ref.DevName)
	if current == "sealed" {
		_ = dockerRun("rm", "-f", ref.NetName)
	}
	if mode == "sealed" {
		if err := createSidecar(name, ref.ID, ref.NetName); err != nil {
			return err
		}
	}
	image := devImage
	if rec, ok := st.Environments[name]; ok && rec.Image != "" {
		image = rec.Image
	}
	if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, mode, image); err != nil {
		return err
	}
	if mode == "sealed" {
		if err := verifySealedEnv(ref.DevName); err != nil {
			return err
		}
	}
	if rec, ok := st.Environments[name]; ok {
		rec.Network = mode
		rec.GatewayGeneration = st.GatewayGeneration
		rec.BlockedReason = ""
		rec.UpdatedAt = time.Now().UTC()
		st.Environments[name] = rec
	}
	ref.Network = mode
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	st.addEvent("env", name, "network changed "+current+" -> "+mode)
	fmt.Fprintf(a.stdout, "Network changed: %s -> %s\n", name, mode)
	return nil
}

func (a app) runPkg(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printPkgHelp()
		return nil
	}
	switch args[0] {
	case "add":
		return a.runPkgAdd(args[1:], st)
	case "suggest":
		return a.runPkgSuggest(args[1:], st)
	case "promote":
		return a.runPkgPromote(args[1:], st)
	default:
		return fmt.Errorf("unknown pkg subcommand %q", args[0])
	}
}

func (a app) runPkgAdd(args []string, st *envdState) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd pkg add PROFILE apt:PACKAGE")
	}
	profileName := args[0]
	if err := validateProfileName(profileName); err != nil {
		return err
	}
	pkg, err := parseProfilePackage(args[1])
	if err != nil {
		return err
	}
	profile, changed, err := addPackageToProfile(st, profileName, pkg)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintf(a.stdout, "Profile unchanged: %s already has %s:%s\n", profileName, pkg.Source, pkg.Name)
		return nil
	}
	_ = pruneProfileImages(st)
	fmt.Fprintf(a.stdout, "Profile:    %s\n", profileName)
	fmt.Fprintf(a.stdout, "Added:      %s:%s\n", pkg.Source, pkg.Name)
	fmt.Fprintf(a.stdout, "Generation: %d\n", profile.Generation)
	fmt.Fprintln(a.stdout, "Build:      deferred until first use")
	return nil
}

func (a app) runPkgSuggest(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd pkg suggest ENV")
	}
	pkgs, err := a.suggestEnvPackages(st, args[0])
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		fmt.Fprintln(a.stdout, "No package suggestions found.")
		return nil
	}
	for _, pkg := range pkgs {
		fmt.Fprintf(a.stdout, "%s:%s\n", pkg.Source, pkg.Name)
	}
	return nil
}

func (a app) runPkgPromote(args []string, st *envdState) error {
	envName, profileName, err := parsePkgPromoteArgs(args)
	if err != nil {
		return err
	}
	pkgs, err := a.suggestEnvPackages(st, envName)
	if err != nil {
		return err
	}
	added := 0
	var profile profileRecord
	for _, pkg := range pkgs {
		var changed bool
		profile, changed, err = addPackageToProfile(st, profileName, pkg)
		if err != nil {
			return err
		}
		if changed {
			added++
		}
	}
	if added > 0 {
		_ = pruneProfileImages(st)
	}
	st.addEvent("profile", profileName, fmt.Sprintf("promoted %d package suggestions from %s", added, envName))
	fmt.Fprintf(a.stdout, "Profile:    %s\n", profileName)
	fmt.Fprintf(a.stdout, "Promoted:   %d packages\n", added)
	if profile.Generation > 0 {
		fmt.Fprintf(a.stdout, "Generation: %d\n", profile.Generation)
	}
	fmt.Fprintln(a.stdout, "Build:      deferred until first use")
	return nil
}

func addPackageToProfile(st *envdState, profileName string, pkg profilePackage) (profileRecord, bool, error) {
	if err := validateProfileName(profileName); err != nil {
		return profileRecord{}, false, err
	}
	now := time.Now().UTC()
	profile, ok := st.Profiles[profileName]
	if !ok {
		id, err := newProfileID(st)
		if err != nil {
			return profileRecord{}, false, err
		}
		profile = profileRecord{Name: profileName, ID: id, Generation: 0, CreatedAt: now}
	} else if profile.ID == "" {
		id, err := newProfileID(st)
		if err != nil {
			return profileRecord{}, false, err
		}
		profile.ID = id
	}
	for _, existing := range profile.Packages {
		if existing == pkg {
			return profile, false, nil
		}
	}
	profile.Packages = append(profile.Packages, pkg)
	profile.Generation++
	profile.Image = ""
	profile.UpdatedAt = now
	st.Profiles[profileName] = profile
	st.addEvent("profile", profileName, fmt.Sprintf("added %s:%s generation %d", pkg.Source, pkg.Name, profile.Generation))
	return profile, true, nil
}

func (a app) ensureProfileImage(st *envdState, profileName string) (string, int, error) {
	if err := validateProfileName(profileName); err != nil {
		return "", 0, err
	}
	profile, ok := st.Profiles[profileName]
	if !ok {
		return "", 0, fmt.Errorf("profile %q not found; add packages first with: envd pkg add %s apt:PACKAGE", profileName, profileName)
	}
	if profile.ID == "" {
		id, err := newProfileID(st)
		if err != nil {
			return "", 0, err
		}
		profile.ID = id
		st.Profiles[profileName] = profile
	}
	if len(profile.Packages) == 0 {
		return "", 0, fmt.Errorf("profile %q has no packages", profileName)
	}
	image := profileImageName(profile.ID, profile.Generation)
	if profile.Image == image && imageExists(image) {
		return image, profile.Generation, nil
	}
	if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[0]); err != nil {
		return "", 0, err
	}
	if err := buildProfileImage(profile); err != nil {
		return "", 0, layerErr("asset cache", err)
	}
	profile.Image = image
	profile.UpdatedAt = time.Now().UTC()
	st.Profiles[profileName] = profile
	st.addEvent("profile", profileName, fmt.Sprintf("built image %s", image))
	_ = pruneProfileImages(st)
	return image, profile.Generation, nil
}

func (a app) suggestEnvPackages(st *envdState, envName string) ([]profilePackage, error) {
	ref, err := resolveEnvRef(st, envName)
	if err != nil {
		return nil, err
	}
	aptOut, _ := exec.Command("docker", "exec", ref.DevName, "sh", "-lc", "grep -hE '^(Start-Date|Install):' /var/log/apt/history.log /var/log/apt/history.log.* 2>/dev/null || true").Output()
	npmOut, _ := exec.Command("docker", "exec", ref.DevName, "sh", "-lc", "npm list -g --depth=0 --parseable 2>/dev/null | tail -n +2 || true").Output()
	since := time.Time{}
	if rec, ok := st.Environments[envName]; ok {
		since = rec.CreatedAt.Add(-2 * time.Minute)
	}
	pkgs := append(parseAptHistoryPackagesSince(string(aptOut), since), parseNpmGlobalPackages(string(npmOut))...)
	return uniqueProfilePackages(pkgs), nil
}

func createSidecar(envName, id, netName string) error {
	port, err := pickPort(2223, 2299)
	if err != nil {
		return err
	}
	if err := dockerRun("run", "-d",
		"--name", netName,
		"--label", "envd.managed=true",
		"--label", "envd.role=net",
		"--label", "envd.name="+envName,
		"--label", "envd.id="+id,
		"--restart", "unless-stopped",
		"--network", gatewayNet,
		"--cap-add", "NET_ADMIN",
		"--device", "/dev/net/tun",
		"-e", "XRAY_HOST=xray",
		"-e", "XRAY_PORT=2088",
		"-e", "XRAY_HTTP_PORT=2089",
		"-p", fmt.Sprintf("127.0.0.1:%d:22", port),
		sidecarImage,
	); err != nil {
		return err
	}
	return waitForHealthy(netName, 90*time.Second)
}

func (a app) createDevContainer(envName, userName, id, devName, netName, storageMode, homeSource, repoSource, networkMode, image string) error {
	authKey, err := ensureEnvdSSHKey()
	if err != nil {
		return err
	}
	if err := removeEnvKnownHost(envName); err != nil {
		return err
	}
	argsRun, err := devContainerRunArgs(envName, userName, id, devName, netName, storageMode, homeSource, repoSource, networkMode, image, authKey.PublicKey)
	if err != nil {
		return err
	}
	if err := dockerRun(argsRun...); err != nil {
		return err
	}
	ref := envRef{Name: envName, UserName: userName, DevName: devName, Network: networkMode}
	return ensureEnvAuthorizedKey(ref)
}

func devContainerRunArgs(envName, userName, id, devName, netName, storageMode, homeSource, repoSource, networkMode, image, authorizedKey string) ([]string, error) {
	repoMount := "/home/" + userName + "/repo"
	if !validStorageMode(storageMode) {
		return nil, fmt.Errorf("invalid storage mode %q", storageMode)
	}
	argsRun := []string{
		"run", "-d",
		"--name", devName,
		"--label", "envd.managed=true",
		"--label", "envd.role=dev",
		"--label", "envd.name=" + envName,
		"--label", "envd.id=" + id,
		"--label", "envd.network=" + networkMode,
		"--label", "envd.storage=" + storageMode,
		"--restart", "unless-stopped",
	}
	switch networkMode {
	case "sealed":
		argsRun = append(argsRun, "--network", "container:"+netName)
	case "direct":
		argsRun = append(argsRun, "--network", "bridge")
	case "offline":
		argsRun = append(argsRun, "--network", "none")
	default:
		return nil, fmt.Errorf("invalid network mode %q", networkMode)
	}
	argsRun = append(argsRun,
		"-e", "DEV_USER="+userName,
		"-e", "REPO_DIR="+repoMount,
		"-e", "ENVD_ENV_NAME="+envName,
		"-e", "ENVD_ENV_ID="+id,
	)
	if strings.TrimSpace(authorizedKey) != "" {
		argsRun = append(argsRun, "-e", "ENVD_AUTHORIZED_KEY="+authorizedKey)
	}
	if socket := hostDockerSocketPath(); socket != "" {
		argsRun = append(argsRun,
			"-v", socket+":/var/run/docker.sock",
			"-e", "DOCKER_HOST=unix:///var/run/docker.sock",
			"-e", "DOCKER_TLS_VERIFY=",
			"-e", "DOCKER_CERT_PATH=",
			"-e", "COMPOSE_PROJECT_NAME=envd_"+sanitizeComposeProjectName(envName),
		)
	}
	argsRun = append(argsRun,
		"-v", homeSource+":/home/"+userName,
		"-v", repoSource+":"+repoMount,
	)
	if networkMode == "sealed" {
		argsRun = append(argsRun, "-e", "ENVD_SEALED_DNS=1")
	}
	argsRun = append(argsRun, image)
	return argsRun, nil
}

func hostDockerSocketPath() string {
	if os.Getenv("ENVD_DOCKER_SOCKET") == "none" {
		return ""
	}
	candidates := []string{os.Getenv("ENVD_DOCKER_SOCKET")}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".docker", "run", "docker.sock"))
	}
	candidates = append(candidates, "/var/run/docker.sock")
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.Mode()&os.ModeSocket != 0 {
			return candidate
		}
	}
	return ""
}

func sanitizeComposeProjectName(name string) string {
	clean := regexp.MustCompile(`[^a-zA-Z0-9_-]+`).ReplaceAllString(name, "_")
	clean = strings.Trim(clean, "_-")
	if clean == "" {
		return "env"
	}
	return clean
}

func devContainerNeedsHostDockerSocketRepair(name string) bool {
	if hostDockerSocketPath() == "" || !containerExists(name) {
		return false
	}
	inspect, err := inspectContainer(name)
	if err != nil {
		return false
	}
	for _, mount := range inspect.Mounts {
		if mount.Destination == "/var/run/docker.sock" {
			return false
		}
	}
	return true
}

func (a app) stopEnv(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd stop ENV")
	}
	name := args[0]
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	if err := stopEnvWorkload(ref); err != nil {
		return err
	}
	st.addEvent("env", name, "stopped")
	fmt.Fprintf(a.stdout, "Stopped: %s\n", name)
	return nil
}

func (a app) rmEnv(args []string, st *envdState) error {
	yes := false
	name := ""
	for _, arg := range args {
		switch arg {
		case "--yes", "-y":
			yes = true
		default:
			if name != "" {
				return fmt.Errorf("usage: envd rm ENV --yes")
			}
			name = arg
		}
	}
	if name == "" || !yes {
		return fmt.Errorf("usage: envd rm ENV --yes")
	}
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	_ = dockerRun("rm", "-f", ref.DevName)
	_ = dockerRun("rm", "-f", ref.NetName)
	if ref.Storage == "protected" {
		_ = dockerRun("volume", "rm", ref.HomeVol)
		_ = dockerRun("volume", "rm", ref.RepoVol)
		_ = removeProtectedStorage(ref.protectedStorage())
	} else {
		_ = dockerRun("volume", "rm", ref.HomeVol)
		_ = dockerRun("volume", "rm", ref.RepoVol)
	}
	removeRecoveryPointsForEnv(st, ref.ID)
	delete(st.Environments, name)
	_ = pruneProfileImages(st)
	st.addEvent("env", name, "removed")
	fmt.Fprintf(a.stdout, "Removed: %s\n", name)
	return nil
}

func (a app) lockEnvd(args []string, st *envdState) error {
	return a.lockEnvdWithStopper(args, st, stopEnvWorkload)
}

type workloadStopper func(envRef) error

func (a app) lockEnvdWithStopper(args []string, st *envdState, stop workloadStopper) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(a.stdout, "Usage: envd lock\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd lock")
	}
	stopped := 0
	failed := 0
	now := time.Now().UTC()
	names := sortedEnvNames(st)
	for _, name := range names {
		ref, err := resolveEnvRef(st, name)
		if err != nil {
			failed++
			st.addEvent("lock", name, "failed to resolve environment: "+redactSensitive(err.Error()))
			continue
		}
		if err := stop(ref); err != nil {
			failed++
			st.addEvent("lock", name, "failed to stop workload: "+redactSensitive(err.Error()))
			continue
		}
		if rec, ok := st.Environments[name]; ok {
			rec.UpdatedAt = now
			st.Environments[name] = rec
		}
		st.addEvent("lock", name, "stopped envd-managed workload")
		stopped++
	}
	st.addEvent("lock", "", fmt.Sprintf("completed: stopped %d workloads; failed %d", stopped, failed))
	_ = clearCachedMasterPassword()
	_ = hideEnvSSHConfig()
	_ = lockRuntimeAccess()
	fmt.Fprintf(a.stdout, "Locked: %d envs\n", stopped)
	if failed > 0 {
		fmt.Fprintf(a.stdout, "Failed: %d\n", failed)
		return fmt.Errorf("lock completed with %d failures", failed)
	}
	return nil
}

func hideEnvSSHConfig() error {
	return syncEnvSSHConfigNames(nil, currentEnvdExecutable())
}

type runtimeAccessState struct {
	Locked    bool                       `json:"locked"`
	UpdatedAt time.Time                  `json:"updated_at"`
	Routes    map[string]runtimeSSHRoute `json:"routes,omitempty"`
}

type runtimeSSHRoute struct {
	Name      string    `json:"name"`
	ID        string    `json:"id"`
	DevName   string    `json:"dev_name"`
	UserName  string    `json:"user_name"`
	Network   string    `json:"network"`
	UpdatedAt time.Time `json:"updated_at"`
}

func runtimeAccessPath() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "access.json"), nil
}

func loadRuntimeAccess() (runtimeAccessState, error) {
	path, err := runtimeAccessPath()
	if err != nil {
		return runtimeAccessState{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeAccessState{Locked: true, Routes: map[string]runtimeSSHRoute{}}, nil
	}
	if err != nil {
		return runtimeAccessState{}, err
	}
	var access runtimeAccessState
	if err := json.Unmarshal(raw, &access); err != nil {
		return runtimeAccessState{}, err
	}
	if access.Routes == nil {
		access.Routes = map[string]runtimeSSHRoute{}
	}
	return access, nil
}

func saveRuntimeAccess(access runtimeAccessState) error {
	path, err := runtimeAccessPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	access.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(access, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func lockRuntimeAccess() error {
	_ = removeIdentityAgentSockets()
	return saveRuntimeAccess(runtimeAccessState{Locked: true, Routes: map[string]runtimeSSHRoute{}})
}

func removeIdentityAgentSockets() error {
	dir, err := envdDataDir()
	if err != nil {
		return err
	}
	agentDir := filepath.Join(dir, "runtime", "identity-agents")
	entries, err := os.ReadDir(agentDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSocket != 0 || strings.HasSuffix(entry.Name(), ".sock") {
			_ = os.Remove(filepath.Join(agentDir, entry.Name()))
		}
	}
	return nil
}

func publishRuntimeRoute(ref envRef, network string) error {
	access, err := loadRuntimeAccess()
	if err != nil {
		return err
	}
	if access.Routes == nil {
		access.Routes = map[string]runtimeSSHRoute{}
	}
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	access.Locked = false
	access.Routes[ref.Name] = runtimeSSHRoute{
		Name:      ref.Name,
		ID:        ref.ID,
		DevName:   ref.DevName,
		UserName:  userName,
		Network:   networkOrSealed(network),
		UpdatedAt: time.Now().UTC(),
	}
	return saveRuntimeAccess(access)
}

func runtimeRoute(name string) (runtimeSSHRoute, error) {
	access, err := loadRuntimeAccess()
	if err != nil {
		return runtimeSSHRoute{}, err
	}
	if access.Locked {
		return runtimeSSHRoute{}, fmt.Errorf("envd access is locked; run envd unlock")
	}
	route, ok := access.Routes[name]
	if !ok {
		return runtimeSSHRoute{}, fmt.Errorf("environment %q is not published for SSH; run envd start %s", name, name)
	}
	return route, nil
}

func stopEnvWorkload(ref envRef) error {
	var errs []string
	if containerExists(ref.DevName) {
		if err := dockerRun("stop", ref.DevName); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if containerExists(ref.NetName) {
		if err := dockerRun("stop", ref.NetName); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if ref.Storage == "protected" {
		if err := persistProtectedVolumes(ref); err != nil {
			errs = append(errs, err.Error())
		}
		if err := dockerRun("rm", "-f", ref.DevName); err != nil && containerExists(ref.DevName) {
			errs = append(errs, err.Error())
		}
		_ = dockerRun("volume", "rm", ref.HomeVol)
		_ = dockerRun("volume", "rm", ref.RepoVol)
		if err := detachProtectedStorage(ref.protectedStorage()); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func persistProtectedVolumes(ref envRef) error {
	rec := ref.protectedStorage()
	if err := ensureProtectedStorageMounted(rec); err != nil {
		return err
	}
	for _, item := range []struct {
		volume string
		path   string
	}{
		{volume: ref.HomeVol, path: rec.HomeDir},
		{volume: ref.RepoVol, path: rec.RepoDir},
	} {
		if !volumeExists(item.volume) {
			continue
		}
		raw, err := exportVolumeTarGzip(item.volume)
		if err != nil {
			return err
		}
		if err := replacePathFromTarGzip(item.path, raw); err != nil {
			return err
		}
	}
	return nil
}

func restoreProtectedVolumes(ref envRef) error {
	rec := ref.protectedStorage()
	if err := ensureProtectedStorageMounted(rec); err != nil {
		return err
	}
	for _, item := range []struct {
		volume string
		path   string
	}{
		{volume: ref.HomeVol, path: rec.HomeDir},
		{volume: ref.RepoVol, path: rec.RepoDir},
	} {
		if err := dockerRun("volume", "create", item.volume); err != nil {
			return err
		}
		raw, err := exportPathTarGzip(item.path)
		if err != nil {
			return err
		}
		if len(raw) > 0 {
			if err := importTarGzipToVolume(raw, item.volume); err != nil {
				return err
			}
		}
	}
	return detachProtectedStorage(rec)
}

type recoveryPayload struct {
	Version   int                       `json:"version"`
	EnvID     string                    `json:"env_id"`
	EnvName   string                    `json:"env_name"`
	Reason    string                    `json:"reason"`
	CreatedAt time.Time                 `json:"created_at"`
	Volumes   map[string]recoveryVolume `json:"volumes"`
}

type recoveryVolume struct {
	Name     string `json:"name"`
	TarGzip  string `json:"tar_gzip_base64"`
	SizeHint int    `json:"size_hint"`
}

func createAutomaticRecoveryPoint(st *envdState, password []byte, envName string, ref envRef, reason string) error {
	if ref.Legacy {
		return nil
	}
	id, err := newRecoveryID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	payload := recoveryPayload{
		Version:   1,
		EnvID:     ref.ID,
		EnvName:   envName,
		Reason:    reason,
		CreatedAt: now,
		Volumes:   map[string]recoveryVolume{},
	}
	for label, source := range map[string]string{"home": ref.HomeVol, "repo": ref.RepoVol} {
		raw, err := exportVolumeTarGzip(source)
		if err != nil {
			return fmt.Errorf("create recovery point for %s: %w", source, err)
		}
		payload.Volumes[label] = recoveryVolume{
			Name:     source,
			TarGzip:  base64.StdEncoding.EncodeToString(raw),
			SizeHint: len(raw),
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env, err := encryptEnvelope(raw, password)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	path, err := recoveryPointPath(ref.ID, id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	info, _ := os.Stat(path)
	size := int64(len(out))
	if info != nil {
		size = info.Size()
	}
	st.RecoveryPoints = append(st.RecoveryPoints, recoveryPointRecord{
		ID:        id,
		EnvID:     ref.ID,
		EnvName:   envName,
		Reason:    reason,
		Path:      path,
		SizeBytes: size,
		CreatedAt: now,
	})
	st.addEvent("recovery", envName, "created encrypted recovery point "+id+" before "+reason)
	pruneRecoveryPoints(st)
	return nil
}

func exportStorageTarGzip(storageMode, source string) ([]byte, error) {
	if storageMode == "protected" {
		return exportPathTarGzip(source)
	}
	return exportVolumeTarGzip(source)
}

func exportVolumeTarGzip(volume string) ([]byte, error) {
	if exec.Command("docker", "volume", "inspect", volume).Run() != nil {
		return []byte{}, nil
	}
	cmd := exec.Command("docker", "run", "--rm", "-v", volume+":/data:ro", "alpine:3.21", "tar", "-C", "/data", "-czf", "-", ".")
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("docker volume export failed: %w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

func exportPathTarGzip(path string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []byte{}, nil
		}
		return nil, err
	}
	cmd := exec.Command("tar", "-C", path, "-czf", "-", ".")
	cmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("path export failed: %w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

func replacePathFromTarGzip(path string, raw []byte) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	cmd := exec.Command("tar", "-C", path, "-xzf", "-")
	cmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	cmd.Stdin = bytes.NewReader(raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("path import failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func importTarGzipToVolume(raw []byte, volume string) error {
	cmd := exec.Command("docker", "run", "--rm", "-i", "-v", volume+":/data", "alpine:3.21", "sh", "-lc", "find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -C /data -xzf -")
	cmd.Stdin = bytes.NewReader(raw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker volume import failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func recoveryPointPath(envID, id string) (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "recovery", envID, id+".enc"), nil
}

func newRecoveryID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func pruneRecoveryPoints(st *envdState) {
	latest := map[string]recoveryPointRecord{}
	for _, rp := range st.RecoveryPoints {
		current, ok := latest[rp.EnvID]
		if !ok || rp.CreatedAt.After(current.CreatedAt) {
			if ok {
				_ = os.Remove(current.Path)
			}
			latest[rp.EnvID] = rp
			continue
		}
		_ = os.Remove(rp.Path)
	}
	out := make([]recoveryPointRecord, 0, len(latest))
	for _, rp := range latest {
		out = append(out, rp)
	}
	sortRecoveryPoints(out)
	st.RecoveryPoints = out
}

func removeRecoveryPointsForEnv(st *envdState, envID string) {
	out := st.RecoveryPoints[:0]
	for _, rp := range st.RecoveryPoints {
		if rp.EnvID == envID {
			_ = os.Remove(rp.Path)
			continue
		}
		out = append(out, rp)
	}
	st.RecoveryPoints = out
	if dir, err := envdDataDir(); err == nil {
		_ = os.Remove(filepath.Join(dir, "recovery", envID))
	}
}

func sortRecoveryPoints(points []recoveryPointRecord) {
	sort.Slice(points, func(i, j int) bool {
		if points[i].EnvID == points[j].EnvID {
			return points[i].CreatedAt.Before(points[j].CreatedAt)
		}
		return points[i].EnvID < points[j].EnvID
	})
}

type workloadRunning func(envRef) (bool, error)

func (a app) runSupervisor(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printSupervisorHelp()
		return nil
	}
	mode := args[0]
	idle, err := parseSupervisorIdle(args[1:])
	if err != nil {
		return err
	}
	store, err := newStateStore()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.dir, 0o700); err != nil {
		return err
	}
	if !fileExists(store.path) {
		return fmt.Errorf("envd is not initialized; run envd init first")
	}
	password, err := readMasterPassword(a.stderr)
	if err != nil {
		return err
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	runTick := func() error {
		stopped, err := supervisorStateTick(store, password, idle, workloadIsRunning, stopEnvWorkload)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Supervisor: stopped %d idle workloads\n", stopped)
		return nil
	}
	switch mode {
	case "tick":
		return runTick()
	case "run":
		if err := runTick(); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		wake := dockerEventWake(ctx)
		fmt.Fprintf(a.stdout, "Supervisor: running idle=%s wake=docker-events+next-idle\n", idle)
		for {
			delay, err := supervisorStateNextDelay(store, password, idle)
			if err != nil {
				fmt.Fprintf(a.stderr, "WARN: supervisor schedule failed: %s\n", redactSensitive(err.Error()))
				delay = 10 * time.Minute
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				stopTimer(timer)
				fmt.Fprintln(a.stdout, "Supervisor: stopped")
				return nil
			case <-wake:
				stopTimer(timer)
				if err := runTick(); err != nil {
					fmt.Fprintf(a.stderr, "WARN: supervisor tick failed: %s\n", redactSensitive(err.Error()))
				}
			case <-timer.C:
				if err := runTick(); err != nil {
					fmt.Fprintf(a.stderr, "WARN: supervisor tick failed: %s\n", redactSensitive(err.Error()))
				}
			}
		}
	default:
		return fmt.Errorf("usage: envd supervisor <run|tick> [--idle 3h]")
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func parseSupervisorIdle(args []string) (time.Duration, error) {
	idle := 3 * time.Hour
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--idle":
			i++
			if i >= len(args) {
				return 0, fmt.Errorf("missing value for --idle")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return 0, fmt.Errorf("invalid --idle duration: %w", err)
			}
			idle = d
		default:
			return 0, fmt.Errorf("usage: envd supervisor <run|tick> [--idle 3h]")
		}
	}
	if idle < 30*time.Minute {
		return 0, fmt.Errorf("--idle must be at least 30m")
	}
	return idle, nil
}

func supervisorStateTick(store stateStore, password []byte, idle time.Duration, running workloadRunning, stop workloadStopper) (int, error) {
	unlock, err := store.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	st, err := store.loadOrCreate(password)
	if err != nil {
		return 0, err
	}
	stopped, err := supervisorTick(&st, idle, time.Now().UTC(), running, stop)
	if saveErr := store.save(st, password); saveErr != nil {
		if err != nil {
			return stopped, fmt.Errorf("%w; additionally failed to save state: %v", err, saveErr)
		}
		return stopped, saveErr
	}
	return stopped, err
}

func supervisorStateNextDelay(store stateStore, password []byte, idle time.Duration) (time.Duration, error) {
	unlock, err := store.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	st, err := store.loadOrCreate(password)
	if err != nil {
		return 0, err
	}
	return supervisorNextDelay(&st, idle, time.Now().UTC()), nil
}

func supervisorNextDelay(st *envdState, idle time.Duration, now time.Time) time.Duration {
	const noWorkDelay = time.Hour
	const maxDelay = time.Hour
	var next time.Time
	for _, rec := range st.Environments {
		last := recLastUsed(rec)
		if last.IsZero() {
			continue
		}
		due := last.Add(idle)
		if due.Before(now) || due.Equal(now) {
			return time.Nanosecond
		}
		if next.IsZero() || due.Before(next) {
			next = due
		}
	}
	if next.IsZero() {
		return noWorkDelay
	}
	delay := next.Sub(now)
	if delay > maxDelay {
		return maxDelay
	}
	if delay < time.Nanosecond {
		return time.Nanosecond
	}
	return delay
}

func dockerEventWake(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	cmd := exec.CommandContext(ctx, "docker", "events", "--filter", "label=envd.managed=true", "--format", "{{.Action}}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ch
	}
	if err := cmd.Start(); err != nil {
		return ch
	}
	go func() {
		defer cmd.Wait()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch
}

func supervisorTick(st *envdState, idle time.Duration, now time.Time, running workloadRunning, stop workloadStopper) (int, error) {
	stopped := 0
	failures := []string{}
	for _, name := range sortedEnvNames(st) {
		rec := st.Environments[name]
		last := recLastUsed(rec)
		if last.IsZero() || now.Sub(last) < idle {
			continue
		}
		ref, err := resolveEnvRef(st, name)
		if err != nil {
			failures = append(failures, name+": "+err.Error())
			st.addEvent("supervisor", name, "idle stop failed: "+redactSensitive(err.Error()))
			continue
		}
		isRunning, err := running(ref)
		if err != nil {
			failures = append(failures, name+": "+err.Error())
			st.addEvent("supervisor", name, "idle check failed: "+redactSensitive(err.Error()))
			continue
		}
		if !isRunning {
			continue
		}
		if err := stop(ref); err != nil {
			failures = append(failures, name+": "+err.Error())
			st.addEvent("supervisor", name, "idle stop failed: "+redactSensitive(err.Error()))
			continue
		}
		rec.UpdatedAt = now
		st.Environments[name] = rec
		st.addEvent("supervisor", name, "idle auto-stopped after "+idle.String())
		stopped++
	}
	if len(failures) > 0 {
		return stopped, fmt.Errorf("supervisor had %d failures: %s", len(failures), strings.Join(failures, "; "))
	}
	return stopped, nil
}

func workloadIsRunning(ref envRef) (bool, error) {
	dev, err := inspectContainer(ref.DevName)
	if err != nil {
		return false, err
	}
	return dev.State.Status == "running", nil
}

func recLastUsed(rec envRecord) time.Time {
	if !rec.LastUsedAt.IsZero() {
		return rec.LastUsedAt
	}
	if !rec.UpdatedAt.IsZero() {
		return rec.UpdatedAt
	}
	return rec.CreatedAt
}

func touchEnvUsed(st *envdState, name string, at time.Time) {
	if rec, ok := st.Environments[name]; ok {
		rec.LastUsedAt = at
		rec.UpdatedAt = at
		st.Environments[name] = rec
	}
}

func (a app) runShell(args []string) error {
	var dockerArgs []string
	if err := a.withState(func(st *envdState) error {
		if len(args) > 0 {
			name := args[0]
			ref, err := resolveEnvRef(st, name)
			if err != nil {
				return err
			}
			rec, ok := st.Environments[name]
			if !ok {
				return fmt.Errorf("unknown environment %q", name)
			}
			if envNeedsStart(ref, rec.Network) {
				if err := a.startEnv([]string{name}, st); err != nil {
					return err
				}
			} else {
				touchEnvUsed(st, name, time.Now().UTC())
			}
		}
		var err error
		dockerArgs, err = prepareShellDockerArgs(args, st)
		return err
	}); err != nil {
		return err
	}
	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	return cmd.Run()
}

func envNeedsStart(ref envRef, networkMode string) bool {
	if dockerContainerStatus(ref.DevName) != "running" {
		return true
	}
	if networkMode == "sealed" && dockerContainerStatus(ref.NetName) != "running" {
		return true
	}
	if devContainerNeedsHostDockerSocketRepair(ref.DevName) {
		return true
	}
	return false
}

func prepareShellDockerArgs(args []string, st *envdState) ([]string, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: envd shell ENV [COMMAND...]")
	}
	name := args[0]
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return nil, err
	}
	command := []string{"bash", "-l"}
	interactive := true
	if len(args) > 1 {
		command = args[1:]
		interactive = false
	}
	dockerArgs := []string{"exec"}
	if interactive && term.IsTerminal(int(os.Stdin.Fd())) {
		dockerArgs = append(dockerArgs, "-it")
	} else {
		dockerArgs = append(dockerArgs, "-i")
	}
	identity, err := singleSSHIdentityForShell(st, name)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		dockerArgs = append(dockerArgs, "-e", "ENVD_IDENTITY_KEY_B64="+base64.StdEncoding.EncodeToString([]byte(identity.PrivateKey)))
		command = shellCommandWithEphemeralSSHAgent(command)
	}
	dockerArgs = append(dockerArgs, "-u", ref.UserName, "-w", "/home/"+ref.UserName+"/repo", ref.DevName)
	dockerArgs = append(dockerArgs, command...)
	return dockerArgs, nil
}

func singleSSHIdentityForShell(st *envdState, envName string) (*identityRecord, error) {
	var out *identityRecord
	names := make([]string, 0, len(st.Identities))
	for name := range st.Identities {
		names = append(names, name)
	}
	sortStrings(names)
	for _, identityName := range names {
		rec := st.Identities[identityName]
		if rec.Type != "ssh" || strings.TrimSpace(rec.PrivateKey) == "" {
			continue
		}
		if out != nil {
			return nil, nil
		}
		decision := evaluateIdentityBrokerGrant(st, envName, identityName, "ssh", runtimeIdentityBrokerHealth(st, envName))
		if !decision.Allow {
			return nil, fmt.Errorf("identity %q denied for %s: %s", identityName, envName, decision.Reason)
		}
		copy := rec
		out = &copy
	}
	return out, nil
}

func (a app) startUnlockedIdentityAgents(st *envdState) (int, error) {
	if len(st.Identities) == 0 || len(st.Environments) == 0 {
		return 0, nil
	}
	var failures []string
	started := 0
	for _, envName := range sortedEnvNames(st) {
		identity, err := singleSSHIdentityForShell(st, envName)
		if err != nil {
			failures = append(failures, envName+": "+redactSensitive(err.Error()))
			continue
		}
		if identity == nil {
			continue
		}
		if err := startStaticIdentityAgent(envName, *identity); err != nil {
			failures = append(failures, envName+": "+redactSensitive(err.Error()))
			continue
		}
		started++
	}
	if len(failures) > 0 {
		return started, fmt.Errorf("identity agent start failed: %s", strings.Join(failures, "; "))
	}
	return started, nil
}

func startStaticIdentityAgent(envName string, identity identityRecord) error {
	socketPath, err := identityAgentSocketPath(envName)
	if err != nil {
		return err
	}
	if unixSocketAccepts(socketPath) {
		return nil
	}
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	cmd := exec.Command(currentEnvdExecutable(), "__identity-agent", envName, identity.Name, socketPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, identity.PrivateKey); err != nil {
		_ = stdin.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return waitForUnixSocket(socketPath, 3*time.Second)
}

func unixSocketAccepts(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitForUnixSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if unixSocketAccepts(path) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("identity agent socket did not become ready: %s", path)
}

func shellCommandWithEphemeralSSHAgent(command []string) []string {
	quoted := make([]string, 0, len(command))
	for _, part := range command {
		quoted = append(quoted, shellQuote(part))
	}
	script := `
set -eu
if command -v ssh-agent >/dev/null 2>&1 && command -v ssh-add >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
  eval "$(ssh-agent -s)" >/dev/null
  trap 'ssh-agent -k >/dev/null 2>&1 || true' EXIT INT TERM
  printf '%s' "$ENVD_IDENTITY_KEY_B64" | base64 -d | ssh-add - >/dev/null 2>&1
  unset ENVD_IDENTITY_KEY_B64
fi
exec ` + strings.Join(quoted, " ")
	return []string{"sh", "-lc", script}
}

func (a app) runSSHProxy(args []string) error {
	if len(args) == 1 {
		stop, err := a.startSSHProxyIdentityAgent(args[0])
		if err != nil {
			return err
		}
		defer stop()
	}
	dockerArgs, err := prepareSSHProxyDockerArgs(args)
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	return cmd.Run()
}

func (a app) startSSHProxyIdentityAgent(envName string) (func(), error) {
	store, err := newStateStore()
	if err != nil {
		return func() {}, err
	}
	socketPath, err := identityAgentSocketPath(envName)
	if err != nil {
		return func() {}, err
	}
	if unixSocketAccepts(socketPath) {
		return func() {}, nil
	}
	staleSocket := false
	if _, err := os.Stat(socketPath); err == nil {
		staleSocket = true
	}
	var identityName string
	if err := store.withState(a.stderr, func(st *envdState) error {
		st.ensureDefaults()
		identity, err := singleSSHIdentityForShell(st, envName)
		if err != nil {
			return err
		}
		if identity == nil {
			return nil
		}
		identityName = identity.Name
		return nil
	}); err != nil {
		if isSSHProxyUnlockUnavailable(err) {
			if staleSocket {
				return func() {}, fmt.Errorf("envd identity agent is stale; run `envd unlock`, then retry SSH")
			}
			return func() {}, nil
		}
		return func() {}, err
	}
	if identityName == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return func() {}, err
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return func() {}, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go a.handleIdentitySSHAgentConn(conn, envName, identityName)
		}
	}()
	stop := func() {
		_ = listener.Close()
		<-done
		_ = os.Remove(socketPath)
	}
	return stop, nil
}

func isSSHProxyUnlockUnavailable(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "master password is not cached and no terminal is available")
}

func prepareSSHProxyDockerArgs(args []string) ([]string, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: envd ssh-proxy ENV")
	}
	name := args[0]
	route, err := runtimeRoute(name)
	if err != nil {
		return nil, err
	}
	if route.Network == "offline" {
		return nil, fmt.Errorf("environment %q is offline; SSH proxy denied", name)
	}
	if dockerContainerStatus(route.DevName) != "running" {
		return nil, fmt.Errorf("environment %q is not running; start it first with: envd start %s", name, name)
	}
	ref := envRef{Name: route.Name, ID: route.ID, UserName: route.UserName, DevName: route.DevName, Network: route.Network}
	if err := ensureEnvAuthorizedKey(ref); err != nil {
		return nil, err
	}
	if err := ensureEnvPrompt(ref); err != nil {
		return nil, err
	}
	return []string{
		"exec", "-i", route.DevName,
		"bash", "-lc", "exec 3<>/dev/tcp/127.0.0.1/22; cat <&3 & cat >&3; kill $! 2>/dev/null || true",
	}, nil
}

func syncEnvSSHConfig(st *envdState) error {
	st.ensureDefaults()
	names := make([]string, 0, len(st.Environments))
	for name := range st.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return syncEnvSSHConfigNames(names, currentEnvdExecutable())
}

func syncEnvSSHConfigNames(names []string, envdPath string) error {
	sshDir, mainConfig, envdConfig, knownHosts, keyPath, _, err := sshConfigPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if _, err := ensureEnvdSSHKey(); err != nil {
		return err
	}
	if err := ensureSSHInclude(mainConfig, envdConfig); err != nil {
		return err
	}
	blocks := make(map[string]string, len(names))
	for _, name := range names {
		if err := validateEnvName(name); err != nil {
			return err
		}
		blocks[name] = envdSSHHostBlock(name, envdPath, knownHosts, keyPath)
	}
	return rewriteManagedSSHBlocks(envdConfig, blocks)
}

type envdSSHKey struct {
	PrivateKey string
	PublicKey  string
}

func ensureEnvSSHConfig(envName, envdPath string) error {
	if err := validateEnvName(envName); err != nil {
		return err
	}
	sshDir, mainConfig, envdConfig, knownHosts, keyPath, _, err := sshConfigPaths()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if _, err := ensureEnvdSSHKey(); err != nil {
		return err
	}
	if err := ensureSSHInclude(mainConfig, envdConfig); err != nil {
		return err
	}
	block := envdSSHHostBlock(envName, envdPath, knownHosts, keyPath)
	return upsertManagedSSHBlock(envdConfig, envName, block)
}

func removeEnvKnownHost(envName string) error {
	if err := validateEnvName(envName); err != nil {
		return err
	}
	_, _, _, knownHosts, _, _, err := sshConfigPaths()
	if err != nil {
		return err
	}
	if !fileExists(knownHosts) {
		return nil
	}
	alias := "envd-" + envName
	cmd := exec.Command("ssh-keygen", "-R", alias, "-f", knownHosts)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove old SSH host key for %s: %w\n%s", alias, err, strings.TrimSpace(string(out)))
	}
	_ = os.Remove(knownHosts + ".old")
	return nil
}

func ensureEnvdSSHKey() (envdSSHKey, error) {
	sshDir, _, _, _, keyPath, pubPath, err := sshConfigPaths()
	if err != nil {
		return envdSSHKey{}, err
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return envdSSHKey{}, err
	}
	if !fileExists(keyPath) || !fileExists(pubPath) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return envdSSHKey{}, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "envd")
		if err != nil {
			return envdSSHKey{}, err
		}
		privatePEM := pem.EncodeToMemory(block)
		if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
			return envdSSHKey{}, err
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return envdSSHKey{}, err
		}
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
			return envdSSHKey{}, err
		}
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return envdSSHKey{}, err
	}
	return envdSSHKey{PrivateKey: keyPath, PublicKey: strings.TrimSpace(string(pubRaw))}, nil
}

func sshConfigPaths() (sshDir, mainConfig, envdConfig, knownHosts, keyPath, pubPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", "", "", "", err
	}
	sshDir = filepath.Join(home, ".ssh")
	keyPath = filepath.Join(sshDir, "envd_ed25519")
	return sshDir, filepath.Join(sshDir, "config"), filepath.Join(sshDir, "envd_config"), filepath.Join(sshDir, "envd_known_hosts"), keyPath, keyPath + ".pub", nil
}

func ensureSSHInclude(mainConfig, envdConfig string) error {
	includeLine := "Include " + envdConfig
	raw, err := os.ReadFile(mainConfig)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := pruneLegacyInlineEnvdSSHBlocks(string(raw))
	if !strings.Contains(content, includeLine) {
		content = strings.TrimRight(content, "\n")
		if content == "" {
			content = includeLine + "\n"
		} else {
			content = includeLine + "\n" + content + "\n"
		}
	}
	return os.WriteFile(mainConfig, []byte(content), 0o600)
}

func pruneLegacyInlineEnvdSSHBlocks(content string) string {
	lines := strings.Split(content, "\n")
	var kept []string
	for i := 0; i < len(lines); {
		if !isSSHHostLine(lines[i]) {
			kept = append(kept, lines[i])
			i++
			continue
		}
		j := i + 1
		for j < len(lines) && !isSSHHostLine(lines[j]) {
			j++
		}
		block := strings.Join(lines[i:j], "\n")
		if isLegacyInlineEnvdSSHBlock(block) {
			for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
				kept = kept[:len(kept)-1]
			}
			i = j
			continue
		}
		kept = append(kept, lines[i:j]...)
		i = j
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
}

func isSSHHostLine(line string) bool {
	fields := strings.Fields(line)
	return len(fields) > 0 && strings.EqualFold(fields[0], "Host")
}

func isLegacyInlineEnvdSSHBlock(block string) bool {
	return strings.Contains(block, "UserKnownHostsFile") &&
		strings.Contains(block, "known_hosts_envd") &&
		strings.Contains(block, "HostName 127.0.0.1")
}

func envdSSHHostBlock(envName, envdPath, knownHosts, keyPath string) string {
	agentSocket, err := identityAgentSocketPath(envName)
	if err != nil {
		agentSocket = "none"
	}
	return fmt.Sprintf(`# envd managed: %s
Host %s
  HostName envd
  User dev
  Port 22
  ProxyCommand %s ssh-proxy %s
  IdentityFile %s
  IdentitiesOnly yes
  ForwardAgent yes
  IdentityAgent %s
  HostKeyAlias envd-%s
  StrictHostKeyChecking accept-new
  UserKnownHostsFile %s
# envd managed end: %s
`, envName, envName, shellWords(envdPath), shellWords(envName), shellWords(keyPath), shellWords(agentSocket), envName, shellWords(knownHosts), envName)
}

func identityAgentSocketPath(envName string) (string, error) {
	if err := validateEnvName(envName); err != nil {
		return "", err
	}
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "identity-agents", envName+".sock"), nil
}

func upsertManagedSSHBlock(path, envName, block string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	start := "# envd managed: " + envName
	end := "# envd managed end: " + envName
	content := string(raw)
	startIdx := strings.Index(content, start)
	if startIdx >= 0 {
		endIdx := strings.Index(content[startIdx:], end)
		if endIdx >= 0 {
			endIdx = startIdx + endIdx + len(end)
			for endIdx < len(content) && (content[endIdx] == '\n' || content[endIdx] == '\r') {
				endIdx++
			}
			content = content[:startIdx] + block + content[endIdx:]
			return os.WriteFile(path, []byte(content), 0o600)
		}
	}
	content = strings.TrimRight(content, "\n")
	if content != "" {
		content += "\n\n"
	}
	content += block
	return os.WriteFile(path, []byte(content), 0o600)
}

func rewriteManagedSSHBlocks(path string, blocks map[string]string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := pruneAllManagedSSHBlocks(string(raw))
	names := make([]string, 0, len(blocks))
	for name := range blocks {
		names = append(names, name)
	}
	sort.Strings(names)
	content = strings.TrimRight(content, "\n")
	for _, name := range names {
		if content != "" {
			content += "\n\n"
		}
		content += strings.TrimRight(blocks[name], "\n") + "\n"
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func pruneAllManagedSSHBlocks(content string) string {
	const marker = "# envd managed: "
	for {
		startIdx := strings.Index(content, marker)
		if startIdx < 0 {
			break
		}
		lineEnd := strings.IndexByte(content[startIdx:], '\n')
		if lineEnd < 0 {
			content = strings.TrimRight(content[:startIdx], "\n")
			break
		}
		name := strings.TrimSpace(content[startIdx+len(marker) : startIdx+lineEnd])
		end := "# envd managed end: " + name
		endIdx := strings.Index(content[startIdx:], end)
		if endIdx < 0 {
			break
		}
		endIdx = startIdx + endIdx + len(end)
		for endIdx < len(content) && (content[endIdx] == '\n' || content[endIdx] == '\r') {
			endIdx++
		}
		content = content[:startIdx] + content[endIdx:]
	}
	return strings.TrimRight(content, "\n")
}

func currentEnvdExecutable() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return "envd"
	}
	return exe
}

func shellWords(value string) string {
	if regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`).MatchString(value) {
		return value
	}
	return shellQuote(value)
}

func (a app) runMigrate(args []string, st *envdState, password []byte) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printMigrateHelp()
		return nil
	}
	switch args[0] {
	case "inspect":
		return a.runMigrateInspect(st)
	case "protected":
		return a.runMigrateProtected(args[1:], st)
	case "adopt":
		yes := false
		for _, arg := range args[1:] {
			if arg == "--yes" || arg == "-y" {
				yes = true
			} else {
				return fmt.Errorf("usage: envd migrate adopt --yes")
			}
		}
		if !yes {
			return fmt.Errorf("usage: envd migrate adopt --yes")
		}
		return a.runMigrateAdopt(st)
	default:
		return a.runMigrateEnvProfile(args, st, password)
	}
}

func (a app) runMigrateEnvProfile(args []string, st *envdState, password []byte) error {
	name, profileName, err := parseMigrateProfileArgs(args)
	if err != nil {
		return err
	}
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	if ref.Legacy {
		return fmt.Errorf("migrate --profile supports envd-owned environments only; adopt/recreate legacy env %q first", name)
	}
	env, err := inspectEnv(st, name)
	if err != nil {
		return err
	}
	mode := env.networkMode()
	image, generation, err := a.ensureProfileImage(st, profileName)
	if err != nil {
		return err
	}
	if mode == "sealed" {
		if err := a.ensureRuntimeAssetRecorded(st, runtimeAssets[1]); err != nil {
			return err
		}
		if err := ensureDockerNetwork(gatewayNet); err != nil {
			return err
		}
	}
	if err := createAutomaticRecoveryPoint(st, password, name, ref, "profile migration to "+profileName); err != nil {
		return err
	}

	_ = dockerRun("stop", ref.DevName)
	_ = dockerRun("rm", "-f", ref.DevName)
	if mode == "sealed" {
		_ = dockerRun("rm", "-f", ref.NetName)
		if err := createSidecar(name, ref.ID, ref.NetName); err != nil {
			return err
		}
	}
	if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, mode, image); err != nil {
		return err
	}
	if mode == "sealed" {
		if err := verifySealedEnv(ref.DevName); err != nil {
			return err
		}
	}
	rec := st.Environments[name]
	rec.Image = image
	rec.Profile = profileName
	rec.ProfileGeneration = generation
	rec.GatewayGeneration = st.GatewayGeneration
	rec.UpdatedAt = time.Now().UTC()
	st.Environments[name] = rec
	ref.Network = mode
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	st.addEvent("env", name, fmt.Sprintf("migrated to profile %s generation %d", profileName, generation))
	_ = pruneProfileImages(st)
	fmt.Fprintf(a.stdout, "Migrated: %s\n", name)
	fmt.Fprintf(a.stdout, "Profile:  %s generation %d\n", profileName, generation)
	fmt.Fprintf(a.stdout, "Network:  %s\n", mode)
	return nil
}

func (a app) runMigrateProtected(args []string, st *envdState) error {
	if len(args) != 2 || (args[1] != "--yes" && args[1] != "-y") {
		return fmt.Errorf("usage: envd migrate protected ENV --yes")
	}
	name := args[0]
	rec, ok := st.Environments[name]
	if !ok {
		return fmt.Errorf("environment %q is not adopted; run envd migrate adopt --yes first", name)
	}
	if !rec.Legacy {
		return fmt.Errorf("environment %q is already envd-owned; protected import is for adopted legacy envs only", name)
	}
	if storageOrPlain(rec.Storage) != "plain" {
		return fmt.Errorf("environment %q is not plain legacy storage", name)
	}
	legacyRef, err := resolveEnvRef(st, name)
	if err != nil {
		return err
	}
	homeRaw, err := exportVolumeTarGzip(legacyRef.HomeVol)
	if err != nil {
		return fmt.Errorf("export legacy home volume: %w", err)
	}
	repoRaw, err := exportVolumeTarGzip(legacyRef.RepoVol)
	if err != nil {
		return fmt.Errorf("export legacy repo volume: %w", err)
	}
	newID, err := newOpaqueID(st)
	if err != nil {
		return err
	}
	protected, err := createProtectedStorage(newID)
	if err != nil {
		return err
	}
	cleanupProtected := true
	defer func() {
		if cleanupProtected {
			_ = removeProtectedStorage(protected)
		}
	}()
	newRef := envRef{
		Name:             name,
		ID:               newID,
		UserName:         "dev",
		DevName:          devContainerName(newID),
		NetName:          netContainerName(newID),
		HomeVol:          homeVolumeName(newID),
		RepoVol:          repoVolumeName(newID),
		HomeSource:       homeVolumeName(newID),
		RepoSource:       repoVolumeName(newID),
		Storage:          "protected",
		StorageBackend:   protected.Backend,
		StorageImagePath: protected.ImagePath,
		StorageMountPath: protected.MountPath,
		StorageKey:       protected.Key,
	}
	if err := dockerRun("volume", "create", newRef.HomeVol); err != nil {
		return err
	}
	if err := dockerRun("volume", "create", newRef.RepoVol); err != nil {
		_ = dockerRun("volume", "rm", newRef.HomeVol)
		return err
	}
	cleanupVolumes := true
	defer func() {
		if cleanupVolumes {
			_ = dockerRun("volume", "rm", newRef.HomeVol)
			_ = dockerRun("volume", "rm", newRef.RepoVol)
		}
	}()
	if len(homeRaw) > 0 {
		if err := importTarGzipToVolume(homeRaw, newRef.HomeVol); err != nil {
			return err
		}
	}
	if len(repoRaw) > 0 {
		if err := importTarGzipToVolume(repoRaw, newRef.RepoVol); err != nil {
			return err
		}
	}
	if err := persistProtectedVolumes(newRef); err != nil {
		return err
	}
	_ = dockerRun("volume", "rm", newRef.HomeVol)
	_ = dockerRun("volume", "rm", newRef.RepoVol)
	if err := detachProtectedStorage(newRef.protectedStorage()); err != nil {
		return err
	}
	cleanupVolumes = false
	cleanupProtected = false

	_ = dockerRun("stop", legacyRef.DevName)
	_ = dockerRun("stop", legacyRef.NetName)
	now := time.Now().UTC()
	st.Environments[name] = envRecord{
		ID:                newID,
		Network:           rec.Network,
		Storage:           "protected",
		StorageBackend:    protected.Backend,
		StorageImagePath:  protected.ImagePath,
		StorageMountPath:  protected.MountPath,
		StorageKey:        protected.Key,
		Image:             firstNonEmpty(rec.Image, devImage),
		Profile:           rec.Profile,
		ProfileGeneration: rec.ProfileGeneration,
		GatewayGeneration: rec.GatewayGeneration,
		CreatedAt:         rec.CreatedAt,
		UpdatedAt:         now,
		LastUsedAt:        now,
	}
	st.addEvent("migration", name, "imported legacy plain volumes into protected storage")
	fmt.Fprintf(a.stdout, "Imported: %s\n", name)
	fmt.Fprintln(a.stdout, "Storage:  protected")
	fmt.Fprintf(a.stdout, "Backend:  %s\n", protected.Backend)
	fmt.Fprintln(a.stdout, "Legacy:   original Docker volumes left untouched")
	return nil
}

func (a app) runMigrateInspect(st *envdState) error {
	envs, err := discoverLegacyEnvs(st)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "%-18s %-10s %-8s %-8s %-12s %-12s %s\n", "NAME", "STATE", "NET", "STORAGE", "HOME_VOL", "REPO_VOL", "NOTE")
	for _, env := range envs {
		ref := legacyRefForEnv(env)
		note := "legacy plain"
		if _, ok := st.Environments[env.Name]; ok {
			note = "already adopted"
		}
		fmt.Fprintf(a.stdout, "%-18s %-10s %-8s %-8s %-12s %-12s %s\n",
			env.Name, env.Dev.State.Status, env.networkMode(), "plain", volumeStatus(ref.HomeVol), volumeStatus(ref.RepoVol), note)
	}
	return nil
}

func (a app) runMigrateAdopt(st *envdState) error {
	envs, err := discoverLegacyEnvs(st)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	adopted := 0
	for _, env := range envs {
		if _, ok := st.Environments[env.Name]; ok {
			continue
		}
		ref := legacyRefForEnv(env)
		st.Environments[env.Name] = envRecord{
			ID:                ref.ID,
			Network:           env.networkMode(),
			Storage:           "plain",
			Image:             env.Dev.Config.Image,
			GatewayGeneration: st.GatewayGeneration,
			Legacy:            true,
			CreatedAt:         now,
			UpdatedAt:         now,
			LastUsedAt:        now,
		}
		st.addEvent("migration", env.Name, "adopted legacy plain environment")
		adopted++
	}
	fmt.Fprintf(a.stdout, "Adopted: %d legacy plain environments\n", adopted)
	return nil
}

func (a app) runGatewayStatus(st *envdState) error {
	cfg, source, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Source: %s\n", source)
	if st.ActiveGateway != "" {
		fmt.Fprintf(a.stdout, "Active: %s\n", st.ActiveGateway)
	}
	if st.PreviousGateway != "" {
		fmt.Fprintf(a.stdout, "Previous: %s\n", st.PreviousGateway)
	}
	fmt.Fprintf(a.stdout, "Remote: %s:%s\n", cfg.ServerIP, cfg.ServerPort)
	fmt.Fprintf(a.stdout, "SOCKS:  %s:%d\n", hostForClient(cfg.BindIP), cfg.SOCKSPort)
	fmt.Fprintf(a.stdout, "HTTP:   %s:%d\n", hostForClient(cfg.BindIP), cfg.HTTPHostPort)
	fmt.Fprintf(a.stdout, "Xray:   %s\n", dockerContainerStatus("vpn-gateway-xray-1"))
	return nil
}

func (a app) runGatewayInspect(st *envdState) error {
	cfg, source, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Source:        %s\n", source)
	fmt.Fprintf(a.stdout, "Provider:      xray\n")
	fmt.Fprintf(a.stdout, "Bind:          %s\n", cfg.BindIP)
	fmt.Fprintf(a.stdout, "Host SOCKS:    %d\n", cfg.SOCKSPort)
	fmt.Fprintf(a.stdout, "Host HTTP:     %d\n", cfg.HTTPHostPort)
	fmt.Fprintf(a.stdout, "Internal SOCKS:%d\n", cfg.SOCKSInner)
	fmt.Fprintf(a.stdout, "Internal HTTP: %d\n", cfg.HTTPInner)
	fmt.Fprintf(a.stdout, "Remote:        %s:%s\n", cfg.ServerIP, cfg.ServerPort)
	return nil
}

func (a app) runGatewayRender(st *envdState) error {
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	provider := xrayProvider{}
	rendered, err := provider.Render(a, cfg)
	if err != nil {
		return layerErr("local gateway", err)
	}
	runtimeDir, err := a.materializeGatewayRuntime(cfg)
	if err != nil {
		return layerErr("local gateway", err)
	}
	fmt.Fprintf(a.stdout, "Provider: %s\n", provider.Name())
	fmt.Fprintf(a.stdout, "Render:   OK\n")
	fmt.Fprintf(a.stdout, "Bytes:    %d\n", len(rendered))
	fmt.Fprintf(a.stdout, "Runtime:  %s\n", runtimeDir)
	return nil
}

func (a app) runGatewayEgress(st *envdState) error {
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	ip, err := a.gatewayEgressIP(cfg)
	if err != nil {
		return layerErr("remote gateway", err)
	}
	fmt.Fprintf(a.stdout, "Egress: %s\n", strings.TrimSpace(ip))
	return nil
}

func (a app) runGatewayRisk(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd gateway risk NAME")
	}
	name := args[0]
	rec, ok := st.Gateways[name]
	if !ok {
		return fmt.Errorf("gateway %q not found", name)
	}
	report := gatewayRiskReport(name, rec, st)
	printGatewayRisk(a.stdout, report)
	st.addEvent("gateway", name, "risk checked: "+report.Level)
	return nil
}

type gatewayRisk struct {
	Name             string
	Level            string
	Provider         string
	ProviderReach    string
	GatewayDiversity string
	Reasons          []string
	Actions          []string
}

type gatewayInstallPlan struct {
	Name     string
	Host     string
	User     string
	Provider string
	Strategy string
	Mode     string
	Password bool
	DryRun   bool
	Yes      bool
	Probe    bool
	Verbose  bool
	Steps    []string
}

func (a app) runGatewayInstall(args []string, st *envdState) error {
	st.ensureDefaults()
	plan, err := parseGatewayInstallPlan(args)
	if err != nil {
		return err
	}
	printGatewayInstallPlan(a.stdout, plan)
	st.addEvent("gateway", plan.Name, "planned remote install "+plan.Mode+" for "+plan.Host+" using "+plan.Provider+"/"+plan.Strategy)
	existing := st.RemoteGateways[plan.Name]
	password := existing.Password
	if !plan.DryRun && !plan.Password && password == "" {
		return fmt.Errorf("remote gateway install apply requires --password or a previously stored remote password")
	}
	if plan.Password || (!plan.DryRun && password == "") {
		password, err = readGatewayPassword(a.stderr)
		if err != nil {
			return err
		}
	}
	var rec remoteGatewayRecord
	if plan.Probe || !plan.DryRun {
		result, err := probeRemoteGateway(plan, password, existing.HostKeySHA256)
		if err != nil {
			st.addEvent("gateway", plan.Name, "remote install probe failed: "+redactSensitive(err.Error()))
			return layerErr("remote gateway", err)
		}
		printRemoteGatewayProbe(a.stdout, result, plan.Verbose)
		material := existing.Material
		_, hasLocalProfile := st.Gateways[plan.Name]
		if plan.Mode == "install" && result.ProviderState.EnvdOwnedConfig && !hasLocalProfile {
			fmt.Fprintln(a.stdout, "Remote:   existing envd-owned gateway config found")
			replacePlan := plan
			replacePlan.Mode = "replace"
			if !plan.Yes {
				fmt.Fprintln(a.stdout, "Ready:    verified; no remote changes applied")
				fmt.Fprintln(a.stdout, "Next:     "+gatewayInstallApplyCommand(replacePlan))
				return nil
			}
			return fmt.Errorf("remote already has envd-owned gateway config; rerun with --replace if you want to replace it")
		}
		if plan.Mode == "replace" || material.ConfigJSON == "" {
			material, err = generateRemoteGatewayMaterial(plan)
			if err != nil {
				return err
			}
			if plan.Mode == "replace" {
				fmt.Fprintln(a.stdout, "Config:   regenerated")
			} else {
				fmt.Fprintln(a.stdout, "Config:   generated")
			}
		} else if material.ConfigJSON != "" {
			fmt.Fprintln(a.stdout, "Config:   reused")
		}
		now := time.Now().UTC()
		rec = remoteGatewayRecord{
			Name:          plan.Name,
			Host:          plan.Host,
			User:          plan.User,
			Provider:      plan.Provider,
			Strategy:      plan.Strategy,
			Mode:          plan.Mode,
			HostKeySHA256: result.HostKeySHA256,
			Inspection:    result.Inspection,
			ProviderState: result.ProviderState,
			Material:      material,
			LastProbeAt:   now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if !existing.CreatedAt.IsZero() {
			rec.CreatedAt = existing.CreatedAt
		}
		if plan.Password {
			rec.Password = password
		} else {
			rec.Password = existing.Password
		}
		st.RemoteGateways[plan.Name] = rec
		st.addEvent("gateway", plan.Name, "remote install probe succeeded; detected "+result.Inspection.OS+"/"+result.Inspection.Arch+"; provider state inspected; install material ready="+strconv.FormatBool(rec.Material.ConfigJSON != ""))
	}
	if plan.DryRun {
		return nil
	}
	if !plan.Yes {
		fmt.Fprintln(a.stdout, "Ready:    verified; no remote changes applied")
		fmt.Fprintln(a.stdout, "Next:     "+gatewayInstallApplyCommand(plan))
		return nil
	}
	if rec.Name == "" {
		return fmt.Errorf("remote gateway install requires a successful probe before apply")
	}
	if err := applyRemoteGatewayInstall(plan, rec); err != nil {
		st.addEvent("gateway", plan.Name, "remote install apply failed: "+redactSensitive(err.Error()))
		return layerErr("remote gateway", err)
	}
	now := time.Now().UTC()
	rec.ProviderState.EnvdOwnedConfig = true
	rec.ProviderState.EnvdOwnedService = rec.Inspection.InitSystem == "systemd"
	rec.ProviderState.XrayVersion = "Xray " + rec.Material.XrayVersion
	rec.UpdatedAt = now
	st.RemoteGateways[plan.Name] = rec
	st.Gateways[plan.Name] = gatewayRecordFromRemoteInstall(rec, now)
	st.addEvent("gateway", plan.Name, "remote install applied and verified; local gateway profile stored")
	fmt.Fprintln(a.stdout, "Apply:    ok")
	fmt.Fprintln(a.stdout, "Verify:   remote process ok; local TCP reachability ok")
	fmt.Fprintln(a.stdout, "Stored:   gateway profile")
	fmt.Fprintln(a.stdout, "Next:     envd gateway use "+plan.Name)
	return nil
}

func gatewayInstallApplyCommand(plan gatewayInstallPlan) string {
	parts := []string{"envd", "gateway", "install", plan.Name, "--host", plan.Host, "--user", plan.User}
	if plan.Mode == "adopt" {
		parts = append(parts, "--adopt")
	}
	if plan.Mode == "replace" {
		parts = append(parts, "--replace")
	}
	parts = append(parts, "--yes")
	return strings.Join(parts, " ")
}

func parseGatewayInstallPlan(args []string) (gatewayInstallPlan, error) {
	if len(args) == 0 {
		return gatewayInstallPlan{}, fmt.Errorf("usage: envd gateway install NAME --host HOST --user USER [--password] [--probe] [--dry-run|--yes] [--adopt|--replace] [--verbose]")
	}
	plan := gatewayInstallPlan{
		Name:     args[0],
		User:     "root",
		Provider: "xray",
		Strategy: "censorship-resistant",
		Mode:     "install",
	}
	if err := validateGatewayName(plan.Name); err != nil {
		return gatewayInstallPlan{}, err
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--host":
			i++
			if i >= len(args) {
				return gatewayInstallPlan{}, fmt.Errorf("--host requires a value")
			}
			plan.Host = args[i]
		case "--user":
			i++
			if i >= len(args) {
				return gatewayInstallPlan{}, fmt.Errorf("--user requires a value")
			}
			plan.User = args[i]
		case "--provider":
			i++
			if i >= len(args) {
				return gatewayInstallPlan{}, fmt.Errorf("--provider requires a value")
			}
			plan.Provider = args[i]
		case "--strategy":
			i++
			if i >= len(args) {
				return gatewayInstallPlan{}, fmt.Errorf("--strategy requires a value")
			}
			plan.Strategy = args[i]
		case "--password":
			plan.Password = true
		case "--dry-run":
			plan.DryRun = true
		case "--probe":
			plan.Probe = true
		case "--verbose", "-v":
			plan.Verbose = true
		case "--yes", "-y":
			plan.Yes = true
		case "--adopt":
			if plan.Mode == "replace" {
				return gatewayInstallPlan{}, fmt.Errorf("--adopt and --replace are mutually exclusive")
			}
			plan.Mode = "adopt"
		case "--replace":
			if plan.Mode == "adopt" {
				return gatewayInstallPlan{}, fmt.Errorf("--adopt and --replace are mutually exclusive")
			}
			plan.Mode = "replace"
		default:
			return gatewayInstallPlan{}, fmt.Errorf("unknown gateway install option %q", args[i])
		}
	}
	if strings.TrimSpace(plan.Host) == "" {
		return gatewayInstallPlan{}, fmt.Errorf("--host is required")
	}
	if strings.TrimSpace(plan.User) == "" {
		return gatewayInstallPlan{}, fmt.Errorf("--user cannot be empty")
	}
	if plan.Provider != "xray" {
		return gatewayInstallPlan{}, fmt.Errorf("unsupported provider %q: only xray is planned", plan.Provider)
	}
	switch plan.Strategy {
	case "censorship-resistant", "fast", "compatibility":
	default:
		return gatewayInstallPlan{}, fmt.Errorf("unsupported strategy %q", plan.Strategy)
	}
	plan.Steps = gatewayInstallPlanSteps(plan)
	return plan, nil
}

func gatewayInstallPlanSteps(plan gatewayInstallPlan) []string {
	steps := []string{
		"connect to " + plan.User + "@" + plan.Host + " over SSH",
		"detect OS, architecture, memory, disk, init system, and firewall",
		"inspect existing provider state without overwriting unknown configs",
	}
	switch plan.Mode {
	case "adopt":
		steps = append(steps, "adopt compatible existing Xray Reality service if safe")
	case "replace":
		steps = append(steps, "save previous envd-owned remote config for rollback before replace")
	default:
		steps = append(steps, "install pinned Xray Reality service if absent")
	}
	steps = append(steps,
		"generate server keys and config only when absent or replacing envd-owned config",
		"install or update systemd service when available",
		"open firewall port only for a supported detected firewall",
		"verify remote process starts",
		"verify local-to-remote handshake before marking gateway usable",
		"store remote password encrypted only after successful verification when --password is used",
	)
	return steps
}

func printGatewayInstallPlan(w io.Writer, plan gatewayInstallPlan) {
	fmt.Fprintf(w, "Name:     %s\n", plan.Name)
	fmt.Fprintf(w, "Remote:   %s@%s\n", plan.User, plan.Host)
	fmt.Fprintf(w, "Gateway:  %s (%s)\n", plan.Provider, plan.Strategy)
	fmt.Fprintf(w, "Action:   %s\n", plan.Mode)
	if plan.Password {
		fmt.Fprintln(w, "Password: requested")
	}
	if plan.Probe {
		fmt.Fprintln(w, "Probe:    enabled")
	}
	if plan.DryRun || !plan.Yes {
		fmt.Fprintln(w, "Apply:    no")
	} else {
		fmt.Fprintln(w, "Apply:    yes")
	}
	if plan.Verbose {
		for i, step := range plan.Steps {
			fmt.Fprintf(w, "Step %02d:  %s\n", i+1, step)
		}
	}
}

type remoteGatewayProbeResult struct {
	HostKeySHA256 string
	Inspection    remoteGatewayInspection
	ProviderState remoteProviderInspection
}

func readGatewayPassword(stderr io.Writer) (string, error) {
	if v := os.Getenv("ENVD_GATEWAY_PASSWORD"); v != "" {
		return v, nil
	}
	fmt.Fprint(stderr, "Remote SSH password: ")
	if term.IsTerminal(int(syscall.Stdin)) {
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		if len(pw) == 0 {
			return "", errors.New("empty remote SSH password is not allowed")
		}
		return string(pw), nil
	}
	var pw string
	if _, err := fmt.Fscan(os.Stdin, &pw); err != nil {
		return "", err
	}
	fmt.Fprintln(stderr)
	pw = strings.TrimSpace(pw)
	if pw == "" {
		return "", errors.New("empty remote SSH password is not allowed")
	}
	return pw, nil
}

func probeRemoteGateway(plan gatewayInstallPlan, password, expectedHostKey string) (remoteGatewayProbeResult, error) {
	if strings.TrimSpace(password) == "" {
		return remoteGatewayProbeResult{}, fmt.Errorf("--probe requires --password and a non-empty remote password for now")
	}
	var seenHostKey string
	cfg := &ssh.ClientConfig{
		User:            plan.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         10 * time.Second,
		HostKeyCallback: remoteHostKeyCallback(expectedHostKey, &seenHostKey),
	}
	client, err := ssh.Dial("tcp", sshAddress(plan.Host), cfg)
	if err != nil {
		return remoteGatewayProbeResult{}, err
	}
	defer client.Close()

	infoRaw, err := runSSHCommand(client, remoteInspectionScript)
	if err != nil {
		return remoteGatewayProbeResult{}, fmt.Errorf("remote inspection failed: %w", err)
	}
	providerRaw, err := runSSHCommand(client, remoteProviderInspectionScript)
	if err != nil {
		return remoteGatewayProbeResult{}, fmt.Errorf("remote provider inspection failed: %w", err)
	}
	result := remoteGatewayProbeResult{
		HostKeySHA256: seenHostKey,
		Inspection:    parseRemoteGatewayInspection(infoRaw),
		ProviderState: parseRemoteProviderInspection(providerRaw),
	}
	return result, nil
}

func applyRemoteGatewayInstall(plan gatewayInstallPlan, rec remoteGatewayRecord) error {
	if rec.Material.ConfigJSON == "" || rec.Material.ServiceUnit == "" || rec.Material.Port == 0 {
		return fmt.Errorf("remote install material is missing")
	}
	if strings.TrimSpace(rec.Password) == "" {
		return fmt.Errorf("remote install requires stored or provided password")
	}
	client, err := dialRemoteGateway(plan, rec.Password, rec.HostKeySHA256)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := runSSHCommandNoOutput(client, remoteInstallXrayScript(rec.Material)); err != nil {
		return fmt.Errorf("install pinned Xray Reality strategy failed: %w", err)
	}
	rollback := func(cause error) error {
		if rec.ProviderState.EnvdOwnedConfig {
			if rbErr := runSSHCommandNoOutput(client, remoteRollbackScript(rec.Inspection.InitSystem)); rbErr != nil {
				return fmt.Errorf("%w; rollback failed: %v", cause, rbErr)
			}
		}
		return cause
	}
	if rec.Inspection.InitSystem == "systemd" {
		if err := runSSHCommandNoOutput(client, remoteSystemdInstallScript(rec.Material)); err != nil {
			return rollback(fmt.Errorf("systemd service install failed: %w", err))
		}
	}
	if script := remoteFirewallScript(rec.Inspection.Firewall, rec.Material.Port); script != "" {
		if err := runSSHCommandNoOutput(client, script); err != nil {
			return rollback(fmt.Errorf("firewall update failed: %w", err))
		}
	}
	if err := runSSHCommandNoOutput(client, remoteProviderVerifyScript(rec.Inspection.InitSystem)); err != nil {
		return rollback(fmt.Errorf("remote provider process verification failed: %w", err))
	}
	if err := verifyRemoteGatewayReachable(plan.Host, rec.Material.Port); err != nil {
		return rollback(fmt.Errorf("local-to-remote reachability check failed: %w", err))
	}
	return nil
}

func dialRemoteGateway(plan gatewayInstallPlan, password, expectedHostKey string) (*ssh.Client, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("empty remote password is not allowed")
	}
	var seenHostKey string
	cfg := &ssh.ClientConfig{
		User:            plan.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         10 * time.Second,
		HostKeyCallback: remoteHostKeyCallback(expectedHostKey, &seenHostKey),
	}
	return ssh.Dial("tcp", sshAddress(plan.Host), cfg)
}

func runSSHCommandNoOutput(client *ssh.Client, script string) error {
	_, err := runSSHCommand(client, script)
	return err
}

func remoteInstallXrayScript(material remoteGatewayMaterial) string {
	return fmt.Sprintf(`set -eu
install -d -m 700 /usr/local/etc/envd/xray
if [ -f /usr/local/etc/envd/xray/config.json ]; then
  cp /usr/local/etc/envd/xray/config.json /usr/local/etc/envd/xray/config.json.envd-rollback
fi
cat > /usr/local/etc/envd/xray/config.json.tmp <<'ENVD_XRAY_CONFIG'
%s
ENVD_XRAY_CONFIG
install -m 600 /usr/local/etc/envd/xray/config.json.tmp /usr/local/etc/envd/xray/config.json
rm -f /usr/local/etc/envd/xray/config.json.tmp
if ! /usr/local/bin/xray version 2>/dev/null | head -n1 | grep -F %s >/dev/null 2>&1; then
  need_pkgs=""
  command -v unzip >/dev/null 2>&1 || need_pkgs="$need_pkgs unzip"
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || need_pkgs="$need_pkgs curl"
  [ -e /etc/ssl/certs/ca-certificates.crt ] || need_pkgs="$need_pkgs ca-certificates"
  if [ -n "$need_pkgs" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends $need_pkgs
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y $need_pkgs
    elif command -v yum >/dev/null 2>&1; then
      yum install -y $need_pkgs
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache $need_pkgs
    else
      echo "missing required install tools:$need_pkgs and no supported package manager found" >&2; exit 1
    fi
  fi
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) xray_arch=64 ;;
    aarch64|arm64) xray_arch=arm64-v8a ;;
    *) echo "unsupported architecture for pinned Xray: $arch" >&2; exit 1 ;;
  esac
  tmp="$(mktemp -d)"
  url="https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-${xray_arch}.zip"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/xray.zip"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp/xray.zip" "$url"
  else
    echo "curl or wget is required to install pinned Xray" >&2; exit 1
  fi
  (cd "$tmp" && unzip -q xray.zip xray)
  install -m 755 "$tmp/xray" /usr/local/bin/xray
  rm -rf "$tmp"
fi
/usr/local/bin/xray version >/dev/null
`, material.ConfigJSON, shellQuote(material.XrayVersion), material.XrayVersion)
}

func remoteSystemdInstallScript(material remoteGatewayMaterial) string {
	return fmt.Sprintf(`set -eu
cat > /etc/systemd/system/envd-xray.service.tmp <<'ENVD_XRAY_SERVICE'
%s
ENVD_XRAY_SERVICE
install -m 644 /etc/systemd/system/envd-xray.service.tmp /etc/systemd/system/envd-xray.service
rm -f /etc/systemd/system/envd-xray.service.tmp
systemctl daemon-reload
systemctl enable envd-xray.service
systemctl restart envd-xray.service
`, material.ServiceUnit)
}

func remoteFirewallScript(firewall string, port int) string {
	switch firewall {
	case "ufw":
		return fmt.Sprintf("set -eu\nufw allow %d/tcp\n", port)
	case "firewalld":
		return fmt.Sprintf("set -eu\nfirewall-cmd --permanent --add-port=%d/tcp\nfirewall-cmd --reload\n", port)
	case "nftables":
		return fmt.Sprintf("set -eu\nnft add rule inet filter input tcp dport %d accept 2>/dev/null || true\n", port)
	case "iptables":
		return fmt.Sprintf("set -eu\niptables -C INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport %d -j ACCEPT\n", port, port)
	default:
		return ""
	}
}

func remoteProviderVerifyScript(initSystem string) string {
	if initSystem == "systemd" {
		return "set -eu\nsystemctl is-active --quiet envd-xray.service\n"
	}
	return "set -eu\npgrep -f '/usr/local/bin/xray.*envd/xray/config.json' >/dev/null\n"
}

func remoteRollbackScript(initSystem string) string {
	restart := "/usr/local/bin/xray version >/dev/null"
	if initSystem == "systemd" {
		restart = "systemctl restart envd-xray.service"
	}
	return "set -eu\nif [ -f /usr/local/etc/envd/xray/config.json.envd-rollback ]; then\n  install -m 600 /usr/local/etc/envd/xray/config.json.envd-rollback /usr/local/etc/envd/xray/config.json\n  " + restart + "\nfi\n"
}

func verifyRemoteGatewayReachable(host string, port int) error {
	targetHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		targetHost = h
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func gatewayRecordFromRemoteInstall(rec remoteGatewayRecord, now time.Time) gatewayRecord {
	host := rec.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	raw := map[string]string{
		"XRAY_BIND_IP":              "0.0.0.0",
		"XRAY_SOCKS_PORT":           "11080",
		"XRAY_INBOUND_PORT":         "2088",
		"XRAY_HTTP_PROXY_PORT":      "2089",
		"XRAY_HTTP_PROXY_HOST_PORT": "11081",
		"XRAY_SERVER_IP":            host,
		"XRAY_SERVER_PORT":          strconv.Itoa(rec.Material.Port),
		"XRAY_UUID":                 rec.Material.UUID,
		"XRAY_PUBLIC_KEY":           rec.Material.RealityPublicKey,
		"XRAY_SNI":                  rec.Material.SNI,
		"XRAY_SHORT_ID":             rec.Material.ShortID,
		"XRAY_FINGERPRINT":          "firefox",
	}
	cfg := gatewayConfig{
		BindIP:       raw["XRAY_BIND_IP"],
		SOCKSPort:    11080,
		HTTPHostPort: 11081,
		SOCKSInner:   2088,
		HTTPInner:    2089,
		ServerIP:     raw["XRAY_SERVER_IP"],
		ServerPort:   raw["XRAY_SERVER_PORT"],
		Raw:          raw,
	}
	return gatewayRecordFromConfig(rec.Name, cfg, now)
}

func remoteHostKeyCallback(expected string, seen *string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		*seen = fp
		if expected == "" || expected == fp {
			return nil
		}
		return fmt.Errorf("remote host key mismatch for %s: expected %s, got %s", hostname, expected, fp)
	}
}

func sshAddress(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "22")
}

func runSSHCommand(client *ssh.Client, script string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	raw, err := session.CombinedOutput("sh -lc " + shellQuote(script))
	if err != nil {
		return string(raw), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(raw)))
	}
	return string(raw), nil
}

const remoteInspectionScript = `
os_id=unknown
os_version=unknown
if [ -r /etc/os-release ]; then
  os_id=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release | head -n1)
  os_version=$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2}' /etc/os-release | head -n1)
fi
arch=$(uname -m 2>/dev/null || echo unknown)
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null | head -n1)
disk_mb=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $2}' | head -n1)
if command -v systemctl >/dev/null 2>&1; then
  init_system=systemd
elif [ -d /run/openrc ]; then
  init_system=openrc
else
  init_system=$(ps -p 1 -o comm= 2>/dev/null | head -n1)
fi
if command -v ufw >/dev/null 2>&1; then
  firewall=ufw
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall=firewalld
elif command -v nft >/dev/null 2>&1; then
  firewall=nftables
elif command -v iptables >/dev/null 2>&1; then
  firewall=iptables
else
  firewall=none
fi
printf 'os=%s\n' "${os_id:-unknown}"
printf 'version=%s\n' "${os_version:-unknown}"
printf 'arch=%s\n' "${arch:-unknown}"
printf 'memory_mb=%s\n' "${mem_mb:-0}"
printf 'disk_mb=%s\n' "${disk_mb:-0}"
printf 'init_system=%s\n' "${init_system:-unknown}"
printf 'firewall=%s\n' "${firewall:-none}"
`

const remoteProviderInspectionScript = `
[ -e /etc/systemd/system/envd-xray.service ] && echo envd_owned_service=true || echo envd_owned_service=false
[ -e /usr/local/etc/envd/xray/config.json ] && echo envd_owned_config=true || echo envd_owned_config=false
for p in /usr/local/etc/xray/config.json /etc/xray/config.json /etc/systemd/system/xray.service /etc/systemd/system/xray@.service; do
  [ -e "$p" ] && printf 'unknown_config=%s\n' "$p"
done
if command -v xray >/dev/null 2>&1; then
  printf 'xray_binary=%s\n' "$(command -v xray)"
  xray version 2>/dev/null | head -n1 | sed 's/^/xray_version=/'
fi
`

func parseRemoteGatewayInspection(raw string) remoteGatewayInspection {
	kv := parseKeyValues(raw)
	return remoteGatewayInspection{
		OS:         defaultString(kv["os"], "unknown"),
		Version:    defaultString(kv["version"], "unknown"),
		Arch:       defaultString(kv["arch"], "unknown"),
		MemoryMB:   atoiDefault(kv["memory_mb"], 0),
		DiskMB:     atoiDefault(kv["disk_mb"], 0),
		InitSystem: defaultString(kv["init_system"], "unknown"),
		Firewall:   defaultString(kv["firewall"], "none"),
	}
}

func parseRemoteProviderInspection(raw string) remoteProviderInspection {
	kv := parseKeyValuesMulti(raw)
	return remoteProviderInspection{
		EnvdOwnedService: firstValue(kv, "envd_owned_service") == "true",
		EnvdOwnedConfig:  firstValue(kv, "envd_owned_config") == "true",
		UnknownConfigs:   kv["unknown_config"],
		XrayBinary:       firstValue(kv, "xray_binary"),
		XrayVersion:      firstValue(kv, "xray_version"),
	}
}

func parseKeyValues(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key != "" {
			out[key] = value
		}
	}
	return out
}

func parseKeyValuesMulti(raw string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key != "" {
			out[key] = append(out[key], value)
		}
	}
	return out
}

func firstValue(values map[string][]string, key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return values[key][0]
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func atoiDefault(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return n
}

func printRemoteGatewayProbe(w io.Writer, result remoteGatewayProbeResult, verbose bool) {
	info := result.Inspection
	provider := result.ProviderState
	fmt.Fprintln(w, "Probe:    ok")
	fmt.Fprintf(w, "Remote:   %s %s %s\n", info.OS, info.Version, info.Arch)
	if verbose {
		fmt.Fprintf(w, "HostKey:  %s\n", result.HostKeySHA256)
		fmt.Fprintf(w, "System:   memory=%dMB disk=%dMB init=%s firewall=%s\n", info.MemoryMB, info.DiskMB, info.InitSystem, info.Firewall)
		fmt.Fprintf(w, "Provider: envd_service=%t envd_config=%t xray=%s\n",
			provider.EnvdOwnedService, provider.EnvdOwnedConfig, defaultString(provider.XrayVersion, "not detected"))
	}
	if len(provider.UnknownConfigs) > 0 {
		fmt.Fprintf(w, "Warning:  existing non-envd Xray config found: %s\n", strings.Join(provider.UnknownConfigs, ", "))
	}
}

func generateRemoteGatewayMaterial(plan gatewayInstallPlan) (remoteGatewayMaterial, error) {
	uuid := randomUUID()
	privateKey, publicKey, err := realityKeyPair()
	if err != nil {
		return remoteGatewayMaterial{}, err
	}
	shortID := hex.EncodeToString(randomBytes(8))
	sni := remoteRealitySNI(plan.Strategy)
	port := 443
	config, err := remoteXrayServerConfig(uuid, privateKey, shortID, sni, port)
	if err != nil {
		return remoteGatewayMaterial{}, err
	}
	return remoteGatewayMaterial{
		XrayVersion:       remoteXrayVersion,
		Port:              port,
		UUID:              uuid,
		RealityPrivateKey: privateKey,
		RealityPublicKey:  publicKey,
		ShortID:           shortID,
		SNI:               sni,
		ConfigJSON:        config,
		ServiceUnit:       remoteXrayServiceUnit(),
	}, nil
}

func realityKeyPair() (privateKey, publicKey string, err error) {
	priv := randomBytes(32)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(pub), nil
}

func randomUUID() string {
	b := randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func remoteRealitySNI(strategy string) string {
	switch strategy {
	case "fast":
		return "www.microsoft.com"
	case "compatibility":
		return "www.apple.com"
	default:
		return "www.cloudflare.com"
	}
}

func remoteXrayServerConfig(uuid, privateKey, shortID, sni string, port int) (string, error) {
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "0.0.0.0",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients": []any{map[string]any{
					"id":   uuid,
					"flow": "xtls-rprx-vision",
				}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"dest":        sni + ":443",
					"xver":        0,
					"serverNames": []any{sni},
					"privateKey":  privateKey,
					"shortIds":    []any{shortID},
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func remoteXrayServiceUnit() string {
	return `[Unit]
Description=envd Xray Reality gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/envd/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
}

func gatewayRiskReport(name string, rec gatewayRecord, st *envdState) gatewayRisk {
	cfg := rec.toConfig()
	provider := gatewayHostingProvider(cfg)
	checks := latestHostingChecks(st)
	reasons := []string{}
	actions := []string{}
	score := 0
	providerReach := "unknown"
	if provider == "" {
		provider = "unknown"
		reasons = append(reasons, "gateway has no hosting provider metadata")
		actions = append(actions, "set XRAY_HOSTING_PROVIDER in gateway config or add a second gateway on a different provider")
		score += 2
	} else if check, ok := checks[provider]; ok {
		if check.Reachable {
			providerReach = "ok"
			reasons = append(reasons, "hosting provider was reachable in latest check")
		} else {
			providerReach = "fail"
			reasons = append(reasons, "hosting provider failed latest reachability check")
			actions = append(actions, "run envd hosting shortlist and prepare a replacement provider")
			score += 3
		}
	} else {
		reasons = append(reasons, "no hosting reachability history for provider "+provider)
		actions = append(actions, "run envd hosting check")
		score++
	}
	diversity := gatewayDiversity(st)
	if diversity < 2 {
		reasons = append(reasons, "only one gateway is configured")
		actions = append(actions, "install a second gateway on a different provider/ASN")
		score += 2
	}
	if cfg.ServerIP == "" {
		reasons = append(reasons, "gateway server address is missing")
		score += 3
	}
	level := "low"
	if score >= 5 {
		level = "high"
	} else if score >= 2 {
		level = "elevated"
	}
	return gatewayRisk{
		Name:             name,
		Level:            level,
		Provider:         provider,
		ProviderReach:    providerReach,
		GatewayDiversity: strconv.Itoa(diversity),
		Reasons:          uniqueStrings(reasons),
		Actions:          uniqueStrings(actions),
	}
}

func printGatewayRisk(w io.Writer, report gatewayRisk) {
	fmt.Fprintf(w, "Gateway:          %s\n", report.Name)
	fmt.Fprintf(w, "Risk:             %s\n", report.Level)
	fmt.Fprintf(w, "Provider:         %s\n", report.Provider)
	fmt.Fprintf(w, "Provider Reach:   %s\n", report.ProviderReach)
	fmt.Fprintf(w, "Gateway Count:    %s\n", report.GatewayDiversity)
	for _, reason := range report.Reasons {
		fmt.Fprintf(w, "Reason:           %s\n", reason)
	}
	for _, action := range report.Actions {
		fmt.Fprintf(w, "Action:           %s\n", action)
	}
}

func gatewayHostingProvider(cfg gatewayConfig) string {
	for _, key := range []string{"XRAY_HOSTING_PROVIDER", "ENVD_HOSTING_PROVIDER", "HOSTING_PROVIDER"} {
		if v := strings.TrimSpace(cfg.Raw[key]); v != "" {
			return v
		}
	}
	return ""
}

func gatewayDiversity(st *envdState) int {
	if st == nil {
		return 0
	}
	return len(st.Gateways)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (a app) runGatewayChain(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printGatewayChainHelp()
		return nil
	}
	switch args[0] {
	case "create":
		return a.runGatewayChainCreate(args[1:], st)
	case "status":
		return a.runGatewayChainStatus(args[1:], st)
	default:
		return fmt.Errorf("unknown gateway chain subcommand %q", args[0])
	}
}

func (a app) runGatewayChainCreate(args []string, st *envdState) error {
	name, entry, exit, err := parseGatewayChainCreateArgs(args)
	if err != nil {
		return err
	}
	if _, ok := st.Gateways[entry]; !ok {
		return fmt.Errorf("entry gateway %q not found", entry)
	}
	if _, ok := st.Gateways[exit]; !ok {
		return fmt.Errorf("exit gateway %q not found", exit)
	}
	now := time.Now().UTC()
	rec := gatewayChainRecord{Name: name, Entry: entry, Exit: exit, CreatedAt: now, UpdatedAt: now}
	if previous, ok := st.GatewayChains[name]; ok {
		rec.CreatedAt = previous.CreatedAt
	}
	st.GatewayChains[name] = rec
	st.addEvent("gateway-chain", name, "configured chain "+entry+" -> "+exit+"; activation disabled until chain backend exists")
	fmt.Fprintf(a.stdout, "Chain:      %s\n", name)
	fmt.Fprintf(a.stdout, "Entry:      %s\n", entry)
	fmt.Fprintf(a.stdout, "Exit:       %s\n", exit)
	fmt.Fprintln(a.stdout, "Activation: disabled fail-closed until chain backend is implemented")
	return nil
}

func (a app) runGatewayChainStatus(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd gateway chain status NAME")
	}
	name := args[0]
	rec, ok := st.GatewayChains[name]
	if !ok {
		return fmt.Errorf("gateway chain %q not found", name)
	}
	entryStatus := "missing"
	if _, ok := st.Gateways[rec.Entry]; ok {
		entryStatus = "configured"
	}
	exitStatus := "missing"
	if _, ok := st.Gateways[rec.Exit]; ok {
		exitStatus = "configured"
	}
	fmt.Fprintf(a.stdout, "Chain:      %s\n", rec.Name)
	fmt.Fprintf(a.stdout, "Entry:      %s (%s)\n", rec.Entry, entryStatus)
	fmt.Fprintf(a.stdout, "Exit:       %s (%s)\n", rec.Exit, exitStatus)
	fmt.Fprintln(a.stdout, "Activation: disabled fail-closed until chain backend is implemented")
	fmt.Fprintln(a.stdout, "Degrade:    direct/single-hop fallback denied")
	return nil
}

func parseGatewayChainCreateArgs(args []string) (name, entry, exit string, err error) {
	if len(args) != 5 {
		return "", "", "", fmt.Errorf("usage: envd gateway chain create NAME --entry ENTRY_GATEWAY --exit EXIT_GATEWAY")
	}
	name = args[0]
	if err := validateGatewayName(name); err != nil {
		return "", "", "", err
	}
	for i := 1; i < len(args); i += 2 {
		switch args[i] {
		case "--entry":
			entry = args[i+1]
		case "--exit":
			exit = args[i+1]
		default:
			return "", "", "", fmt.Errorf("usage: envd gateway chain create NAME --entry ENTRY_GATEWAY --exit EXIT_GATEWAY")
		}
	}
	if entry == "" || exit == "" {
		return "", "", "", fmt.Errorf("usage: envd gateway chain create NAME --entry ENTRY_GATEWAY --exit EXIT_GATEWAY")
	}
	if entry == exit {
		return "", "", "", fmt.Errorf("gateway chain requires different entry and exit gateways")
	}
	if err := validateGatewayName(entry); err != nil {
		return "", "", "", err
	}
	if err := validateGatewayName(exit); err != nil {
		return "", "", "", err
	}
	return name, entry, exit, nil
}

func (a app) runGatewayUse(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd gateway use NAME")
	}
	name := args[0]
	return a.activateGateway(name, st, "use", a.verifyGatewayActivation, stopEnvWorkload)
}

func (a app) runGatewayRollback(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd gateway rollback")
	}
	if st.ActiveGateway == "" {
		return fmt.Errorf("no active gateway to roll back from")
	}
	if st.PreviousGateway == "" {
		return fmt.Errorf("no previous gateway recorded")
	}
	return a.activateGateway(st.PreviousGateway, st, "rollback", a.verifyGatewayActivation, stopEnvWorkload)
}

type gatewayActivationVerifier func(gatewayConfig) (string, error)

func (a app) verifyGatewayActivation(cfg gatewayConfig) (string, error) {
	if _, err := (xrayProvider{}).Render(a, cfg); err != nil {
		return "", layerErr("local gateway", err)
	}
	runtimeDir, err := a.materializeGatewayRuntime(cfg)
	if err != nil {
		return "", layerErr("local gateway", err)
	}
	if err := startGatewayRuntime(runtimeDir); err != nil {
		return "", layerErr("local gateway", err)
	}
	gatewayEgress, err := a.gatewayEgressIP(cfg)
	if err != nil {
		return "", layerErr("remote gateway", err)
	}
	return strings.TrimSpace(gatewayEgress), nil
}

func (a app) activateGateway(name string, st *envdState, reason string, verify gatewayActivationVerifier, stop workloadStopper) error {
	rec, ok := st.Gateways[name]
	if !ok {
		if chain, chainOK := st.GatewayChains[name]; chainOK {
			st.addEvent("gateway", name, "chain activation refused fail-closed; chain backend unavailable")
			return fmt.Errorf("gateway chain %q (%s -> %s) cannot be activated yet; refusing to degrade to direct or single-hop", name, chain.Entry, chain.Exit)
		}
		return fmt.Errorf("gateway %q not found; install it first with: envd gateway install %s --host HOST --user root --password", name, name)
	}
	cfg := rec.toConfig()
	gatewayEgress, err := verify(cfg)
	if err != nil {
		st.addEvent("gateway", name, reason+" activation failed during verification: "+redactSensitive(err.Error()))
		return err
	}
	runtimeDir, err := a.materializeGatewayRuntime(cfg)
	if err != nil {
		st.addEvent("gateway", name, reason+" activation failed while materializing local runtime: "+redactSensitive(err.Error()))
		return layerErr("local gateway", err)
	}
	previous := st.ActiveGateway
	if previous != name {
		st.PreviousGateway = previous
		st.GatewayGeneration++
	}
	st.ActiveGateway = name
	rec.UpdatedAt = time.Now().UTC()
	st.Gateways[name] = rec
	result := reconcileSealedEnvGenerationsFailClosed(st, strings.TrimSpace(gatewayEgress), stop)
	eventMessage := fmt.Sprintf("%s activated generation %d; previous=%s; reconciled %d sealed env records; blocked %d", reason, st.GatewayGeneration, previous, result.Reconciled, result.Blocked)
	st.addEvent("gateway", name, eventMessage)
	fmt.Fprintf(a.stdout, "Active gateway: %s\n", name)
	fmt.Fprintf(a.stdout, "Generation:     %d\n", st.GatewayGeneration)
	fmt.Fprintf(a.stdout, "Runtime:        %s\n", runtimeDir)
	fmt.Fprintf(a.stdout, "Reconciled:     %d\n", result.Reconciled)
	if result.Blocked > 0 {
		fmt.Fprintf(a.stdout, "Blocked:        %d sealed envs failed reconciliation and were stopped fail-closed\n", result.Blocked)
	}
	if previous != "" && previous != name {
		fmt.Fprintf(a.stdout, "Previous:       %s\n", previous)
	}
	if reason == "rollback" {
		fmt.Fprintln(a.stdout, "Rollback:       verified and applied")
	}
	return nil
}

func (a app) runUser(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, "Usage: envd user uri GATEWAY\n")
		return nil
	}
	switch args[0] {
	case "uri":
		return a.runUserURI(args[1:], st)
	default:
		return fmt.Errorf("unknown user subcommand %q", args[0])
	}
}

func (a app) runUserURI(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd user uri GATEWAY")
	}
	name := args[0]
	rec, ok := st.Gateways[name]
	if !ok {
		return fmt.Errorf("gateway %q not found; install it first with: envd gateway install %s --host HOST --user root --password", name, name)
	}
	uri, err := gatewayUserURI(name, rec.toConfig())
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, uri)
	st.addEvent("gateway", name, "generated user import URI")
	return nil
}

func (a app) runGatewayShare(args []string, st *envdState) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: envd gateway share NAME [LABEL]")
	}
	gatewayName := args[0]
	label := "phone"
	if len(args) == 2 {
		label = args[1]
	}
	shareName, err := nextGatewayShareName(st, gatewayName, label)
	if err != nil {
		return err
	}
	rec, ok := st.RemoteGateways[gatewayName]
	if !ok {
		return fmt.Errorf("gateway %q is not remotely managed by envd; cannot add/remove app users", gatewayName)
	}
	uuid := randomUUID()
	now := time.Now().UTC()
	share := gatewayShareRecord{Name: shareName, UUID: uuid, CreatedAt: now, UpdatedAt: now}
	shares := append([]gatewayShareRecord(nil), st.GatewayShares[gatewayName]...)
	shares = append(shares, share)
	updated, err := remoteGatewayConfigWithShares(rec.Material.ConfigJSON, shares)
	if err != nil {
		return err
	}
	rec.Material.ConfigJSON = updated
	if err := a.applyRemoteGatewayConfig(rec); err != nil {
		return layerErr("remote gateway", err)
	}
	rec.UpdatedAt = now
	st.RemoteGateways[gatewayName] = rec
	st.GatewayShares[gatewayName] = shares
	st.addEvent("gateway", gatewayName, "shared app user "+shareName)
	cfg := gatewayRecordFromRemoteInstall(rec, now).toConfig()
	uri, err := gatewayUserURIForUUID(gatewayShareURILabel(gatewayName, shareName), cfg, uuid)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Share: %s\n", shareName)
	fmt.Fprintln(a.stdout, uri)
	return nil
}

func (a app) runGatewayShares(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd gateway shares NAME")
	}
	gatewayName := args[0]
	rec, ok := st.Gateways[gatewayName]
	if !ok {
		return fmt.Errorf("gateway %q not found", gatewayName)
	}
	fmt.Fprintf(a.stdout, "%-18s %-10s %-20s\n", "SHARE", "TYPE", "CREATED")
	fmt.Fprintf(a.stdout, "%-18s %-10s %-20s\n", "default", "built-in", rec.CreatedAt.Format("2006-01-02 15:04"))
	for _, share := range st.GatewayShares[gatewayName] {
		fmt.Fprintf(a.stdout, "%-18s %-10s %-20s\n", share.Name, "app", share.CreatedAt.Format("2006-01-02 15:04"))
	}
	return nil
}

func (a app) runGatewayURI(args []string, st *envdState) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd gateway uri NAME SHARE")
	}
	gatewayName, shareName := args[0], args[1]
	uri, err := gatewayShareURI(st, gatewayName, shareName)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, uri)
	return nil
}

func (a app) runGatewayRevoke(args []string, st *envdState) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd gateway revoke NAME SHARE")
	}
	gatewayName, shareName := args[0], args[1]
	if shareName == "default" {
		return fmt.Errorf("cannot revoke built-in default gateway user")
	}
	rec, ok := st.RemoteGateways[gatewayName]
	if !ok {
		return fmt.Errorf("gateway %q is not remotely managed by envd; cannot add/remove app users", gatewayName)
	}
	shares := st.GatewayShares[gatewayName]
	next := make([]gatewayShareRecord, 0, len(shares))
	found := false
	for _, share := range shares {
		if share.Name == shareName {
			found = true
			continue
		}
		next = append(next, share)
	}
	if !found {
		return fmt.Errorf("share %q not found on gateway %q", shareName, gatewayName)
	}
	updated, err := remoteGatewayConfigWithShares(rec.Material.ConfigJSON, next)
	if err != nil {
		return err
	}
	rec.Material.ConfigJSON = updated
	if err := a.applyRemoteGatewayConfig(rec); err != nil {
		return layerErr("remote gateway", err)
	}
	rec.UpdatedAt = time.Now().UTC()
	st.RemoteGateways[gatewayName] = rec
	st.GatewayShares[gatewayName] = next
	st.addEvent("gateway", gatewayName, "revoked app user "+shareName)
	fmt.Fprintf(a.stdout, "Revoked: %s\n", shareName)
	return nil
}

func nextGatewayShareName(st *envdState, gatewayName, label string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(label))
	clean = regexp.MustCompile(`[^a-z0-9_.-]+`).ReplaceAllString(clean, "-")
	clean = strings.Trim(clean, "-.")
	if clean == "" {
		clean = "share"
	}
	if len(clean) > 32 {
		clean = clean[:32]
	}
	used := map[string]bool{"default": true}
	for _, share := range st.GatewayShares[gatewayName] {
		used[share.Name] = true
	}
	if !used[clean] {
		return clean, nil
	}
	for i := 2; i < 1000; i++ {
		name := fmt.Sprintf("%s-%d", clean, i)
		if !used[name] {
			return name, nil
		}
	}
	return "", fmt.Errorf("too many shares named like %q", clean)
}

func remoteGatewayConfigWithShares(configJSON string, shares []gatewayShareRecord) (string, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", fmt.Errorf("parse remote xray config: %w", err)
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		return "", fmt.Errorf("remote xray config has no inbounds")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("remote xray inbound has invalid shape")
	}
	settings, ok := inbound["settings"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("remote xray inbound settings have invalid shape")
	}
	clients, ok := settings["clients"].([]any)
	if !ok || len(clients) == 0 {
		return "", fmt.Errorf("remote xray config has no clients")
	}
	base := clients[0]
	next := []any{base}
	for _, share := range shares {
		next = append(next, map[string]any{"id": share.UUID, "flow": "xtls-rprx-vision"})
	}
	settings["clients"] = next
	raw, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return "", err
	}
	return string(raw) + "\n", nil
}

func (a app) applyRemoteGatewayConfig(rec remoteGatewayRecord) error {
	if strings.TrimSpace(rec.Password) == "" {
		return fmt.Errorf("remote password is missing; rerun gateway install with --password")
	}
	plan := gatewayInstallPlan{Name: rec.Name, Host: rec.Host, User: rec.User, Provider: rec.Provider, Strategy: rec.Strategy, Mode: rec.Mode}
	client, err := dialRemoteGateway(plan, rec.Password, rec.HostKeySHA256)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := runSSHCommandNoOutput(client, remoteInstallXrayScript(rec.Material)); err != nil {
		return err
	}
	if rec.Inspection.InitSystem == "systemd" {
		if err := runSSHCommandNoOutput(client, remoteSystemdInstallScript(rec.Material)); err != nil {
			return err
		}
	}
	if err := runSSHCommandNoOutput(client, remoteProviderVerifyScript(rec.Inspection.InitSystem)); err != nil {
		return err
	}
	return verifyRemoteGatewayReachable(rec.Host, rec.Material.Port)
}

func gatewayUserURI(name string, cfg gatewayConfig) (string, error) {
	return gatewayUserURIForUUID(name, cfg, cfg.Raw["XRAY_UUID"])
}

func gatewayShareURI(st *envdState, gatewayName, shareName string) (string, error) {
	rec, ok := st.Gateways[gatewayName]
	if !ok {
		return "", fmt.Errorf("gateway %q not found", gatewayName)
	}
	if shareName == "default" {
		return gatewayUserURI(gatewayName, rec.toConfig())
	}
	for _, share := range st.GatewayShares[gatewayName] {
		if share.Name == shareName {
			return gatewayUserURIForUUID(gatewayShareURILabel(gatewayName, shareName), rec.toConfig(), share.UUID)
		}
	}
	return "", fmt.Errorf("share %q not found on gateway %q; list shares with: envd gateway shares %s", shareName, gatewayName, gatewayName)
}

func gatewayShareURILabel(gatewayName, shareName string) string {
	return gatewayName + "-" + shareName
}

func gatewayUserURIForUUID(name string, cfg gatewayConfig, uuid string) (string, error) {
	required := []string{
		"XRAY_PUBLIC_KEY",
		"XRAY_SNI",
		"XRAY_SHORT_ID",
	}
	for _, key := range required {
		if strings.TrimSpace(cfg.Raw[key]) == "" {
			return "", fmt.Errorf("gateway %q cannot generate URI: missing %s", name, key)
		}
	}
	if strings.TrimSpace(uuid) == "" {
		return "", fmt.Errorf("gateway %q cannot generate URI: missing user UUID", name)
	}
	if cfg.ServerIP == "" || cfg.ServerPort == "" {
		return "", fmt.Errorf("gateway %q cannot generate URI: missing server address", name)
	}
	fingerprint := cfg.Raw["XRAY_FINGERPRINT"]
	if fingerprint == "" {
		fingerprint = "firefox"
	}
	flow := cfg.Raw["XRAY_FLOW"]
	if flow == "" {
		flow = "xtls-rprx-vision"
	}
	q := url.Values{}
	q.Set("type", "tcp")
	q.Set("security", "reality")
	q.Set("encryption", "none")
	q.Set("flow", flow)
	q.Set("sni", cfg.Raw["XRAY_SNI"])
	q.Set("fp", fingerprint)
	q.Set("pbk", cfg.Raw["XRAY_PUBLIC_KEY"])
	q.Set("sid", cfg.Raw["XRAY_SHORT_ID"])
	return "vless://" + uuid + "@" + net.JoinHostPort(cfg.ServerIP, cfg.ServerPort) + "?" + q.Encode() + "#" + url.QueryEscape(name), nil
}

func (a app) runInternet(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printInternetHelp()
		return nil
	}
	switch args[0] {
	case "status":
		return a.runInternetStatus(args[1:], st)
	case "report":
		return a.runInternetReport(args[1:], st)
	default:
		return fmt.Errorf("unknown internet subcommand %q", args[0])
	}
}

func (a app) runInternetStatus(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd internet status")
	}
	check := a.internetCheck(st)
	recordInternetCheck(st, check)
	printInternetCheck(a.stdout, check)
	return nil
}

func (a app) runInternetReport(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd internet report")
	}
	if len(st.InternetChecks) == 0 {
		fmt.Fprintln(a.stdout, "No internet checks recorded yet. Run envd internet status.")
		return nil
	}
	for _, check := range st.InternetChecks {
		fmt.Fprintf(a.stdout, "%s ok=%d fail=%d skip=%d total=%d\n",
			check.Time.Format(time.RFC3339), check.Summary.OK, check.Summary.Fail, check.Summary.Skip, check.Summary.Total)
		for _, r := range check.Results {
			fmt.Fprintf(a.stdout, "  %-18s %-7s %s\n", r.Name, r.Status, r.Detail)
		}
	}
	return nil
}

func (a app) internetCheck(st *envdState) internetCheckRecord {
	results := []internetProbeRecord{
		probeDirectURL("Direct HTTPS", "direct", "https://api.ipify.org/", 8*time.Second),
		probeDirectURL("Direct Docker Hub", "direct", "https://registry-1.docker.io/v2/", 8*time.Second),
	}
	cfg, source, err := a.activeGatewayConfig(st)
	if err != nil {
		results = append(results,
			internetProbeRecord{Name: "Gateway HTTPS", Path: "gateway", Status: "skip", Detail: redactSensitive(err.Error())},
			internetProbeRecord{Name: "Gateway Docker Hub", Path: "gateway", Status: "skip", Detail: "gateway config unavailable"},
		)
	} else {
		proxy := net.JoinHostPort(hostForClient(cfg.BindIP), strconv.Itoa(cfg.HTTPHostPort))
		results = append(results,
			probeHTTPProxyURL("Gateway HTTPS", "gateway "+source, proxy, "https://api.ipify.org/", 10*time.Second),
			probeHTTPProxyURL("Gateway Docker Hub", "gateway "+source, proxy, "https://registry-1.docker.io/v2/", 10*time.Second),
		)
	}
	return internetCheckRecord{Time: time.Now().UTC(), Results: results, Summary: summarizeInternetResults(results)}
}

func printInternetCheck(w io.Writer, check internetCheckRecord) {
	fmt.Fprintf(w, "Checked: %s\n", check.Time.Format(time.RFC3339))
	fmt.Fprintf(w, "Summary: ok=%d fail=%d skip=%d total=%d\n", check.Summary.OK, check.Summary.Fail, check.Summary.Skip, check.Summary.Total)
	for _, r := range check.Results {
		fmt.Fprintf(w, "%-18s %-7s %-14s %s\n", r.Name, r.Status, r.Path, r.Detail)
	}
}

func recordInternetCheck(st *envdState, check internetCheckRecord) {
	st.ensureDefaults()
	st.InternetChecks = append(st.InternetChecks, check)
	if len(st.InternetChecks) > 50 {
		st.InternetChecks = append([]internetCheckRecord{}, st.InternetChecks[len(st.InternetChecks)-50:]...)
	}
	st.addEvent("internet", "", fmt.Sprintf("status ok=%d fail=%d skip=%d", check.Summary.OK, check.Summary.Fail, check.Summary.Skip))
}

func summarizeInternetResults(results []internetProbeRecord) internetCheckSummary {
	s := internetCheckSummary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case "ok":
			s.OK++
		case "skip":
			s.Skip++
		default:
			s.Fail++
		}
	}
	return s
}

func probeDirectURL(name, path, target string, timeout time.Duration) internetProbeRecord {
	status, body, err := fetchURL(nil, target, timeout)
	if err != nil {
		return internetProbeRecord{Name: name, Path: path, Status: "fail", Detail: redactSensitive(err.Error())}
	}
	return internetProbeRecord{Name: name, Path: path, Status: "ok", Detail: httpStatusDetail(status, body)}
}

func probeHTTPProxyURL(name, path, proxyAddr, target string, timeout time.Duration) internetProbeRecord {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return internetProbeRecord{Name: name, Path: path, Status: "fail", Detail: err.Error()}
	}
	status, body, err := fetchURL(proxyURL, target, timeout)
	if err != nil {
		return internetProbeRecord{Name: name, Path: path, Status: "fail", Detail: redactSensitive(err.Error())}
	}
	return internetProbeRecord{Name: name, Path: path, Status: "ok", Detail: httpStatusDetail(status, body)}
}

func fetchURL(proxy *url.URL, target string, timeout time.Duration) (int, string, error) {
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	if proxy == nil {
		transport.Proxy = nil
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Get(target)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode >= 500 {
		return resp.StatusCode, string(body), fmt.Errorf("HTTP %d from %s", resp.StatusCode, target)
	}
	return resp.StatusCode, string(body), nil
}

func httpStatusDetail(status int, body string) string {
	body = strings.TrimSpace(body)
	if net.ParseIP(body) != nil {
		return "egress " + body
	}
	if body != "" && len(body) <= 80 {
		return fmt.Sprintf("HTTP %d %s", status, body)
	}
	return fmt.Sprintf("HTTP %d", status)
}

func (a app) runHosting(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printHostingHelp()
		return nil
	}
	switch args[0] {
	case "check":
		return a.runHostingCheck(args[1:], st)
	case "shortlist":
		return a.runHostingShortlist(args[1:], st)
	case "update":
		return a.runHostingUpdate(args[1:], st)
	default:
		return fmt.Errorf("unknown hosting subcommand %q", args[0])
	}
}

func (a app) runHostingCheck(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd hosting check")
	}
	catalog, err := a.loadHostingCatalog()
	if err != nil {
		return err
	}
	checks := checkHostingProviders(catalog.Providers)
	recordHostingChecks(st, checks)
	printHostingCheck(a.stdout, checks)
	return nil
}

func (a app) runHostingShortlist(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd hosting shortlist")
	}
	catalog, err := a.loadHostingCatalog()
	if err != nil {
		return err
	}
	printHostingShortlist(a.stdout, catalog.Providers, latestHostingChecks(st))
	return nil
}

func (a app) runIdentity(args []string, st *envdState) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printIdentityHelp()
		return nil
	}
	switch args[0] {
	case "add":
		return a.runIdentityAdd(args[1:], st)
	case "list":
		return a.runIdentityList(args[1:], st)
	case "wrappers":
		return a.runIdentityWrappers(args[1:], st)
	case "credential-helper":
		return a.runIdentityCredentialHelper(args[1:], st)
	default:
		return fmt.Errorf("unknown identity subcommand %q", args[0])
	}
}

type identityWrapperOptions struct {
	EnvName      string
	IdentityName string
	Dir          string
}

func (a app) runIdentityWrappers(args []string, st *envdState) error {
	opts, err := parseIdentityWrapperOptions(args)
	if err != nil {
		return err
	}
	if _, ok := st.Environments[opts.EnvName]; !ok {
		return fmt.Errorf("environment %q not found", opts.EnvName)
	}
	if _, ok := st.Identities[opts.IdentityName]; !ok {
		return fmt.Errorf("identity %q not found", opts.IdentityName)
	}
	scripts := identityWrapperScripts(opts.EnvName, opts.IdentityName, currentEnvdExecutable())
	if opts.Dir == "" {
		fmt.Fprintln(a.stdout, "# envd identity wrappers are convenience/diagnostics only.")
		fmt.Fprintln(a.stdout, "# Broker policy remains the security boundary even if these are bypassed.")
		for name, body := range scripts {
			fmt.Fprintf(a.stdout, "\n# %s\n%s", name, body)
		}
		st.addEvent("identity", opts.IdentityName, "printed convenience wrappers for "+opts.EnvName)
		return nil
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return err
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(opts.Dir, name), []byte(body), 0o700); err != nil {
			return err
		}
	}
	st.addEvent("identity", opts.IdentityName, "wrote convenience wrappers for "+opts.EnvName+" to "+opts.Dir)
	fmt.Fprintf(a.stdout, "Wrappers: %s\n", opts.Dir)
	fmt.Fprintln(a.stdout, "Add this directory first in PATH for convenience only; broker denial still works if wrappers are bypassed.")
	return nil
}

func parseIdentityWrapperOptions(args []string) (identityWrapperOptions, error) {
	if len(args) < 2 {
		return identityWrapperOptions{}, fmt.Errorf("usage: envd identity wrappers ENV IDENTITY [--dir PATH]")
	}
	opts := identityWrapperOptions{EnvName: args[0], IdentityName: args[1]}
	if err := validateEnvName(opts.EnvName); err != nil {
		return identityWrapperOptions{}, err
	}
	if err := validateIdentityName(opts.IdentityName); err != nil {
		return identityWrapperOptions{}, err
	}
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i >= len(args) {
				return identityWrapperOptions{}, fmt.Errorf("--dir requires a value")
			}
			opts.Dir = args[i]
		default:
			return identityWrapperOptions{}, fmt.Errorf("unknown identity wrappers option %q", args[i])
		}
	}
	return opts, nil
}

func identityWrapperScripts(envName, identityName, envdPath string) map[string]string {
	envd := shellWords(envdPath)
	env := shellWords(envName)
	identity := shellWords(identityName)
	return map[string]string{
		"ssh": fmt.Sprintf(`#!/bin/sh
set -eu
%s identity broker check %s %s --class ssh >/dev/null
exec "${ENVD_REAL_SSH:-/usr/bin/ssh}" "$@"
`, envd, env, identity),
		"git": fmt.Sprintf(`#!/bin/sh
set -eu
case "${1:-}" in
  clone|fetch|pull|push|submodule)
    %s identity broker check %s %s --class git-https >/dev/null
    ;;
esac
exec "${ENVD_REAL_GIT:-/usr/bin/git}" "$@"
`, envd, env, identity),
	}
}

func (a app) runIdentityCredentialHelper(args []string, st *envdState) error {
	envName, identityName, op, err := parseIdentityCredentialHelperArgs(args)
	if err != nil {
		return err
	}
	response, err := gitCredentialHelperResponse(st, envName, identityName, op, a.stdin(), runtimeIdentityBrokerHealth(st, envName))
	if err != nil {
		return err
	}
	if response != "" {
		fmt.Fprint(a.stdout, response)
	}
	st.addEvent("identity", identityName, "served git HTTPS credential helper "+op+" for "+envName)
	return nil
}

func (a app) stdin() io.Reader {
	return os.Stdin
}

func parseIdentityCredentialHelperArgs(args []string) (envName, identityName, op string, err error) {
	if len(args) < 2 || len(args) > 3 {
		return "", "", "", fmt.Errorf("usage: envd identity credential-helper ENV IDENTITY [get|store|erase]")
	}
	envName, identityName = args[0], args[1]
	if len(args) == 3 {
		op = args[2]
	} else {
		op = "get"
	}
	if err := validateEnvName(envName); err != nil {
		return "", "", "", err
	}
	if err := validateIdentityName(identityName); err != nil {
		return "", "", "", err
	}
	switch op {
	case "get", "fill", "store", "approve", "erase", "reject":
	default:
		return "", "", "", fmt.Errorf("unsupported git credential helper operation %q", op)
	}
	return envName, identityName, op, nil
}

func gitCredentialHelperResponse(st *envdState, envName, identityName, op string, input io.Reader, health identityBrokerHealth) (string, error) {
	if _, err := readGitCredentialInput(input); err != nil {
		return "", err
	}
	switch op {
	case "store", "approve", "erase", "reject":
		return "", nil
	}
	decision := evaluateIdentityBrokerGrant(st, envName, identityName, "git-https", health)
	if !decision.Allow {
		return "", fmt.Errorf("identity broker denied: %s", decision.Reason)
	}
	rec := st.Identities[identityName]
	if rec.Type != "git-https" || rec.Username == "" || rec.Password == "" {
		return "", fmt.Errorf("identity %q is not a complete git-https identity", identityName)
	}
	return "username=" + rec.Username + "\npassword=" + rec.Password + "\n\n", nil
}

func readGitCredentialInput(input io.Reader) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid git credential input line")
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

type identitySSHAgentOptions struct {
	EnvName      string
	IdentityName string
	SocketPath   string
}

func (a app) runIdentitySSHAgent(args []string) error {
	opts, err := parseIdentitySSHAgentArgs(args)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(opts.SocketPath)
	listener, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(opts.SocketPath)
	fmt.Fprintf(a.stdout, "SSH agent socket: %s\n", opts.SocketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go a.handleIdentitySSHAgentConn(conn, opts.EnvName, opts.IdentityName)
	}
}

func runStaticIdentityAgentCLI(args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: envd __identity-agent ENV IDENTITY SOCKET")
	}
	envName, identityName, socketPath := args[0], args[1], args[2]
	if err := validateEnvName(envName); err != nil {
		return err
	}
	if err := validateIdentityName(identityName); err != nil {
		return err
	}
	privateKey, err := io.ReadAll(io.LimitReader(os.Stdin, 1024*1024))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(privateKey))) == 0 {
		return fmt.Errorf("identity key was empty")
	}
	rec := identityRecord{Name: identityName, Type: "ssh", PrivateKey: string(privateKey), Policy: defaultIdentityPolicy()}
	defer zeroBytes(privateKey)
	return serveStaticIdentityAgent(envName, rec, socketPath)
}

func serveStaticIdentityAgent(envName string, rec identityRecord, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	oldMask := syscall.Umask(0o077)
	listener, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	_ = os.Chmod(socketPath, 0o600)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			agent.ServeAgent(policySSHAgent{
				base: agent.NewKeyring(),
				check: func() (*identityRecord, error) {
					if err := runtimeStaticIdentityHealth(envName); err != nil {
						return nil, err
					}
					copy := rec
					return &copy, nil
				},
			}, conn)
		}()
	}
}

func runtimeStaticIdentityHealth(envName string) error {
	route, err := runtimeRoute(envName)
	if err != nil {
		return err
	}
	if networkOrSealed(route.Network) != "sealed" {
		return fmt.Errorf("identity requires sealed networking")
	}
	if dockerContainerStatus(route.DevName) != "running" {
		return fmt.Errorf("dev container is not running")
	}
	netName := netContainerName(route.ID)
	if dockerContainerStatus(netName) != "running" {
		return fmt.Errorf("sealed sidecar is not running")
	}
	stub := &envdState{GatewayGeneration: 0, Environments: map[string]envRecord{
		envName: {ID: route.ID, Network: "sealed"},
	}}
	env, err := inspectEnvByRef(stub, envRef{
		Name:     envName,
		ID:       route.ID,
		UserName: route.UserName,
		DevName:  route.DevName,
		NetName:  netName,
		Network:  "sealed",
	})
	if err != nil {
		return err
	}
	if env.netHealth() != "ok" {
		return fmt.Errorf("sealed route unhealthy: %s", env.netHealth())
	}
	return nil
}

func parseIdentitySSHAgentArgs(args []string) (identitySSHAgentOptions, error) {
	if len(args) != 4 || args[2] != "--socket" {
		return identitySSHAgentOptions{}, fmt.Errorf("usage: envd identity ssh-agent ENV IDENTITY --socket PATH")
	}
	opts := identitySSHAgentOptions{EnvName: args[0], IdentityName: args[1], SocketPath: args[3]}
	if err := validateEnvName(opts.EnvName); err != nil {
		return identitySSHAgentOptions{}, err
	}
	if err := validateIdentityName(opts.IdentityName); err != nil {
		return identitySSHAgentOptions{}, err
	}
	if strings.TrimSpace(opts.SocketPath) == "" {
		return identitySSHAgentOptions{}, fmt.Errorf("ssh agent socket path is required")
	}
	return opts, nil
}

func (a app) handleIdentitySSHAgentConn(conn net.Conn, envName, identityName string) {
	defer conn.Close()
	agent.ServeAgent(policySSHAgent{
		base: agent.NewKeyring(),
		check: func() (*identityRecord, error) {
			return a.authorizeSSHAgentIdentity(envName, identityName)
		},
	}, conn)
}

func (a app) authorizeSSHAgentIdentity(envName, identityName string) (*identityRecord, error) {
	store, err := newStateStore()
	if err != nil {
		return nil, err
	}
	var rec identityRecord
	if err := store.withState(a.stderr, func(st *envdState) error {
		st.ensureDefaults()
		decision := evaluateIdentityBrokerGrant(st, envName, identityName, "ssh", runtimeIdentityBrokerHealth(st, envName))
		if !decision.Allow {
			return fmt.Errorf("identity broker denied: %s", decision.Reason)
		}
		identity, ok := st.Identities[identityName]
		if !ok {
			return fmt.Errorf("identity %q not found", identityName)
		}
		rec = identity
		return nil
	}); err != nil {
		return nil, err
	}
	return &rec, nil
}

type policySSHAgent struct {
	base  agent.Agent
	check func() (*identityRecord, error)
}

func (p policySSHAgent) keyring() (agent.Agent, error) {
	rec, err := p.check()
	if err != nil {
		return nil, err
	}
	if rec.Type != "ssh" {
		return nil, fmt.Errorf("identity type %s cannot satisfy ssh", rec.Type)
	}
	privateKey, err := ssh.ParseRawPrivateKey([]byte(rec.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("cannot parse encrypted SSH identity: %w", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey, Comment: rec.Name}); err != nil {
		return nil, err
	}
	return keyring, nil
}

func (p policySSHAgent) List() ([]*agent.Key, error) {
	keyring, err := p.keyring()
	if err != nil {
		return nil, err
	}
	return keyring.List()
}

func (p policySSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	keyring, err := p.keyring()
	if err != nil {
		return nil, err
	}
	return keyring.Sign(key, data)
}

func (p policySSHAgent) Add(agent.AddedKey) error {
	return fmt.Errorf("envd identity ssh-agent is read-only")
}

func (p policySSHAgent) Remove(ssh.PublicKey) error {
	return fmt.Errorf("envd identity ssh-agent is read-only")
}

func (p policySSHAgent) RemoveAll() error {
	return fmt.Errorf("envd identity ssh-agent is read-only")
}

func (p policySSHAgent) Lock([]byte) error {
	return fmt.Errorf("envd identity ssh-agent cannot be locked by clients")
}

func (p policySSHAgent) Unlock([]byte) error {
	return fmt.Errorf("envd identity ssh-agent cannot be unlocked by clients")
}

func (p policySSHAgent) Signers() ([]ssh.Signer, error) {
	keyring, err := p.keyring()
	if err != nil {
		return nil, err
	}
	return keyring.Signers()
}

func (a app) runIdentityBroker(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.printIdentityBrokerHelp()
		return nil
	}
	switch args[0] {
	case "check":
		envName, identityName, class, err := parseIdentityBrokerTargetArgs(args[1:])
		if err != nil {
			return err
		}
		store, err := newStateStore()
		if err != nil {
			return err
		}
		var result identityBrokerDecision
		if err := store.withState(a.stderr, func(st *envdState) error {
			st.ensureDefaults()
			result = evaluateIdentityBrokerGrant(st, envName, identityName, class, runtimeIdentityBrokerHealth(st, envName))
			return nil
		}); err != nil {
			return err
		}
		printIdentityBrokerDecision(a.stdout, result)
		if !result.Allow {
			return fmt.Errorf("identity broker denied: %s", result.Reason)
		}
		return nil
	case "serve":
		envName, identityName, class, socketPath, err := parseIdentityBrokerServeArgs(args[1:])
		if err != nil {
			return err
		}
		return a.serveIdentityBroker(envName, identityName, class, socketPath)
	default:
		return fmt.Errorf("unknown identity broker subcommand %q", args[0])
	}
}

func parseIdentityBrokerTargetArgs(args []string) (envName, identityName, class string, err error) {
	if len(args) != 4 || args[2] != "--class" {
		return "", "", "", fmt.Errorf("usage: envd identity broker check ENV IDENTITY --class ssh|git-https")
	}
	envName, identityName, class = args[0], args[1], args[3]
	if err := validateEnvName(envName); err != nil {
		return "", "", "", err
	}
	if err := validateIdentityName(identityName); err != nil {
		return "", "", "", err
	}
	if !validBrokerClass(class) {
		return "", "", "", fmt.Errorf("invalid broker class %q: use ssh or git-https", class)
	}
	return envName, identityName, class, nil
}

func parseIdentityBrokerServeArgs(args []string) (envName, identityName, class, socketPath string, err error) {
	if len(args) != 6 || args[2] != "--class" || args[4] != "--socket" {
		return "", "", "", "", fmt.Errorf("usage: envd identity broker serve ENV IDENTITY --class ssh|git-https --socket PATH")
	}
	envName, identityName, class, socketPath = args[0], args[1], args[3], args[5]
	if err := validateEnvName(envName); err != nil {
		return "", "", "", "", err
	}
	if err := validateIdentityName(identityName); err != nil {
		return "", "", "", "", err
	}
	if !validBrokerClass(class) {
		return "", "", "", "", fmt.Errorf("invalid broker class %q: use ssh or git-https", class)
	}
	if strings.TrimSpace(socketPath) == "" {
		return "", "", "", "", fmt.Errorf("broker socket path is required")
	}
	return envName, identityName, class, socketPath, nil
}

func validBrokerClass(class string) bool {
	return class == "ssh" || class == "git-https"
}

type identityBrokerDecision struct {
	Allow             bool
	EnvName           string
	EnvID             string
	Identity          string
	Class             string
	GatewayGeneration int
	Reason            string
}

type identityBrokerHealth func() error

func evaluateIdentityBrokerGrant(st *envdState, envName, identityName, class string, health identityBrokerHealth) identityBrokerDecision {
	result := identityBrokerDecision{EnvName: envName, Identity: identityName, Class: class, GatewayGeneration: st.GatewayGeneration}
	rec, ok := st.Environments[envName]
	if !ok {
		result.Reason = "environment not found"
		return result
	}
	result.EnvID = rec.ID
	identity, ok := st.Identities[identityName]
	if !ok {
		result.Reason = "identity not found"
		return result
	}
	if !validBrokerClass(class) {
		result.Reason = "unsupported command class"
		return result
	}
	if class == "ssh" && identity.Type != "ssh" {
		result.Reason = "identity type " + identity.Type + " cannot satisfy ssh"
		return result
	}
	if class == "git-https" && identity.Type != "git-https" {
		result.Reason = "identity type " + identity.Type + " cannot satisfy git-https"
		return result
	}
	if !identityPolicyAllowsSealedOnly(identity.Policy) {
		result.Reason = "identity policy is not sealed-only"
		return result
	}
	if rec.Network != "sealed" {
		result.Reason = "identity requires sealed networking"
		return result
	}
	if rec.GatewayGeneration != st.GatewayGeneration {
		result.Reason = "gateway generation changed; revalidation required"
		return result
	}
	if health == nil {
		result.Reason = "sealed route health is unavailable"
		return result
	}
	if err := health(); err != nil {
		result.Reason = "sealed route unhealthy: " + redactSensitive(err.Error())
		return result
	}
	result.Allow = true
	result.Reason = "policy passed"
	return result
}

func runtimeIdentityBrokerHealth(st *envdState, envName string) identityBrokerHealth {
	return func() error {
		env, err := inspectEnv(st, envName)
		if err != nil {
			return err
		}
		if env.netHealth() != "ok" {
			return fmt.Errorf(env.netHealth())
		}
		return nil
	}
}

func printIdentityBrokerDecision(w io.Writer, result identityBrokerDecision) {
	status := "DENY"
	if result.Allow {
		status = "OK"
	}
	fmt.Fprintf(w, "%s identity=%s env=%s env_id=%s class=%s generation=%d reason=%s\n",
		status, result.Identity, result.EnvName, result.EnvID, result.Class, result.GatewayGeneration, result.Reason)
}

func (a app) serveIdentityBroker(envName, identityName, class, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	fmt.Fprintf(a.stdout, "Identity broker socket: %s\n", socketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go a.handleIdentityBrokerConn(conn, envName, identityName, class)
	}
}

func (a app) handleIdentityBrokerConn(conn net.Conn, envName, identityName, class string) {
	defer conn.Close()
	store, err := newStateStore()
	if err != nil {
		fmt.Fprintf(conn, "DENY reason=%s\n", redactSensitive(err.Error()))
		return
	}
	var result identityBrokerDecision
	if err := store.withState(a.stderr, func(st *envdState) error {
		st.ensureDefaults()
		result = evaluateIdentityBrokerGrant(st, envName, identityName, class, runtimeIdentityBrokerHealth(st, envName))
		return nil
	}); err != nil {
		fmt.Fprintf(conn, "DENY reason=%s\n", redactSensitive(err.Error()))
		return
	}
	printIdentityBrokerDecision(conn, result)
}

type identityAddOptions struct {
	Name       string
	Type       string
	SSHKeyPath string
	Username   string
	TokenFile  string
}

func (a app) runIdentityAdd(args []string, st *envdState) error {
	opts, err := parseIdentityAddArgs(args)
	if err != nil {
		return err
	}
	var rec identityRecord
	now := time.Now().UTC()
	previous, existed := st.Identities[opts.Name]
	switch opts.Type {
	case "ssh":
		privateKey, err := os.ReadFile(opts.SSHKeyPath)
		if err != nil {
			return err
		}
		if !looksLikePrivateKey(privateKey) {
			return fmt.Errorf("%s does not look like an SSH private key", opts.SSHKeyPath)
		}
		publicKey := ""
		if raw, err := os.ReadFile(opts.SSHKeyPath + ".pub"); err == nil {
			publicKey = strings.TrimSpace(string(raw))
		}
		rec = identityRecord{
			Name:        opts.Name,
			Type:        "ssh",
			PrivateKey:  string(privateKey),
			PublicKey:   publicKey,
			Fingerprint: identityFingerprint(privateKey, []byte(publicKey)),
			Policy:      defaultIdentityPolicy(),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	case "git-https":
		token, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return err
		}
		tokenText := strings.TrimSpace(string(token))
		if tokenText == "" {
			return fmt.Errorf("git HTTPS token file is empty")
		}
		rec = identityRecord{
			Name:        opts.Name,
			Type:        "git-https",
			Username:    opts.Username,
			Password:    tokenText,
			Fingerprint: identityFingerprint([]byte(opts.Username+"\n"+tokenText), nil),
			Policy:      defaultIdentityPolicy(),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	default:
		return fmt.Errorf("unsupported identity type %q", opts.Type)
	}
	if existed {
		rec.CreatedAt = previous.CreatedAt
	}
	st.Identities[opts.Name] = rec
	if existed {
		st.addEvent("identity", opts.Name, "updated "+opts.Type+" identity in encrypted state")
		fmt.Fprintf(a.stdout, "Updated identity: %s\n", opts.Name)
	} else {
		st.addEvent("identity", opts.Name, "added "+opts.Type+" identity to encrypted state")
		fmt.Fprintf(a.stdout, "Added identity: %s\n", opts.Name)
	}
	fmt.Fprintf(a.stdout, "Type: %s\n", rec.Type)
	fmt.Fprintf(a.stdout, "Fingerprint: %s\n", rec.Fingerprint)
	fmt.Fprintf(a.stdout, "Access: sealed envs only; healthy gateway required\n")
	return nil
}

func (a app) runIdentityList(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd identity list")
	}
	if len(st.Identities) == 0 {
		fmt.Fprintln(a.stdout, "No identities configured.")
		return nil
	}
	names := make([]string, 0, len(st.Identities))
	for name := range st.Identities {
		names = append(names, name)
	}
	sortStrings(names)
	fmt.Fprintf(a.stdout, "%-18s %-8s %-24s %s\n", "NAME", "TYPE", "FINGERPRINT", "ACCESS")
	for _, name := range names {
		rec := st.Identities[name]
		fmt.Fprintf(a.stdout, "%-18s %-8s %-24s %s\n", name, rec.Type, rec.Fingerprint, identityAccessSummary(rec.Policy))
	}
	return nil
}

func parseIdentityAddArgs(args []string) (identityAddOptions, error) {
	if len(args) < 3 {
		return identityAddOptions{}, fmt.Errorf("usage: envd identity add NAME (--ssh-key PATH|--git-https --username USER --token-file PATH)")
	}
	opts := identityAddOptions{Name: args[0]}
	if err := validateIdentityName(opts.Name); err != nil {
		return identityAddOptions{}, err
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--ssh-key":
			i++
			if i >= len(args) {
				return identityAddOptions{}, fmt.Errorf("--ssh-key requires a value")
			}
			opts.Type = "ssh"
			opts.SSHKeyPath = strings.TrimSpace(args[i])
		case "--git-https":
			opts.Type = "git-https"
		case "--username":
			i++
			if i >= len(args) {
				return identityAddOptions{}, fmt.Errorf("--username requires a value")
			}
			opts.Username = strings.TrimSpace(args[i])
		case "--token-file":
			i++
			if i >= len(args) {
				return identityAddOptions{}, fmt.Errorf("--token-file requires a value")
			}
			opts.TokenFile = strings.TrimSpace(args[i])
		default:
			return identityAddOptions{}, fmt.Errorf("unknown identity add option %q", args[i])
		}
	}
	switch opts.Type {
	case "ssh":
		if opts.SSHKeyPath == "" {
			return identityAddOptions{}, fmt.Errorf("identity ssh key path is required")
		}
		if opts.Username != "" || opts.TokenFile != "" {
			return identityAddOptions{}, fmt.Errorf("--ssh-key cannot be combined with git HTTPS options")
		}
	case "git-https":
		if opts.Username == "" || opts.TokenFile == "" {
			return identityAddOptions{}, fmt.Errorf("git HTTPS identity requires --username and --token-file")
		}
	default:
		return identityAddOptions{}, fmt.Errorf("usage: envd identity add NAME (--ssh-key PATH|--git-https --username USER --token-file PATH)")
	}
	return opts, nil
}

func validateIdentityName(name string) error {
	return validateEnvName(name)
}

func looksLikePrivateKey(raw []byte) bool {
	text := strings.TrimSpace(string(raw))
	return strings.Contains(text, "PRIVATE KEY") && strings.HasPrefix(text, "-----BEGIN ")
}

func identityFingerprint(privateKey, publicKey []byte) string {
	source := publicKey
	if len(strings.TrimSpace(string(source))) == 0 {
		source = privateKey
	}
	sum := sha256.Sum256(source)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

func defaultIdentityPolicy() identityPolicy {
	return identityPolicy{
		AllowedNetworks:       []string{"sealed"},
		RequireHealthySealed:  true,
		RequireGatewayCurrent: true,
	}
}

func identityPolicySummary(policy identityPolicy) string {
	return "net=" + strings.Join(policy.AllowedNetworks, ",") +
		" healthy_sealed=" + strconv.FormatBool(policy.RequireHealthySealed) +
		" gateway_current=" + strconv.FormatBool(policy.RequireGatewayCurrent)
}

func identityAccessSummary(policy identityPolicy) string {
	if identityPolicyAllowsSealedOnly(policy) {
		return "sealed envs only"
	}
	return "invalid"
}

func probeIdentityRecords(st *envdState) []probeResult {
	if len(st.Identities) == 0 {
		return []probeResult{{Name: "Identity store", Detail: "no identities configured"}}
	}
	results := []probeResult{}
	names := make([]string, 0, len(st.Identities))
	for name := range st.Identities {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		rec := st.Identities[name]
		switch rec.Type {
		case "ssh":
			if !looksLikePrivateKey([]byte(rec.PrivateKey)) {
				results = append(results, probeResult{Name: "Identity " + name, Err: fmt.Errorf("missing ssh private key material")})
				continue
			}
		case "git-https":
			if strings.TrimSpace(rec.Username) == "" || strings.TrimSpace(rec.Password) == "" {
				results = append(results, probeResult{Name: "Identity " + name, Err: fmt.Errorf("missing git HTTPS username or token")})
				continue
			}
		default:
			results = append(results, probeResult{Name: "Identity " + name, Err: fmt.Errorf("unsupported identity type %q", rec.Type)})
			continue
		}
		if !identityPolicyAllowsSealedOnly(rec.Policy) {
			results = append(results, probeResult{Name: "Identity " + name, Err: fmt.Errorf("identity policy is not sealed-only")})
			continue
		}
		results = append(results, probeResult{Name: "Identity " + name, Detail: rec.Type + " " + rec.Fingerprint + " " + identityPolicySummary(rec.Policy)})
	}
	return results
}

func identityPolicyAllowsSealedOnly(policy identityPolicy) bool {
	if len(policy.AllowedNetworks) != 1 || policy.AllowedNetworks[0] != "sealed" {
		return false
	}
	return policy.RequireHealthySealed && policy.RequireGatewayCurrent
}

func (a app) runHostingUpdate(args []string, st *envdState) error {
	urlValue := ""
	sigValue := ""
	keyValue := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--url":
			i++
			if i >= len(args) {
				return fmt.Errorf("missing value for --url")
			}
			urlValue = args[i]
		case "--sig":
			i++
			if i >= len(args) {
				return fmt.Errorf("missing value for --sig")
			}
			sigValue = args[i]
		case "--key":
			i++
			if i >= len(args) {
				return fmt.Errorf("missing value for --key")
			}
			keyValue = args[i]
		default:
			return fmt.Errorf("usage: envd hosting update --url <url-or-file> --sig <signature-url-file-or-base64> --key <ed25519-public-key-file-hex-or-base64>")
		}
	}
	if urlValue == "" || sigValue == "" || keyValue == "" {
		return fmt.Errorf("usage: envd hosting update --url <url-or-file> --sig <signature-url-file-or-base64> --key <ed25519-public-key-file-hex-or-base64>")
	}
	raw, err := readSourceBytes(urlValue)
	if err != nil {
		return err
	}
	sigRaw, err := readSourceOrLiteral(sigValue)
	if err != nil {
		return err
	}
	sig, err := decodeBinaryPayload(sigRaw, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("invalid hosting catalog signature: %w", err)
	}
	keyRaw, err := readSourceOrLiteral(keyValue)
	if err != nil {
		return err
	}
	key, err := decodeBinaryPayload(keyRaw, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("invalid hosting catalog public key: %w", err)
	}
	catalog, err := verifySignedHostingCatalog(raw, sig, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	path, err := signedHostingCatalogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	st.addEvent("hosting", "", fmt.Sprintf("updated signed catalog with %d providers", len(catalog.Providers)))
	fmt.Fprintf(a.stdout, "Updated: %s\n", path)
	fmt.Fprintf(a.stdout, "Providers: %d\n", len(catalog.Providers))
	return nil
}

func (a app) loadHostingCatalog() (hostingCatalog, error) {
	raw, err := loadBaseHostingCatalogRaw(a.root)
	if err != nil {
		raw = []byte(builtInHostingCatalogJSON)
	}
	catalog, err := parseHostingCatalog(raw)
	if err != nil {
		return hostingCatalog{}, err
	}
	overlay, ok, err := loadHostingOverlay()
	if err != nil {
		return hostingCatalog{}, err
	}
	if ok {
		catalog = mergeHostingCatalogs(catalog, overlay)
	}
	return catalog, nil
}

func loadBaseHostingCatalogRaw(root string) ([]byte, error) {
	if path, err := signedHostingCatalogPath(); err == nil {
		if raw, readErr := os.ReadFile(path); readErr == nil {
			return raw, nil
		}
	}
	return os.ReadFile(filepath.Join(root, "data", "hosting", "providers.json"))
}

func verifySignedHostingCatalog(raw, sig []byte, key ed25519.PublicKey) (hostingCatalog, error) {
	if len(key) != ed25519.PublicKeySize {
		return hostingCatalog{}, fmt.Errorf("invalid hosting catalog public key length %d", len(key))
	}
	if len(sig) != ed25519.SignatureSize {
		return hostingCatalog{}, fmt.Errorf("invalid hosting catalog signature length %d", len(sig))
	}
	if !ed25519.Verify(key, raw, sig) {
		return hostingCatalog{}, fmt.Errorf("hosting catalog signature verification failed")
	}
	catalog, err := parseHostingCatalog(raw)
	if err != nil {
		return hostingCatalog{}, err
	}
	return catalog, nil
}

func readSourceBytes(source string) ([]byte, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, fmt.Errorf("empty source")
	}
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, source)
		}
		return raw, nil
	}
	return os.ReadFile(source)
}

func readSourceOrLiteral(source string) ([]byte, error) {
	source = strings.TrimSpace(source)
	if raw, err := readSourceBytes(source); err == nil {
		return raw, nil
	} else if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		return nil, err
	}
	return []byte(source), nil
}

func decodeBinaryPayload(raw []byte, want int) ([]byte, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == want {
		return raw, nil
	}
	text := strings.TrimSpace(string(raw))
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil && len(decoded) == want {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(text); err == nil && len(decoded) == want {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(text); err == nil && len(decoded) == want {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == want {
		return decoded, nil
	}
	return nil, fmt.Errorf("expected %d bytes, got %d bytes", want, len(raw))
}

func bytesTrimSpace(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func signedHostingCatalogPath() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hosting", "catalog.json"), nil
}

func parseHostingCatalog(raw []byte) (hostingCatalog, error) {
	var catalog hostingCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return hostingCatalog{}, fmt.Errorf("hosting catalog is invalid JSON: %w", err)
	}
	if catalog.Version < 1 {
		return hostingCatalog{}, fmt.Errorf("hosting catalog has invalid version %d", catalog.Version)
	}
	seen := map[string]bool{}
	for _, p := range catalog.Providers {
		if err := validateHostingProvider(p); err != nil {
			return hostingCatalog{}, err
		}
		if seen[p.ID] {
			return hostingCatalog{}, fmt.Errorf("hosting catalog has duplicate provider %q", p.ID)
		}
		seen[p.ID] = true
	}
	return catalog, nil
}

func validateHostingProvider(p hostingProvider) error {
	if err := validateProviderID(p.ID); err != nil {
		return err
	}
	if p.Name == "" {
		return fmt.Errorf("hosting provider %q missing name", p.ID)
	}
	if _, err := url.ParseRequestURI(p.Homepage); err != nil {
		return fmt.Errorf("hosting provider %q has invalid homepage: %w", p.ID, err)
	}
	if p.SignupURL != "" {
		if _, err := url.ParseRequestURI(p.SignupURL); err != nil {
			return fmt.Errorf("hosting provider %q has invalid signup_url: %w", p.ID, err)
		}
	}
	if p.APIURL != nil && *p.APIURL != "" {
		if _, err := url.ParseRequestURI(*p.APIURL); err != nil {
			return fmt.Errorf("hosting provider %q has invalid api_url: %w", p.ID, err)
		}
	}
	if len(p.Regions) == 0 {
		return fmt.Errorf("hosting provider %q has no regions", p.ID)
	}
	switch p.Confidence {
	case "verified", "community", "user", "stale", "unknown":
	default:
		return fmt.Errorf("hosting provider %q has invalid confidence %q", p.ID, p.Confidence)
	}
	return nil
}

func validateProviderID(id string) error {
	if len(id) < 2 || len(id) > 64 {
		return fmt.Errorf("invalid provider id %q", id)
	}
	for i, ch := range id {
		if i == 0 && (ch < 'a' || ch > 'z') {
			return fmt.Errorf("invalid provider id %q: must start with lowercase letter", id)
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return fmt.Errorf("invalid provider id %q: use lowercase letters, digits, and hyphen", id)
		}
	}
	return nil
}

func loadHostingOverlay() (hostingCatalog, bool, error) {
	path := os.Getenv("ENVD_HOSTING_CATALOG")
	if path == "" {
		dir, err := envdDataDir()
		if err != nil {
			return hostingCatalog{}, false, err
		}
		path = filepath.Join(dir, "hosting", "local.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return hostingCatalog{}, false, nil
		}
		return hostingCatalog{}, false, err
	}
	catalog, err := parseHostingCatalog(raw)
	if err != nil {
		return hostingCatalog{}, false, fmt.Errorf("local hosting catalog %s: %w", path, err)
	}
	for i := range catalog.Providers {
		if catalog.Providers[i].Confidence == "" {
			catalog.Providers[i].Confidence = "user"
		}
	}
	return catalog, true, nil
}

func mergeHostingCatalogs(base, overlay hostingCatalog) hostingCatalog {
	index := map[string]int{}
	for i, p := range base.Providers {
		index[p.ID] = i
	}
	for _, p := range overlay.Providers {
		if i, ok := index[p.ID]; ok {
			base.Providers[i] = p
			continue
		}
		base.Providers = append(base.Providers, p)
	}
	return base
}

func checkHostingProviders(providers []hostingProvider) []hostingCheckRecord {
	checks := make([]hostingCheckRecord, 0, len(providers))
	now := time.Now().UTC()
	for _, p := range providers {
		homepage := probeDirectURL(p.ID+" homepage", "hosting", p.Homepage, 8*time.Second)
		api := internetProbeRecord{Name: p.ID + " api", Path: "hosting", Status: "skip", Detail: "no api_url"}
		if p.APIURL != nil && *p.APIURL != "" {
			api = probeDirectURL(p.ID+" api", "hosting", *p.APIURL, 8*time.Second)
		}
		checks = append(checks, hostingCheckRecord{
			Time:      now,
			Provider:  p.ID,
			Homepage:  homepage,
			API:       api,
			Reachable: homepage.Status == "ok" || api.Status == "ok",
		})
	}
	return checks
}

func recordHostingChecks(st *envdState, checks []hostingCheckRecord) {
	st.ensureDefaults()
	st.HostingChecks = append(st.HostingChecks, checks...)
	if len(st.HostingChecks) > 250 {
		st.HostingChecks = append([]hostingCheckRecord{}, st.HostingChecks[len(st.HostingChecks)-250:]...)
	}
	ok := 0
	for _, c := range checks {
		if c.Reachable {
			ok++
		}
	}
	st.addEvent("hosting", "", fmt.Sprintf("checked %d providers; reachable %d", len(checks), ok))
}

func printHostingCheck(w io.Writer, checks []hostingCheckRecord) {
	reachable := 0
	for _, c := range checks {
		if c.Reachable {
			reachable++
		}
	}
	fmt.Fprintf(w, "Checked: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Reachable providers: %d/%d\n", reachable, len(checks))
	fmt.Fprintf(w, "%-18s %-8s %-8s %s\n", "PROVIDER", "WEB", "API", "DETAIL")
	for _, c := range checks {
		fmt.Fprintf(w, "%-18s %-8s %-8s %s\n", c.Provider, c.Homepage.Status, c.API.Status, c.Homepage.Detail)
	}
}

func latestHostingChecks(st *envdState) map[string]hostingCheckRecord {
	out := map[string]hostingCheckRecord{}
	for _, check := range st.HostingChecks {
		out[check.Provider] = check
	}
	return out
}

func printHostingShortlist(w io.Writer, providers []hostingProvider, checks map[string]hostingCheckRecord) {
	sortHostingProviders(providers, checks)
	fmt.Fprintf(w, "%-18s %-10s %-12s %-9s %-18s %s\n", "PROVIDER", "REACH", "CONFIDENCE", "REGIONS", "PAYMENTS", "NOTES")
	for _, p := range providers {
		reach := "unknown"
		if c, ok := checks[p.ID]; ok {
			if c.Reachable {
				reach = "ok"
			} else {
				reach = "fail"
			}
		}
		fmt.Fprintf(w, "%-18s %-10s %-12s %-9d %-18s %s\n",
			p.ID, reach, p.Confidence, len(p.Regions), strings.Join(p.Payments, ","), strings.Join(p.Notes, "; "))
	}
}

func sortHostingProviders(providers []hostingProvider, checks map[string]hostingCheckRecord) {
	for i := 1; i < len(providers); i++ {
		for j := i; j > 0 && hostingProviderLess(providers[j], providers[j-1], checks); j-- {
			providers[j], providers[j-1] = providers[j-1], providers[j]
		}
	}
}

func hostingProviderLess(a, b hostingProvider, checks map[string]hostingCheckRecord) bool {
	ar, br := hostingReachScore(a.ID, checks), hostingReachScore(b.ID, checks)
	if ar != br {
		return ar > br
	}
	ac, bc := confidenceScore(a.Confidence), confidenceScore(b.Confidence)
	if ac != bc {
		return ac > bc
	}
	if len(a.Regions) != len(b.Regions) {
		return len(a.Regions) > len(b.Regions)
	}
	return a.ID < b.ID
}

func hostingReachScore(id string, checks map[string]hostingCheckRecord) int {
	c, ok := checks[id]
	if !ok {
		return 1
	}
	if c.Reachable {
		return 2
	}
	return 0
}

func confidenceScore(confidence string) int {
	switch confidence {
	case "verified":
		return 4
	case "community":
		return 3
	case "user":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func (a app) gatewayEgressIP(cfg gatewayConfig) (string, error) {
	addr := net.JoinHostPort(hostForClient(cfg.BindIP), strconv.Itoa(cfg.HTTPHostPort))
	ip, err := fetchViaHTTPProxy(addr, "https://api.ipify.org/", 10*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(ip), nil
}

func (a app) activeGatewayConfig(st *envdState) (gatewayConfig, string, error) {
	if st == nil {
		return gatewayConfig{}, "", fmt.Errorf("active gateway requires encrypted envd state")
	}
	st.ensureDefaults()
	if st.ActiveGateway != "" {
		rec, ok := st.Gateways[st.ActiveGateway]
		if !ok {
			return gatewayConfig{}, "", fmt.Errorf("active gateway %q is missing from encrypted state", st.ActiveGateway)
		}
		return rec.toConfig(), "encrypted state", nil
	}
	if names := sortedGatewayProfileNames(st); len(names) > 0 {
		return gatewayConfig{}, "", fmt.Errorf("no active gateway configured; activate one with: envd gateway use %s", names[0])
	}
	if names := sortedGatewayNames(st); len(names) > 0 {
		return gatewayConfig{}, "", fmt.Errorf("no active gateway configured; gateway %s exists but is not ready; rerun gateway install or check with: envd gateway list", names[0])
	}
	return gatewayConfig{}, "", fmt.Errorf("no active gateway configured; install one with: envd gateway install NAME --host HOST --user root --password; then activate it with: envd gateway use NAME")
}

func sortedGatewayProfileNames(st *envdState) []string {
	names := make([]string, 0, len(st.Gateways))
	for name := range st.Gateways {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func gatewayRecordFromConfig(name string, cfg gatewayConfig, now time.Time) gatewayRecord {
	raw := map[string]string{}
	for k, v := range cfg.Raw {
		raw[k] = v
	}
	return gatewayRecord{
		Name:              name,
		Provider:          "xray",
		BindIP:            cfg.BindIP,
		SOCKSPort:         cfg.SOCKSPort,
		HTTPHostPort:      cfg.HTTPHostPort,
		SOCKSInner:        cfg.SOCKSInner,
		HTTPInner:         cfg.HTTPInner,
		ServerIP:          cfg.ServerIP,
		ServerPort:        cfg.ServerPort,
		Raw:               raw,
		ImportedFromLocal: true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func (r gatewayRecord) toConfig() gatewayConfig {
	raw := map[string]string{}
	for k, v := range r.Raw {
		raw[k] = v
	}
	return gatewayConfig{
		BindIP:       r.BindIP,
		SOCKSPort:    r.SOCKSPort,
		HTTPHostPort: r.HTTPHostPort,
		SOCKSInner:   r.SOCKSInner,
		HTTPInner:    r.HTTPInner,
		ServerIP:     r.ServerIP,
		ServerPort:   r.ServerPort,
		Raw:          raw,
	}
}

type reconciliationResult struct {
	Reconciled int
	Blocked    int
}

type reconciliationVerifier func(envRef) error

func reconcileSealedEnvGenerations(st *envdState) int {
	result := reconcileSealedEnvGenerationsWith(st, func(envRef) error { return nil }, func(envRef) error { return nil })
	return result.Reconciled
}

func reconcileSealedEnvGenerationsFailClosed(st *envdState, gatewayEgress string, stop workloadStopper) reconciliationResult {
	return reconcileSealedEnvGenerationsWith(st, func(ref envRef) error {
		dev, err := inspectContainer(ref.DevName)
		if err != nil {
			return err
		}
		if dev.State.Status != "running" {
			return nil
		}
		return verifyReconciledSealedEnv(ref, gatewayEgress)
	}, stop)
}

func verifyReconciledSealedEnv(ref envRef, gatewayEgress string) error {
	if _, err := inspectContainer(ref.NetName); err != nil {
		return err
	}
	_, err := verifySealedEnvAgainstGateway(ref.DevName, gatewayEgress)
	return err
}

func reconcileSealedEnvGenerationsWith(st *envdState, verify reconciliationVerifier, stop workloadStopper) reconciliationResult {
	result := reconciliationResult{}
	reconciled := 0
	now := time.Now().UTC()
	for _, name := range sortedEnvNames(st) {
		rec := st.Environments[name]
		if rec.Network != "sealed" {
			continue
		}
		if rec.GatewayGeneration == st.GatewayGeneration && rec.BlockedReason == "" {
			continue
		}
		ref, err := resolveEnvRef(st, name)
		if err == nil {
			err = verify(ref)
		}
		if err != nil {
			if ref.DevName != "" {
				_ = stop(ref)
			}
			rec.BlockedReason = "gateway reconciliation failed: " + redactSensitive(err.Error())
			rec.UpdatedAt = now
			st.Environments[name] = rec
			st.addEvent("gateway", name, "reconciliation failed; stopped fail-closed: "+redactSensitive(err.Error()))
			result.Blocked++
			continue
		}
		rec.GatewayGeneration = st.GatewayGeneration
		rec.BlockedReason = ""
		rec.UpdatedAt = now
		st.Environments[name] = rec
		st.addEvent("gateway", name, fmt.Sprintf("reconciled to generation %d", st.GatewayGeneration))
		reconciled++
	}
	result.Reconciled = reconciled
	return result
}

func (a app) runEvents(args []string, st *envdState) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(a.stdout, "Usage: envd events\n")
		return nil
	}
	if len(st.Events) == 0 {
		fmt.Fprintln(a.stdout, "No events recorded.")
		return nil
	}
	for _, ev := range st.Events {
		subject := ev.Subject
		if subject != "" {
			subject = " " + subject
		}
		fmt.Fprintf(a.stdout, "%s %-12s%s %s\n", ev.Time.Format(time.RFC3339), ev.Kind, subject, ev.Message)
	}
	return nil
}

func (a app) runWhy(args []string, st *envdState) error {
	if len(args) != 1 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, "Usage: envd why ENV\n")
		return nil
	}
	name := args[0]
	for i := len(st.Events) - 1; i >= 0; i-- {
		ev := st.Events[i]
		if ev.Subject == name {
			fmt.Fprintf(a.stdout, "%s: %s\n", name, ev.Message)
			return nil
		}
	}
	fmt.Fprintf(a.stdout, "%s: no events recorded yet\n", name)
	return nil
}

func (a app) probeDocker() probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	out, err := cmd.Output()
	if err != nil {
		return probeResult{Name: "Host Docker", Err: fmt.Errorf("docker daemon unavailable: %w", err)}
	}
	return probeResult{Name: "Host Docker", Detail: "server " + strings.TrimSpace(string(out))}
}

func (a app) probeRuntimeAsset(asset assetSpec) probeResult {
	if imageExists(asset.Image) {
		id, err := imageID(asset.Image)
		if err != nil {
			return probeResult{Name: asset.Name, Err: layerErr("asset cache", err)}
		}
		return probeResult{Name: asset.Name, Detail: asset.Image + " " + shortID(id)}
	}
	if err := a.ensureRuntimeAsset(asset); err != nil {
		return probeResult{Name: asset.Name, Err: layerErr("asset cache", err)}
	}
	id, err := imageID(asset.Image)
	if err != nil {
		return probeResult{Name: asset.Name, Err: layerErr("asset cache", err)}
	}
	return probeResult{Name: asset.Name, Detail: "restored " + asset.Image + " " + shortID(id)}
}

func (a app) probeGatewayRender(cfg gatewayConfig) probeResult {
	provider := xrayProvider{}
	rendered, err := provider.Render(a, cfg)
	if err != nil {
		return probeResult{Name: "Gateway render", Err: layerErr("local gateway", err)}
	}
	return probeResult{Name: "Gateway render", Detail: provider.Name() + " config " + strconv.Itoa(len(rendered)) + " bytes"}
}

func (a app) probeGatewayRuntime(st *envdState) probeResult {
	if err := a.ensureActiveGatewayRuntime(st); err != nil {
		return probeResult{Name: "Gateway runtime", Err: err}
	}
	return probeResult{Name: "Gateway runtime", Detail: "rendered and running"}
}

func (a app) probeEnvWorkloads(st *envdState) []probeResult {
	names := sortedEnvNames(st)
	if len(names) == 0 {
		return []probeResult{{Name: "Environments", Detail: "none"}}
	}
	results := make([]probeResult, 0, len(names))
	for _, name := range names {
		ref, err := resolveEnvRef(st, name)
		if err != nil {
			results = append(results, probeResult{Name: "Env " + name, Err: err})
			continue
		}
		rec := st.Environments[name]
		if envNeedsStart(ref, rec.Network) {
			repairApp := a
			repairApp.stdout = io.Discard
			if err := repairApp.startEnv([]string{name}, st); err != nil {
				results = append(results, probeResult{Name: "Env " + name, Err: err})
				continue
			}
			results = append(results, probeResult{Name: "Env " + name, Detail: networkOrSealed(rec.Network) + " repaired and running"})
			continue
		}
		if err := repairEnvSSHAccessForRef(ref); err != nil {
			results = append(results, probeResult{Name: "Env " + name, Err: err})
			continue
		}
		devStatus := dockerContainerStatus(ref.DevName)
		if devStatus == "missing" {
			results = append(results, probeResult{Name: "Env " + name, Err: fmt.Errorf("%s", missingEnvIssue(ref))})
			continue
		}
		if rec.Network == "sealed" {
			netStatus := dockerContainerStatus(ref.NetName)
			if netStatus == "missing" {
				results = append(results, probeResult{Name: "Env " + name, Err: fmt.Errorf("sidecar missing; run envd start %s", name)})
				continue
			}
			if netStatus != "running" {
				results = append(results, probeResult{Name: "Env " + name, Err: fmt.Errorf("sidecar %s; run envd start %s", netStatus, name)})
				continue
			}
		}
		if devStatus == "running" {
			results = append(results, probeResult{Name: "Env " + name, Detail: networkOrSealed(rec.Network) + " running"})
		} else {
			results = append(results, probeResult{Name: "Env " + name, Detail: networkOrSealed(rec.Network) + " " + devStatus + "; run envd start " + name})
		}
	}
	return results
}

func repairEnvSSHAccess(name string) error {
	if err := removeEnvKnownHost(name); err != nil {
		return err
	}
	return ensureEnvSSHConfig(name, currentEnvdExecutable())
}

func repairEnvSSHAccessForRef(ref envRef) error {
	if err := repairEnvSSHAccess(ref.Name); err != nil {
		return err
	}
	if containerExists(ref.DevName) && dockerContainerStatus(ref.DevName) == "running" {
		if err := ensureEnvAuthorizedKey(ref); err != nil {
			return err
		}
		if err := ensureEnvPrompt(ref); err != nil {
			return err
		}
	}
	return publishRuntimeRoute(ref, networkOrSealed(ref.Network))
}

func ensureEnvAuthorizedKey(ref envRef) error {
	authKey, err := ensureEnvdSSHKey()
	if err != nil {
		return err
	}
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	script := `
set -eu
home_dir="/home/${DEV_USER}"
ssh_dir="${home_dir}/.ssh"
authorized_keys="${ssh_dir}/authorized_keys"
mkdir -p "${ssh_dir}"
touch "${authorized_keys}"
if ! grep -qxF "${ENVD_AUTHORIZED_KEY}" "${authorized_keys}" 2>/dev/null; then
  printf '%s\n' "${ENVD_AUTHORIZED_KEY}" >> "${authorized_keys}"
fi
chown -R "${DEV_USER}:${DEV_USER}" "${ssh_dir}"
chmod 700 "${ssh_dir}"
chmod 600 "${authorized_keys}"
`
	return dockerRun("exec", "-e", "DEV_USER="+userName, "-e", "ENVD_AUTHORIZED_KEY="+authKey.PublicKey, ref.DevName, "sh", "-lc", script)
}

func ensureEnvPrompt(ref envRef) error {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	envName := ref.Name
	if envName == "" {
		envName = "envd"
	}
	script := `
set -eu
home_dir="/home/${DEV_USER}"
mkdir -p "${home_dir}"
bashrc="${home_dir}/.bashrc"
touch "${bashrc}"
tmp="${bashrc}.envd-tmp.$$"
trap 'rm -f "${tmp}"' EXIT INT TERM
awk '
  /# --- envd: prompt start ---/ {skip=1; next}
  /# --- envd: prompt end ---/ {skip=0; next}
  /# --- envd: ensure colored prompt ---/ {skip=1; next}
  /^unset color_prompt force_color_prompt$/ && skip == 1 {skip=0; next}
  skip != 1 {print}
' "${bashrc}" > "${tmp}"
cat >> "${tmp}" <<EOF

# --- envd: prompt start ---
export ENVD_ENV_NAME="${ENVD_ENV_NAME_VALUE}"
if [ -n "\${BASH_VERSION:-}" ]; then
  __envd_prompt() {
    if [ -z "\${ENVD_AUTO_CD_DONE:-}" ] && [ "\${PWD}" = "\${HOME}" ] && [ -d /repo ]; then
      cd /repo 2>/dev/null || true
      export ENVD_AUTO_CD_DONE=1
    fi
    PS1='[\[\e[01;32m\]\${ENVD_ENV_NAME}\[\e[00m\]] \u@envd:\w\$ '
  }
  case ";\${PROMPT_COMMAND:-};" in
    *";__envd_prompt;"*) ;;
    *) PROMPT_COMMAND="__envd_prompt\${PROMPT_COMMAND:+;\${PROMPT_COMMAND}}" ;;
  esac
  __envd_prompt
fi
# --- envd: prompt end ---
EOF
mv "${tmp}" "${bashrc}"
chown "${DEV_USER}:${DEV_USER}" "${bashrc}"
`
	return dockerRun("exec", "-e", "DEV_USER="+userName, "-e", "ENVD_ENV_NAME_VALUE="+envName, ref.DevName, "sh", "-lc", script)
}

func setVSCodeExtensionsLocked(ref envRef, locked bool) error {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	mode := "lock"
	if !locked {
		mode = "unlock"
	}
	script := `
set -eu
home_dir="/home/${DEV_USER}"
for base in ".vscode-server" ".vscode-server-insiders"; do
  dir="${home_dir}/${base}/extensions"
  mkdir -p "${dir}"
  chown -R "${DEV_USER}:${DEV_USER}" "${home_dir}/${base}"
  if [ "${ENVD_VSCODE_EXTENSIONS_MODE}" = "lock" ]; then
    chmod -R a-w "${dir}"
  else
    chmod -R u+w "${dir}"
  fi
done
`
	return dockerRun("exec", "-e", "DEV_USER="+userName, "-e", "ENVD_VSCODE_EXTENSIONS_MODE="+mode, ref.DevName, "sh", "-lc", script)
}

func (a app) probeGatewayPorts(cfg gatewayConfig) probeResult {
	if dockerContainerStatus("vpn-gateway-xray-1") == "missing" {
		return probeResult{Name: "Gateway ports", Err: layerErr("local gateway", fmt.Errorf("vpn-gateway-xray-1 is missing"))}
	}
	for _, check := range []struct {
		name     string
		internal int
		host     int
	}{
		{name: "SOCKS", internal: cfg.SOCKSInner, host: cfg.SOCKSPort},
		{name: "HTTP", internal: cfg.HTTPInner, host: cfg.HTTPHostPort},
	} {
		out, err := exec.Command("docker", "port", "vpn-gateway-xray-1", strconv.Itoa(check.internal)+"/tcp").Output()
		if err != nil {
			return probeResult{Name: "Gateway ports", Err: layerErr("local gateway", fmt.Errorf("%s internal port %d is not published", check.name, check.internal))}
		}
		if !publishedPortMatches(string(out), check.host) {
			return probeResult{Name: "Gateway ports", Err: layerErr("local gateway", fmt.Errorf("%s configured host port %d does not match Docker mapping %q", check.name, check.host, strings.TrimSpace(string(out))))}
		}
	}
	return probeResult{Name: "Gateway ports", Detail: "Docker mappings match config"}
}

func (a app) probeGatewayPortConflicts(cfg gatewayConfig) probeResult {
	if dockerContainerStatus("vpn-gateway-xray-1") != "missing" {
		if ports := a.probeGatewayPorts(cfg); ports.Err == nil {
			return probeResult{Name: "Gateway preflight", Detail: "configured ports owned by gateway"}
		}
	}
	for _, check := range []struct {
		name string
		port int
	}{
		{name: "SOCKS", port: cfg.SOCKSPort},
		{name: "HTTP", port: cfg.HTTPHostPort},
	} {
		addr := net.JoinHostPort(hostForClient(cfg.BindIP), strconv.Itoa(check.port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return probeResult{Name: "Gateway preflight", Err: layerErr("local gateway", fmt.Errorf("%s port conflict on %s: %w", check.name, addr, err))}
		}
		_ = ln.Close()
	}
	return probeResult{Name: "Gateway preflight", Detail: "configured ports are free"}
}

func (a app) probeSealedEnvTraffic(st *envdState) probeResult {
	envs, err := listEnvContainers(&envdState{Environments: map[string]envRecord{}})
	if err != nil {
		return probeResult{Name: "Sealed HTTPS", Err: layerErr("sealed sidecar", err)}
	}
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return probeResult{Name: "Sealed HTTPS", Err: layerErr("local gateway", err)}
	}
	gatewayEgress, err := a.gatewayEgressIP(cfg)
	if err != nil {
		return probeResult{Name: "Sealed HTTPS", Err: layerErr("remote gateway", err)}
	}
	for _, env := range envs {
		if env.networkMode() == "sealed" && env.Dev.State.Status == "running" {
			egress, err := verifySealedEnvAgainstGateway(env.dockerDevName(), gatewayEgress)
			if err != nil {
				return probeResult{Name: "Sealed HTTPS", Err: layerErr("sealed sidecar", fmt.Errorf("%s: %w", env.Name, err))}
			}
			return probeResult{Name: "Sealed HTTPS", Detail: env.Name + " DNS/TCP/TLS/DockerHub OK egress " + egress}
		}
	}
	return probeResult{Name: "Sealed HTTPS", Detail: "skipped: no running sealed env"}
}

func extractLastIPLine(raw string) string {
	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if net.ParseIP(line) != nil {
			return line
		}
	}
	return ""
}

func dockerContainerStatus(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Status}}", name)
	out, err := cmd.Output()
	if err != nil {
		return "missing"
	}
	return strings.TrimSpace(string(out))
}

func dockerRun(args ...string) error {
	cmd := exec.Command("docker", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker %s failed: %w\n%s", strings.Join(redactDockerArgs(args), " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func redactDockerArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	for i, arg := range redacted {
		if strings.HasPrefix(arg, "ENVD_AUTHORIZED_KEY=") {
			redacted[i] = "ENVD_AUTHORIZED_KEY=<redacted>"
		}
		if arg == "-e" && i+1 < len(redacted) && strings.HasPrefix(redacted[i+1], "ENVD_AUTHORIZED_KEY=") {
			redacted[i+1] = "ENVD_AUTHORIZED_KEY=<redacted>"
		}
	}
	return redacted
}

func containerExists(name string) bool {
	return exec.Command("docker", "container", "inspect", name).Run() == nil
}

func volumeExists(name string) bool {
	return exec.Command("docker", "volume", "inspect", name).Run() == nil
}

func sealedRuntimeRecreateStatus(ref envRef) (bool, string, error) {
	if !containerExists(ref.NetName) {
		return true, "missing sidecar container", nil
	}
	if !containerExists(ref.DevName) {
		return true, "missing dev container", nil
	}
	if devContainerNeedsHostDockerSocketRepair(ref.DevName) {
		return true, "Docker socket mount missing", nil
	}
	current, err := containerImageID(ref.NetName)
	if err != nil {
		return false, "", err
	}
	desired, err := imageID(sidecarImage)
	if err != nil {
		return false, "", err
	}
	return sealedRuntimeRecreateReason(current, desired)
}

func sealedRuntimeRecreateReason(currentSidecarImageID, desiredSidecarImageID string) (bool, string, error) {
	current := strings.TrimSpace(currentSidecarImageID)
	desired := strings.TrimSpace(desiredSidecarImageID)
	if current == "" || desired == "" {
		return false, "", fmt.Errorf("cannot compare sealed sidecar image drift")
	}
	if current != desired {
		return true, "sidecar image drift " + shortID(current) + " -> " + shortID(desired), nil
	}
	return false, "", nil
}

func containerImageID(name string) (string, error) {
	out, err := exec.Command("docker", "inspect", "-f", "{{.Image}}", name).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func imageExists(ref string) bool {
	return exec.Command("docker", "image", "inspect", ref).Run() == nil
}

type protectedStorageRecord struct {
	ID        string
	Backend   string
	ImagePath string
	MountPath string
	HomeDir   string
	RepoDir   string
	DockerDir string
	Key       string
}

func createProtectedStorage(id string) (protectedStorageRecord, error) {
	rec, err := newProtectedStorageRecord(id)
	if err != nil {
		return protectedStorageRecord{}, err
	}
	key, err := generateStorageKey()
	if err != nil {
		return protectedStorageRecord{}, err
	}
	rec.Key = key
	if err := os.MkdirAll(filepath.Dir(rec.ImagePath), 0o700); err != nil {
		return protectedStorageRecord{}, err
	}
	if err := os.MkdirAll(rec.MountPath, 0o755); err != nil {
		return protectedStorageRecord{}, err
	}
	if runtime.GOOS == "darwin" && !fileExists(rec.ImagePath) {
		if err := runWithPassword(key, "hdiutil", "create", "-type", "SPARSE", "-size", "8g", "-fs", "APFS", "-volname", "envd-"+shortID(id), "-encryption", "AES-256", "-stdinpass", rec.ImagePath); err != nil {
			return protectedStorageRecord{}, fmt.Errorf("create protected APFS image: %w", err)
		}
	} else if runtime.GOOS == "linux" && !fileExists(rec.ImagePath) {
		if err := runCommand("truncate", "-s", "8G", rec.ImagePath); err != nil {
			return protectedStorageRecord{}, fmt.Errorf("create protected LUKS image: %w", err)
		}
		if err := runWithPassword(key, "cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", rec.ImagePath); err != nil {
			_ = os.Remove(rec.ImagePath)
			return protectedStorageRecord{}, fmt.Errorf("format protected LUKS image: %w", err)
		}
	} else if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return protectedStorageRecord{}, fmt.Errorf("protected storage backend unavailable on %s", runtime.GOOS)
	}
	if err := ensureProtectedStorageMounted(rec); err != nil {
		return protectedStorageRecord{}, err
	}
	return rec, nil
}

func newProtectedStorageRecord(id string) (protectedStorageRecord, error) {
	base, err := envdDataDir()
	if err != nil {
		return protectedStorageRecord{}, err
	}
	root := filepath.Join(base, "protected", id)
	mountPath := filepath.Join("/tmp", "envd-"+id)
	backend := "apfs-sparseimage"
	image := filepath.Join(root, "storage.sparseimage")
	if runtime.GOOS == "linux" {
		backend = "luks2-dmcrypt"
		image = filepath.Join(root, "storage.luks")
	}
	return protectedStorageRecord{
		ID:        id,
		Backend:   backend,
		ImagePath: image,
		MountPath: mountPath,
		HomeDir:   filepath.Join(mountPath, "home"),
		RepoDir:   filepath.Join(mountPath, "repo"),
		DockerDir: filepath.Join(mountPath, "project-docker"),
	}, nil
}

func generateStorageKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func ensureProtectedStorageMounted(rec protectedStorageRecord) error {
	if rec.Backend == "" {
		return fmt.Errorf("protected storage backend is missing")
	}
	if rec.Key == "" || rec.ImagePath == "" || rec.MountPath == "" {
		return fmt.Errorf("protected storage metadata is incomplete")
	}
	switch rec.Backend {
	case "apfs-sparseimage":
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("protected storage backend %q unavailable on %s", rec.Backend, runtime.GOOS)
		}
	case "luks2-dmcrypt":
		if runtime.GOOS != "linux" {
			return fmt.Errorf("protected storage backend %q unavailable on %s", rec.Backend, runtime.GOOS)
		}
	default:
		return fmt.Errorf("unsupported protected storage backend %q", rec.Backend)
	}
	if protectedStorageMounted(rec.MountPath) {
		return ensureProtectedStorageDirs(rec)
	}
	if err := os.MkdirAll(rec.MountPath, 0o755); err != nil {
		return err
	}
	if rec.Backend == "apfs-sparseimage" {
		if err := runWithPassword(rec.Key, "hdiutil", "attach", "-stdinpass", "-nobrowse", "-mountpoint", rec.MountPath, rec.ImagePath); err != nil {
			return fmt.Errorf("attach protected APFS image: %w", err)
		}
	} else if rec.Backend == "luks2-dmcrypt" {
		mapper := luksMapperName(rec.ID)
		if !luksMapperOpen(mapper) {
			if err := runWithPassword(rec.Key, "cryptsetup", "open", "--key-file", "-", rec.ImagePath, mapper); err != nil {
				return fmt.Errorf("open protected LUKS image: %w", err)
			}
		}
		if err := ensureLUKSFilesystem(mapper); err != nil {
			_ = runCommand("cryptsetup", "close", mapper)
			return err
		}
		if err := runCommand("mount", "/dev/mapper/"+mapper, rec.MountPath); err != nil {
			_ = runCommand("cryptsetup", "close", mapper)
			return fmt.Errorf("mount protected LUKS image: %w", err)
		}
	}
	return ensureProtectedStorageDirs(rec)
}

func ensureProtectedStorageDirs(rec protectedStorageRecord) error {
	for _, dir := range []string{rec.HomeDir, rec.RepoDir, rec.DockerDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		_ = os.Chmod(dir, 0o755)
	}
	_ = os.Chmod(rec.MountPath, 0o755)
	return nil
}

func detachProtectedStorage(rec protectedStorageRecord) error {
	if rec.Backend == "" || rec.MountPath == "" {
		return nil
	}
	if rec.Backend == "luks2-dmcrypt" {
		if runtime.GOOS != "linux" {
			return nil
		}
		var errs []string
		if protectedStorageMounted(rec.MountPath) {
			if err := runCommand("umount", rec.MountPath); err != nil {
				errs = append(errs, err.Error())
			}
		}
		mapper := luksMapperName(rec.ID)
		if luksMapperOpen(mapper) {
			if err := runCommand("cryptsetup", "close", mapper); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}
	if rec.Backend != "apfs-sparseimage" {
		return fmt.Errorf("unsupported protected storage backend %q", rec.Backend)
	}
	if runtime.GOOS != "darwin" {
		return nil
	}
	if !protectedStorageMounted(rec.MountPath) {
		return nil
	}
	if err := runCommand("hdiutil", "detach", rec.MountPath); err != nil {
		if forceErr := runCommand("diskutil", "unmount", "force", rec.MountPath); forceErr != nil {
			return fmt.Errorf("detach protected APFS image: %w; force unmount also failed: %v", err, forceErr)
		}
		if detachErr := detachAttachedImage(rec.ImagePath); detachErr != nil {
			return fmt.Errorf("detach protected APFS image: %w; force unmounted filesystem but image detach failed: %v", err, detachErr)
		}
	}
	return nil
}

func luksMapperName(id string) string {
	safe := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(id, "_")
	if safe == "" {
		safe = "unknown"
	}
	return "envd-" + safe
}

func luksMapperOpen(mapper string) bool {
	return fileExists(filepath.Join("/dev/mapper", mapper))
}

func ensureLUKSFilesystem(mapper string) error {
	device := "/dev/mapper/" + mapper
	if exec.Command("blkid", device).Run() == nil {
		return nil
	}
	if err := runCommand("mkfs.ext4", "-q", device); err != nil {
		return fmt.Errorf("create protected LUKS filesystem: %w", err)
	}
	return nil
}

func detachAttachedImage(imagePath string) error {
	devices, err := attachedImageDevices(imagePath)
	if err != nil {
		return err
	}
	var errs []string
	for _, dev := range devices {
		if err := runCommand("hdiutil", "detach", dev); err != nil {
			if forceErr := runCommand("hdiutil", "detach", "-force", dev); forceErr != nil {
				errs = append(errs, err.Error()+"; "+forceErr.Error())
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if stillAttached, _ := attachedImageDevices(imagePath); len(stillAttached) > 0 {
		return fmt.Errorf("image still attached: %s", strings.Join(stillAttached, ", "))
	}
	return nil
}

func attachedImageDevices(imagePath string) ([]string, error) {
	out, err := exec.Command("hdiutil", "info").Output()
	if err != nil {
		return nil, err
	}
	cleanImagePath := filepath.Clean(imagePath)
	deviceLine := regexp.MustCompile(`^(/dev/disk[0-9]+)\s`)
	hit := false
	seen := map[string]bool{}
	devices := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "image-path") {
			parts := strings.SplitN(line, ":", 2)
			hit = len(parts) == 2 && filepath.Clean(strings.TrimSpace(parts[1])) == cleanImagePath
			continue
		}
		if strings.HasPrefix(line, "================================================") {
			hit = false
			continue
		}
		if !hit {
			continue
		}
		match := deviceLine.FindStringSubmatch(line)
		if len(match) == 2 && !seen[match[1]] {
			seen[match[1]] = true
			devices = append(devices, match[1])
		}
	}
	return devices, nil
}

func removeProtectedStorage(rec protectedStorageRecord) error {
	var errs []string
	if err := detachProtectedStorage(rec); err != nil {
		errs = append(errs, err.Error())
	}
	root := filepath.Dir(rec.ImagePath)
	if root != "." && root != "" {
		if err := os.RemoveAll(root); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func protectedStorageMounted(mountPath string) bool {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return false
	}
	mounts := string(out)
	candidates := []string{mountPath, filepath.Clean(mountPath)}
	if strings.HasPrefix(mountPath, "/tmp/") {
		candidates = append(candidates, "/private"+mountPath)
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(mountPath)); err == nil {
		candidates = append(candidates, filepath.Join(resolved, filepath.Base(mountPath)))
	}
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(mounts, " on "+candidate+" ") {
			return true
		}
	}
	return false
}

func runWithPassword(password, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s failed: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s failed: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a app) ensureRuntimeAsset(asset assetSpec) error {
	return ensureImage(asset.Image, filepath.Join(a.root, asset.ContextDir), asset.EmbeddedDir)
}

func (a app) ensureRuntimeAssetRecorded(st *envdState, asset assetSpec) error {
	existed := imageExists(asset.Image)
	if err := a.ensureRuntimeAsset(asset); err != nil {
		return err
	}
	meta, err := currentAssetRecord(asset.Image)
	if err != nil {
		return layerErr("asset cache", err)
	}
	recordAssetMetadata(st, asset.Image, meta, existed)
	return nil
}

func recordAssetMetadata(st *envdState, image string, meta assetRecord, existed bool) {
	st.ensureDefaults()
	previous, hadPrevious := st.Assets[image]
	st.Assets[image] = meta
	if !existed {
		st.addEvent("asset", image, "restored "+image+" "+shortID(meta.ImageID))
		return
	}
	if hadPrevious && previous.ImageID != "" && meta.ImageID != "" && previous.ImageID != meta.ImageID {
		st.addEvent("asset", image, "image drift "+shortID(previous.ImageID)+" -> "+shortID(meta.ImageID))
	}
}

func ensureImage(ref, contextDir, embeddedDir string) error {
	if imageExists(ref) {
		_ = saveImageToAssetCache(ref)
		return nil
	}
	if restored, err := loadImageFromAssetCache(ref); err != nil {
		return fmt.Errorf("cannot restore required image %s from asset cache: %w", ref, err)
	} else if restored {
		return nil
	}
	if _, err := os.Stat(filepath.Join(contextDir, "Dockerfile")); err != nil {
		if embeddedDir == "" {
			return fmt.Errorf("cannot restore required image %s: %w", ref, err)
		}
		var materializeErr error
		contextDir, materializeErr = materializeEmbeddedAssetContext(ref, embeddedDir)
		if materializeErr != nil {
			return fmt.Errorf("cannot restore required image %s from embedded assets: %w", ref, materializeErr)
		}
	}
	if err := dockerRun("build", "-t", ref, contextDir); err != nil {
		return fmt.Errorf("cannot restore required image %s: %w", ref, err)
	}
	_ = saveImageToAssetCache(ref)
	return nil
}

func materializeEmbeddedAssetContext(ref, embeddedDir string) (string, error) {
	dataDir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dataDir, "assets", "contexts", safeAssetName(ref))
	if err := materializeEmbeddedDir(embeddedDir, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func materializeEmbeddedDir(sourceDir, dest string) error {
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	return fs.WalkDir(envdassets.FS, sourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := envdassets.FS.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(path, ".sh") {
			mode = 0o700
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, raw, mode)
	})
}

func envdDataDir() (string, error) {
	dir := os.Getenv("ENVD_DATA_DIR")
	if dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "envd"), nil
}

func assetImagePath(ref string) (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "assets", "images", safeAssetName(ref)+".tar"), nil
}

func safeAssetName(ref string) string {
	name := strings.TrimSpace(ref)
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "@", "_")
	name = regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(name, "_")
	name = strings.Trim(name, "._-")
	if name == "" {
		return "image"
	}
	return name
}

func loadImageFromAssetCache(ref string) (bool, error) {
	path, err := assetImagePath(ref)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if err := dockerRun("load", "-i", path); err != nil {
		return false, err
	}
	return imageExists(ref), nil
}

func saveImageToAssetCache(ref string) error {
	path, err := assetImagePath(ref)
	if err != nil {
		return err
	}
	if fileExists(path) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := dockerRun("save", "-o", tmp, ref); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func currentAssetRecord(image string) (assetRecord, error) {
	id, err := imageID(image)
	if err != nil {
		return assetRecord{}, err
	}
	digest, err := imageRepoDigest(image)
	if err != nil {
		return assetRecord{}, err
	}
	return assetRecord{
		Image:      image,
		ImageID:    id,
		RepoDigest: digest,
		UpdatedAt:  time.Now().UTC(),
	}, nil
}

func ensureDockerNetwork(name string) error {
	if exec.Command("docker", "network", "inspect", name).Run() == nil {
		return nil
	}
	return fmt.Errorf("required Docker network %s is missing; start the gateway compose stack first", name)
}

func pickPort(start, end int) (int, error) {
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free localhost port in %d-%d", start, end)
}

func waitForHealthy(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		item, err := inspectContainer(name)
		if err == nil && item.State.Status == "running" {
			if item.State.Health == nil || item.State.Health.Status == "healthy" {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("container %s did not become healthy", name)
}

func verifySealedEnv(name string) error {
	_, err := verifySealedEnvAgainstGateway(name, "")
	return err
}

func verifySealedEnvAgainstGateway(name, gatewayEgress string) (string, error) {
	if _, err := dockerExecOutput(name, 8*time.Second, "getent", "hosts", "example.com"); err != nil {
		return "", layerErr("DNS", err)
	}
	if _, err := dockerExecOutput(name, 12*time.Second, "curl", "-fsSI", "--max-time", "12", "https://example.com"); err != nil {
		return "", layerErr("sealed sidecar", fmt.Errorf("HTTPS probe failed: %w", err))
	}
	if _, err := dockerExecOutput(name, 12*time.Second, "curl", "-sSI", "--max-time", "12", "https://registry-1.docker.io/v2/"); err != nil {
		return "", layerErr("DNS", fmt.Errorf("Docker Hub probe failed: %w", err))
	}
	egress, err := dockerExecOutput(name, 12*time.Second, "curl", "-fsS", "--max-time", "12", "https://api.ipify.org")
	if err != nil {
		return "", layerErr("egress policy", err)
	}
	egress = strings.TrimSpace(egress)
	if gatewayEgress != "" && egress != strings.TrimSpace(gatewayEgress) {
		return egress, layerErr("egress policy", fmt.Errorf("sealed egress %s differs from gateway egress %s", egress, strings.TrimSpace(gatewayEgress)))
	}
	return egress, nil
}

func dockerExecOutput(container string, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dockerArgs := append([]string{"exec", container}, args...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("docker %s timed out after %s", strings.Join(dockerArgs, " "), timeout)
	}
	if err != nil {
		return "", fmt.Errorf("docker %s failed: %w\n%s", strings.Join(dockerArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func validateEnvName(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return fmt.Errorf("invalid env name %q: length must be 1-32", name)
	}
	for i, ch := range name {
		if i == 0 {
			if ch < 'a' || ch > 'z' {
				return fmt.Errorf("invalid env name %q: must start with lowercase letter", name)
			}
			continue
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return fmt.Errorf("invalid env name %q: use lowercase letters and digits only", name)
		}
	}
	return nil
}

func dirHasFiles(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

type envInspect struct {
	Name              string
	ID                string
	GatewayGeneration int
	Legacy            bool
	BlockedReason     string
	Dev               dockerInspect
	Net               *dockerInspect
}

func (e envInspect) storageMode(st *envdState) string {
	if st != nil {
		if rec, ok := st.Environments[e.Name]; ok {
			return storageOrPlain(rec.Storage)
		}
	}
	if mode := strings.TrimSpace(e.Dev.Config.Labels["envd.storage"]); mode != "" {
		return storageOrPlain(mode)
	}
	return "plain"
}

type envRef struct {
	Name              string
	ID                string
	UserName          string
	DevName           string
	NetName           string
	ProjectDockerName string
	Network           string
	HomeVol           string
	RepoVol           string
	ProjectDockerVol  string
	HomeSource        string
	RepoSource        string
	Storage           string
	StorageBackend    string
	StorageImagePath  string
	StorageMountPath  string
	StorageKey        string
	Legacy            bool
}

func (r envRef) protectedStorage() protectedStorageRecord {
	return protectedStorageRecord{
		ID:        r.ID,
		Backend:   r.StorageBackend,
		ImagePath: r.StorageImagePath,
		MountPath: r.StorageMountPath,
		HomeDir:   filepath.Join(r.StorageMountPath, "home"),
		RepoDir:   filepath.Join(r.StorageMountPath, "repo"),
		DockerDir: filepath.Join(r.StorageMountPath, "project-docker"),
		Key:       r.StorageKey,
	}
}

func listEnvContainers(st *envdState) ([]envInspect, error) {
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "label=envd.managed=true",
		"--filter", "label=envd.role=dev",
		"--format", "{{.Names}}",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}
	names := strings.Fields(string(out))
	envs := make([]envInspect, 0, len(names))
	for _, name := range names {
		env, err := inspectEnvByDocker(st, name)
		if err != nil {
			return nil, err
		}
		envs = append(envs, env)
	}
	return envs, nil
}

func inspectEnv(st *envdState, name string) (envInspect, error) {
	ref, err := resolveEnvRef(st, name)
	if err != nil {
		return envInspect{}, err
	}
	return inspectEnvByRef(st, ref)
}

func inspectEnvByDocker(st *envdState, devName string) (envInspect, error) {
	dev, err := inspectContainer(devName)
	if err != nil {
		return envInspect{}, err
	}
	if dev.Config.Labels["envd.managed"] != "true" || dev.Config.Labels["envd.role"] != "dev" {
		return envInspect{}, fmt.Errorf("%s is not an envd dev container", devName)
	}
	id := dev.Config.Labels["envd.id"]
	name := ""
	legacy := false
	for candidate, rec := range st.Environments {
		if rec.ID == id {
			name = candidate
			legacy = rec.Legacy
			envBlocked := rec.BlockedReason
			env := envInspect{Name: name, ID: id, GatewayGeneration: envGatewayGeneration(st, name), Legacy: legacy, BlockedReason: envBlocked, Dev: dev}
			netName := netContainerName(id)
			if legacy {
				netName = strings.TrimPrefix(dev.Name, "/") + "-net"
			}
			if netContainer, err := inspectContainer(netName); err == nil {
				env.Net = &netContainer
			}
			return env, nil
		}
	}
	if name == "" {
		legacy = true
		name = dev.Config.Labels["envd.name"]
		if name == "" {
			name = strings.TrimPrefix(dev.Name, "/")
		}
	}
	env := envInspect{Name: name, ID: id, GatewayGeneration: envGatewayGeneration(st, name), Legacy: legacy, Dev: dev}
	netName := netContainerName(id)
	if legacy {
		netName = strings.TrimPrefix(dev.Name, "/") + "-net"
	}
	if netContainer, err := inspectContainer(netName); err == nil {
		env.Net = &netContainer
	}
	return env, nil
}

func inspectEnvByRef(st *envdState, ref envRef) (envInspect, error) {
	dev, err := inspectContainer(ref.DevName)
	if err != nil {
		return envInspect{}, err
	}
	if dev.Config.Labels["envd.managed"] != "true" || dev.Config.Labels["envd.role"] != "dev" {
		return envInspect{}, fmt.Errorf("%s is not an envd dev container", ref.DevName)
	}
	blocked := ""
	if rec, ok := st.Environments[ref.Name]; ok {
		blocked = rec.BlockedReason
	}
	env := envInspect{Name: ref.Name, ID: ref.ID, GatewayGeneration: envGatewayGeneration(st, ref.Name), Legacy: ref.Legacy, BlockedReason: blocked, Dev: dev}
	if netContainer, err := inspectContainer(ref.NetName); err == nil {
		env.Net = &netContainer
	}
	_ = st
	return env, nil
}

func resolveEnvRef(st *envdState, name string) (envRef, error) {
	if rec, ok := st.Environments[name]; ok {
		if rec.Legacy {
			return envRef{
				Name:              name,
				ID:                rec.ID,
				UserName:          name,
				DevName:           rec.ID,
				NetName:           rec.ID + "-net",
				ProjectDockerName: rec.ID + "-docker",
				Network:           networkOrSealed(rec.Network),
				HomeVol:           rec.ID + "-home",
				RepoVol:           rec.ID + "-repo",
				ProjectDockerVol:  rec.ID + "-docker",
				HomeSource:        rec.ID + "-home",
				RepoSource:        rec.ID + "-repo",
				Storage:           "plain",
				Legacy:            true,
			}, nil
		}
		homeSource := homeVolumeName(rec.ID)
		repoSource := repoVolumeName(rec.ID)
		return envRef{
			Name:              name,
			ID:                rec.ID,
			UserName:          "dev",
			DevName:           devContainerName(rec.ID),
			NetName:           netContainerName(rec.ID),
			ProjectDockerName: projectDockerContainerName(rec.ID),
			Network:           networkOrSealed(rec.Network),
			HomeVol:           homeVolumeName(rec.ID),
			RepoVol:           repoVolumeName(rec.ID),
			ProjectDockerVol:  projectDockerVolumeName(rec.ID),
			HomeSource:        homeSource,
			RepoSource:        repoSource,
			Storage:           storageOrPlain(rec.Storage),
			StorageBackend:    rec.StorageBackend,
			StorageImagePath:  rec.StorageImagePath,
			StorageMountPath:  rec.StorageMountPath,
			StorageKey:        rec.StorageKey,
		}, nil
	}
	if containerExists(name) {
		return envRef{
			Name:              name,
			ID:                name,
			UserName:          name,
			DevName:           name,
			NetName:           name + "-net",
			ProjectDockerName: name + "-docker",
			Network:           "sealed",
			HomeVol:           name + "-home",
			RepoVol:           name + "-repo",
			ProjectDockerVol:  name + "-docker",
			HomeSource:        name + "-home",
			RepoSource:        name + "-repo",
			Storage:           "plain",
			Legacy:            true,
		}, nil
	}
	return envRef{}, fmt.Errorf("environment %q not found", name)
}

func sortedEnvNames(st *envdState) []string {
	names := make([]string, 0, len(st.Environments))
	for name := range st.Environments {
		names = append(names, name)
	}
	sortStrings(names)
	return names
}

func sortedGatewayNames(st *envdState) []string {
	seen := map[string]bool{}
	for name := range st.Gateways {
		seen[name] = true
	}
	for name := range st.RemoteGateways {
		seen[name] = true
	}
	for name := range st.GatewayChains {
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sortStrings(names)
	return names
}

func discoverLegacyEnvs(st *envdState) ([]envInspect, error) {
	envs, err := listEnvContainers(st)
	if err != nil {
		return nil, err
	}
	legacy := make([]envInspect, 0)
	for _, env := range envs {
		if env.Legacy || env.Dev.Config.Labels["envd.name"] != "" {
			legacy = append(legacy, env)
		}
	}
	return legacy, nil
}

func legacyRefForEnv(env envInspect) envRef {
	devName := env.dockerDevName()
	name := env.Name
	if name == "" {
		name = devName
	}
	return envRef{
		Name:              name,
		ID:                devName,
		UserName:          name,
		DevName:           devName,
		NetName:           devName + "-net",
		ProjectDockerName: devName + "-docker",
		Network:           env.networkMode(),
		HomeVol:           devName + "-home",
		RepoVol:           devName + "-repo",
		ProjectDockerVol:  devName + "-docker",
		HomeSource:        devName + "-home",
		RepoSource:        devName + "-repo",
		Storage:           "plain",
		Legacy:            true,
	}
}

func volumeStatus(name string) string {
	if exec.Command("docker", "volume", "inspect", name).Run() == nil {
		return "plain"
	}
	return "missing"
}

func inspectContainer(name string) (dockerInspect, error) {
	out, err := exec.Command("docker", "inspect", name).Output()
	if err != nil {
		return dockerInspect{}, fmt.Errorf("docker inspect %s failed: %w", name, err)
	}
	var items []dockerInspect
	if err := json.Unmarshal(out, &items); err != nil {
		return dockerInspect{}, err
	}
	if len(items) != 1 {
		return dockerInspect{}, fmt.Errorf("docker inspect %s returned %d items", name, len(items))
	}
	return items[0], nil
}

func (e envInspect) netHealth() string {
	if e.networkMode() != "sealed" {
		return "n/a"
	}
	if e.Net == nil {
		return "blocked"
	}
	if e.Net.State.Status != "running" {
		return "blocked"
	}
	if e.Net.State.Health != nil && e.Net.State.Health.Status != "healthy" {
		return "blocked"
	}
	return "ok"
}

func (e envInspect) issue(activeGeneration int) string {
	if e.BlockedReason != "" {
		return "blocked: " + e.BlockedReason
	}
	if e.GatewayGeneration != activeGeneration {
		return "gateway generation mismatch"
	}
	if e.networkMode() != "sealed" {
		return ""
	}
	if e.Net == nil {
		return "sidecar missing"
	}
	if e.Net.State.Status != "running" {
		return "sidecar stopped"
	}
	if e.Net.State.Health != nil && e.Net.State.Health.Status != "healthy" {
		return "sidecar " + e.Net.State.Health.Status
	}
	if looksLikeImageID(e.Dev.Config.Image) {
		return "image identity drift"
	}
	if e.Dev.Config.Image != "" {
		currentID, err := imageID(e.Dev.Config.Image)
		if err == nil && currentID != "" && e.Dev.Image != "" && currentID != e.Dev.Image {
			return "image drift"
		}
	}
	return ""
}

func envGatewayGeneration(st *envdState, name string) int {
	if rec, ok := st.Environments[name]; ok {
		return rec.GatewayGeneration
	}
	return 0
}

func (e envInspect) egressSummary() string {
	if e.Dev.State.Status != "running" {
		return "-"
	}
	switch e.networkMode() {
	case "sealed":
		if e.netHealth() != "ok" {
			return "blocked"
		}
	case "offline":
		return "none"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", e.dockerDevName(), "curl", "-fsS", "--max-time", "8", "https://api.ipify.org")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func (e envInspect) dockerDevName() string {
	return strings.TrimPrefix(e.Dev.Name, "/")
}

func (e envInspect) networkMode() string {
	if mode := e.Dev.Config.Labels["envd.network"]; mode != "" {
		return mode
	}
	if e.Net != nil {
		return "sealed"
	}
	return "direct"
}

func shortImage(image string) string {
	if len(image) > 14 {
		return image[:14]
	}
	return image
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "-"
	}
	return id
}

func newOpaqueID(st *envdState) (string, error) {
	for attempts := 0; attempts < 32; attempts++ {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		id := hex.EncodeToString(raw)
		if containerExists(devContainerName(id)) || containerExists(netContainerName(id)) {
			continue
		}
		used := false
		for _, rec := range st.Environments {
			if rec.ID == id {
				used = true
				break
			}
		}
		if !used {
			return id, nil
		}
	}
	return "", fmt.Errorf("could not allocate unique environment id")
}

func devContainerName(id string) string {
	return "envd-" + id + "-dev"
}

func netContainerName(id string) string {
	return "envd-" + id + "-net"
}

func projectDockerContainerName(id string) string {
	return "envd-" + id + "-docker"
}

func homeVolumeName(id string) string {
	return "envd-" + id + "-home"
}

func repoVolumeName(id string) string {
	return "envd-" + id + "-repo"
}

func projectDockerVolumeName(id string) string {
	return "envd-" + id + "-docker"
}

func imageID(ref string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "-f", "{{.Id}}", ref).Output()
	if err != nil {
		return "", fmt.Errorf("docker image inspect %s failed: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func imageRepoDigest(ref string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "-f", "{{json .RepoDigests}}", ref).Output()
	if err != nil {
		return "", fmt.Errorf("docker image inspect %s failed: %w", ref, err)
	}
	var digests []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &digests); err != nil {
		return "", err
	}
	if len(digests) == 0 {
		return "", nil
	}
	return digests[0], nil
}

func looksLikeImageID(image string) bool {
	if len(image) < 12 || len(image) > 64 {
		return false
	}
	for _, ch := range image {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func validateProfileName(name string) error {
	return validateEnvName(name)
}

func parseProfilePackage(spec string) (profilePackage, error) {
	source, name, ok := strings.Cut(spec, ":")
	if !ok || source == "" || name == "" {
		return profilePackage{}, fmt.Errorf("package must use apt:PACKAGE, npm:PACKAGE, or tool:NAME")
	}
	switch source {
	case "apt", "npm", "tool":
	default:
		return profilePackage{}, fmt.Errorf("unsupported package source %q: use apt, npm, or tool", source)
	}
	if err := validatePackageName(name); err != nil {
		return profilePackage{}, err
	}
	return profilePackage{Source: source, Name: name}, nil
}

func parsePkgPromoteArgs(args []string) (envName, profileName string, err error) {
	if len(args) != 3 || args[1] != "--to" {
		return "", "", fmt.Errorf("usage: envd pkg promote ENV --to PROFILE")
	}
	if err := validateEnvName(args[0]); err != nil {
		return "", "", err
	}
	if err := validateProfileName(args[2]); err != nil {
		return "", "", err
	}
	return args[0], args[2], nil
}

func parseAptHistoryPackages(raw string) []profilePackage {
	return parseAptHistoryPackagesSince(raw, time.Time{})
}

func parseAptHistoryPackagesSince(raw string, since time.Time) []profilePackage {
	var pkgs []profilePackage
	includeBlock := true
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Start-Date:") {
			includeBlock = true
			if !since.IsZero() {
				started, err := parseAptHistoryTime(strings.TrimSpace(strings.TrimPrefix(line, "Start-Date:")))
				includeBlock = err == nil && !started.Before(since)
			}
			continue
		}
		if !strings.HasPrefix(line, "Install:") {
			continue
		}
		if !includeBlock {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "Install:"))
		for _, item := range strings.Split(line, "),") {
			item = strings.TrimSpace(strings.TrimSuffix(item, ")"))
			if item == "" {
				continue
			}
			if strings.Contains(item, ", automatic") {
				continue
			}
			name := strings.Fields(item)
			if len(name) == 0 {
				continue
			}
			pkg := name[0]
			if idx := strings.Index(pkg, ":"); idx > 0 {
				pkg = pkg[:idx]
			}
			if err := validatePackageName(pkg); err == nil {
				pkgs = append(pkgs, profilePackage{Source: "apt", Name: pkg})
			}
		}
	}
	return pkgs
}

func parseAptHistoryTime(value string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02  15:04:05", value, time.UTC)
}

func parseNpmGlobalPackages(raw string) []profilePackage {
	var pkgs []profilePackage
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name := filepath.Base(line)
		parent := filepath.Base(filepath.Dir(line))
		if strings.HasPrefix(parent, "@") {
			name = parent + "/" + name
		}
		if name == "node_modules" || name == "lib" {
			continue
		}
		if err := validatePackageName(name); err == nil {
			pkgs = append(pkgs, profilePackage{Source: "npm", Name: name})
		}
	}
	return pkgs
}

func uniqueProfilePackages(pkgs []profilePackage) []profilePackage {
	seen := map[profilePackage]bool{}
	out := make([]profilePackage, 0, len(pkgs))
	for _, pkg := range pkgs {
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		out = append(out, pkg)
	}
	return out
}

func validatePackageName(name string) error {
	if len(name) < 1 || len(name) > 128 {
		return fmt.Errorf("invalid package name %q: length must be 1-128", name)
	}
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case '.', '_', '+', '-', '@', '/', ':':
			continue
		default:
			return fmt.Errorf("invalid package name %q: unsupported character %q", name, ch)
		}
	}
	return nil
}

func newProfileID(st *envdState) (string, error) {
	for attempts := 0; attempts < 32; attempts++ {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		id := hex.EncodeToString(raw)
		used := false
		for _, profile := range st.Profiles {
			if profile.ID == id {
				used = true
				break
			}
		}
		if !used {
			return id, nil
		}
	}
	return "", fmt.Errorf("could not allocate unique profile id")
}

func profileImageName(profileID string, generation int) string {
	return "envd-profile-" + profileID + ":" + strconv.Itoa(generation)
}

func buildProfileImage(profile profileRecord) error {
	dir, err := profileBuildDir(profile.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dockerfile := profileDockerfile(profile)
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(dockerfile), 0o600); err != nil {
		return err
	}
	image := profileImageName(profile.ID, profile.Generation)
	return dockerRun("build",
		"-f", path,
		"-t", image,
		"--label", "envd.managed=true",
		"--label", "envd.role=profile-image",
		"--label", "envd.profile-id="+profile.ID,
		"--label", "envd.profile-generation="+strconv.Itoa(profile.Generation),
		dir,
	)
}

func profileBuildDir(profileID string) (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles", profileID), nil
}

func profileDockerfile(profile profileRecord) string {
	aptSet := map[string]bool{}
	npm := []string{}
	for _, pkg := range profile.Packages {
		switch pkg.Source {
		case "apt":
			aptSet[pkg.Name] = true
		case "npm":
			aptSet["nodejs"] = true
			aptSet["npm"] = true
			npm = append(npm, pkg.Name)
		case "tool":
			for _, aptName := range toolAptPackages(pkg.Name) {
				aptSet[aptName] = true
			}
		}
	}
	apt := make([]string, 0, len(aptSet))
	for name := range aptSet {
		apt = append(apt, name)
	}
	sortStrings(apt)
	var b strings.Builder
	b.WriteString("FROM " + devImage + "\n")
	if len(apt) > 0 {
		b.WriteString("RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends")
		for _, name := range apt {
			b.WriteString(" " + shellQuote(name))
		}
		b.WriteString(" && rm -rf /var/lib/apt/lists/*\n")
	}
	if len(npm) > 0 {
		b.WriteString("RUN npm install -g")
		for _, name := range npm {
			b.WriteString(" " + shellQuote(name))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func toolAptPackages(name string) []string {
	switch name {
	case "build-essential":
		return []string{"build-essential"}
	case "curl":
		return []string{"curl"}
	case "ffmpeg":
		return []string{"ffmpeg"}
	case "git":
		return []string{"git"}
	case "go", "golang":
		return []string{"golang-go"}
	case "jq":
		return []string{"jq"}
	case "node", "nodejs":
		return []string{"nodejs", "npm"}
	case "python", "python3":
		return []string{"python3", "python3-pip", "python3-venv"}
	case "rg", "ripgrep":
		return []string{"ripgrep"}
	case "unzip":
		return []string{"unzip"}
	case "zip":
		return []string{"zip"}
	default:
		return []string{name}
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func pruneProfileImages(st *envdState) error {
	keep := map[string]bool{}
	for _, profile := range st.Profiles {
		if profile.ID != "" && profile.Generation > 0 {
			keep[profileImageName(profile.ID, profile.Generation)] = true
		}
		if profile.Image != "" {
			keep[profile.Image] = true
		}
	}
	for _, rec := range st.Environments {
		if rec.Image != "" {
			keep[rec.Image] = true
		}
	}
	out, err := exec.Command("docker", "image", "ls",
		"--filter", "label=envd.managed=true",
		"--filter", "label=envd.role=profile-image",
		"--format", "{{.Repository}}:{{.Tag}}",
	).Output()
	if err != nil {
		return nil
	}
	for _, image := range strings.Fields(string(out)) {
		if strings.Contains(image, "<none>") || keep[image] {
			continue
		}
		_ = dockerRun("rmi", image)
	}
	return nil
}

func validNetworkMode(mode string) bool {
	return mode == "sealed" || mode == "direct" || mode == "offline"
}

func validStorageMode(mode string) bool {
	return mode == "plain" || mode == "protected"
}

func storageOrPlain(mode string) string {
	if mode == "" {
		return "plain"
	}
	return mode
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseRunArgs(args []string) (runOptions, error) {
	opts := runOptions{Network: "sealed", Storage: "plain"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--network":
			i++
			if i >= len(args) {
				return runOptions{}, fmt.Errorf("--network requires a value")
			}
			opts.Network = args[i]
			opts.NetworkExplicit = true
		case strings.HasPrefix(arg, "--network="):
			opts.Network = strings.TrimPrefix(arg, "--network=")
			opts.NetworkExplicit = true
		case arg == "--storage":
			i++
			if i >= len(args) {
				return runOptions{}, fmt.Errorf("--storage requires a value")
			}
			opts.Storage = args[i]
			opts.StorageExplicit = true
		case strings.HasPrefix(arg, "--storage="):
			opts.Storage = strings.TrimPrefix(arg, "--storage=")
			opts.StorageExplicit = true
		case arg == "--profile":
			i++
			if i >= len(args) {
				return runOptions{}, fmt.Errorf("--profile requires a value")
			}
			opts.Profile = args[i]
			opts.ProfileExplicit = true
		case strings.HasPrefix(arg, "--profile="):
			opts.Profile = strings.TrimPrefix(arg, "--profile=")
			opts.ProfileExplicit = true
		case strings.HasPrefix(arg, "-"):
			return runOptions{}, fmt.Errorf("unknown option %s", arg)
		default:
			if opts.Name != "" {
				return runOptions{}, fmt.Errorf("usage: envd start ENV")
			}
			opts.Name = arg
		}
	}
	return opts, nil
}

func applyProjectManifestDefaults(opts *runOptions) error {
	manifest, ok, err := loadProjectManifest()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if !opts.NetworkExplicit && manifest.Network != "" {
		opts.Network = manifest.Network
	}
	if !opts.StorageExplicit && manifest.Storage != "" {
		opts.Storage = manifest.Storage
	}
	if !opts.ProfileExplicit && manifest.Profile != "" {
		opts.Profile = manifest.Profile
	}
	return nil
}

func loadProjectManifest() (projectManifest, bool, error) {
	wd, err := os.Getwd()
	if err != nil {
		return projectManifest{}, false, err
	}
	path := filepath.Join(wd, ".envd.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return projectManifest{}, false, nil
		}
		return projectManifest{}, false, err
	}
	manifest, err := parseProjectManifest(raw)
	if err != nil {
		return projectManifest{}, false, fmt.Errorf(".envd.yaml: %w", err)
	}
	return manifest, true, nil
}

func parseProjectManifest(raw []byte) (projectManifest, error) {
	var manifest projectManifest
	for lineNo, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return projectManifest{}, fmt.Errorf("line %d must be key: value", lineNo+1)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		switch key {
		case "network":
			if !validNetworkMode(value) {
				return projectManifest{}, fmt.Errorf("line %d has invalid network %q", lineNo+1, value)
			}
			manifest.Network = value
		case "storage":
			if value != "plain" {
				return projectManifest{}, fmt.Errorf("line %d has unsupported storage %q", lineNo+1, value)
			}
			manifest.Storage = value
		case "profile":
			if value != "" {
				if err := validateProfileName(value); err != nil {
					return projectManifest{}, fmt.Errorf("line %d: %w", lineNo+1, err)
				}
			}
			manifest.Profile = value
		default:
			return projectManifest{}, fmt.Errorf("line %d has unsupported key %q", lineNo+1, key)
		}
	}
	return manifest, nil
}

func parseMigrateProfileArgs(args []string) (name, profile string, err error) {
	if len(args) != 3 || args[1] != "--profile" {
		return "", "", fmt.Errorf("usage: envd migrate ENV --profile PROFILE")
	}
	name = args[0]
	profile = args[2]
	if err := validateEnvName(name); err != nil {
		return "", "", err
	}
	if err := validateProfileName(profile); err != nil {
		return "", "", err
	}
	return name, profile, nil
}

func validateGatewayName(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return fmt.Errorf("invalid gateway name %q: length must be 1-32", name)
	}
	for i, ch := range name {
		if i == 0 {
			if ch < 'a' || ch > 'z' {
				return fmt.Errorf("invalid gateway name %q: must start with lowercase letter", name)
			}
			continue
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return fmt.Errorf("invalid gateway name %q: use lowercase letters and digits only", name)
		}
	}
	return nil
}

func (xrayProvider) Name() string {
	return "xray"
}

func (xrayProvider) Render(a app, cfg gatewayConfig) ([]byte, error) {
	raw, err := loadGatewayTemplate(a.root)
	if err != nil {
		return nil, err
	}
	vals := map[string]string{}
	for k, v := range cfg.Raw {
		vals[k] = v
	}
	vals["XRAY_INBOUND_PORT"] = strconv.Itoa(cfg.SOCKSInner)
	vals["XRAY_HTTP_PROXY_PORT"] = strconv.Itoa(cfg.HTTPInner)
	vals["XRAY_SERVER_IP"] = cfg.ServerIP
	vals["XRAY_SERVER_PORT"] = cfg.ServerPort
	if vals["XRAY_FINGERPRINT"] == "" {
		vals["XRAY_FINGERPRINT"] = "firefox"
	}
	for _, key := range []string{
		"XRAY_INBOUND_PORT",
		"XRAY_HTTP_PROXY_PORT",
		"XRAY_SERVER_IP",
		"XRAY_SERVER_PORT",
		"XRAY_UUID",
		"XRAY_PUBLIC_KEY",
		"XRAY_SNI",
		"XRAY_SHORT_ID",
		"XRAY_FINGERPRINT",
	} {
		if vals[key] == "" {
			return nil, fmt.Errorf("missing %s in gateway config", key)
		}
	}
	rendered := string(raw)
	for key, val := range vals {
		rendered = strings.ReplaceAll(rendered, "${"+key+"}", val)
	}
	if strings.Contains(rendered, "${") {
		return nil, fmt.Errorf("unresolved template variable remains")
	}
	if !json.Valid([]byte(rendered)) {
		return nil, fmt.Errorf("rendered Xray config is not valid JSON")
	}
	return []byte(rendered), nil
}

func loadGatewayTemplate(root string) ([]byte, error) {
	return envdassets.FS.ReadFile("gateway/config.template.json")
}

func (a app) materializeGatewayRuntime(cfg gatewayConfig) (string, error) {
	dir, err := gatewayRuntimeDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	rendered, err := (xrayProvider{}).Render(a, cfg)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), rendered, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(gatewayComposeYAML(cfg)), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func (a app) ensureActiveGatewayRuntime(st *envdState) error {
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	runtimeDir, err := a.materializeGatewayRuntime(cfg)
	if err != nil {
		return layerErr("local gateway", err)
	}
	if err := startGatewayRuntime(runtimeDir); err != nil {
		return layerErr("local gateway", err)
	}
	return nil
}

func gatewayRuntimeDir() (string, error) {
	dataDir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "gateway"), nil
}

func startGatewayRuntime(runtimeDir string) error {
	return dockerRun("compose", "-f", filepath.Join(runtimeDir, "compose.yml"), "up", "-d")
}

func gatewayComposeYAML(cfg gatewayConfig) string {
	bind := hostForClient(cfg.BindIP)
	return fmt.Sprintf(`name: vpn-gateway

services:
  xray:
    image: teddysun/xray@sha256:5ced88b51b157890fbadeb5dc6d70f157f5d577cd5d93ec09b30d14b86b07fde
    restart: unless-stopped
    ports:
      - "%s:%d:%d"
      - "%s:%d:%d"
    volumes:
      - ./config.json:/etc/xray/config.json:ro
    command: ["xray", "-config", "/etc/xray/config.json"]
    networks:
      outside:
        priority: 1000
        gw_priority: 1
      inside:
        priority: 100
        gw_priority: 0

networks:
  inside:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "false"
  outside: {}
`, bind, cfg.SOCKSPort, cfg.SOCKSInner, bind, cfg.HTTPHostPort, cfg.HTTPInner)
}

type probeResult struct {
	Name   string
	Detail string
	Err    error
}

func probeTCP(name, addr string, timeout time.Duration) probeResult {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", fmt.Errorf("cannot connect to %s: %w", addr, err))}
	}
	_ = conn.Close()
	return probeResult{Name: name, Detail: addr}
}

func probeSOCKS(name, proxyAddr, target string, timeout time.Duration) probeResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", err)}
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", fmt.Errorf("SOCKS greeting failed: %w", err))}
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return probeResult{Name: name, Err: layerErr("local proxy", fmt.Errorf("unexpected SOCKS greeting response %x", buf))}
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return probeResult{Name: name, Err: err}
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return probeResult{Name: name, Err: err}
	}
	if len(host) > 255 {
		return probeResult{Name: name, Err: fmt.Errorf("target hostname too long")}
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", err)}
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return probeResult{Name: name, Err: layerErr("remote gateway", fmt.Errorf("SOCKS connect failed: %w", err))}
	}
	if resp[1] != 0x00 {
		return probeResult{Name: name, Err: layerErr("remote gateway", fmt.Errorf("SOCKS connect rejected with code %d", resp[1]))}
	}
	if err := drainSOCKSBind(conn, resp[3]); err != nil {
		return probeResult{Name: name, Err: layerErr("local proxy", err)}
	}
	if err := probeTLS(conn, host); err != nil {
		return probeResult{Name: name, Err: layerErr("remote gateway", err)}
	}
	return probeResult{Name: name, Detail: "CONNECT " + target}
}

func drainSOCKSBind(r io.Reader, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(r, make([]byte, 4+2))
		return err
	case 0x03:
		l := []byte{0}
		if _, err := io.ReadFull(r, l); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(l[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(r, make([]byte, 16+2))
		return err
	default:
		return fmt.Errorf("unknown SOCKS address type %d", atyp)
	}
}

func probeHTTPProxy(name, proxyAddr, target string, timeout time.Duration) probeResult {
	proxyURL := "http://" + proxyAddr
	tr := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(proxyURL)),
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest("HEAD", "https://"+target, nil)
	if err != nil {
		return probeResult{Name: name, Err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Name: name, Err: layerErr("remote gateway", err)}
	}
	defer resp.Body.Close()
	return probeResult{Name: name, Detail: fmt.Sprintf("CONNECT %s -> HTTP %d", target, resp.StatusCode)}
}

func fetchViaHTTPProxy(proxyAddr, target string, timeout time.Duration) (string, error) {
	tr := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL("http://" + proxyAddr)),
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func probeTLS(conn net.Conn, serverName string) error {
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS through proxy failed: %w", err)
	}
	return nil
}

func layerErr(layer string, err error) error {
	return diagnosticError{Layer: layer, Err: err}
}

type diagnosticError struct {
	Layer string
	Err   error
}

func (e diagnosticError) Error() string {
	return fmt.Sprintf("%s layer: %s", e.Layer, e.Err)
}

func (e diagnosticError) Unwrap() error {
	return e.Err
}

func diagnosticLayer(err error) string {
	var diag diagnosticError
	if errors.As(err, &diag) {
		return diag.Layer
	}
	if strings.Contains(err.Error(), "docker daemon unavailable") {
		return "host Docker"
	}
	return "unknown"
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(password|passwd|token|secret|private[_-]?key)=([^ \n\r\t]+)`),
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

func redactSensitive(text string) string {
	out := text
	for _, pattern := range sensitivePatterns {
		out = pattern.ReplaceAllStringFunc(out, func(match string) string {
			if strings.Contains(match, "=") {
				key, _, ok := strings.Cut(match, "=")
				if ok {
					return key + "=<redacted>"
				}
			}
			if strings.HasPrefix(strings.ToLower(match), "bearer ") {
				return "Bearer <redacted>"
			}
			return "<redacted>"
		})
	}
	return out
}

func nextActionForError(err error) string {
	switch diagnosticLayer(err) {
	case "host Docker":
		return "Start Docker/Desktop and rerun envd doctor --deep."
	case "asset cache":
		return "Rerun the command from the envd repo so envd can rebuild required runtime images."
	case "local gateway":
		return "Run envd gateway render, then restart the gateway compose stack if render is OK."
	case "local proxy":
		return "Check envd proxy; if ports differ from Docker mappings, restart the gateway compose stack."
	case "remote gateway":
		return "Run envd gateway egress; if it fails, the remote gateway path is down."
	case "sealed sidecar":
		return "Run envd list and recreate or restart the affected sealed environment."
	case "DNS":
		return "Keep the env blocked; DNS inside the sealed route is not resolving."
	case "egress policy":
		return "Keep the env blocked; sealed egress does not match the gateway path."
	case "state":
		return "Unlock envd state with the correct master password and rerun the command."
	default:
		return ""
	}
}

func publishedPortMatches(output string, want int) bool {
	for _, line := range strings.Fields(output) {
		_, portText, err := net.SplitHostPort(line)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err == nil && port == want {
			return true
		}
	}
	return false
}

func hostForClient(bindIP string) string {
	switch bindIP {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	default:
		return bindIP
	}
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if isRepoRoot(wd) {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		for {
			if isRepoRoot(dir) {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", errors.New("repo root not found")
}

func isRepoRoot(dir string) bool {
	markers := []string{
		"go.mod",
		filepath.Join("internal", "assets", "assets.go"),
	}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
