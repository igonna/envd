package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	envdassets "github.com/envd/envd/internal/assets"
)

//go:embed hosting_providers.tsv
var builtInHostingProvidersTSV string

//go:embed hosting_ru_payments.tsv
var builtInRussianPaymentProvidersTSV string

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
	defaultIdleTimeout = 2 * time.Hour
	minIdleTimeout     = 30 * time.Minute
	idleLeaseStale     = 2 * time.Minute
	idleStopGrace      = 5 * time.Second
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
	if len(os.Args) > 1 && os.Args[1] == "__idle-tick" {
		_ = disableRuntimeIdleScheduler()
		return
	}

	root, err := findRepoRoot()
	if err != nil {
		root, _ = os.Getwd()
	}

	a := app{stdout: os.Stdout, stderr: os.Stderr, root: root}
	args := os.Args[1:]
	if strings.EqualFold(filepath.Base(os.Args[0]), "Vhrome") {
		args = append([]string{"browser"}, args...)
	}
	disableLegacyRuntimeIdleSchedulerBestEffort()
	if err := a.run(args); err != nil {
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
	case "completion":
		return a.runCompletion(args[1:])
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
		if isGatewayRemoveSubcommand(args[1:]) && !isGatewayRemoveCommand(args[1:]) {
			return a.runGateway(args[1:], nil)
		}
		if isGatewayRemoveCommand(args[1:]) {
			return a.withStateExplicitPassword(func(st *envdState, _ []byte) error { return a.runGateway(args[1:], st) })
		}
		return a.withState(func(st *envdState) error { return a.runGateway(args[1:], st) })
	case "hosting":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"hosting"})
		}
		return a.withState(func(st *envdState) error { return a.runHosting(args[1:], st) })
	case "browser":
		if len(args) > 1 && isHelpArg(args[1]) {
			return a.printCommandHelp([]string{"browser"})
		}
		if isBrowserResetCommand(args[1:]) {
			return a.withStateExplicitPassword(func(_ *envdState, _ []byte) error { return a.runBrowser(args[1:], nil) })
		}
		if len(args) == 1 || args[1] == "install" || args[1] == "update" || args[1] == "reset" || args[1] == "status" {
			return a.runBrowser(args[1:], nil)
		}
		return a.withState(func(st *envdState) error { return a.runBrowser(args[1:], st) })
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
	case "details":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"details"})
		}
		return a.withState(func(st *envdState) error { return a.runDetails(args[1:], st) })
	case "cp":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"cp"})
		}
		return a.runCopy(args[1:])
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
		return a.withStateExplicitPassword(func(st *envdState, _ []byte) error { return a.rmEnv(args[1:], st) })
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
	case "vscode":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"vscode"})
		}
		return a.runVSCode(args[1:])
	case "idle":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"idle"})
		}
		return a.runIdle(args[1:])
	case "network":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"network"})
		}
		return a.withStatePasswordSaveOnError(func(st *envdState, password []byte) error { return a.networkEnv(args[1:], st, password) })
	case "pkg":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"pkg"})
		}
		if isPkgRemoveCommand(args[1:]) {
			return a.withStateExplicitPassword(func(st *envdState, _ []byte) error { return a.runPkg(args[1:], st) })
		}
		return a.withState(func(st *envdState) error { return a.runPkg(args[1:], st) })
	case "supervisor":
		return fmt.Errorf("unknown command %q\n\nRun envd help for available commands.", args[0])
	case "migrate":
		if len(args) == 1 || (len(args) > 1 && isHelpArg(args[1])) {
			return a.printCommandHelp([]string{"migrate"})
		}
		if isMigrateProtectedCommand(args[1:]) {
			return a.withStateExplicitPassword(func(st *envdState, password []byte) error { return a.runMigrate(args[1:], st, password) })
		}
		return a.withStatePasswordSaveOnError(func(st *envdState, password []byte) error { return a.runMigrate(args[1:], st, password) })
	default:
		return fmt.Errorf("unknown command %q\n\nRun envd help for available commands.", args[0])
	}
}

func isBrowserResetCommand(args []string) bool {
	return len(args) == 2 && args[0] == "reset" && args[1] == "--yes"
}

func isPkgRemoveCommand(args []string) bool {
	return len(args) == 3 && args[0] == "rm" && args[2] == "--yes"
}

func isGatewayRemoveCommand(args []string) bool {
	return len(args) == 3 && (args[0] == "rm" || args[0] == "remove") && args[2] == "--yes"
}

func isGatewayRemoveSubcommand(args []string) bool {
	return len(args) > 0 && (args[0] == "rm" || args[0] == "remove")
}

func isMigrateProtectedCommand(args []string) bool {
	return len(args) == 3 && args[0] == "protected" && (args[2] == "--yes" || args[2] == "-y")
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
		fmt.Fprint(a.stdout, "Usage: envd status\n\nShows access, gateway, and environments. Use envd doctor for deep checks and repairs.\n")
		return nil
	}
	if len(args) != 0 {
		return fmt.Errorf("usage: envd status")
	}
	_ = runOpportunisticIdleSweep()
	if _, ok := cachedMasterPassword(); !ok && os.Getenv("ENVD_MASTER_PASSWORD") == "" {
		return a.printRuntimeStatus(true)
	}
	store, err := newStateStore()
	if err == nil {
		if statusErr := store.withStateReadOnly(a.stderr, func(st *envdState) error {
			st.ensureDefaults()
			access, err := loadRuntimeAccess()
			if err != nil {
				return err
			}
			a.repairRunningIdentityAgents(st)
			containerStates, err := dockerContainerStates()
			if err != nil {
				return err
			}
			a.printStatusSummary(st, access, containerStates["vpn-gateway-xray-1"])
			return a.printEnvStatusTable(st, access, containerStates)
		}); statusErr == nil {
			return nil
		}
	}
	return a.printRuntimeStatus(true)
}

func (a app) printStatusSummary(st *envdState, access runtimeAccessState, gatewayState string) {
	accessState := "locked"
	if !access.Locked {
		accessState = "unlocked"
	}
	if gatewayState == "" {
		if st.ActiveGateway == "" {
			gatewayState = "none"
		} else {
			gatewayState = "missing"
		}
	}
	envCount := len(st.Environments)
	fmt.Fprintf(a.stdout, "Access:  %s\n", accessState)
	fmt.Fprintf(a.stdout, "Gateway: %s", gatewayState)
	if st.ActiveGateway != "" {
		fmt.Fprintf(a.stdout, " (%s)", st.ActiveGateway)
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintf(a.stdout, "Idle:    %s\n", idleStatusText())
	fmt.Fprintf(a.stdout, "Envs:    %d\n\n", envCount)
}

func (a app) printRuntimeStatus(showRouteNames bool) error {
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
	fmt.Fprintf(a.stdout, "Idle:         %s\n", idleStatusText())
	if showRouteNames {
		return a.printRuntimeEnvStatusTable(access)
	}
	return nil
}

type envStatusRow struct {
	Name    string
	State   string
	Network string
	Storage string
	Egress  string
	Issue   string
}

func (a app) printEnvStatusTable(st *envdState, access runtimeAccessState, containerStates map[string]string) error {
	rows := envStatusRows(st, access, containerStates)
	if len(rows) == 0 {
		fmt.Fprintln(a.stdout, "No environments.")
		return nil
	}
	printEnvStatusRows(a.stdout, rows)
	return nil
}

func (a app) printRuntimeEnvStatusTable(access runtimeAccessState) error {
	rows := runtimeEnvStatusRows(access)
	if len(rows) == 0 {
		return nil
	}
	fmt.Fprintln(a.stdout)
	printEnvStatusRows(a.stdout, rows)
	return nil
}

func printEnvStatusRows(w io.Writer, rows []envStatusRow) {
	widths := []int{4, 5, 3, 7, 6}
	for _, row := range rows {
		widths[0] = maxInt(widths[0], len(row.Name))
		widths[1] = maxInt(widths[1], len(row.State))
		widths[2] = maxInt(widths[2], len(row.Network))
		widths[3] = maxInt(widths[3], len(row.Storage))
		widths[4] = maxInt(widths[4], len(row.Egress))
	}
	format := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%-%ds  %%-%ds  %%s\n", widths[0], widths[1], widths[2], widths[3], widths[4])
	fmt.Fprintf(w, format, "NAME", "STATE", "NET", "STORAGE", "EGRESS", "ISSUE")
	for _, row := range rows {
		fmt.Fprintf(w, format, row.Name, row.State, row.Network, row.Storage, row.Egress, row.Issue)
	}
}

func envStatusRows(st *envdState, access runtimeAccessState, containerStates map[string]string) []envStatusRow {
	names := sortedEnvNames(st)
	rows := make([]envStatusRow, 0, len(names))
	for _, name := range names {
		rec := st.Environments[name]
		ref, err := resolveEnvRef(st, name)
		if err != nil {
			continue
		}
		state := containerStates[ref.DevName]
		if state == "" {
			state = "missing"
		}
		if access.Locked {
			state = "locked"
		}
		network := networkOrSealed(rec.Network)
		issue := envStatusIssue(st, access, name, rec, state)
		rows = append(rows, envStatusRow{
			Name:    name,
			State:   state,
			Network: network,
			Storage: storageOrPlain(rec.Storage),
			Egress:  envStatusEgress(st, network),
			Issue:   issue,
		})
	}
	return rows
}

func runtimeEnvStatusRows(access runtimeAccessState) []envStatusRow {
	if len(access.Routes) == 0 {
		return nil
	}
	containerStates, err := dockerContainerStates()
	if err != nil {
		containerStates = map[string]string{}
	}
	names := make([]string, 0, len(access.Routes))
	for name := range access.Routes {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]envStatusRow, 0, len(names))
	for _, name := range names {
		route := access.Routes[name]
		state := containerStates[route.DevName]
		if state == "" {
			state = "missing"
		}
		if access.Locked {
			state = "locked"
		}
		issue := ""
		if state == "missing" {
			issue = "run envd start " + name
		}
		rows = append(rows, envStatusRow{
			Name:    name,
			State:   state,
			Network: networkOrSealed(route.Network),
			Storage: storageOrPlain(route.Storage),
			Egress:  "-",
			Issue:   issue,
		})
	}
	return rows
}

func dockerContainerStates() (map[string]string, error) {
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}
	states := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		name, state, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		states[strings.TrimSpace(name)] = strings.TrimSpace(state)
	}
	return states, scanner.Err()
}

func envStatusEgress(st *envdState, network string) string {
	switch network {
	case "sealed":
		if rec, ok := st.Gateways[st.ActiveGateway]; ok && rec.ServerIP != "" {
			return rec.ServerIP
		}
		return "-"
	case "direct":
		return "direct"
	case "offline":
		return "-"
	default:
		return "-"
	}
}

func envStatusIssue(st *envdState, access runtimeAccessState, name string, rec envRecord, state string) string {
	if access.Locked {
		return "locked"
	}
	if rec.BlockedReason != "" {
		return "blocked: " + rec.BlockedReason
	}
	if networkOrSealed(rec.Network) == "sealed" && rec.GatewayGeneration != st.GatewayGeneration {
		return "stale gateway"
	}
	if state == "missing" {
		return "run envd start " + name
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func identityAgentRuntimeStatus(access runtimeAccessState) string {
	if len(access.Routes) == 0 {
		return ""
	}
	stale := []string{}
	missing := []string{}
	live := 0
	for name, route := range access.Routes {
		ref := runtimeRefFromRoute(route)
		if dockerContainerStatus(ref.DevName) != "running" {
			missing = append(missing, name)
			continue
		}
		if envContainerIdentityAgentReady(ref) {
			live++
			continue
		}
		stale = append(stale, name)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		return "stale for " + strings.Join(stale, ", ") + "; run envd unlock"
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "missing for " + strings.Join(missing, ", ") + "; run envd unlock"
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

func (a app) withStateReadOnly(fn func(*envdState) error) error {
	store, err := newStateStore()
	if err != nil {
		return err
	}
	return store.withStateReadOnly(a.stderr, func(st *envdState) error {
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

func (a app) withStateExplicitPassword(fn func(*envdState, []byte) error) error {
	store, err := newStateStore()
	if err != nil {
		return err
	}
	return store.withStateExplicitPasswordSaveOnError(a.stderr, func(st *envdState, password []byte) error {
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
  status               show access, gateway, and environments
  completion           install or print shell completion
  lock                 stop envd-managed workloads
  unlock               restore access after lock
  password             change master password
  idle                 manage background idle cleanup
  reset-state          reset forgotten-password state

Environment:
  start                create or start an environment
  shell                open a shell or run a command
  details              show environment details
  cp                   copy files to/from an environment
  stop                 stop an environment
  rm                   remove an environment
  vscode               apply minimal VS Code settings
  vscode-extensions    lock/unlock remote VS Code extensions

Gateway:
  gateway              install/use/list gateways
  proxy                show/test local proxy ports

Diagnostics:
  doctor               diagnose what is broken

Advanced:
  browser              install/open Vhrome sealed browser
  hosting              find reachable VPS providers
  network              change network mode
  pkg                  manage package profiles
  identity             manage encrypted identities
  migrate              adopt legacy envd containers
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
		fmt.Fprint(a.stdout, "Usage: envd status\n\nShows access, gateway, and environment state. Falls back to runtime-only status when encrypted state is locked.\n")
	case "completion":
		a.printCompletionHelp()
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
	case "idle":
		a.printIdleHelp()
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
	case "details":
		fmt.Fprint(a.stdout, "Usage: envd details ENV\n")
	case "cp":
		a.printCopyHelp()
	case "stop":
		fmt.Fprint(a.stdout, "Usage: envd stop ENV\n")
	case "rm":
		fmt.Fprint(a.stdout, "Usage: envd rm ENV --yes\n\nDeletes an environment after explicitly asking for the current master password. Cached unlock is not enough for deletion.\n")
	case "vscode-extensions":
		a.printVSCodeExtensionsHelp()
	case "vscode":
		a.printVSCodeHelp()
	case "lock":
		fmt.Fprint(a.stdout, "Usage: envd lock\n\nStops envd-managed workloads, hides envd SSH targets, and clears cached unlock.\n")
	case "doctor":
		a.printDoctorHelp()
	case "hosting":
		a.printHostingHelp()
	case "browser":
		a.printBrowserHelp()
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
	case "version":
		fmt.Fprint(a.stdout, "Usage: envd version\n")
	case "help":
		fmt.Fprint(a.stdout, "Usage:\n  envd help\n  envd help COMMAND\n")
	default:
		return fmt.Errorf("unknown help topic %q", args[0])
	}
	return nil
}

func (a app) runCompletion(args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		a.printCompletionHelp()
		return nil
	}
	switch args[0] {
	case "zsh":
		fmt.Fprint(a.stdout, zshCompletionScript())
		return nil
	case "bash":
		fmt.Fprint(a.stdout, bashCompletionScript())
		return nil
	case "install":
		return a.installCompletion(args[1:])
	case "envs":
		for _, name := range completionEnvNames() {
			fmt.Fprintln(a.stdout, name)
		}
		return nil
	case "commands":
		for _, name := range topLevelCompletionCommands() {
			fmt.Fprintln(a.stdout, name)
		}
		return nil
	default:
		return fmt.Errorf("usage: envd completion install|zsh|bash")
	}
}

func (a app) printCompletionHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd completion install
  envd completion zsh
  envd completion bash

Install:
  installs completion for the current shell and adds a small managed profile block

`)
}

func (a app) installCompletion(args []string) error {
	quiet := false
	shellName := ""
	for _, arg := range args {
		switch arg {
		case "--quiet":
			quiet = true
		case "zsh", "bash":
			shellName = arg
		default:
			return fmt.Errorf("usage: envd completion install [zsh|bash] [--quiet]")
		}
	}
	if shellName == "" {
		shellName = detectCompletionShell()
	}
	switch shellName {
	case "zsh":
		return a.installZshCompletion(quiet)
	case "bash":
		return a.installBashCompletion(quiet)
	default:
		if !quiet {
			fmt.Fprintln(a.stdout, "Completion: skipped (unknown shell)")
		}
		return nil
	}
}

func detectCompletionShell() string {
	base := filepath.Base(os.Getenv("SHELL"))
	switch base {
	case "zsh", "bash":
		return base
	}
	if runtime.GOOS == "darwin" {
		return "zsh"
	}
	if runtime.GOOS == "linux" {
		return "bash"
	}
	return ""
}

func (a app) installZshCompletion(quiet bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".zsh", "completions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "_envd")
	if err := os.WriteFile(path, []byte(zshCompletionScript()), 0o644); err != nil {
		return err
	}
	zshrc := filepath.Join(home, ".zshrc")
	block := `
# envd zsh completion
fpath=("$HOME/.zsh/completions" $fpath)
autoload -Uz compinit
compinit
`
	raw, err := os.ReadFile(zshrc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !strings.Contains(string(raw), "# envd zsh completion") {
		prefix := ""
		if len(raw) > 0 && !strings.HasSuffix(string(raw), "\n") {
			prefix = "\n"
		}
		if err := os.WriteFile(zshrc, append(raw, []byte(prefix+block)...), 0o644); err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintln(a.stdout, "Completion: zsh installed")
			fmt.Fprintf(a.stdout, "Script:     %s\n", path)
			fmt.Fprintln(a.stdout, "Shell:      restart terminal or run `exec zsh`")
		}
		return nil
	}
	if !quiet {
		fmt.Fprintln(a.stdout, "Completion: zsh installed")
		fmt.Fprintf(a.stdout, "Script:     %s\n", path)
	}
	return nil
}

func (a app) installBashCompletion(quiet bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".local", "share", "bash-completion", "completions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "envd")
	if err := os.WriteFile(path, []byte(bashCompletionScript()), 0o644); err != nil {
		return err
	}
	bashrc := filepath.Join(home, ".bashrc")
	block := `
# envd bash completion
if [ -f "$HOME/.local/share/bash-completion/completions/envd" ]; then
  . "$HOME/.local/share/bash-completion/completions/envd"
fi
`
	raw, err := os.ReadFile(bashrc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !strings.Contains(string(raw), "# envd bash completion") {
		prefix := ""
		if len(raw) > 0 && !strings.HasSuffix(string(raw), "\n") {
			prefix = "\n"
		}
		if err := os.WriteFile(bashrc, append(raw, []byte(prefix+block)...), 0o644); err != nil {
			return err
		}
	}
	if !quiet {
		fmt.Fprintln(a.stdout, "Completion: bash installed")
		fmt.Fprintf(a.stdout, "Script:     %s\n", path)
		fmt.Fprintln(a.stdout, "Shell:      restart terminal or run `exec bash`")
	}
	return nil
}

func topLevelCompletionCommands() []string {
	return []string{
		"init",
		"status",
		"completion",
		"lock",
		"unlock",
		"password",
		"idle",
		"reset-state",
		"start",
		"shell",
		"details",
		"cp",
		"stop",
		"rm",
		"vscode",
		"vscode-extensions",
		"gateway",
		"proxy",
		"doctor",
		"browser",
		"hosting",
		"network",
		"pkg",
		"identity",
		"migrate",
		"version",
		"help",
	}
}

func completionEnvNames() []string {
	seen := map[string]bool{}
	if access, err := loadRuntimeAccess(); err == nil && !access.Locked {
		for name := range access.Routes {
			if name != "" {
				seen[name] = true
			}
		}
	}
	out, err := exec.Command(dockerBinary(), "ps", "-a",
		"--filter", "label=envd.managed=true",
		"--filter", "label=envd.role=dev",
		"--format", "{{.Label \"envd.name\"}}",
	).Output()
	if err == nil {
		for _, name := range strings.Fields(string(out)) {
			if name != "" {
				seen[name] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sortStrings(names)
	return names
}

func zshCompletionScript() string {
	return `#compdef envd

_envd() {
  local -a commands env_commands gateway_commands doctor_commands browser_commands pkg_commands identity_commands idle_commands network_modes extension_modes completion_commands

  commands=(
    init:'create encrypted state'
    status:'show access, gateway, and environments'
    completion:'install or print shell completion'
    lock:'stop envd-managed workloads'
    unlock:'restore access after lock'
    password:'change master password'
    idle:'manage idle cleanup'
    reset-state:'reset forgotten-password state'
    start:'create or start an environment'
    shell:'open a shell or run a command'
    details:'show environment details'
    cp:'copy files to/from an environment'
    stop:'stop an environment'
    rm:'remove an environment'
    vscode:'open VS Code for an environment'
    vscode-extensions:'lock or unlock remote VS Code extensions'
    gateway:'manage gateways'
    proxy:'show or test local proxy ports'
    doctor:'diagnose what is broken'
    browser:'install or open Vhrome'
    hosting:'find reachable VPS providers'
    network:'change network mode'
    pkg:'manage package profiles'
    identity:'manage encrypted identities'
    migrate:'adopt legacy containers'
    version:'print version'
    help:'show help'
  )

  env_commands=(start shell details cp stop rm vscode ssh-proxy)
  gateway_commands=(install list use status inspect render egress share shares view revoke rollback rm remove chain)
  doctor_commands=(network why history identity)
  browser_commands=(install update status reset open)
  pkg_commands=(list show add remove apply)
  identity_commands=(add list)
  idle_commands=(status on off)
  network_modes=(sealed direct offline)
  extension_modes=(lock unlock)
  completion_commands=(install zsh bash)

  _envd_envs() {
    local -a envs
    envs=("${(@f)$(_call_program envs envd completion envs 2>/dev/null)}")
    _describe 'environment' envs
  }

  _envd_cp_target() {
    local -a remotes
    remotes=("${(@f)$(_call_program envs envd completion envs 2>/dev/null)}")
    remotes=("${(@)^remotes}:")
    _alternative \
      'files:local file:_files' \
      'envs:environment prefix:_describe -t envs "environment prefix" remotes'
  }

  if (( CURRENT == 2 )); then
    _describe 'command' commands
    return
  fi

  case "$words[2]" in
    help)
      _describe 'command' commands
      ;;
    start|shell|details|stop|rm|vscode|ssh-proxy)
      if (( CURRENT == 3 )); then
        _envd_envs
      fi
      ;;
    cp)
      if (( CURRENT == 3 || CURRENT == 4 )); then
        _envd_cp_target
      fi
      ;;
    vscode-extensions)
      if (( CURRENT == 3 )); then
        _describe 'mode' extension_modes
      elif (( CURRENT == 4 )); then
        _envd_envs
      fi
      ;;
    network)
      if (( CURRENT == 3 )); then
        compadd set
      elif (( CURRENT == 4 )); then
        _envd_envs
      elif (( CURRENT == 5 )); then
        _describe 'mode' network_modes
      fi
      ;;
    gateway)
      if (( CURRENT == 3 )); then
        _describe 'gateway command' gateway_commands
      fi
      ;;
    doctor)
      if (( CURRENT == 3 )); then
        _describe 'doctor command' doctor_commands
      elif (( CURRENT == 4 && "$words[3]" == "why" )); then
        _envd_envs
      fi
      ;;
    browser)
      if (( CURRENT == 3 )); then
        _describe 'browser command' browser_commands
      fi
      ;;
    pkg)
      if (( CURRENT == 3 )); then
        _describe 'pkg command' pkg_commands
      fi
      ;;
    identity)
      if (( CURRENT == 3 )); then
        _describe 'identity command' identity_commands
      fi
      ;;
    idle)
      if (( CURRENT == 3 )); then
        _describe 'idle command' idle_commands
      fi
      ;;
    completion)
      if (( CURRENT == 3 )); then
        _describe 'completion command' completion_commands
      fi
      ;;
  esac
}

compdef _envd envd
`
}

func bashCompletionScript() string {
	return `# envd bash completion

_envd_completion() {
  local cur prev command
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  command="${COMP_WORDS[1]}"

  local commands="init status completion lock unlock password idle reset-state start shell details cp stop rm vscode vscode-extensions gateway proxy doctor browser hosting network pkg identity migrate version help"
  local gateway_commands="install list use status inspect render egress share shares view revoke rollback rm remove chain"
  local doctor_commands="network why history identity"
  local browser_commands="install update status reset open"
  local pkg_commands="list show add remove apply"
  local identity_commands="add list"
  local idle_commands="status on off"
  local network_modes="sealed direct offline"
  local extension_modes="lock unlock"
  local completion_commands="install zsh bash"

  _envd_envs() {
    envd completion envs 2>/dev/null
  }

  _envd_cp_targets() {
    local envs env
    envs="$(_envd_envs)"
    for env in $envs; do
      printf '%s:\n' "$env"
    done
  }

  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    return 0
  fi

  case "$command" in
    help)
      COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
      ;;
    start|shell|details|stop|rm|vscode|ssh-proxy)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$(_envd_envs)" -- "$cur") )
      fi
      ;;
    cp)
      if [ "$COMP_CWORD" -eq 2 ] || [ "$COMP_CWORD" -eq 3 ]; then
        COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "$(_envd_cp_targets)" -- "$cur") )
      fi
      ;;
    vscode-extensions)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$extension_modes" -- "$cur") )
      elif [ "$COMP_CWORD" -eq 3 ]; then
        COMPREPLY=( $(compgen -W "$(_envd_envs)" -- "$cur") )
      fi
      ;;
    network)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "set" -- "$cur") )
      elif [ "$COMP_CWORD" -eq 3 ]; then
        COMPREPLY=( $(compgen -W "$(_envd_envs)" -- "$cur") )
      elif [ "$COMP_CWORD" -eq 4 ]; then
        COMPREPLY=( $(compgen -W "$network_modes" -- "$cur") )
      fi
      ;;
    gateway)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$gateway_commands" -- "$cur") )
      fi
      ;;
    doctor)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$doctor_commands" -- "$cur") )
      elif [ "$COMP_CWORD" -eq 3 ] && [ "${COMP_WORDS[2]}" = "why" ]; then
        COMPREPLY=( $(compgen -W "$(_envd_envs)" -- "$cur") )
      fi
      ;;
    browser)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$browser_commands" -- "$cur") )
      fi
      ;;
    pkg)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$pkg_commands" -- "$cur") )
      fi
      ;;
    identity)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$identity_commands" -- "$cur") )
      fi
      ;;
    idle)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$idle_commands" -- "$cur") )
      fi
      ;;
    completion)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$completion_commands" -- "$cur") )
      fi
      ;;
  esac
}

complete -F _envd_completion envd
`
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
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			a.printDoctorHelp()
			return nil
		case "why":
			return a.runDoctorWhy(args[1:], st)
		case "history":
			return a.runDoctorHistory(args[1:], st)
		case "network":
			return a.runDoctorNetwork(args[1:], st)
		case "identity":
			return a.runDoctorIdentity(args[1:], st)
		}
		if !strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("unknown doctor subcommand %q", args[0])
		}
	}
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

	ok, currentFailures := a.printProbeResults(checks)
	recordDoctorEvents(st, currentFailures)

	if !ok {
		return errors.New("doctor found failures")
	}
	return nil
}

func (a app) runDoctorIdentity(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd doctor identity")
	}
	ok, _ := a.printProbeResults(probeIdentityRecords(st))
	if !ok {
		return errors.New("doctor found failures")
	}
	return nil
}

func (a app) printProbeResults(checks []probeResult) (bool, map[string]string) {
	width := len("CHECK")
	for _, c := range checks {
		width = maxInt(width, len(c.Name))
	}
	ok := true
	currentFailures := map[string]string{}
	for _, c := range checks {
		if c.Err != nil {
			ok = false
			currentFailures[c.Name] = redactSensitive(c.Err.Error())
			fmt.Fprintf(a.stdout, "%-*s  FAIL  %s\n", width, c.Name, redactSensitive(c.Err.Error()))
			if next := nextActionForError(c.Err); next != "" {
				fmt.Fprintf(a.stdout, "%-*s        Next: %s\n", width, "", next)
			}
		} else {
			fmt.Fprintf(a.stdout, "%-*s  OK    %s\n", width, c.Name, c.Detail)
		}
	}
	return ok, currentFailures
}

func (a app) runDoctorNetwork(args []string, st *envdState) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: envd doctor network [history]")
	}
	if len(args) == 1 {
		if args[0] != "history" {
			return fmt.Errorf("usage: envd doctor network [history]")
		}
		return a.runNetworkReport(nil, st)
	}
	checks := []probeResult{}
	width := len("Gateway SOCKS HTTPS")
	directResults := []internetProbeRecord{
		timedInternetProbe(func() internetProbeRecord {
			return probeDirectURL("Direct HTTPS", "direct", "https://api.ipify.org/", 5*time.Second)
		}),
		timedInternetProbe(func() internetProbeRecord {
			return probeDirectURL("Direct Docker Hub", "direct", "https://registry-1.docker.io/v2/", 5*time.Second)
		}),
		probeWebQuorum("Direct web quorum", "direct", nil, 5*time.Second, 20*time.Second),
	}
	for _, result := range networkCheckProbeResults(internetCheckRecord{Results: directResults}) {
		checks = append(checks, result)
		a.printProbeResult(result, width)
	}
	cfg, source, err := a.activeGatewayConfig(st)
	gatewayResults := []internetProbeRecord{}
	if err != nil {
		result := probeResult{Name: "Gateway config", Err: err}
		checks = append(checks, result)
		a.printProbeResult(result, width)
		gatewayResults = append(gatewayResults,
			internetProbeRecord{Name: "Gateway HTTPS", Path: "gateway", Status: "skip", Detail: redactSensitive(err.Error())},
			internetProbeRecord{Name: "Gateway Docker Hub", Path: "gateway", Status: "skip", Detail: "gateway config unavailable"},
		)
	} else {
		host := hostForClient(cfg.BindIP)
		socks := net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
		httpProxy := net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort))
		portAndProxyChecks := []probeResult{
			timedProbe(func() probeResult { return probeTCP("Gateway SOCKS port", socks, 3*time.Second) }),
			timedProbe(func() probeResult { return probeTCP("Gateway HTTP port", httpProxy, 3*time.Second) }),
			timedProbe(func() probeResult {
				return probeSOCKS("Gateway SOCKS HTTPS", socks, "api.ipify.org:443", 6*time.Second)
			}),
			timedProbe(func() probeResult {
				return probeHTTPProxy("Gateway HTTP HTTPS", httpProxy, "api.ipify.org:443", 6*time.Second)
			}),
		}
		for _, result := range portAndProxyChecks {
			checks = append(checks, result)
			a.printProbeResult(result, width)
		}
		started := time.Now()
		if ip, err := a.gatewayEgressIP(cfg); err != nil {
			result := probeResult{Name: "Gateway egress IP", Err: layerErr("remote gateway", err)}
			result = withProbeDuration(result, time.Since(started))
			checks = append(checks, result)
			a.printProbeResult(result, width)
		} else {
			result := probeResult{Name: "Gateway egress IP", Detail: strings.TrimSpace(ip) + " via " + source}
			result = withProbeDuration(result, time.Since(started))
			checks = append(checks, result)
			a.printProbeResult(result, width)
		}
		proxy := net.JoinHostPort(hostForClient(cfg.BindIP), strconv.Itoa(cfg.HTTPHostPort))
		gatewayResults = append(gatewayResults,
			timedInternetProbe(func() internetProbeRecord {
				return probeHTTPProxyURL("Gateway HTTPS", "gateway "+source, proxy, "https://api.ipify.org/", 6*time.Second)
			}),
			timedInternetProbe(func() internetProbeRecord {
				return probeHTTPProxyURL("Gateway Docker Hub", "gateway "+source, proxy, "https://registry-1.docker.io/v2/", 6*time.Second)
			}),
			probeWebQuorum("Gateway web quorum", "gateway "+source, mustParseURL("http://"+proxy), 6*time.Second, 20*time.Second),
		)
	}
	for _, result := range networkCheckProbeResults(internetCheckRecord{Results: gatewayResults}) {
		checks = append(checks, result)
		a.printProbeResult(result, width)
	}
	sealed := timedProbe(func() probeResult { return a.probeSealedEnvTraffic(st) })
	checks = append(checks, sealed)
	a.printProbeResult(sealed, width)
	if err == nil && gatewayRecoveryNeeded(checks) {
		recovery := timedProbe(func() probeResult { return a.probeGatewayRecovery(st) })
		checks = append(checks, recovery)
		a.printProbeResult(recovery, width)
		if recovery.Err == nil {
			host := hostForClient(cfg.BindIP)
			socks := net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
			httpProxy := net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort))
			rechecks := []probeResult{
				timedProbe(func() probeResult { return probeTCP("Gateway SOCKS port", socks, 3*time.Second) }),
				timedProbe(func() probeResult { return probeTCP("Gateway HTTP port", httpProxy, 3*time.Second) }),
				timedProbe(func() probeResult {
					return probeSOCKS("Gateway SOCKS HTTPS", socks, "api.ipify.org:443", 8*time.Second)
				}),
				timedProbe(func() probeResult {
					return probeHTTPProxy("Gateway HTTP HTTPS", httpProxy, "api.ipify.org:443", 8*time.Second)
				}),
			}
			for _, result := range rechecks {
				checks = append(checks, result)
				a.printProbeResult(result, width)
			}
			started := time.Now()
			if ip, err := a.gatewayEgressIP(cfg); err != nil {
				result := withProbeDuration(probeResult{Name: "Gateway egress IP", Err: layerErr("remote gateway", err)}, time.Since(started))
				checks = append(checks, result)
				a.printProbeResult(result, width)
			} else {
				result := withProbeDuration(probeResult{Name: "Gateway egress IP", Detail: strings.TrimSpace(ip) + " via " + source}, time.Since(started))
				checks = append(checks, result)
				a.printProbeResult(result, width)
			}
			recheckedGatewayResults := []internetProbeRecord{
				timedInternetProbe(func() internetProbeRecord {
					return probeHTTPProxyURL("Gateway HTTPS", "gateway "+source, httpProxy, "https://api.ipify.org/", 8*time.Second)
				}),
				timedInternetProbe(func() internetProbeRecord {
					return probeHTTPProxyURL("Gateway Docker Hub", "gateway "+source, httpProxy, "https://registry-1.docker.io/v2/", 8*time.Second)
				}),
				probeWebQuorum("Gateway web quorum", "gateway "+source, mustParseURL("http://"+httpProxy), 8*time.Second, 20*time.Second),
			}
			gatewayResults = append(gatewayResults, recheckedGatewayResults...)
			for _, result := range networkCheckProbeResults(internetCheckRecord{Results: recheckedGatewayResults}) {
				checks = append(checks, result)
				a.printProbeResult(result, width)
			}
			sealed = timedProbe(func() probeResult { return a.probeSealedEnvTraffic(st) })
			checks = append(checks, sealed)
			a.printProbeResult(sealed, width)
		}
	}
	recordNetworkCheck(st, internetCheckRecord{
		Time:    time.Now().UTC(),
		Results: append(directResults, gatewayResults...),
		Summary: summarizeInternetResults(append(directResults, gatewayResults...)),
	})
	if latestProbeFailures(checks) {
		return errors.New("doctor found failures")
	}
	return nil
}

func gatewayRecoveryNeeded(checks []probeResult) bool {
	latest := map[string]error{}
	for _, check := range checks {
		latest[check.Name] = check.Err
	}
	if err, ok := latest["Gateway web quorum"]; ok && err == nil {
		for _, name := range gatewaySingleSourceProbeNames() {
			delete(latest, name)
		}
	}
	for _, check := range checks {
		if _, ok := latest[check.Name]; !ok {
			continue
		}
		if latest[check.Name] != nil && gatewayRecoverableProbe(check) {
			return true
		}
	}
	return false
}

func gatewayRecoverableProbe(check probeResult) bool {
	switch check.Name {
	case "Gateway SOCKS port", "Gateway HTTP port", "Gateway SOCKS HTTPS", "Gateway HTTP HTTPS",
		"Gateway egress IP", "Gateway HTTPS", "Gateway Docker Hub", "Gateway web quorum":
		return true
	case "Sealed HTTPS":
		return strings.Contains(check.Err.Error(), "gateway")
	default:
		return false
	}
}

func latestProbeFailures(checks []probeResult) bool {
	latest := map[string]error{}
	for _, check := range checks {
		latest[check.Name] = check.Err
	}
	if err, ok := latest["Gateway web quorum"]; ok && err == nil {
		for _, name := range gatewaySingleSourceProbeNames() {
			delete(latest, name)
		}
	}
	for _, err := range latest {
		if err != nil {
			return true
		}
	}
	return false
}

func gatewaySingleSourceProbeNames() []string {
	return []string{
		"Gateway SOCKS HTTPS",
		"Gateway HTTP HTTPS",
		"Gateway egress IP",
		"Gateway HTTPS",
		"Gateway Docker Hub",
	}
}

func (a app) probeGatewayRecovery(st *envdState) probeResult {
	if err := a.restartActiveGatewayRuntime(st); err != nil {
		return probeResult{Name: "Gateway recovery", Err: err}
	}
	return probeResult{Name: "Gateway recovery", Detail: "restarted local gateway"}
}

func timedProbe(fn func() probeResult) probeResult {
	started := time.Now()
	return withProbeDuration(fn(), time.Since(started))
}

func timedInternetProbe(fn func() internetProbeRecord) internetProbeRecord {
	started := time.Now()
	result := fn()
	result.Detail = appendDuration(result.Detail, time.Since(started))
	return result
}

func withProbeDuration(result probeResult, elapsed time.Duration) probeResult {
	if result.Err != nil {
		result.Err = fmt.Errorf("%w (%s)", result.Err, formatProbeDuration(elapsed))
		return result
	}
	result.Detail = appendDuration(result.Detail, elapsed)
	return result
}

func appendDuration(detail string, elapsed time.Duration) string {
	if strings.TrimSpace(detail) == "" {
		return formatProbeDuration(elapsed)
	}
	return detail + " (" + formatProbeDuration(elapsed) + ")"
}

func formatProbeDuration(elapsed time.Duration) string {
	if elapsed < time.Second {
		return strconv.FormatInt(elapsed.Milliseconds(), 10) + "ms"
	}
	return fmt.Sprintf("%.1fs", elapsed.Seconds())
}

func (a app) printProbeResult(c probeResult, width int) {
	width = maxInt(width, len(c.Name))
	if c.Err != nil {
		fmt.Fprintf(a.stdout, "%-*s  FAIL  %s\n", width, c.Name, redactSensitive(c.Err.Error()))
		if next := nextActionForError(c.Err); next != "" {
			fmt.Fprintf(a.stdout, "%-*s        Next: %s\n", width, "", next)
		}
		return
	}
	fmt.Fprintf(a.stdout, "%-*s  OK    %s\n", width, c.Name, c.Detail)
}

func (a app) runDoctorHistory(args []string, st *envdState) error {
	if len(args) > 2 {
		return fmt.Errorf("usage: envd doctor history [SUBJECT]")
	}
	return a.runEvents(args, st)
}

func (a app) runDoctorWhy(args []string, st *envdState) error {
	if len(args) != 1 || isHelpArg(args[0]) {
		return fmt.Errorf("usage: envd doctor why ENV")
	}
	return a.runWhy(args, st)
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
	case "view":
		return a.runGatewayView(args[1:], st)
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
	case "rm", "remove":
		return a.runGatewayRemove(args[1:], st)
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
  envd gateway rm NAME --yes

App Access:
  envd gateway share NAME [LABEL]
  envd gateway view NAME SHARE
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

func (a app) printCopyHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd cp LOCAL ENV:PATH
  envd cp ENV:PATH LOCAL

Examples:
  envd cp ./file books:/repo/
  envd cp ./folder books:/repo/folder
  envd cp books:/repo/file .
  envd cp books:logs ./logs

Rules:
  one side must be local and one side must be ENV:PATH
  ENV:relative/path is relative to /home/dev/repo
  ENV:~/path is relative to /home/dev
  ENV:/absolute/path is absolute inside the environment

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

const (
	vhromeName           = "Vhrome"
	ublockOriginLiteID   = "ddkjiahejlhfcafbddmgiahcphecmpfh"
	chromeWebStoreUpdate = "https://clients2.google.com/service/update2/crx"
	chromiumWebStoreCRX  = "https://github.com/NeverDecaf/chromium-web-store/raw/master/Chromium%20Web%20Store.crx"
	chromiumSnapshots    = "https://storage.googleapis.com/chromium-browser-snapshots"
)

type browserInstall struct {
	Root         string
	BrowserDir   string
	ProfileDir   string
	DownloadDir  string
	ExtensionDir string
	Executable   string
	VersionFile  string
	Launcher     string
}

func (a app) runBrowser(args []string, st *envdState) error {
	if len(args) == 0 {
		return a.runBrowserOpen(nil, st)
	}
	switch args[0] {
	case "help", "-h", "--help":
		a.printBrowserHelp()
		return nil
	case "install":
		if len(args) != 1 {
			return fmt.Errorf("usage: envd browser install")
		}
		return a.runBrowserInstall(false)
	case "update":
		if len(args) != 1 {
			return fmt.Errorf("usage: envd browser update")
		}
		return a.runBrowserInstall(true)
	case "status":
		if len(args) != 1 {
			return fmt.Errorf("usage: envd browser status")
		}
		return a.runBrowserStatus(st)
	case "reset":
		if len(args) != 2 || args[1] != "--yes" {
			return fmt.Errorf("usage: envd browser reset --yes")
		}
		return a.runBrowserReset()
	case "open":
		return a.runBrowserOpen(args[1:], st)
	default:
		return a.runBrowserOpen(args, st)
	}
}

func (a app) runBrowserInstall(force bool) error {
	inst, err := browserInstallPaths()
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" && preferredMacChromiumEngine() == "" {
		if err := installMacStableChromium(); err != nil {
			return err
		}
		inst, err = browserInstallPaths()
		if err != nil {
			return err
		}
	}
	if force {
		_ = os.RemoveAll(inst.BrowserDir)
	}
	_ = os.RemoveAll(filepath.Join(inst.Root, "extensions", "vhrome-new-tab"))
	_ = os.RemoveAll(filepath.Join(inst.Root, "extensions", "blank-new-tab-page"))
	if _, err := os.Stat(inst.Executable); errors.Is(err, os.ErrNotExist) {
		revision, err := installChromiumSnapshot(inst)
		if err != nil {
			return err
		}
		_ = os.RemoveAll(filepath.Join(inst.Root, "chrome-for-testing"))
		fmt.Fprintf(a.stdout, "Browser: installed Chromium %s\n", revision)
	} else if err != nil {
		return err
	} else {
		fmt.Fprintln(a.stdout, "Browser: already installed")
	}
	if err := seedBrowserProfile(inst.ProfileDir); err != nil {
		return err
	}
	if err := installUBlockLite(inst); err != nil {
		fmt.Fprintf(a.stderr, "WARN: uBlock Origin Lite install failed: %s\n", redactSensitive(err.Error()))
	}
	if err := installChromiumWebStore(inst); err != nil {
		fmt.Fprintf(a.stderr, "WARN: Chromium Web Store install failed: %s\n", redactSensitive(err.Error()))
	}
	if err := installBrowserNewTabPage(inst); err != nil {
		return err
	}
	if err := installVhromeLauncher(inst); err != nil {
		return err
	}
	cleanupOldVhromeLaunchers(inst.Launcher)
	fmt.Fprintf(a.stdout, "App:     %s\n", inst.Launcher)
	fmt.Fprintf(a.stdout, "Profile: %s\n", inst.ProfileDir)
	return nil
}

func (a app) runBrowserStatus(st *envdState) error {
	inst, err := browserInstallPaths()
	if err != nil {
		return err
	}
	browser := "missing"
	if _, err := os.Stat(inst.Executable); err == nil {
		browser = "installed"
	}
	appStatus := "missing"
	if _, err := os.Stat(inst.Launcher); err == nil {
		appStatus = "installed"
	}
	gateway := "unknown"
	proxy := "-"
	egress := "-"
	if st != nil {
		if cfg, _, err := a.activeGatewayConfig(st); err == nil {
			host := hostForClient(cfg.BindIP)
			proxy = net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
			if ip, err := a.gatewayEgressIP(cfg); err == nil {
				gateway = "running"
				egress = strings.TrimSpace(ip)
			} else {
				gateway = "unreachable"
			}
		} else if st.ActiveGateway == "" {
			gateway = "none"
		} else {
			gateway = "broken"
		}
	} else if socks, httpProxy, err := gatewayRuntimeProxyEndpoints(); err == nil {
		proxy = socks
		if probeTCP("Gateway SOCKS port", socks, 3*time.Second).Err == nil &&
			probeHTTPProxy("Gateway HTTP HTTPS", httpProxy, "api.ipify.org:443", 10*time.Second).Err == nil {
			gateway = "running"
			if ip, err := fetchViaHTTPProxy(httpProxy, "https://api.ipify.org/", 5*time.Second); err == nil {
				egress = strings.TrimSpace(ip)
			}
		} else {
			gateway = "unreachable"
		}
	}
	fmt.Fprintf(a.stdout, "Browser: %s\n", browser)
	fmt.Fprintf(a.stdout, "App:     %s\n", appStatus)
	fmt.Fprintf(a.stdout, "Gateway: %s\n", gateway)
	fmt.Fprintf(a.stdout, "Proxy:   %s\n", proxy)
	fmt.Fprintf(a.stdout, "Profile: %s\n", inst.ProfileDir)
	fmt.Fprintf(a.stdout, "Egress:  %s\n", egress)
	return nil
}

func (a app) runBrowserReset() error {
	inst, err := browserInstallPaths()
	if err != nil {
		return err
	}
	_ = stopVhromeProcesses(inst.ProfileDir)
	if err := os.RemoveAll(inst.ProfileDir); err != nil {
		return err
	}
	if err := seedBrowserProfile(inst.ProfileDir); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Browser profile reset")
	return nil
}

func (a app) runBrowserOpen(urls []string, st *envdState) error {
	if st == nil {
		if err := a.runBrowserOpenRuntime(urls); err == nil {
			return nil
		} else if !stdinIsTerminal() {
			return err
		}
		return a.withState(func(st *envdState) error { return a.runBrowserOpen(urls, st) })
	}
	inst, err := browserInstallPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(inst.Executable); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Vhrome is not installed; run envd browser install")
	}
	if err := seedBrowserProfile(inst.ProfileDir); err != nil {
		return err
	}
	if err := a.ensureActiveGatewayRuntime(st); err != nil {
		return err
	}
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	host := hostForClient(cfg.BindIP)
	socks := net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
	httpProxy := net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort))
	if err := verifyRuntimeGatewayProxy(socks, httpProxy, 10*time.Second); err != nil {
		return err
	}
	flags := browserLaunchFlags(inst.ProfileDir, socks)
	flags = append(flags, urls...)
	return launchVhrome(inst.Executable, flags)
}

func (a app) runBrowserOpenRuntime(urls []string) error {
	inst, err := browserInstallPaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(inst.Executable); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Vhrome is not installed; run envd browser install")
	}
	access, err := loadRuntimeAccess()
	if err != nil {
		return err
	}
	if access.Locked {
		return fmt.Errorf("envd is locked; run envd unlock")
	}
	if len(urls) == 0 && vhromeIsRunning(inst.ProfileDir) {
		return activateVhrome(inst.Executable)
	}
	if err := seedBrowserProfile(inst.ProfileDir); err != nil {
		return err
	}
	socks, httpProxy, err := gatewayRuntimeProxyEndpoints()
	if err != nil {
		return err
	}
	if err := ensureRuntimeGatewayProxy(socks, httpProxy); err != nil {
		return err
	}
	flags := browserLaunchFlags(inst.ProfileDir, socks)
	flags = append(flags, urls...)
	return launchVhrome(inst.Executable, flags)
}

func ensureRuntimeGatewayProxy(socks, httpProxy string) error {
	if err := verifyGatewayProxyCached(socks, httpProxy, 10*time.Second); err == nil {
		return nil
	}
	runtimeDir, err := gatewayRuntimeDir()
	if err != nil {
		return err
	}
	if err := restartGatewayRuntime(runtimeDir); err != nil {
		return layerErr("local gateway", err)
	}
	return verifyGatewayProxyCached(socks, httpProxy, 10*time.Second)
}

func verifyGatewayProxyCached(socks, httpProxy string, timeout time.Duration) error {
	if gatewayHealthCacheValid(socks, httpProxy, time.Now()) {
		return nil
	}
	if err := verifyRuntimeGatewayProxy(socks, httpProxy, timeout); err != nil {
		return err
	}
	_ = saveGatewayHealthCache(socks, httpProxy, time.Now())
	return nil
}

func verifyRuntimeGatewayProxy(socks, httpProxy string, timeout time.Duration) error {
	if res := probeTCP("Gateway SOCKS port", socks, 3*time.Second); res.Err != nil {
		return res.Err
	}
	if res := probeTCP("Gateway HTTP port", httpProxy, 3*time.Second); res.Err != nil {
		return res.Err
	}
	if err := probeSOCKSWebQuorum(socks, timeout); err != nil {
		return err
	}
	proxyURL, err := url.Parse("http://" + httpProxy)
	if err != nil {
		return err
	}
	if err := probeHTTPWebQuorum(proxyURL, timeout); err != nil {
		return err
	}
	return nil
}

const gatewayHealthCacheTTL = 20 * time.Second

type gatewayHealthCache struct {
	SOCKS     string    `json:"socks"`
	HTTP      string    `json:"http"`
	CheckedAt time.Time `json:"checked_at"`
}

func gatewayHealthCacheValid(socks, httpProxy string, now time.Time) bool {
	cache, err := loadGatewayHealthCache()
	if err != nil {
		return false
	}
	if cache.SOCKS != socks || cache.HTTP != httpProxy {
		return false
	}
	if cache.CheckedAt.IsZero() || now.Before(cache.CheckedAt) {
		return false
	}
	return now.Sub(cache.CheckedAt) <= gatewayHealthCacheTTL
}

func saveGatewayHealthCache(socks, httpProxy string, now time.Time) error {
	path, err := gatewayHealthCachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(gatewayHealthCache{SOCKS: socks, HTTP: httpProxy, CheckedAt: now.UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func loadGatewayHealthCache() (gatewayHealthCache, error) {
	path, err := gatewayHealthCachePath()
	if err != nil {
		return gatewayHealthCache{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return gatewayHealthCache{}, err
	}
	var cache gatewayHealthCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return gatewayHealthCache{}, err
	}
	return cache, nil
}

func gatewayHealthCachePath() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gateway", "health.json"), nil
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func gatewayRuntimeProxyEndpoints() (string, string, error) {
	dir, err := gatewayRuntimeDir()
	if err != nil {
		return "", "", err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		return "", "", fmt.Errorf("gateway runtime missing; run envd doctor")
	}
	socks := ""
	httpProxy := ""
	re := regexp.MustCompile(`"([^"]+):([0-9]+):(2088|2089)"`)
	for _, match := range re.FindAllStringSubmatch(string(raw), -1) {
		addr := net.JoinHostPort(match[1], match[2])
		switch match[3] {
		case "2088":
			socks = addr
		case "2089":
			httpProxy = addr
		}
	}
	if socks == "" || httpProxy == "" {
		return "", "", fmt.Errorf("gateway runtime ports missing; run envd doctor")
	}
	return socks, httpProxy, nil
}

func browserLaunchFlags(profileDir, socksProxy string) []string {
	flags := []string{
		"--user-data-dir=" + profileDir,
		"--proxy-server=socks5://" + socksProxy,
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-features=OptimizationHints,MediaRouter,TabSearch,AvatarToolbarButton,ExtensionsToolbarMenu,SidePanelPinning",
		"--force-dark-mode",
		"--use-mock-keychain",
		"--no-first-run",
		"--no-default-browser-check",
		"--custom-ntp=" + fileURL(browserNewTabPagePath(filepath.Dir(profileDir))),
		"--extension-mime-request-handling=always-prompt-for-install",
	}
	if extensionDirs := browserExtensionDirsForProfile(profileDir); len(extensionDirs) > 0 {
		flags = append(flags, "--load-extension="+strings.Join(extensionDirs, ","))
	}
	return flags
}

func browserInstallPaths() (browserInstall, error) {
	dataDir, err := envdDataDir()
	if err != nil {
		return browserInstall{}, err
	}
	root := filepath.Join(dataDir, "browser")
	inst := browserInstall{
		Root:         root,
		BrowserDir:   filepath.Join(root, "chromium"),
		ProfileDir:   filepath.Join(root, "profile"),
		DownloadDir:  filepath.Join(root, "downloads"),
		ExtensionDir: filepath.Join(root, "extensions", "ublock-origin-lite"),
		VersionFile:  filepath.Join(root, "chromium-revision.txt"),
	}
	switch runtime.GOOS {
	case "darwin":
		inst.Executable = filepath.Join(inst.BrowserDir, "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium")
		if system := preferredMacChromiumEngine(); system != "" {
			inst.Executable = system
		}
		if dirWritable("/Applications") {
			inst.Launcher = filepath.Join("/Applications", "Vhrome.app")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return browserInstall{}, err
			}
			inst.Launcher = filepath.Join(home, "Applications", "Vhrome.app")
		}
	case "linux":
		inst.Executable = filepath.Join(inst.BrowserDir, "chrome-linux", "chrome")
		configHome := os.Getenv("XDG_DATA_HOME")
		if configHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return browserInstall{}, err
			}
			configHome = filepath.Join(home, ".local", "share")
		}
		inst.Launcher = filepath.Join(configHome, "applications", "vhrome.desktop")
	default:
		return browserInstall{}, fmt.Errorf("envd browser is not supported on %s yet", runtime.GOOS)
	}
	return inst, nil
}

func preferredMacChromiumEngine() string {
	for _, path := range []string{
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/hidden/Chromium.app/Contents/MacOS/Chromium",
	} {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	for _, root := range []string{
		"/opt/homebrew/Caskroom/ungoogled-chromium",
		"/usr/local/Caskroom/ungoogled-chromium",
	} {
		if path := newestChromiumCaskExecutable(root); path != "" {
			return path
		}
	}
	return ""
}

func installMacStableChromium() error {
	brew, err := exec.LookPath("brew")
	if err != nil {
		for _, path := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
			if st, statErr := os.Stat(path); statErr == nil && !st.IsDir() {
				brew = path
				err = nil
				break
			}
		}
	}
	if err != nil {
		return fmt.Errorf("stable Chromium is not installed; install Chromium or Homebrew ungoogled-chromium")
	}
	cmd := exec.Command(brew, "install", "--cask", "ungoogled-chromium")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stable Chromium install failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	if preferredMacChromiumEngine() == "" {
		return fmt.Errorf("stable Chromium install completed but Chromium.app was not found")
	}
	return nil
}

func newestChromiumCaskExecutable(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for i := len(names) - 1; i >= 0; i-- {
		path := filepath.Join(root, names[i], "Chromium.app", "Contents", "MacOS", "Chromium")
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".envd-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

type chromiumSnapshotPlatform struct {
	Name string
	Zip  string
}

func chromiumSnapshotPlatformForRuntime() (chromiumSnapshotPlatform, error) {
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return chromiumSnapshotPlatform{Name: "Mac_Arm", Zip: "chrome-mac.zip"}, nil
		}
		if runtime.GOARCH == "amd64" {
			return chromiumSnapshotPlatform{Name: "Mac", Zip: "chrome-mac.zip"}, nil
		}
	case "linux":
		if runtime.GOARCH == "amd64" {
			return chromiumSnapshotPlatform{Name: "Linux_x64", Zip: "chrome-linux.zip"}, nil
		}
	}
	return chromiumSnapshotPlatform{}, fmt.Errorf("Chromium snapshot is not available for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func installChromiumSnapshot(inst browserInstall) (string, error) {
	platform, err := chromiumSnapshotPlatformForRuntime()
	if err != nil {
		return "", err
	}
	lastChangeURL := chromiumSnapshots + "/" + platform.Name + "/LAST_CHANGE"
	resp, err := http.Get(lastChangeURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Chromium snapshot metadata returned HTTP %d", resp.StatusCode)
	}
	rawRevision, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	revision := strings.TrimSpace(string(rawRevision))
	if revision == "" {
		return "", fmt.Errorf("Chromium snapshot metadata returned empty revision")
	}
	downloadURL := chromiumSnapshots + "/" + platform.Name + "/" + revision + "/" + platform.Zip
	if err := os.MkdirAll(inst.Root, 0o700); err != nil {
		return "", err
	}
	tmpZip := filepath.Join(inst.Root, "chromium-download.zip")
	if err := downloadFile(tmpZip, downloadURL); err != nil {
		return "", err
	}
	defer os.Remove(tmpZip)
	_ = os.RemoveAll(inst.BrowserDir)
	if err := unzipFile(tmpZip, inst.BrowserDir); err != nil {
		return "", err
	}
	if err := os.WriteFile(inst.VersionFile, []byte(revision+"\n"), 0o600); err != nil {
		return "", err
	}
	return revision, nil
}

func installUBlockLite(inst browserInstall) error {
	if dirHasManifest(inst.ExtensionDir) {
		return nil
	}
	version := "120.0.0.0"
	rawURL := "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=" + url.QueryEscape(version) +
		"&acceptformat=crx2,crx3&x=id%3D" + ublockOriginLiteID + "%26installsource%3Dondemand%26uc"
	crxPath := filepath.Join(inst.Root, "ublock-origin-lite.crx")
	if err := downloadFile(crxPath, rawURL); err != nil {
		return err
	}
	defer os.Remove(crxPath)
	zipPath := filepath.Join(inst.Root, "ublock-origin-lite.zip")
	if err := crxToZip(crxPath, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)
	_ = os.RemoveAll(inst.ExtensionDir)
	if err := unzipFile(zipPath, inst.ExtensionDir); err != nil {
		return err
	}
	if !dirHasManifest(inst.ExtensionDir) {
		return fmt.Errorf("uBlock Origin Lite unpacked without manifest")
	}
	return nil
}

func installChromiumWebStore(inst browserInstall) error {
	dir := chromiumWebStoreExtensionDir(inst.Root)
	if dirHasManifest(dir) {
		return nil
	}
	crxPath := filepath.Join(inst.Root, "chromium-web-store.crx")
	if err := downloadFile(crxPath, chromiumWebStoreCRX); err != nil {
		return err
	}
	defer os.Remove(crxPath)
	zipPath := filepath.Join(inst.Root, "chromium-web-store.zip")
	if err := crxToZip(crxPath, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)
	_ = os.RemoveAll(dir)
	if err := unzipFile(zipPath, dir); err != nil {
		return err
	}
	if !dirHasManifest(dir) {
		return fmt.Errorf("Chromium Web Store unpacked without manifest")
	}
	return nil
}

func installBrowserNewTabPage(inst browserInstall) error {
	dir := browserNewTabPageDir(inst.Root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	html := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="color-scheme" content="light dark">
  <meta name="theme-color" content="#3c3c3c">
  <link rel="icon" href="empty.png">
  <title>New Tab</title>
  <style>
    html {
      color-scheme: light dark;
      background: #f1f3f4;
    }
    @media (prefers-color-scheme: dark) {
      html {
        background: #3c3c3c;
      }
    }
    body {
      margin: 0;
      min-height: 100%;
      background: inherit;
    }
  </style>
</head>
<body></body>
</html>
`
	if err := os.WriteFile(filepath.Join(dir, "newtab.html"), []byte(html), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "empty.png"), transparentPNG(), 0o600)
}

func transparentPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
		0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
		0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
		0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
		0x42, 0x60, 0x82,
	}
}

func crxToZip(crxPath, zipPath string) error {
	raw, err := os.ReadFile(crxPath)
	if err != nil {
		return err
	}
	if len(raw) < 4 || string(raw[:4]) != "Cr24" {
		return os.WriteFile(zipPath, raw, 0o600)
	}
	if len(raw) < 12 {
		return fmt.Errorf("invalid CRX header")
	}
	version := binary.LittleEndian.Uint32(raw[4:8])
	var offset uint32
	switch version {
	case 2:
		if len(raw) < 16 {
			return fmt.Errorf("invalid CRX2 header")
		}
		pubLen := binary.LittleEndian.Uint32(raw[8:12])
		sigLen := binary.LittleEndian.Uint32(raw[12:16])
		offset = 16 + pubLen + sigLen
	case 3:
		headerLen := binary.LittleEndian.Uint32(raw[8:12])
		offset = 12 + headerLen
	default:
		return fmt.Errorf("unsupported CRX version %d", version)
	}
	if int(offset) >= len(raw) {
		return fmt.Errorf("invalid CRX zip offset")
	}
	return os.WriteFile(zipPath, raw[offset:], 0o600)
}

func dirHasManifest(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "manifest.json"))
	return err == nil
}

func browserExtensionDirForProfile(profileDir string) string {
	return filepath.Join(filepath.Dir(profileDir), "extensions", "ublock-origin-lite")
}

func browserExtensionDirsForProfile(profileDir string) []string {
	root := filepath.Dir(profileDir)
	candidates := []string{
		browserExtensionDirForProfile(profileDir),
		chromiumWebStoreExtensionDir(root),
	}
	dirs := make([]string, 0, len(candidates))
	for _, dir := range candidates {
		if dirHasManifest(dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func chromiumWebStoreExtensionDir(root string) string {
	return filepath.Join(root, "extensions", "chromium-web-store")
}

func browserNewTabPageDir(root string) string {
	return filepath.Join(root, "newtab")
}

func browserNewTabPagePath(root string) string {
	return filepath.Join(browserNewTabPageDir(root), "newtab.html")
}

func fileURL(path string) string {
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func downloadFile(path, rawURL string) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := downloadFileOnce(path, rawURL); err != nil {
			lastErr = err
			if attempt < 3 {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			continue
		}
		return nil
	}
	return lastErr
}

func downloadFileOnce(path, rawURL string) error {
	client := http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func downloadFileWithProgress(path, rawURL, label string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	offset := int64(0)
	if info, err := os.Stat(tmp); err == nil {
		offset = info.Size()
	}
	client := http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   45 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
	}}
	var lastErr error
	for attempt := 1; attempt <= 20; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(min(attempt, 10)) * time.Second)
		}
		if info, err := os.Stat(tmp); err == nil {
			offset = info.Size()
		}
		err := downloadFileRange(client, tmp, rawURL, label, offset)
		if err == nil {
			fmt.Fprintln(os.Stderr)
			return os.Rename(tmp, path)
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "\nDownload interrupted: %s; retrying %d/20\n", err, attempt)
	}
	return lastErr
}

func downloadFileRange(client http.Client, tmp, rawURL, label string, offset int64) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := doRequestWithStatus(client, req, label, offset)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	appendMode := offset > 0 && resp.StatusCode == http.StatusPartialContent
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if !appendMode {
		offset = 0
	}
	total := int64(-1)
	if resp.ContentLength > 0 {
		total = offset + resp.ContentLength
	}
	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(tmp, flags, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	progress := downloadProgress{label: label, done: offset, total: total, last: time.Now(), lastPercent: -1}
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			progress.add(int64(n))
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			progress.print(true)
			return nil
		}
		return readErr
	}
}

func doRequestWithStatus(client http.Client, req *http.Request, label string, offset int64) (*http.Response, error) {
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		done <- result{resp: resp, err: err}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	start := time.Now()
	printConnectStatus(label, offset, 0)
	for {
		select {
		case res := <-done:
			return res.resp, res.err
		case <-ticker.C:
			printConnectStatus(label, offset, time.Since(start))
		}
	}
}

func printConnectStatus(label string, offset int64, elapsed time.Duration) {
	resume := ""
	if offset > 0 {
		resume = " resume " + formatBytes(offset)
	}
	printDownloadStatus(fmt.Sprintf("%s: connecting%s (%s)", label, resume, elapsed.Round(time.Second)), false)
}

type downloadProgress struct {
	label       string
	done        int64
	total       int64
	last        time.Time
	lastPercent int
}

func (p *downloadProgress) add(n int64) {
	p.done += n
	percent := -1
	if p.total > 0 {
		percent = int(float64(p.done) * 100 / float64(p.total))
	}
	if time.Since(p.last) >= 5*time.Second || (percent >= 0 && percent != p.lastPercent) {
		p.print(false)
	}
}

func (p *downloadProgress) print(final bool) {
	p.last = time.Now()
	if p.total > 0 {
		percent := float64(p.done) * 100 / float64(p.total)
		p.lastPercent = int(percent)
		printDownloadStatus(fmt.Sprintf("%s: %s/%s %.1f%%", p.label, formatBytes(p.done), formatBytes(p.total), percent), final)
	} else {
		printDownloadStatus(fmt.Sprintf("%s: %s", p.label, formatBytes(p.done)), final)
	}
	if final {
		printDownloadStatus(p.label+": done", true)
	}
}

func printDownloadStatus(line string, final bool) {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintf(os.Stderr, "\r\x1b[2K%s", line)
		if final {
			fmt.Fprintln(os.Stderr)
		}
		return
	}
	fmt.Fprintln(os.Stderr, line)
}

func formatBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d%s", n, units[unit])
	}
	return fmt.Sprintf("%.1f%s", value, units[unit])
}

func unzipFile(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	cleanDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cleanDest, 0o700); err != nil {
		return err
	}
	for _, f := range r.File {
		target := filepath.Join(cleanDest, f.Name)
		if !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) && target != cleanDest {
			return fmt.Errorf("unsafe zip path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func seedBrowserProfile(profileDir string) error {
	defaultDir := filepath.Join(profileDir, "Default")
	if err := os.MkdirAll(defaultDir, 0o700); err != nil {
		return err
	}
	if err := seedBrowserLocalState(filepath.Join(profileDir, "Local State")); err != nil {
		return err
	}
	if err := seedBrowserPreferences(filepath.Join(defaultDir, "Preferences")); err != nil {
		return err
	}
	if err := clearBrowserNewTabData(defaultDir); err != nil {
		return err
	}
	if err := clearBrowserStartupSession(defaultDir); err != nil {
		return err
	}
	_, err := seedBrowserSearchEngine(defaultDir)
	return err
}

func seedBrowserLocalState(path string) error {
	state := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &state)
	}
	browser, _ := state["browser"].(map[string]any)
	if browser == nil {
		browser = map[string]any{}
	}
	experiments := stringSetFromAnySlice(browser["enabled_labs_experiments"])
	experiments["disable-top-sites"] = true
	experiments["hide-extensions-menu"] = true
	experiments["remove-tabsearch-button"] = true
	experiments["show-avatar-button@3"] = true
	experiments["extensions-toolbar-menu@2"] = true
	experiments["extension-mime-request-handling@2"] = true
	experiments["custom-ntp"] = true
	browser["enabled_labs_experiments"] = sortedKeys(experiments)
	state["browser"] = browser
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func seedBrowserPreferences(path string) error {
	prefs := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &prefs)
	}
	ntp, _ := prefs["ntp"].(map[string]any)
	if ntp == nil {
		ntp = map[string]any{}
	}
	ntp["shortcust_visible"] = false
	ntp["custom_links_visible"] = false
	ntp["enterprise_shortcuts_visible"] = false
	ntp["use_most_visited_tiles"] = false
	ntp["num_personal_suggestions"] = 0
	ntp["shortcuts_auto_removal_disabled"] = true
	ntp["shortcuts_type"] = 0
	prefs["ntp"] = ntp
	customLinks, _ := prefs["custom_links"].(map[string]any)
	if customLinks == nil {
		customLinks = map[string]any{}
	}
	customLinks["initialized"] = true
	customLinks["list"] = []any{}
	prefs["custom_links"] = customLinks
	raw, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func clearBrowserNewTabData(defaultDir string) error {
	dbs := map[string][]string{
		"Top Sites": {"top_sites"},
		"Shortcuts": {"omni_box_shortcuts"},
	}
	for db, tables := range dbs {
		if err := clearSQLiteTables(filepath.Join(defaultDir, db), tables); err != nil {
			return err
		}
	}
	return nil
}

func clearBrowserStartupSession(defaultDir string) error {
	for _, name := range []string{"Current Session", "Current Tabs", "Last Session", "Last Tabs"} {
		if err := os.Remove(filepath.Join(defaultDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	sessionsDir := filepath.Join(defaultDir, "Sessions")
	entries, err := os.ReadDir(sessionsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "Session_") || strings.HasPrefix(name, "Tabs_") {
			if err := os.Remove(filepath.Join(sessionsDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func clearSQLiteTables(dbPath string, tables []string) error {
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		sqlite = "/usr/bin/sqlite3"
	}
	if _, err := os.Stat(sqlite); err != nil {
		return nil
	}
	for _, table := range tables {
		out, err := exec.Command(sqlite, dbPath, "DELETE FROM "+table+";").CombinedOutput()
		if err != nil {
			msg := strings.ToLower(string(out) + err.Error())
			if strings.Contains(msg, "locked") {
				return fmt.Errorf("Vhrome profile is in use; quit Vhrome and retry")
			}
			if strings.Contains(msg, "no such table") {
				continue
			}
			return fmt.Errorf("clear browser data failed: %w\n%s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func stringSetFromAnySlice(v any) map[string]bool {
	out := map[string]bool{}
	items, _ := v.([]any)
	for _, item := range items {
		text, _ := item.(string)
		if text != "" {
			out[text] = true
		}
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func seedBrowserSearchEngine(defaultDir string) (string, error) {
	dbPath := filepath.Join(defaultDir, "Web Data")
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return "0", nil
	} else if err != nil {
		return "", err
	}
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		sqlite = "/usr/bin/sqlite3"
	}
	if _, err := os.Stat(sqlite); err != nil {
		return "0", nil
	}
	now := chromiumTime(time.Now())
	sql := fmt.Sprintf(`
DELETE FROM keywords WHERE short_name = 'GoogleEn' OR keyword = 'google.com/?hl=en';
INSERT INTO keywords (
  short_name, keyword, favicon_url, url, safe_for_autoreplace, originating_url,
  date_created, usage_count, input_encodings, suggest_url, prepopulate_id,
  created_by_policy, last_modified, sync_guid, alternate_urls, image_url,
  search_url_post_params, suggest_url_post_params, image_url_post_params,
  new_tab_url, last_visited, created_from_play_api, is_active, starter_pack_id,
  enforced_by_policy, featured_by_policy, url_hash
) VALUES (
  'GoogleEn',
  'google.com/?hl=en',
  '',
  'https://www.google.com/search?q={searchTerms}&hl=en',
  0,
  '',
  %d,
  0,
  'UTF-8',
  'https://www.google.com/complete/search?client=chrome&q={searchTerms}&hl=en',
  0,
  0,
  %d,
  'envd-google-en',
  '',
  '',
  '',
  '',
  '',
  '',
  0,
  0,
  1,
  0,
  0,
  0,
  X''
);
SELECT id FROM keywords WHERE sync_guid = 'envd-google-en' LIMIT 1;
`, now, now)
	out, err := exec.Command(sqlite, dbPath, sql).CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out) + err.Error())
		if strings.Contains(msg, "locked") || strings.Contains(msg, "no such table") {
			return "0", nil
		}
		return "", fmt.Errorf("seed browser search engine failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	rowID := strings.TrimSpace(string(out))
	if rowID == "" {
		rowID = "0"
	}
	return rowID, nil
}

func chromiumTime(t time.Time) int64 {
	return t.UTC().UnixMicro() + 11644473600000000
}

func installVhromeLauncher(inst browserInstall) error {
	switch runtime.GOOS {
	case "darwin":
		return installVhromeMacLauncher(inst)
	case "linux":
		return installVhromeLinuxLauncher(inst)
	default:
		return nil
	}
}

func installVhromeMacLauncher(inst browserInstall) error {
	if err := os.MkdirAll(filepath.Dir(inst.Launcher), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(inst.Launcher)
	logPath := "$HOME/.local/share/envd/browser/vhrome.log"
	appDir := inst.Executable
	for !strings.HasSuffix(appDir, ".app") && appDir != filepath.Dir(appDir) {
		appDir = filepath.Dir(appDir)
	}
	flags := browserLaunchFlags(inst.ProfileDir, net.JoinHostPort("127.0.0.1", "11080"))
	quotedFlags := make([]string, 0, len(flags))
	for _, flag := range flags {
		quotedFlags = append(quotedFlags, shellWords(flag))
	}
	shellScript := fmt.Sprintf(`PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
LOG=%s
mkdir -p "$(dirname "$LOG")"
ACCESS="$HOME/.local/share/envd/runtime/access.json"
echo "Vhrome launch $(date)" >>"$LOG"
if [ ! -f "$ACCESS" ] || /usr/bin/grep -Eq '"locked"[[:space:]]*:[[:space:]]*true' "$ACCESS"; then
  echo "ERROR: envd is locked; run envd unlock" >>"$LOG"
  exit 1
fi
if /usr/bin/pgrep -f -- %s >/dev/null 2>&1; then
  /usr/bin/open %s >>"$LOG" 2>&1
  echo "Vhrome focused $(date)" >>"$LOG"
else
  /usr/bin/open -na %s --args %s >>"$LOG" 2>&1
  echo "Vhrome opened $(date)" >>"$LOG"
fi`, logPath, shellWords(filepath.Join(appDir, "Contents", "MacOS", "Chromium")+" --user-data-dir="+inst.ProfileDir), shellWords(appDir), shellWords(appDir), strings.Join(quotedFlags, " "))
	script := fmt.Sprintf("do shell script %q", shellScript)
	if out, err := exec.Command("osacompile", "-o", inst.Launcher, "-e", script).CombinedOutput(); err != nil {
		return fmt.Errorf("create Vhrome app failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	resourcesDir := filepath.Join(inst.Launcher, "Contents", "Resources")
	_ = os.Remove(filepath.Join(resourcesDir, "Assets.car"))
	iconPath := filepath.Join(resourcesDir, "applet.icns")
	if err := writeVhromeICNS(iconPath); err != nil {
		return err
	}
	_ = exec.Command("xattr", "-cr", inst.Launcher).Run()
	_ = exec.Command("codesign", "--force", "--deep", "--sign", "-", inst.Launcher).Run()
	registerMacAppBundle(inst.Launcher)
	return nil
}

func writeVhromeICNS(path string) error {
	var pngBuf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
	for y := 0; y < 1024; y++ {
		for x := 0; x < 1024; x++ {
			bg := vhromeIconPixel(x, y)
			img.SetRGBA(x, y, bg)
		}
	}
	if err := png.Encode(&pngBuf, img); err != nil {
		return err
	}
	return writePNGICNS(path, pngBuf.Bytes())
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func vhromeIconPixel(x, y int) color.RGBA {
	return color.RGBA{A: 255}
}

func insideRoundedRect(x, y, left, top, width, height, radius int) bool {
	right := left + width
	bottom := top + height
	if x < left || x >= right || y < top || y >= bottom {
		return false
	}
	cx := x
	if x < left+radius {
		cx = left + radius
	} else if x >= right-radius {
		cx = right - radius - 1
	}
	cy := y
	if y < top+radius {
		cy = top + radius
	} else if y >= bottom-radius {
		cy = bottom - radius - 1
	}
	dx := x - cx
	dy := y - cy
	return dx*dx+dy*dy <= radius*radius
}

func writePNGICNS(path string, pngBytes []byte) error {
	totalLen := 8 + 8 + len(pngBytes)
	var icns bytes.Buffer
	icns.WriteString("icns")
	_ = binary.Write(&icns, binary.BigEndian, uint32(totalLen))
	icns.WriteString("ic10")
	_ = binary.Write(&icns, binary.BigEndian, uint32(8+len(pngBytes)))
	_, _ = icns.Write(pngBytes)
	if err := os.WriteFile(path, icns.Bytes(), 0o644); err != nil {
		return err
	}
	_ = os.Chmod(path, 0o644)
	return nil
}

func registerMacAppBundle(appPath string) {
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	_ = exec.Command(lsregister, "-f", appPath).Run()
	_ = exec.Command("mdimport", appPath).Run()
}

func cleanupOldVhromeLaunchers(active string) {
	if runtime.GOOS != "darwin" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, old := range []string{filepath.Join(home, "Applications", "Vhrome.app")} {
		if old != active {
			_ = os.RemoveAll(old)
		}
	}
}

func installVhromeLinuxLauncher(inst browserInstall) error {
	if err := os.MkdirAll(filepath.Dir(inst.Launcher), 0o700); err != nil {
		return err
	}
	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Vhrome
Comment=envd sealed browser
Exec=%s browser
Terminal=false
Categories=Network;WebBrowser;
`, currentEnvdExecutable())
	return os.WriteFile(inst.Launcher, []byte(desktop), 0o600)
}

func launchVhrome(executable string, flags []string) error {
	switch runtime.GOOS {
	case "darwin":
		appDir := executable
		for !strings.HasSuffix(appDir, ".app") && appDir != filepath.Dir(appDir) {
			appDir = filepath.Dir(appDir)
		}
		args := append([]string{"-na", appDir, "--args"}, flags...)
		return exec.Command("open", args...).Start()
	case "linux":
		return exec.Command(executable, flags...).Start()
	default:
		return fmt.Errorf("envd browser is not supported on %s", runtime.GOOS)
	}
}

func vhromeIsRunning(profileDir string) bool {
	if strings.TrimSpace(profileDir) == "" {
		return false
	}
	return exec.Command("pgrep", "-f", "--", "--user-data-dir="+profileDir).Run() == nil
}

func activateVhrome(executable string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	appDir := executable
	for !strings.HasSuffix(appDir, ".app") && appDir != filepath.Dir(appDir) {
		appDir = filepath.Dir(appDir)
	}
	return exec.Command("open", appDir).Start()
}

func stopVhromeProcesses(profileDir string) error {
	if strings.TrimSpace(profileDir) == "" {
		return nil
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		killVhromePIDs(profileDir, "")
		time.Sleep(2 * time.Second)
		killVhromePIDs(profileDir, "-KILL")
	}
	return nil
}

func killVhromePIDs(profileDir, signal string) {
	out, err := exec.Command("pgrep", "-f", "--", "--user-data-dir="+profileDir).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		pidText := strings.TrimSpace(line)
		if pidText == "" || pidText == strconv.Itoa(os.Getpid()) {
			continue
		}
		args := []string{}
		if signal != "" {
			args = append(args, signal)
		}
		args = append(args, pidText)
		_ = exec.Command("kill", args...).Run()
	}
}

func (a app) printDoctorHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd doctor
  envd doctor --deep
  envd doctor why ENV
  envd doctor history
  envd doctor network

Checks:
  host Docker, embedded images, gateway runtime, proxy ports, and env repair

Deep:
  also runs real direct/gateway reachability probes

Other:
  why ENV     explain the last state change for an env
  history     show recent envd events
  network     test direct/gateway reachability, proxy handshakes, sealed HTTPS

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

func (a app) printVSCodeHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd vscode setup
  envd vscode ENV

Effect:
  applies minimal VS Code user settings
  keeps existing unrelated settings
  writes a .bak backup before changing settings
  installs Remote SSH when the code CLI is available
  opens ENV with a preseeded VS Code server

`)
}

func (a app) printIdleHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd idle status
  envd idle on
  envd idle off

Effect:
  on      enables cleanup during normal envd commands
  off     disables cleanup and removes old background scheduler
  status  shows whether idle cleanup is enabled

`)
}

func (a app) printHostingHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd hosting COMMAND [args]

Commands:
  check        test provider reachability from this machine
  global       show global provider candidates
  russian      show Russian-card/ruble-friendly provider candidates

Check:
  envd hosting check
  envd hosting check --verbose

Lists:
  envd hosting global
  envd hosting russian

`)
}

func (a app) printBrowserHelp() {
	fmt.Fprint(a.stdout, `Usage:
  envd browser
  envd browser install
  envd browser status
  envd browser update
  envd browser reset --yes

Vhrome is an envd-managed Chromium profile forced through the active gateway.
It protects browser traffic only; it is not a whole-machine VPN.
Reset asks for the current master password; cached unlock is not enough.
Search: GoogleEn is added as a search option, but Chromium protects the
default-search setting. Choose it manually in Vhrome settings if needed.

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

Profiles:
  envd pkg list
  envd pkg show PROFILE
  envd pkg rm PROFILE --yes

Add:
  envd pkg add PROFILE apt:PACKAGE
  envd pkg add PROFILE npm:PACKAGE
  envd pkg add PROFILE pip:PACKAGE
  envd pkg add PROFILE tool:NAME

Apply:
  envd start ENV --profile PROFILE

Remove asks for the current master password; cached unlock is not enough.

Common tools:
  tool:codex      installs Node/npm and @openai/codex
  tool:node       installs Node/npm
  tool:rg         installs ripgrep
  tool:go         installs Go
  tool:python     installs Python/pip/venv

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

Protected migration asks for the current master password; cached unlock is not enough.

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

func (a app) printEnvTable(st *envdState) error {
	envs, err := listEnvContainers(st)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Environments:")
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

func (a app) runDetails(args []string, st *envdState) error {
	if len(args) != 1 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, "Usage: envd details ENV\n")
		return nil
	}
	env, err := inspectEnv(st, args[0])
	if err != nil {
		return err
	}
	rows := []detailRow{
		{"Name", env.Name},
		{"State", env.Dev.State.Status},
		{"Network", env.networkMode()},
		{"Storage", env.storageMode(st)},
	}
	if env.networkMode() == "sealed" {
		rows = append(rows, detailRow{"VPN", env.netHealth()})
	}
	if ref, err := resolveEnvRef(st, args[0]); err == nil {
		rows = append(rows, sshConnectionDetailRows(ref)...)
	}
	if env.storageMode(st) == "protected" {
		if rec, ok := st.Environments[args[0]]; ok {
			rows = append(rows, detailRow{"Backend", rec.StorageBackend})
		}
	}
	rows = append(rows, detailRow{"Image", env.Dev.Config.Image})
	if env.BlockedReason != "" {
		rows = append(rows, detailRow{"Blocked", env.BlockedReason})
	}
	if rec, ok := st.Environments[args[0]]; ok && rec.Profile != "" {
		rows = append(rows, detailRow{"Profile", fmt.Sprintf("%s generation %d", rec.Profile, rec.ProfileGeneration)})
	}
	rows = append(rows, detailRow{"Egress", env.egressSummary()})
	if env.Legacy {
		rows = append(rows, detailRow{"Legacy", "true"})
	}
	if issue := env.issue(st.GatewayGeneration); issue != "" {
		rows = append(rows, detailRow{"Issue", issue})
	}
	printDetailRows(a.stdout, rows)
	return nil
}

func sshConnectionDetailRows(ref envRef) []detailRow {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	rows := []detailRow{
		{"SSH", "ssh " + ref.Name},
		{"SFTP", "sftp " + ref.Name},
	}
	_, _, envdConfig, knownHosts, keyPath, _, err := sshConfigPaths()
	if ref.NetName != "" {
		if port, portErr := dockerPublishedPort(ref.NetName, "22/tcp"); portErr == nil {
			rows = append(rows, detailRow{"Direct SFTP", fmt.Sprintf("%s@127.0.0.1:%d", userName, port)})
			if err == nil {
				rows = append(rows, detailRow{"SFTP command", fmt.Sprintf("sftp -o UserKnownHostsFile=%s -i %s -P %d %s@127.0.0.1", displayPath(knownHosts), displayPath(keyPath), port, userName)})
			}
		}
	}
	if err == nil {
		rows = append(rows,
			detailRow{"Key", displayPath(keyPath)},
			detailRow{"SSH config", displayPath(envdConfig)},
			detailRow{"Known hosts", displayPath(knownHosts)},
		)
	}
	return rows
}

func displayPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~/" + strings.TrimPrefix(path, prefix)
	}
	return path
}

type detailRow struct {
	Label string
	Value string
}

func printDetailRows(w io.Writer, rows []detailRow) {
	width := 0
	for _, row := range rows {
		width = maxInt(width, len(row.Label))
	}
	for _, row := range rows {
		fmt.Fprintf(w, "%-*s  %s\n", width+1, row.Label+":", row.Value)
	}
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
	ref := runtimeRefFromRoute(route)
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

func (a app) runVSCode(args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		a.printVSCodeHelp()
		return nil
	}
	if len(args) == 1 && args[0] == "setup" {
		return a.runVSCodeSetup()
	}
	if len(args) == 1 {
		return a.runVSCodeOpen(args[0])
	}
	return fmt.Errorf("usage: envd vscode setup|ENV")
}

func (a app) runVSCodeSetup() error {
	settingsPath, err := vscodeUserSettingsPath()
	if err != nil {
		return err
	}
	changed, backup, err := applyMinimalVSCodeSettings(settingsPath)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintln(a.stdout, "VS Code: minimal settings applied")
		if backup != "" {
			fmt.Fprintf(a.stdout, "Backup:  %s\n", backup)
		}
	} else {
		fmt.Fprintln(a.stdout, "VS Code: already minimal")
	}
	fmt.Fprintf(a.stdout, "Settings: %s\n", settingsPath)
	if err := installVSCodeRemoteSSH(); err != nil {
		fmt.Fprintf(a.stdout, "Remote SSH: skipped (%s)\n", redactSensitive(err.Error()))
	} else {
		fmt.Fprintln(a.stdout, "Remote SSH: installed")
	}
	return nil
}

func (a app) runVSCodeOpen(envName string) error {
	if err := validateEnvName(envName); err != nil {
		return err
	}
	ref, err := vscodeEnvRef(envName)
	if err != nil || dockerContainerStatus(ref.DevName) != "running" {
		if err := a.withState(func(st *envdState) error {
			if err := a.startEnv([]string{envName}, st); err != nil {
				return err
			}
			ref, err = resolveEnvRef(st, envName)
			return err
		}); err != nil {
			return err
		}
	}
	if dockerContainerStatus(ref.DevName) != "running" {
		return fmt.Errorf("environment %q is not running", envName)
	}
	if err := ensureEnvSSHConfig(envName, currentEnvdExecutable()); err != nil {
		return err
	}
	if err := preseedVSCodeServer(ref); err != nil {
		return err
	}
	if err := a.ensureVSCodeEnvRunning(envName, &ref); err != nil {
		return err
	}
	code, err := exec.LookPath("code")
	if err != nil {
		return fmt.Errorf("code CLI not found")
	}
	cmd := exec.Command(code, "--new-window", "--remote", "ssh-remote+"+envName, "/home/dev/repo")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("code remote launch failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	fmt.Fprintf(a.stdout, "VS Code: ssh %s\n", envName)
	return nil
}

func (a app) ensureVSCodeEnvRunning(envName string, ref *envRef) error {
	if dockerContainerStatus(ref.DevName) == "running" && (networkOrSealed(ref.Network) != "sealed" || sidecarReadyNow(ref.NetName)) {
		return nil
	}
	route := runtimeRouteFromRef(*ref, ref.Network)
	if err := startRuntimeRouteContainers(route); err == nil && dockerContainerStatus(ref.DevName) == "running" {
		return nil
	}
	return a.withState(func(st *envdState) error {
		if err := a.startEnv([]string{envName}, st); err != nil {
			return err
		}
		next, err := resolveEnvRef(st, envName)
		if err == nil {
			*ref = next
		}
		return err
	})
}

func vscodeEnvRef(envName string) (envRef, error) {
	route, err := runtimeRoute(envName)
	if err != nil {
		return envRef{}, err
	}
	return runtimeRefFromRoute(route), nil
}

func vscodeUserSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"), nil
	case "linux":
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return filepath.Join(configHome, "Code", "User", "settings.json"), nil
	default:
		return "", fmt.Errorf("envd vscode setup is not supported on %s", runtime.GOOS)
	}
}

func applyMinimalVSCodeSettings(path string) (bool, string, error) {
	settings := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(normalizeJSONC(raw), &settings); err != nil {
			return false, "", fmt.Errorf("cannot parse VS Code settings: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, "", err
	}
	changed := false
	for key, value := range minimalVSCodeSettings() {
		if !reflect.DeepEqual(settings[key], value) {
			settings[key] = value
			changed = true
		}
	}
	for _, key := range obsoleteMinimalVSCodeSettings() {
		if _, ok := settings[key]; ok {
			delete(settings, key)
			changed = true
		}
	}
	if !changed {
		return false, "", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, "", err
	}
	backup := ""
	if raw, err := os.ReadFile(path); err == nil {
		backup = path + ".bak"
		if _, statErr := os.Stat(backup); errors.Is(statErr, os.ErrNotExist) {
			if err := os.WriteFile(backup, raw, 0o600); err != nil {
				return false, "", err
			}
		}
	}
	raw, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, "", err
	}
	return true, backup, os.WriteFile(path, append(raw, '\n'), 0o600)
}

func normalizeJSONC(raw []byte) []byte {
	withoutComments := stripJSONComments(raw)
	return stripJSONTrailingCommas(withoutComments)
}

func stripJSONComments(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	inString := false
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			i += 2
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
			if i < len(raw) {
				out = append(out, raw[i])
			}
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i+1 < len(raw) && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}

func stripJSONTrailingCommas(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	inString := false
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func minimalVSCodeSettings() map[string]any {
	return map[string]any{
		"workbench.statusBar.visible":            false,
		"window.commandCenter":                   false,
		"workbench.layoutControl.enabled":        false,
		"workbench.startupEditor":                "none",
		"workbench.activityBar.location":         "top",
		"terminal.integrated.initialHint":        false,
		"editor.minimap.enabled":                 false,
		"editor.stickyScroll.enabled":            false,
		"workbench.editor.showTabs":              "none",
		"workbench.editor.editorActionsLocation": "hidden",
		"window.title":                           " ",
		"window.titleSeparator":                  " ",
		"breadcrumbs.enabled":                    false,
		"chat.disableAIFeatures":                 true,
		"extensions.ignoreRecommendations":       true,
		"security.workspace.trust.enabled":       false,
		"workbench.colorTheme":                   "Dark Modern",
		"update.mode":                            "manual",
		"git.openRepositoryInParentFolders":      "never",
	}
}

func obsoleteMinimalVSCodeSettings() []string {
	return []string{
		"task.allowAutomaticTasks",
	}
}

func installVSCodeRemoteSSH() error {
	code, err := exec.LookPath("code")
	if err != nil {
		return fmt.Errorf("code CLI not found")
	}
	cmd := exec.Command(code, "--install-extension", "ms-vscode-remote.remote-ssh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func preseedVSCodeServer(ref envRef) error {
	commit, artifact, err := vscodeServerArtifact()
	if err != nil {
		return err
	}
	serverArtifact := strings.TrimPrefix(strings.ReplaceAll(artifact, "cli-alpine", "server-linux"), "cli-")
	user := ref.UserName
	if user == "" {
		user = "dev"
	}
	remoteDir := filepath.Join("/home", user, ".vscode-server")
	remoteCode := filepath.Join(remoteDir, "code-"+commit)
	serverName := "Stable-" + commit
	serverTopDir := "vscode-" + serverArtifact
	serverRoot := filepath.Join(remoteDir, "cli", "servers")
	serverTarget := filepath.Join(serverRoot, serverName)
	serverInstall := filepath.Join(serverTarget, "server")
	serverStaging := filepath.Join(serverRoot, serverName+".staging")
	if vscodeServerReady(ref.DevName, remoteCode, filepath.Join(serverInstall, "bin", "code-server")) {
		return nil
	}
	cliArchivePath, err := ensureVSCodeArchive(commit, artifact, artifact+".tar.gz")
	if err != nil {
		return err
	}
	serverArchivePath, err := ensureVSCodeArchive(commit, serverArtifact, serverArtifact+".tar.gz")
	if err != nil {
		return err
	}
	if err := dockerRun("exec", "-u", "root", ref.DevName, "sh", "-lc",
		"mkdir -p "+shellQuote(remoteDir)+" && chown "+shellQuote(user+":"+user)+" "+shellQuote(remoteDir)); err != nil {
		return err
	}
	remoteCLIArchive := "/tmp/envd-vscode-cli-" + commit + ".tar.gz"
	if err := dockerRun("cp", cliArchivePath, ref.DevName+":"+remoteCLIArchive); err != nil {
		return err
	}
	remoteServerArchive := "/tmp/envd-vscode-server-" + commit + ".tar.gz"
	if err := dockerRun("cp", serverArchivePath, ref.DevName+":"+remoteServerArchive); err != nil {
		return err
	}
	script := strings.Join([]string{
		"set -eu",
		"if [ ! -x " + shellQuote(remoteCode) + " ]; then",
		"  rm -f " + shellQuote(remoteCode),
		"  tar -xzf " + shellQuote(remoteCLIArchive) + " -C " + shellQuote(remoteDir) + " code",
		"  mv " + shellQuote(filepath.Join(remoteDir, "code")) + " " + shellQuote(remoteCode),
		"  chmod 755 " + shellQuote(remoteCode),
		"  chown " + shellQuote(user+":"+user) + " " + shellQuote(remoteCode),
		"fi",
		"mkdir -p " + shellQuote(serverRoot),
		"if [ ! -x " + shellQuote(filepath.Join(serverInstall, "bin", "code-server")) + " ]; then",
		"  rm -rf " + shellQuote(serverTarget) + " " + shellQuote(serverStaging),
		"  mkdir -p " + shellQuote(serverStaging),
		"  tar -xzf " + shellQuote(remoteServerArchive) + " -C " + shellQuote(serverStaging),
		"  if [ -d " + shellQuote(filepath.Join(serverStaging, serverTopDir)) + " ]; then",
		"    mkdir -p " + shellQuote(serverTarget),
		"    mv " + shellQuote(filepath.Join(serverStaging, serverTopDir)) + " " + shellQuote(serverInstall),
		"    rmdir " + shellQuote(serverStaging) + " 2>/dev/null || true",
		"  else",
		"    mkdir -p " + shellQuote(serverTarget),
		"    mv " + shellQuote(serverStaging) + " " + shellQuote(serverInstall),
		"  fi",
		"  chown -R " + shellQuote(user+":"+user) + " " + shellQuote(serverTarget),
		"fi",
		"rm -f " + shellQuote(remoteCLIArchive),
		"rm -f " + shellQuote(remoteServerArchive),
	}, "\n")
	if err := dockerRun("exec", "-u", "root", ref.DevName, "sh", "-lc", script); err != nil {
		return err
	}
	return nil
}

func vscodeServerReady(container, cliDone, codeServer string) bool {
	err := dockerRun("exec", container, "sh", "-lc",
		"test -f "+shellQuote(cliDone)+" && test -x "+shellQuote(codeServer))
	return err == nil
}

func vscodeServerArtifact() (commit string, artifact string, err error) {
	code, err := exec.LookPath("code")
	if err != nil {
		return "", "", fmt.Errorf("code CLI not found")
	}
	out, err := exec.Command(code, "--version").Output()
	if err != nil {
		return "", "", fmt.Errorf("code --version failed: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[1]) == "" {
		return "", "", fmt.Errorf("cannot determine VS Code commit")
	}
	commit = strings.TrimSpace(lines[1])
	switch runtime.GOARCH {
	case "arm64":
		artifact = "cli-alpine-arm64"
	case "amd64":
		artifact = "cli-alpine-x64"
	default:
		return "", "", fmt.Errorf("unsupported VS Code remote architecture %s", runtime.GOARCH)
	}
	return commit, artifact, nil
}

func ensureVSCodeArchive(commit, artifact, filename string) (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "vscode", commit, filename)
	if fileExists(path) {
		if validTarGz(path) {
			return path, nil
		}
		_ = os.Rename(path, path+".tmp")
	}
	label := "Downloading VS Code archive"
	if strings.HasPrefix(artifact, "server-linux-") {
		label = "Downloading VS Code server"
		fmt.Fprintf(os.Stderr, "%s: %s (cached after first use)\n", label, artifact)
	}
	rawURL := fmt.Sprintf("https://update.code.visualstudio.com/commit:%s/%s/stable", commit, artifact)
	if err := downloadFileWithProgress(path, rawURL, label); err != nil {
		return "", err
	}
	if !validTarGz(path) {
		_ = os.Remove(path)
		return "", fmt.Errorf("downloaded VS Code archive is invalid: %s", artifact)
	}
	return path, nil
}

func validTarGz(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		_, err := tr.Next()
		if err == nil {
			continue
		}
		return errors.Is(err, io.EOF)
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
		if err := verifySealedEnvStartup(devName); err != nil {
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
	ref := envRef{Name: name, ID: id, UserName: "dev", DevName: devName, NetName: netName, ProjectDockerName: projectDockerContainerName(id), Network: network, HomeVol: homeVol, RepoVol: repoVol, HomeSource: homeSource, RepoSource: repoSource, Storage: storage, Image: image}
	if err := repairCreatedEnvAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	if err := a.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
		st.addEvent("identity", name, "identity agent refresh failed: "+redactSensitive(err.Error()))
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
	opts, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	name := opts.Name
	if name == "" {
		return fmt.Errorf("usage: envd start ENV [--network sealed|direct|offline] [--storage plain|protected] [--profile PROFILE]")
	}
	if _, ok := st.Environments[name]; ok {
		if opts.ProfileExplicit {
			if opts.NetworkExplicit || opts.StorageExplicit {
				return fmt.Errorf("environment %q already exists; only --profile can be changed with start", name)
			}
			return a.applyProfileToEnv(st, name, opts.Profile)
		}
		if len(args) != 1 {
			return fmt.Errorf("environment %q already exists; usage: envd start %s [--profile PROFILE]", name, name)
		}
		return a.startEnv(args, st)
	}
	return a.runEnv(args, st)
}

func (a app) tryRuntimeStart(name string) (bool, error) {
	if err := validateEnvName(name); err != nil {
		return true, err
	}
	route, err := runtimeRoute(name)
	if err != nil {
		return false, nil
	}
	if route.Storage == "protected" {
		return false, nil
	}
	if route.Network == "offline" {
		if containerExists(route.DevName) {
			if dockerContainerStatus(route.DevName) != "running" {
				if err := dockerRun("start", route.DevName); err != nil {
					return true, err
				}
			}
			fmt.Fprintf(a.stdout, "Started: %s\n", name)
			fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
			return true, nil
		}
		return false, nil
	}
	if !containerExists(route.DevName) {
		return false, nil
	}
	if devContainerNeedsMountRepair(route.DevName) {
		return false, nil
	}
	if route.Network == "sealed" {
		if !containerExists(runtimeRefFromRoute(route).NetName) {
			return false, nil
		}
	}
	if err := startRuntimeRouteContainers(route); err != nil {
		return true, err
	}
	if dockerContainerStatus(route.DevName) != "running" {
		return false, nil
	}
	ref := runtimeRefFromRoute(route)
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return true, err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return true, err
	}
	if err := publishRuntimeRoute(ref, route.Network); err != nil {
		return true, err
	}
	fmt.Fprintf(a.stdout, "Started: %s\n", name)
	fmt.Fprintf(a.stdout, "SSH:     ssh %s\n", name)
	return true, nil
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
				if _, _, err := ensureSidecarReady(name, ref.ID, ref.NetName); err != nil {
					return err
				}
			}
			if err := a.createDevContainer(name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, networkMode, image); err != nil {
				return err
			}
			if networkMode == "sealed" {
				if err := verifySealedEnvStartup(ref.DevName); err != nil {
					return err
				}
			}
			touchEnvUsed(st, name, time.Now().UTC())
			if err := repairCreatedEnvAccessForRef(ref); err != nil {
				return err
			}
			if err := setVSCodeExtensionsLocked(ref, true); err != nil {
				return err
			}
			if err := a.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
				st.addEvent("identity", name, "identity agent refresh failed: "+redactSensitive(err.Error()))
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
		recreated, reason, err := a.ensureSealedRuntimeReady(st, name, ref)
		if err != nil {
			return err
		}
		if recreated {
			fmt.Fprintf(a.stdout, "Recreated sealed runtime: %s\n", reason)
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
	} else if devContainerNeedsMountRepair(ref.DevName) {
		if err := a.recreateDevContainerForHostIntegrations(st, name, ref, networkMode); err != nil {
			return err
		}
	}
	for _, cmd := range devStartCommandsForMode(networkMode, ref.DevName) {
		if err := dockerRun(cmd...); err != nil {
			return err
		}
	}
	touchEnvUsed(st, name, time.Now().UTC())
	if err := repairCreatedEnvAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	if err := a.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
		st.addEvent("identity", name, "identity agent refresh failed: "+redactSensitive(err.Error()))
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

func (a app) recreateDevContainerForHostIntegrations(st *envdState, name string, ref envRef, networkMode string) error {
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
	st.addEvent("env", name, "recreated dev container to attach host integrations")
	return nil
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
	if err := verifySealedEnvStartup(ref.DevName); err != nil {
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

func (a app) ensureSealedRuntimeReady(st *envdState, name string, ref envRef) (bool, string, error) {
	recreate, reason, err := sealedRuntimeRecreateStatus(ref)
	if err != nil {
		return false, "", err
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
			return false, "", err
		}
		touchEnvUsed(st, name, time.Now().UTC())
		if err := repairEnvSSHAccessForRef(ref); err != nil {
			return false, "", err
		}
		if err := setVSCodeExtensionsLocked(ref, true); err != nil {
			return false, "", err
		}
		if err := a.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
			st.addEvent("identity", name, "identity agent refresh failed: "+redactSensitive(err.Error()))
		}
		st.addEvent("env", name, "recreated sealed runtime before start: "+reason)
		return true, reason, nil
	}
	if _, _, err := ensureSidecarReady(name, ref.ID, ref.NetName); err != nil {
		reason := "sidecar readiness failed: " + redactSensitive(err.Error())
		if err := a.recreateSealedRuntime(st, name, ref, reason); err != nil {
			return false, "", err
		}
		st.addEvent("env", name, "recreated sealed runtime before start: "+reason)
		return true, reason, nil
	}
	return false, "", nil
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
		if err := verifySealedEnvStartup(ref.DevName); err != nil {
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
	if err := repairCreatedEnvAccessForRef(ref); err != nil {
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
	case "list":
		return a.runPkgList(args[1:], st)
	case "show":
		return a.runPkgShow(args[1:], st)
	case "add":
		return a.runPkgAdd(args[1:], st)
	case "rm":
		return a.runPkgRemove(args[1:], st)
	default:
		return fmt.Errorf("unknown pkg subcommand %q", args[0])
	}
}

func (a app) runPkgList(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd pkg list")
	}
	names := sortedProfileNames(st)
	if len(names) == 0 {
		fmt.Fprintln(a.stdout, "No package profiles.")
		return nil
	}
	widths := []int{7, 3, 10, 5}
	rows := make([]profileRecord, 0, len(names))
	for _, name := range names {
		profile := st.Profiles[name]
		rows = append(rows, profile)
		widths[0] = maxInt(widths[0], len(name))
		widths[1] = maxInt(widths[1], len(strconv.Itoa(len(profile.Packages))))
		widths[2] = maxInt(widths[2], len(profilePackageSummary(profile.Packages)))
		widths[3] = maxInt(widths[3], len(profile.Image))
	}
	format := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%-%ds  %%s\n", widths[0], widths[1], widths[2], widths[3])
	fmt.Fprintf(a.stdout, format, "PROFILE", "PKG", "PACKAGES", "GEN", "IMAGE")
	for _, profile := range rows {
		image := "-"
		if profile.Image != "" {
			image = profile.Image
		}
		fmt.Fprintf(a.stdout, format, profile.Name, strconv.Itoa(len(profile.Packages)), profilePackageSummary(profile.Packages), strconv.Itoa(profile.Generation), image)
	}
	return nil
}

func (a app) runPkgShow(args []string, st *envdState) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd pkg show PROFILE")
	}
	name := args[0]
	if err := validateProfileName(name); err != nil {
		return err
	}
	profile, ok := st.Profiles[name]
	if !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	fmt.Fprintf(a.stdout, "Profile:    %s\n", profile.Name)
	fmt.Fprintf(a.stdout, "Generation: %d\n", profile.Generation)
	if profile.Image != "" {
		fmt.Fprintf(a.stdout, "Image:      %s\n", profile.Image)
	}
	if len(profile.Packages) == 0 {
		fmt.Fprintln(a.stdout, "Packages:   none")
		return nil
	}
	fmt.Fprintln(a.stdout, "Packages:")
	for _, pkg := range sortedProfilePackages(profile.Packages) {
		fmt.Fprintf(a.stdout, "  %s:%s\n", pkg.Source, pkg.Name)
	}
	return nil
}

func (a app) runPkgAdd(args []string, st *envdState) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd pkg add PROFILE apt:PACKAGE|npm:PACKAGE|pip:PACKAGE|tool:NAME")
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

func (a app) runPkgRemove(args []string, st *envdState) error {
	if len(args) != 2 || args[1] != "--yes" {
		return fmt.Errorf("usage: envd pkg rm PROFILE --yes")
	}
	name := args[0]
	if err := validateProfileName(name); err != nil {
		return err
	}
	profile, ok := st.Profiles[name]
	if !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	var users []string
	for envName, rec := range st.Environments {
		if rec.Profile == name {
			users = append(users, envName)
		}
	}
	sort.Strings(users)
	if len(users) > 0 {
		return fmt.Errorf("profile %q is used by env: %s", name, strings.Join(users, ", "))
	}
	delete(st.Profiles, name)
	st.addEvent("profile", name, "removed package profile")
	_ = dockerRun("rmi", profileImageName(profile.ID, profile.Generation))
	if profile.Image != "" {
		_ = dockerRun("rmi", profile.Image)
	}
	_ = pruneProfileImages(st)
	fmt.Fprintf(a.stdout, "Removed profile: %s\n", name)
	return nil
}

func (a app) applyProfileToEnv(st *envdState, envName, profileName string) error {
	if err := validateEnvName(envName); err != nil {
		return err
	}
	if err := validateProfileName(profileName); err != nil {
		return err
	}
	ref, err := resolveEnvRef(st, envName)
	if err != nil {
		return err
	}
	rec, ok := st.Environments[envName]
	if !ok {
		return fmt.Errorf("environment %q not found", envName)
	}
	if rec.BlockedReason != "" {
		return fmt.Errorf("environment %q is blocked fail-closed: %s", envName, rec.BlockedReason)
	}
	image, generation, err := a.ensureProfileImage(st, profileName)
	if err != nil {
		return err
	}
	if rec.Profile == profileName && rec.ProfileGeneration == generation && rec.Image == image && containerExists(ref.DevName) {
		fmt.Fprintf(a.stdout, "Profile already active: %s generation %d on %s\n", profileName, generation, envName)
		return nil
	}
	networkMode := networkOrSealed(rec.Network)
	if ref.Storage == "protected" {
		if err := restoreProtectedVolumes(ref); err != nil {
			return err
		}
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
		if _, _, err := ensureSidecarReady(envName, ref.ID, ref.NetName); err != nil {
			return err
		}
	}
	_ = dockerRun("stop", ref.DevName)
	_ = dockerRun("rm", "-f", ref.DevName)
	if err := a.createDevContainer(envName, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, networkMode, image); err != nil {
		return err
	}
	if networkMode == "sealed" {
		if err := verifySealedEnvStartup(ref.DevName); err != nil {
			return err
		}
	}
	rec.Image = image
	rec.Profile = profileName
	rec.ProfileGeneration = generation
	rec.BlockedReason = ""
	rec.UpdatedAt = time.Now().UTC()
	rec.LastUsedAt = rec.UpdatedAt
	st.Environments[envName] = rec
	if err := repairCreatedEnvAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	st.addEvent("env", envName, fmt.Sprintf("applied profile %s generation %d", profileName, generation))
	fmt.Fprintf(a.stdout, "Profile applied: %s -> %s generation %d\n", envName, profileName, generation)
	fmt.Fprintf(a.stdout, "SSH:             ssh %s\n", envName)
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

func sortedProfileNames(st *envdState) []string {
	names := make([]string, 0, len(st.Profiles))
	for name := range st.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedProfilePackages(pkgs []profilePackage) []profilePackage {
	out := append([]profilePackage(nil), pkgs...)
	sort.Slice(out, func(i, j int) bool {
		left := out[i].Source + ":" + out[i].Name
		right := out[j].Source + ":" + out[j].Name
		return left < right
	})
	return out
}

func profilePackageSummary(pkgs []profilePackage) string {
	if len(pkgs) == 0 {
		return "-"
	}
	counts := map[string]int{}
	for _, pkg := range pkgs {
		counts[pkg.Source]++
	}
	var sources []string
	for source := range counts {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	parts := make([]string, 0, len(sources))
	for _, source := range sources {
		parts = append(parts, source+":"+strconv.Itoa(counts[source]))
	}
	return strings.Join(parts, ",")
}

func (a app) ensureProfileImage(st *envdState, profileName string) (string, int, error) {
	if err := validateProfileName(profileName); err != nil {
		return "", 0, err
	}
	profile, ok := st.Profiles[profileName]
	if !ok {
		return "", 0, fmt.Errorf("profile %q not found; add packages first with: envd pkg add %s apt:PACKAGE|npm:PACKAGE|pip:PACKAGE|tool:NAME", profileName, profileName)
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
	return waitForSidecarReady(netName, 20*time.Second)
}

func ensureSidecarReady(envName, id, netName string) (bool, string, error) {
	recreate, reason, err := sidecarRecreateReason(netName)
	if err != nil {
		return false, "", err
	}
	if recreate {
		_ = dockerRun("rm", "-f", netName)
		if err := createSidecar(envName, id, netName); err != nil {
			return false, "", err
		}
		return true, reason, nil
	}
	if err := dockerRun("start", netName); err != nil {
		reason := "sidecar start failed: " + redactSensitive(err.Error())
		_ = dockerRun("rm", "-f", netName)
		if err := createSidecar(envName, id, netName); err != nil {
			return false, "", err
		}
		return true, reason, nil
	}
	if err := waitForSidecarReady(netName, 20*time.Second); err != nil {
		reason := "sidecar readiness failed: " + redactSensitive(err.Error())
		_ = dockerRun("rm", "-f", netName)
		if err := createSidecar(envName, id, netName); err != nil {
			return false, "", err
		}
		return true, reason, nil
	}
	return false, "", nil
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
	return ensureEnvContainerAccess(ref)
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
	return !containerHasMountDestination(name, "/var/run/docker.sock")
}

func devContainerNeedsMountRepair(name string) bool {
	return devContainerNeedsHostDockerSocketRepair(name)
}

func containerHasMountDestination(name, destination string) bool {
	out, err := exec.Command("docker", "inspect", "--format", "{{range .Mounts}}{{println .Destination}}{{end}}", name).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == destination {
			return true
		}
	}
	return false
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
	_ = stopIdentityAgentProcess(name)
	_ = removeIdentityAgentSocket(name)
	_ = unpublishRuntimeRoute(name)
	_ = syncEnvSSHConfig(st)
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
	if inst, err := browserInstallPaths(); err == nil {
		_ = stopVhromeProcesses(inst.ProfileDir)
	}
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
	Name           string    `json:"name"`
	ID             string    `json:"id"`
	DevName        string    `json:"dev_name"`
	NetName        string    `json:"net_name,omitempty"`
	UserName       string    `json:"user_name"`
	Network        string    `json:"network"`
	Storage        string    `json:"storage,omitempty"`
	HomeSource     string    `json:"home_source,omitempty"`
	RepoSource     string    `json:"repo_source,omitempty"`
	Image          string    `json:"image,omitempty"`
	HasSSHIdentity bool      `json:"has_ssh_identity,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type runtimeIdleActivity struct {
	UpdatedAt time.Time                     `json:"updated_at"`
	Envs      map[string]runtimeEnvActivity `json:"envs,omitempty"`
}

type runtimeEnvActivity struct {
	LastActiveAt time.Time `json:"last_active_at"`
}

type runtimeSessionLease struct {
	ID         string    `json:"id"`
	Env        string    `json:"env"`
	Kind       string    `json:"kind"`
	PID        int       `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
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

func runtimeActivityPath() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "activity.json"), nil
}

func loadRuntimeActivity() (runtimeIdleActivity, error) {
	path, err := runtimeActivityPath()
	if err != nil {
		return runtimeIdleActivity{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeIdleActivity{Envs: map[string]runtimeEnvActivity{}}, nil
	}
	if err != nil {
		return runtimeIdleActivity{}, err
	}
	var activity runtimeIdleActivity
	if err := json.Unmarshal(raw, &activity); err != nil {
		return runtimeIdleActivity{}, err
	}
	if activity.Envs == nil {
		activity.Envs = map[string]runtimeEnvActivity{}
	}
	return activity, nil
}

func saveRuntimeActivity(activity runtimeIdleActivity) error {
	path, err := runtimeActivityPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	activity.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(activity, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func touchRuntimeActivity(envName string, at time.Time) error {
	activity, err := loadRuntimeActivity()
	if err != nil {
		return err
	}
	if activity.Envs == nil {
		activity.Envs = map[string]runtimeEnvActivity{}
	}
	activity.Envs[envName] = runtimeEnvActivity{LastActiveAt: at.UTC()}
	return saveRuntimeActivity(activity)
}

func runtimeSessionsDir() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "sessions"), nil
}

func runtimeSessionPath(envName, id string) (string, error) {
	dir, err := runtimeSessionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, envName, id+".json"), nil
}

func newRuntimeSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

func startRuntimeSession(envName, kind string) (func(), error) {
	now := time.Now().UTC()
	id := newRuntimeSessionID()
	path, err := runtimeSessionPath(envName, id)
	if err != nil {
		return func() {}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return func() {}, err
	}
	lease := runtimeSessionLease{ID: id, Env: envName, Kind: kind, PID: os.Getpid(), StartedAt: now, LastSeenAt: now}
	if err := writeRuntimeSessionLease(path, lease); err != nil {
		return func() {}, err
	}
	_ = touchRuntimeActivity(envName, now)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				lease.LastSeenAt = time.Now().UTC()
				_ = writeRuntimeSessionLease(path, lease)
				_ = touchRuntimeActivity(envName, lease.LastSeenAt)
			}
		}
	}()
	return func() {
		close(done)
		_ = os.Remove(path)
		_ = touchRuntimeActivity(envName, time.Now().UTC())
	}, nil
}

func writeRuntimeSessionLease(path string, lease runtimeSessionLease) error {
	raw, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func activeRuntimeSessionEnvs(now time.Time) (map[string]bool, error) {
	dir, err := runtimeSessionsDir()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, envEntry := range entries {
		if !envEntry.IsDir() {
			continue
		}
		envDir := filepath.Join(dir, envEntry.Name())
		files, err := os.ReadDir(envDir)
		if err != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			path := filepath.Join(envDir, file.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var lease runtimeSessionLease
			if err := json.Unmarshal(raw, &lease); err != nil {
				_ = os.Remove(path)
				continue
			}
			if now.Sub(lease.LastSeenAt) <= idleLeaseStale && processLikelyAlive(lease.PID) {
				out[lease.Env] = true
				continue
			}
			if now.Sub(lease.LastSeenAt) > idleLeaseStale {
				_ = os.Remove(path)
			}
		}
	}
	return out, nil
}

func processLikelyAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func runRuntimeIdleTick(idle time.Duration) error {
	if !idleSchedulerEnabled() {
		return nil
	}
	stopped, err := runtimeIdleTick(idle, time.Now().UTC(), dockerRouteIsRunning, stopRuntimeRouteWorkload)
	if err != nil {
		return err
	}
	if stopped > 0 {
		fmt.Fprintf(os.Stdout, "Idle: stopped %d envs\n", stopped)
	}
	return nil
}

func runOpportunisticIdleSweep() error {
	if strings.HasSuffix(os.Args[0], ".test") || !idleSchedulerEnabled() {
		return nil
	}
	_, err := opportunisticIdleSweep(time.Now().UTC(), dockerRouteIsRunning, stopRuntimeRouteWorkload)
	return err
}

func opportunisticIdleSweep(now time.Time, running func(runtimeSSHRoute) bool, stop func(runtimeSSHRoute) error) (int, error) {
	if !idleSchedulerEnabled() {
		return 0, nil
	}
	return runtimeIdleTick(defaultIdleTimeout, now, running, stop)
}

func runtimeIdleTick(idle time.Duration, now time.Time, running func(runtimeSSHRoute) bool, stop func(runtimeSSHRoute) error) (int, error) {
	if idle < minIdleTimeout {
		return 0, fmt.Errorf("idle timeout must be at least %s", minIdleTimeout)
	}
	access, err := loadRuntimeAccess()
	if err != nil {
		return 0, err
	}
	if access.Locked || len(access.Routes) == 0 {
		return 0, nil
	}
	active, err := activeRuntimeSessionEnvs(now)
	if err != nil {
		return 0, err
	}
	activity, err := loadRuntimeActivity()
	if err != nil {
		return 0, err
	}
	stopped := 0
	var failures []string
	names := make([]string, 0, len(access.Routes))
	for name := range access.Routes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		route := access.Routes[name]
		if active[name] {
			continue
		}
		last := activity.Envs[name].LastActiveAt
		if last.IsZero() {
			last = route.UpdatedAt
		}
		if last.IsZero() || now.Sub(last) < idle {
			continue
		}
		if !running(route) {
			continue
		}
		time.Sleep(idleStopGrace)
		activeAgain, err := activeRuntimeSessionEnvs(time.Now().UTC())
		if err != nil {
			failures = append(failures, name+": "+err.Error())
			continue
		}
		if activeAgain[name] {
			continue
		}
		if err := stop(route); err != nil {
			failures = append(failures, name+": "+err.Error())
			continue
		}
		stopped++
		_ = touchRuntimeActivity(name, time.Now().UTC())
	}
	if len(failures) > 0 {
		return stopped, fmt.Errorf("idle tick had %d failures: %s", len(failures), strings.Join(failures, "; "))
	}
	return stopped, nil
}

func dockerRouteIsRunning(route runtimeSSHRoute) bool {
	return dockerContainerStatus(route.DevName) == "running"
}

func stopRuntimeRouteWorkload(route runtimeSSHRoute) error {
	ref := runtimeRefFromRoute(route)
	return stopEnvWorkload(ref)
}

func disableLegacyRuntimeIdleSchedulerBestEffort() {
	if strings.HasSuffix(os.Args[0], ".test") {
		return
	}
	dir, err := envdDataDir()
	if err != nil {
		return
	}
	marker := filepath.Join(dir, "runtime", "idle-background-disabled")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if err := disableRuntimeIdleScheduler(); err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(marker), 0o700)
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func ensureRuntimeIdleScheduler() error {
	if strings.HasSuffix(os.Args[0], ".test") || os.Getenv("ENVD_DISABLE_IDLE_SCHEDULER") == "1" {
		return nil
	}
	if !idleSchedulerEnabled() {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return ensureLaunchdIdleScheduler()
	case "linux":
		return ensureSystemdIdleScheduler()
	default:
		return nil
	}
}

func (a app) runIdle(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd idle status|on|off")
	}
	switch args[0] {
	case "status":
		fmt.Fprintf(a.stdout, "Idle: %s\n", idleStatusText())
		return nil
	case "on":
		if err := setIdleSchedulerEnabled(true); err != nil {
			return err
		}
		_ = disableRuntimeIdleScheduler()
		fmt.Fprintf(a.stdout, "Idle: %s\n", idleStatusText())
		return nil
	case "off":
		if err := setIdleSchedulerEnabled(false); err != nil {
			return err
		}
		if err := disableRuntimeIdleScheduler(); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "Idle: off")
		return nil
	default:
		return fmt.Errorf("usage: envd idle status|on|off")
	}
}

func idleStatusText() string {
	if idleSchedulerEnabled() {
		return "on, opportunistic after " + defaultIdleTimeout.String() + " disconnected"
	}
	return "off"
}

func idleSchedulerEnabled() bool {
	path, err := idlePreferencePath()
	if err != nil {
		return true
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(raw)) != "off"
}

func setIdleSchedulerEnabled(enabled bool) error {
	path, err := idlePreferencePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	value := "off\n"
	if enabled {
		value = "on\n"
	}
	return os.WriteFile(path, []byte(value), 0o600)
}

func idlePreferencePath() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "idle"), nil
}

func disableRuntimeIdleScheduler() error {
	switch runtime.GOOS {
	case "darwin":
		return disableLaunchdIdleScheduler()
	case "linux":
		return disableSystemdIdleScheduler()
	default:
		return nil
	}
}

func ensureLaunchdIdleScheduler() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dataDir, err := envdDataDir()
	if err != nil {
		return err
	}
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return err
	}
	label := "dev.envd.idle"
	plist := filepath.Join(agentDir, label+".plist")
	envdPath := currentEnvdExecutable()
	logPath := filepath.Join(dataDir, "runtime", "idle.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return err
	}
	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>__idle-tick</string>
  </array>
  <key>StartInterval</key><integer>600</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, label, envdPath, logPath, logPath)
	changed, err := writeFileIfChanged(plist, []byte(content), 0o600)
	if err != nil {
		return err
	}
	if !changed && launchdServiceLoaded(label) {
		return nil
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.Command("launchctl", "bootstrap", domain, plist).Run()
	_ = exec.Command("launchctl", "enable", domain+"/"+label).Run()
	return nil
}

func ensureSystemdIdleScheduler() error {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHome = filepath.Join(home, ".config")
	}
	unitDir := filepath.Join(configHome, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		return err
	}
	envdPath := currentEnvdExecutable()
	servicePath := filepath.Join(unitDir, "envd-idle.service")
	timerPath := filepath.Join(unitDir, "envd-idle.timer")
	service := fmt.Sprintf(`[Unit]
Description=envd idle cleanup

[Service]
Type=oneshot
ExecStart=%s __idle-tick
`, envdPath)
	timer := `[Unit]
Description=Run envd idle cleanup

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min
AccuracySec=1min
Unit=envd-idle.service

[Install]
WantedBy=timers.target
`
	serviceChanged, err := writeFileIfChanged(servicePath, []byte(service), 0o600)
	if err != nil {
		return err
	}
	timerChanged, err := writeFileIfChanged(timerPath, []byte(timer), 0o600)
	if err != nil {
		return err
	}
	if serviceChanged || timerChanged {
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		_ = exec.Command("systemctl", "--user", "enable", "--now", "envd-idle.timer").Run()
	}
	return nil
}

func writeFileIfChanged(path string, content []byte, mode fs.FileMode) (bool, error) {
	if raw, err := os.ReadFile(path); err == nil && bytes.Equal(raw, content) {
		return false, nil
	}
	return true, os.WriteFile(path, content, mode)
}

func launchdServiceLoaded(label string) bool {
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	return exec.Command("launchctl", "print", domain+"/"+label).Run() == nil
}

func disableLaunchdIdleScheduler() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	label := "dev.envd.idle"
	plist := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	_ = exec.Command("launchctl", "disable", domain+"/"+label).Run()
	if err := os.Remove(plist); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func disableSystemdIdleScheduler() error {
	_ = exec.Command("systemctl", "--user", "disable", "--now", "envd-idle.timer").Run()
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHome = filepath.Join(home, ".config")
	}
	unitDir := filepath.Join(configHome, "systemd", "user")
	for _, name := range []string{"envd-idle.service", "envd-idle.timer"} {
		if err := os.Remove(filepath.Join(unitDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

func lockRuntimeAccess() error {
	_ = stopAllIdentityAgentProcesses()
	_ = removeIdentityAgentSockets()
	return saveRuntimeAccess(runtimeAccessState{Locked: true, Routes: map[string]runtimeSSHRoute{}})
}

func removeIdentityAgentSocket(envName string) error {
	socketPath, err := identityAgentSocketPath(envName)
	if err != nil {
		return err
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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

func stopIdentityAgentProcess(envName string) error {
	if err := validateEnvName(envName); err != nil {
		return err
	}
	pattern := "__identity-agent " + envName + " "
	return stopProcessesMatching(pattern)
}

func stopAllIdentityAgentProcesses() error {
	return stopProcessesMatching("__identity-agent ")
}

func stopProcessesMatching(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return nil
	}
	cmd := exec.Command("pkill", "-f", pattern)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil
		}
		return err
	}
	return nil
}

func pruneIdentityAgentsForState(st *envdState) {
	keep := map[string]bool{}
	for _, name := range sortedEnvNames(st) {
		keep[name] = true
	}
	pruneIdentityAgentSockets(keep)
	pruneIdentityAgentProcesses(keep)
}

func pruneIdentityAgentSockets(keep map[string]bool) {
	dir, err := identityAgentDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sock") {
			continue
		}
		envName := strings.TrimSuffix(entry.Name(), ".sock")
		if !keep[envName] {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

func pruneIdentityAgentProcesses(keep map[string]bool) {
	out, err := exec.Command("pgrep", "-fl", "__identity-agent ").Output()
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		for i, field := range fields {
			if field != "__identity-agent" || i+1 >= len(fields) {
				continue
			}
			envName := fields[i+1]
			if !keep[envName] && validateEnvName(envName) == nil {
				_ = stopIdentityAgentProcess(envName)
			}
			break
		}
	}
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
	netName := ref.NetName
	if netName == "" && ref.ID != "" && networkOrSealed(network) == "sealed" {
		netName = netContainerName(ref.ID)
	}
	homeSource := ref.HomeSource
	if homeSource == "" && ref.ID != "" {
		homeSource = homeVolumeName(ref.ID)
	}
	repoSource := ref.RepoSource
	if repoSource == "" && ref.ID != "" {
		repoSource = repoVolumeName(ref.ID)
	}
	image := imageOrDefault(ref.Image)
	if image == devImage {
		if current := containerConfigImage(ref.DevName); current != "" {
			image = current
		}
	}
	hasSSHIdentity := false
	if existing, ok := access.Routes[ref.Name]; ok {
		hasSSHIdentity = existing.HasSSHIdentity
	}
	access.Locked = false
	access.Routes[ref.Name] = runtimeSSHRoute{
		Name:           ref.Name,
		ID:             ref.ID,
		DevName:        ref.DevName,
		NetName:        netName,
		UserName:       userName,
		Network:        networkOrSealed(network),
		Storage:        storageOrPlain(ref.Storage),
		HomeSource:     homeSource,
		RepoSource:     repoSource,
		Image:          image,
		HasSSHIdentity: hasSSHIdentity,
		UpdatedAt:      time.Now().UTC(),
	}
	_ = touchRuntimeActivity(ref.Name, time.Now().UTC())
	if err := saveRuntimeAccess(access); err != nil {
		return err
	}
	_ = runOpportunisticIdleSweep()
	return nil
}

func updateRuntimeRouteSSHIdentity(envName string, hasSSHIdentity bool) error {
	access, err := loadRuntimeAccess()
	if err != nil {
		return err
	}
	route, ok := access.Routes[envName]
	if !ok {
		return nil
	}
	if route.HasSSHIdentity == hasSSHIdentity {
		return nil
	}
	route.HasSSHIdentity = hasSSHIdentity
	route.UpdatedAt = time.Now().UTC()
	access.Routes[envName] = route
	return saveRuntimeAccess(access)
}

func runtimeRefFromRoute(route runtimeSSHRoute) envRef {
	userName := route.UserName
	if userName == "" {
		userName = "dev"
	}
	netName := route.NetName
	if netName == "" && route.ID != "" && networkOrSealed(route.Network) == "sealed" {
		netName = netContainerName(route.ID)
	}
	homeSource := route.HomeSource
	if homeSource == "" && route.ID != "" {
		homeSource = homeVolumeName(route.ID)
	}
	repoSource := route.RepoSource
	if repoSource == "" && route.ID != "" {
		repoSource = repoVolumeName(route.ID)
	}
	return envRef{
		Name:       route.Name,
		ID:         route.ID,
		UserName:   userName,
		DevName:    route.DevName,
		NetName:    netName,
		Network:    networkOrSealed(route.Network),
		HomeSource: homeSource,
		RepoSource: repoSource,
		Storage:    storageOrPlain(route.Storage),
		Image:      imageOrDefault(route.Image),
	}
}

func runtimeRouteFromRef(ref envRef, network string) runtimeSSHRoute {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	return runtimeSSHRoute{
		Name:       ref.Name,
		ID:         ref.ID,
		DevName:    ref.DevName,
		NetName:    ref.NetName,
		UserName:   userName,
		Network:    networkOrSealed(network),
		Storage:    storageOrPlain(ref.Storage),
		HomeSource: ref.HomeSource,
		RepoSource: ref.RepoSource,
		Image:      imageOrDefault(ref.Image),
		UpdatedAt:  time.Now().UTC(),
	}
}

func containerConfigImage(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	item, err := inspectContainer(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(item.Config.Image)
}

func unpublishRuntimeRoute(name string) error {
	access, err := loadRuntimeAccess()
	if err != nil {
		return err
	}
	if access.Routes == nil {
		return nil
	}
	delete(access.Routes, name)
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
	envName := ""
	if err := a.withState(func(st *envdState) error {
		if len(args) > 0 {
			name := args[0]
			envName = name
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
				if err := repairEnvSSHAccessForRef(ref); err != nil {
					return err
				}
				touchEnvUsed(st, name, time.Now().UTC())
			}
		}
		var err error
		dockerArgs, err = prepareShellDockerArgs(args, st)
		return err
	}); err != nil {
		return err
	}
	stopSession, err := startRuntimeSession(envName, "shell")
	if err != nil {
		return err
	}
	defer stopSession()
	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	return cmd.Run()
}

type copyEndpoint struct {
	Raw    string
	Env    string
	Path   string
	Remote bool
}

func (a app) runCopy(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd cp LOCAL ENV:PATH or envd cp ENV:PATH LOCAL")
	}
	src, err := parseCopyEndpoint(args[0])
	if err != nil {
		return err
	}
	dst, err := parseCopyEndpoint(args[1])
	if err != nil {
		return err
	}
	if src.Remote == dst.Remote {
		if src.Remote {
			return fmt.Errorf("env-to-env copy is not supported yet")
		}
		return fmt.Errorf("one side must be ENV:PATH")
	}
	remote := src
	if !src.Remote {
		remote = dst
	}
	route, err := a.ensureCopyEnvRunning(remote.Env)
	if err != nil {
		return err
	}
	containerPath := envCopyContainerPath(remote.Path)
	if src.Remote {
		return copyFromEnv(route.DevName, containerPath, dst.Path)
	}
	return copyToEnv(route.DevName, src.Path, containerPath)
}

func parseCopyEndpoint(raw string) (copyEndpoint, error) {
	if env, remotePath, ok := splitCopyRemote(raw); ok {
		if err := validateEnvName(env); err != nil {
			return copyEndpoint{}, err
		}
		if strings.TrimSpace(remotePath) == "" {
			remotePath = "."
		}
		return copyEndpoint{Raw: raw, Env: env, Path: remotePath, Remote: true}, nil
	}
	return copyEndpoint{Raw: raw, Path: raw}, nil
}

func splitCopyRemote(raw string) (string, string, bool) {
	idx := strings.Index(raw, ":")
	if idx <= 0 {
		return "", "", false
	}
	left := raw[:idx]
	if strings.Contains(left, "/") || strings.Contains(left, "\\") {
		return "", "", false
	}
	if runtime.GOOS == "windows" && len(left) == 1 {
		return "", "", false
	}
	if validateEnvName(left) != nil {
		return "", "", false
	}
	return left, raw[idx+1:], true
}

func envCopyContainerPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "." || p == "~" {
		return "/home/dev"
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.ToSlash(filepath.Join("/home/dev", strings.TrimPrefix(p, "~/")))
	}
	if strings.HasPrefix(p, "/") {
		return filepath.Clean(p)
	}
	return filepath.ToSlash(filepath.Join("/home/dev/repo", p))
}

func (a app) ensureCopyEnvRunning(name string) (runtimeSSHRoute, error) {
	route, err := runtimeRoute(name)
	if err != nil {
		return runtimeSSHRoute{}, err
	}
	if dockerContainerStatus(route.DevName) == "running" && (networkOrSealed(route.Network) != "sealed" || sidecarReadyNow(runtimeRefFromRoute(route).NetName)) {
		return route, nil
	}
	if err := startRuntimeRouteContainers(route); err == nil && dockerContainerStatus(route.DevName) == "running" {
		return route, nil
	}
	quiet := app{stdout: io.Discard, stderr: a.stderr, root: a.root}
	if err := quiet.withState(func(st *envdState) error {
		return quiet.startEnv([]string{name}, st)
	}); err != nil {
		return runtimeSSHRoute{}, err
	}
	route, err = runtimeRoute(name)
	if err != nil {
		return runtimeSSHRoute{}, err
	}
	if dockerContainerStatus(route.DevName) != "running" {
		return runtimeSSHRoute{}, fmt.Errorf("environment %q is not running", name)
	}
	return route, nil
}

func copyToEnv(container, localPath, remotePath string) error {
	if strings.TrimSpace(localPath) == "" {
		return fmt.Errorf("local source path is empty")
	}
	if _, err := os.Stat(localPath); err != nil {
		return fmt.Errorf("local source %q: %w", localPath, err)
	}
	if err := ensureContainerDirForCopy(container, remotePath); err != nil {
		return err
	}
	if err := dockerRun("cp", localPath, container+":"+remotePath); err != nil {
		return err
	}
	return chownContainerPath(container, remotePath)
}

func copyFromEnv(container, remotePath, localPath string) error {
	if strings.TrimSpace(localPath) == "" {
		return fmt.Errorf("local destination path is empty")
	}
	if err := ensureLocalParentForCopy(localPath); err != nil {
		return err
	}
	return dockerRun("cp", container+":"+remotePath, localPath)
}

func ensureContainerDirForCopy(container, remotePath string) error {
	dir := remotePath
	if !strings.HasSuffix(remotePath, "/") {
		dir = path.Dir(remotePath)
	}
	if dir == "." || dir == "/" {
		return nil
	}
	return dockerRun("exec", "-u", "root", container, "mkdir", "-p", dir)
}

func chownContainerPath(container, remotePath string) error {
	return dockerRun("exec", "-u", "root", container, "sh", "-lc", "chown -R dev:dev "+shellQuote(remotePath)+" 2>/dev/null || true")
}

func ensureLocalParentForCopy(localPath string) error {
	if localPath == "." {
		return nil
	}
	if strings.HasSuffix(localPath, string(os.PathSeparator)) {
		return os.MkdirAll(localPath, 0o755)
	}
	parent := filepath.Dir(localPath)
	if parent == "." || parent == "" {
		return nil
	}
	return os.MkdirAll(parent, 0o755)
}

func envNeedsStart(ref envRef, networkMode string) bool {
	if dockerContainerStatus(ref.DevName) != "running" {
		return true
	}
	if networkMode == "sealed" && dockerContainerStatus(ref.NetName) != "running" {
		return true
	}
	if devContainerNeedsMountRepair(ref.DevName) {
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
	gitHTTPSIdentity, err := singleGitHTTPSIdentityForShell(st, name)
	if err != nil {
		return nil, err
	}
	if gitHTTPSIdentity != nil {
		dockerArgs = append(dockerArgs,
			"-e", "ENVD_GIT_HTTPS_USERNAME="+gitHTTPSIdentity.Username,
			"-e", "ENVD_GIT_HTTPS_PASSWORD_B64="+base64.StdEncoding.EncodeToString([]byte(gitHTTPSIdentity.Password)),
		)
		command = shellCommandWithEphemeralGitHTTPSHelper(command)
	}
	dockerArgs = append(dockerArgs, "-u", ref.UserName, "-w", "/home/"+ref.UserName+"/repo", ref.DevName)
	dockerArgs = append(dockerArgs, command...)
	return dockerArgs, nil
}

func singleSSHIdentityForShell(st *envdState, envName string) (*identityRecord, error) {
	return singleSSHIdentityForEnv(st, envName, shellIdentityBrokerHealth(st, envName))
}

func singleSSHIdentityForEnv(st *envdState, envName string, health identityBrokerHealth) (*identityRecord, error) {
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
		decision := evaluateIdentityBrokerGrant(st, envName, identityName, "ssh", health)
		if !decision.Allow {
			return nil, fmt.Errorf("identity %q denied for %s: %s", identityName, envName, decision.Reason)
		}
		copy := rec
		out = &copy
	}
	return out, nil
}

var shellIdentityBrokerHealth = runtimeIdentityBrokerHealth

func singleGitHTTPSIdentityForShell(st *envdState, envName string) (*identityRecord, error) {
	var out *identityRecord
	names := make([]string, 0, len(st.Identities))
	for name := range st.Identities {
		names = append(names, name)
	}
	sortStrings(names)
	for _, identityName := range names {
		rec := st.Identities[identityName]
		if rec.Type != "git-https" || strings.TrimSpace(rec.Username) == "" || strings.TrimSpace(rec.Password) == "" {
			continue
		}
		if out != nil {
			return nil, nil
		}
		decision := evaluateIdentityBrokerGrant(st, envName, identityName, "git-https", shellIdentityBrokerHealth(st, envName))
		if !decision.Allow {
			return nil, fmt.Errorf("identity %q denied for %s: %s", identityName, envName, decision.Reason)
		}
		copy := rec
		out = &copy
	}
	return out, nil
}

func (a app) startUnlockedIdentityAgents(st *envdState) (int, error) {
	pruneIdentityAgentsForState(st)
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
		ref, err := resolveEnvRef(st, envName)
		if err != nil || dockerContainerStatus(ref.DevName) != "running" {
			continue
		}
		if err := startStaticIdentityAgent(envName, *identity); err != nil {
			failures = append(failures, envName+": "+redactSensitive(err.Error()))
			continue
		}
		if err := startEnvContainerIdentityAgent(ref, *identity); err != nil {
			failures = append(failures, envName+": container identity agent: "+redactSensitive(err.Error()))
			continue
		}
		started++
	}
	if len(failures) > 0 {
		return started, fmt.Errorf("identity agent start failed: %s", strings.Join(failures, "; "))
	}
	return started, nil
}

func (a app) refreshUnlockedIdentityAgents(st *envdState) {
	if _, err := a.startUnlockedIdentityAgents(st); err != nil {
		st.addEvent("identity", "", "identity agent refresh failed: "+redactSensitive(err.Error()))
	}
}

func (a app) repairRunningIdentityAgents(st *envdState) {
	for _, name := range sortedEnvNames(st) {
		ref, err := resolveEnvRef(st, name)
		if err != nil || dockerContainerStatus(ref.DevName) != "running" {
			continue
		}
		if envContainerIdentityAgentReady(ref) {
			continue
		}
		if err := a.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
			st.addEvent("identity", name, "identity agent repair failed: "+redactSensitive(err.Error()))
		}
	}
}

func (a app) refreshStartedEnvIdentityAgent(st *envdState, envName string, ref envRef) error {
	identity, err := singleSSHIdentityForEnv(st, envName, func() error {
		if networkOrSealed(ref.Network) == "sealed" {
			return waitForSidecarReady(ref.NetName, 10*time.Second)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if identity == nil {
		_ = updateRuntimeRouteSSHIdentity(envName, false)
		return nil
	}
	if err := startStaticIdentityAgent(envName, *identity); err != nil {
		return err
	}
	if dockerContainerStatus(ref.DevName) == "running" {
		if err := startEnvContainerIdentityAgent(ref, *identity); err != nil {
			return err
		}
	}
	_ = updateRuntimeRouteSSHIdentity(envName, true)
	return nil
}

func envContainerIdentityAgentReady(ref envRef) bool {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	if dockerContainerStatus(ref.DevName) != "running" {
		return false
	}
	check := `SSH_AUTH_SOCK="${HOME}/.envd/ssh-agent.sock" ssh-add -l >/dev/null`
	return dockerRun("exec", "-u", userName, ref.DevName, "sh", "-lc", check) == nil
}

func cachedOrEnvMasterPasswordAvailable() bool {
	if _, ok := cachedMasterPassword(); ok {
		return true
	}
	return os.Getenv("ENVD_MASTER_PASSWORD") != ""
}

func startStaticIdentityAgent(envName string, identity identityRecord) error {
	socketPath, err := identityAgentSocketPath(envName)
	if err != nil {
		return err
	}
	if unixSocketAccepts(socketPath) {
		return nil
	}
	_ = stopIdentityAgentProcess(envName)
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

func startEnvContainerIdentityAgent(ref envRef, identity identityRecord) error {
	userName := ref.UserName
	if userName == "" {
		userName = "dev"
	}
	if strings.TrimSpace(identity.PrivateKey) == "" {
		return fmt.Errorf("identity key is empty")
	}
	script := `
set -eu
home_dir="/home/${DEV_USER}"
agent_dir="${home_dir}/.envd"
sock="${agent_dir}/ssh-agent.sock"
mkdir -p "${agent_dir}"
chmod 700 "${agent_dir}"

if [ -S "${sock}" ] && SSH_AUTH_SOCK="${sock}" ssh-add -l >/dev/null 2>&1; then
  exit 0
fi

if [ -f "${agent_dir}/ssh-agent.env" ]; then
  set +u
  . "${agent_dir}/ssh-agent.env" >/dev/null 2>&1 || true
  if [ -n "${SSH_AGENT_PID:-}" ]; then
    kill "${SSH_AGENT_PID}" >/dev/null 2>&1 || true
  fi
  set -u
fi

rm -f "${sock}" "${agent_dir}/ssh-agent.env"
ssh-agent -a "${sock}" -s > "${agent_dir}/ssh-agent.env"
. "${agent_dir}/ssh-agent.env" >/dev/null
tmp_key="${agent_dir}/identity-key.$$"
trap 'rm -f "${tmp_key}"' EXIT INT TERM
printf '%s' "${ENVD_IDENTITY_KEY_B64}" | base64 -d > "${tmp_key}"
chmod 600 "${tmp_key}"
ssh-add "${tmp_key}" >/dev/null
rm -f "${tmp_key}"
chmod 600 "${agent_dir}/ssh-agent.env"
`
	if err := dockerRun("exec",
		"-u", userName,
		"-e", "DEV_USER="+userName,
		"-e", "ENVD_IDENTITY_KEY_B64="+base64.StdEncoding.EncodeToString([]byte(identity.PrivateKey)),
		ref.DevName, "sh", "-lc", script); err != nil {
		return err
	}
	return waitForEnvContainerIdentityAgent(ref, userName, 3*time.Second)
}

func waitForEnvContainerIdentityAgent(ref envRef, userName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	check := `SSH_AUTH_SOCK="${HOME}/.envd/ssh-agent.sock" ssh-add -l >/dev/null`
	for time.Now().Before(deadline) {
		if dockerRun("exec", "-u", userName, ref.DevName, "sh", "-lc", check) == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("container identity agent did not become ready")
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

func shellCommandWithEphemeralGitHTTPSHelper(command []string) []string {
	quoted := make([]string, 0, len(command))
	for _, part := range command {
		quoted = append(quoted, shellQuote(part))
	}
	helper := `!f() {
  case "${1:-get}" in
    get|fill|"") ;;
    *) exit 0 ;;
  esac
  while IFS= read -r line; do
    [ -z "$line" ] && break
  done
  printf 'username=%s\npassword=%s\n\n' "$ENVD_GIT_HTTPS_USERNAME" "$(printf '%s' "$ENVD_GIT_HTTPS_PASSWORD_B64" | base64 -d)"
}; f`
	script := `
set -eu
if command -v git >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
  export GIT_TERMINAL_PROMPT=0
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0=credential.helper
  export GIT_CONFIG_VALUE_0=` + shellQuote(helper) + `
fi
exec ` + strings.Join(quoted, " ")
	return []string{"sh", "-lc", script}
}

func (a app) runSSHProxy(args []string) error {
	_ = runOpportunisticIdleSweep()
	envName := ""
	if len(args) == 1 {
		envName = args[0]
	}
	if err := a.ensureSSHProxyEnvRunning(args); err != nil {
		return err
	}
	dockerArgs, err := prepareSSHProxyDockerArgs(args)
	if err != nil {
		return err
	}
	stopSession, err := startRuntimeSession(envName, "ssh")
	if err != nil {
		return err
	}
	defer stopSession()
	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	err = cmd.Run()
	_ = runOpportunisticIdleSweep()
	return err
}

func (a app) ensureSSHProxyEnvRunning(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: envd ssh-proxy ENV")
	}
	name := args[0]
	route, err := runtimeRoute(name)
	if err != nil {
		return err
	}
	if route.Network == "offline" {
		return fmt.Errorf("environment %q is offline; SSH proxy denied", name)
	}
	if dockerContainerStatus(route.DevName) == "running" && (networkOrSealed(route.Network) != "sealed" || sidecarReadyNow(runtimeRefFromRoute(route).NetName)) {
		return a.ensureSSHProxyIdentityAgent(name, route)
	}
	if err := startRuntimeRouteContainers(route); err == nil && dockerContainerStatus(route.DevName) == "running" {
		return a.ensureSSHProxyIdentityAgent(name, route)
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) && !cachedOrEnvMasterPasswordAvailable() {
		return fmt.Errorf("environment %q needs repair; run envd unlock, then retry SSH", name)
	}
	quiet := app{stdout: io.Discard, stderr: a.stderr, root: a.root}
	return quiet.withState(func(st *envdState) error {
		return quiet.startEnv([]string{name}, st)
	})
}

func (a app) ensureSSHProxyIdentityAgent(name string, route runtimeSSHRoute) error {
	ref := runtimeRefFromRoute(route)
	if envContainerIdentityAgentReady(ref) {
		return nil
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) && !cachedOrEnvMasterPasswordAvailable() {
		if route.HasSSHIdentity {
			return fmt.Errorf("identity agent for %q is not ready; run `envd unlock`, then reconnect", name)
		}
		return nil
	}
	quiet := app{stdout: io.Discard, stderr: a.stderr, root: a.root}
	if err := quiet.withStateReadOnly(func(st *envdState) error {
		st.ensureDefaults()
		if err := quiet.refreshStartedEnvIdentityAgent(st, name, ref); err != nil {
			return fmt.Errorf("repair identity agent for %q: %w", name, err)
		}
		return nil
	}); err != nil {
		if route.HasSSHIdentity {
			return err
		}
		return nil
	}
	return nil
}

func startRuntimeRouteContainers(route runtimeSSHRoute) error {
	route.Network = networkOrSealed(route.Network)
	route.Storage = storageOrPlain(route.Storage)
	if dockerContainerStatus(route.DevName) == "running" && (route.Network != "sealed" || sidecarReadyNow(runtimeRefFromRoute(route).NetName)) {
		return nil
	}
	if route.Storage == "plain" && route.ID != "" && route.DevName != "" {
		return repairRuntimeRouteContainers(route)
	}
	if containerExists(route.DevName) && dockerContainerStatus(route.DevName) != "running" {
		if err := dockerRun("start", route.DevName); err != nil {
			return err
		}
	}
	return nil
}

func repairRuntimeRouteContainers(route runtimeSSHRoute) error {
	ref := runtimeRefFromRoute(route)
	if ref.Storage != "plain" {
		return fmt.Errorf("runtime repair requires decrypted state for %s storage", ref.Storage)
	}
	if ref.DevName == "" || ref.ID == "" {
		return fmt.Errorf("runtime route is incomplete")
	}
	if ref.Image == devImage {
		if current := containerConfigImage(ref.DevName); current != "" {
			ref.Image = current
		}
	}
	if ref.HomeSource == "" || ref.RepoSource == "" {
		return fmt.Errorf("runtime route is missing volume metadata")
	}
	if err := dockerRun("volume", "create", ref.HomeSource); err != nil {
		return err
	}
	if err := dockerRun("volume", "create", ref.RepoSource); err != nil {
		return err
	}
	a := app{stdout: io.Discard, stderr: os.Stderr}
	switch ref.Network {
	case "sealed":
		if err := ensureDockerNetwork(gatewayNet); err != nil {
			return err
		}
		if !sidecarReadyNow(ref.NetName) || !containerExists(ref.DevName) {
			_ = dockerRun("rm", "-f", ref.DevName)
			_ = dockerRun("rm", "-f", ref.NetName)
			if err := createSidecar(ref.Name, ref.ID, ref.NetName); err != nil {
				return err
			}
			if err := a.createDevContainer(ref.Name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, ref.Network, ref.Image); err != nil {
				return err
			}
			if err := verifySealedEnvStartup(ref.DevName); err != nil {
				return err
			}
		} else if dockerContainerStatus(ref.DevName) != "running" {
			if err := dockerRun("start", ref.DevName); err != nil {
				return err
			}
		}
	case "direct", "offline":
		if !containerExists(ref.DevName) {
			if err := a.createDevContainer(ref.Name, ref.UserName, ref.ID, ref.DevName, ref.NetName, ref.Storage, ref.HomeSource, ref.RepoSource, ref.Network, ref.Image); err != nil {
				return err
			}
		} else if dockerContainerStatus(ref.DevName) != "running" {
			if err := dockerRun("start", ref.DevName); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown network mode %q", ref.Network)
	}
	if dockerContainerStatus(ref.DevName) != "running" {
		return fmt.Errorf("environment %q did not become running", ref.Name)
	}
	if err := repairEnvSSHAccessForRef(ref); err != nil {
		return err
	}
	if err := setVSCodeExtensionsLocked(ref, true); err != nil {
		return err
	}
	return publishRuntimeRoute(ref, ref.Network)
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
	ref := runtimeRefFromRoute(route)
	if err := ensureEnvContainerAccess(ref); err != nil {
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
  PubkeyAuthentication unbound
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
	dir, err := identityAgentDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, envName+".sock"), nil
}

func identityAgentDir() (string, error) {
	dir, err := envdDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "runtime", "identity-agents"), nil
}

func ensureIdentityAgentDir() error {
	dir, err := identityAgentDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o700)
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
		if err := verifySealedEnvStartup(ref.DevName); err != nil {
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
	if err := repairCreatedEnvAccessForRef(ref); err != nil {
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

func (a app) runGatewayRemove(args []string, st *envdState) error {
	if len(args) != 2 || args[1] != "--yes" {
		return fmt.Errorf("usage: envd gateway rm NAME --yes")
	}
	if st == nil {
		return fmt.Errorf("gateway remove requires encrypted envd state")
	}
	name := args[0]
	if err := validateGatewayName(name); err != nil {
		return err
	}
	st.ensureDefaults()
	if st.ActiveGateway == name {
		return fmt.Errorf("cannot remove active gateway %q; switch first with: envd gateway use NAME", name)
	}
	if _, ok := st.Gateways[name]; !ok {
		if _, ok := st.RemoteGateways[name]; !ok {
			if _, ok := st.GatewayChains[name]; !ok {
				return fmt.Errorf("gateway %q not found", name)
			}
		}
	}
	for chainName, chain := range st.GatewayChains {
		if chainName == name {
			continue
		}
		if chain.Entry == name || chain.Exit == name {
			return fmt.Errorf("cannot remove gateway %q; chain %q still uses it", name, chainName)
		}
	}
	delete(st.Gateways, name)
	delete(st.RemoteGateways, name)
	delete(st.GatewayShares, name)
	delete(st.GatewayChains, name)
	if st.PreviousGateway == name {
		st.PreviousGateway = ""
	}
	st.addEvent("gateway", name, "removed local gateway metadata")
	fmt.Fprintf(a.stdout, "Removed gateway: %s\n", name)
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
			actions = append(actions, "run envd hosting global and prepare a replacement provider")
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

func (a app) runGatewayView(args []string, st *envdState) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: envd gateway view NAME SHARE")
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

func (a app) runNetworkReport(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd doctor network history")
	}
	if len(st.InternetChecks) == 0 {
		fmt.Fprintln(a.stdout, "No network checks recorded yet. Run envd doctor network.")
		return nil
	}
	for _, check := range st.InternetChecks {
		printNetworkCheck(a.stdout, check)
	}
	return nil
}

func (a app) networkCheck(st *envdState) internetCheckRecord {
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

func printNetworkCheck(w io.Writer, check internetCheckRecord) {
	fmt.Fprintf(w, "Checked: %s ok=%d fail=%d skip=%d total=%d\n", check.Time.Format(time.RFC3339), check.Summary.OK, check.Summary.Fail, check.Summary.Skip, check.Summary.Total)
	width := 0
	for _, r := range check.Results {
		width = maxInt(width, len(r.Name))
	}
	for _, r := range check.Results {
		fmt.Fprintf(w, "%-*s  %-4s  %s\n", width, r.Name, strings.ToUpper(r.Status), r.Detail)
	}
}

func networkCheckProbeResults(check internetCheckRecord) []probeResult {
	results := make([]probeResult, 0, len(check.Results))
	for _, r := range check.Results {
		switch r.Status {
		case "ok":
			results = append(results, probeResult{Name: r.Name, Detail: r.Detail})
		case "skip":
			results = append(results, probeResult{Name: r.Name, Detail: "skipped: " + r.Detail})
		default:
			results = append(results, probeResult{Name: r.Name, Err: fmt.Errorf("%s", r.Detail)})
		}
	}
	return results
}

func recordNetworkCheck(st *envdState, check internetCheckRecord) {
	st.ensureDefaults()
	st.InternetChecks = append(st.InternetChecks, check)
	if len(st.InternetChecks) > 50 {
		st.InternetChecks = append([]internetCheckRecord{}, st.InternetChecks[len(st.InternetChecks)-50:]...)
	}
	st.addEvent("network", "", fmt.Sprintf("status ok=%d fail=%d skip=%d", check.Summary.OK, check.Summary.Fail, check.Summary.Skip))
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

var fetchURLFunc = fetchURL

func probeDirectURL(name, path, target string, timeout time.Duration) internetProbeRecord {
	status, body, err := fetchURLFunc(nil, target, timeout)
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
	status, body, err := fetchURLFunc(proxyURL, target, timeout)
	if err != nil {
		return internetProbeRecord{Name: name, Path: path, Status: "fail", Detail: redactSensitive(err.Error())}
	}
	return internetProbeRecord{Name: name, Path: path, Status: "ok", Detail: httpStatusDetail(status, body)}
}

type webQuorumTarget struct {
	Label string
	URL   string
}

type webQuorumTargetResult struct {
	Label   string
	Status  int
	Elapsed time.Duration
	Retried bool
	Err     error
}

var defaultWebQuorumTargets = []webQuorumTarget{
	{Label: "google", URL: "https://www.google.com/generate_204"},
	{Label: "cloudflare", URL: "https://www.cloudflare.com/cdn-cgi/trace"},
	{Label: "github", URL: "https://github.com/"},
	{Label: "npm", URL: "https://registry.npmjs.org/"},
}

func probeWebQuorum(name, path string, proxy *url.URL, fastTimeout, slowTimeout time.Duration) internetProbeRecord {
	results := probeWebQuorumTargets(proxy, defaultWebQuorumTargets, fastTimeout, slowTimeout)
	ok := 0
	parts := make([]string, 0, len(results))
	for _, result := range results {
		if result.Err == nil {
			ok++
			slow := ""
			if result.Retried {
				slow = " slow"
			}
			parts = append(parts, fmt.Sprintf("%s HTTP %d %s%s", result.Label, result.Status, formatProbeDuration(result.Elapsed), slow))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s fail %s", result.Label, formatProbeDuration(result.Elapsed)))
	}
	detail := fmt.Sprintf("%d/%d %s", ok, len(results), strings.Join(parts, ", "))
	status := "ok"
	if ok < minInt(3, len(results)) {
		status = "fail"
	}
	return internetProbeRecord{Name: name, Path: path, Status: status, Detail: detail}
}

func probeWebQuorumTargets(proxy *url.URL, targets []webQuorumTarget, fastTimeout, slowTimeout time.Duration) []webQuorumTargetResult {
	type indexedResult struct {
		Index  int
		Result webQuorumTargetResult
	}
	ch := make(chan indexedResult, len(targets))
	for i, target := range targets {
		go func(index int, target webQuorumTarget) {
			ch <- indexedResult{Index: index, Result: probeWebQuorumTarget(proxy, target, fastTimeout, slowTimeout)}
		}(i, target)
	}
	results := make([]webQuorumTargetResult, len(targets))
	for range targets {
		got := <-ch
		results[got.Index] = got.Result
	}
	return results
}

func probeWebQuorumTarget(proxy *url.URL, target webQuorumTarget, fastTimeout, slowTimeout time.Duration) webQuorumTargetResult {
	started := time.Now()
	status, _, err := fetchURLFunc(proxy, target.URL, fastTimeout)
	if err == nil {
		return webQuorumTargetResult{Label: target.Label, Status: status, Elapsed: time.Since(started)}
	}
	status, _, retryErr := fetchURLFunc(proxy, target.URL, slowTimeout)
	if retryErr == nil {
		return webQuorumTargetResult{Label: target.Label, Status: status, Elapsed: time.Since(started), Retried: true}
	}
	return webQuorumTargetResult{Label: target.Label, Elapsed: time.Since(started), Retried: true, Err: retryErr}
}

func probeHTTPWebQuorum(proxy *url.URL, timeout time.Duration) error {
	return probeFastQuorum(defaultWebQuorumTargets, minInt(3, len(defaultWebQuorumTargets)), timeout, func(target webQuorumTarget) error {
		_, _, err := fetchURLFunc(proxy, target.URL, timeout)
		return err
	})
}

func probeSOCKSWebQuorum(socks string, timeout time.Duration) error {
	return probeFastQuorum(defaultWebQuorumTargets, minInt(3, len(defaultWebQuorumTargets)), timeout, func(target webQuorumTarget) error {
		hostPort, err := webQuorumTargetHostPort(target)
		if err != nil {
			return err
		}
		return probeSOCKS("Gateway SOCKS HTTPS", socks, hostPort, timeout).Err
	})
}

func probeFastQuorum(targets []webQuorumTarget, quorum int, timeout time.Duration, probe func(webQuorumTarget) error) error {
	if len(targets) == 0 || quorum <= 0 {
		return fmt.Errorf("web quorum has no targets")
	}
	type result struct {
		label string
		err   error
	}
	ch := make(chan result, len(targets))
	for _, target := range targets {
		go func(target webQuorumTarget) {
			ch <- result{label: target.Label, err: probe(target)}
		}(target)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ok := 0
	fail := 0
	failures := []string{}
	for received := 0; received < len(targets); received++ {
		select {
		case got := <-ch:
			if got.err == nil {
				ok++
				if ok >= quorum {
					return nil
				}
			} else {
				fail++
				failures = append(failures, got.label)
				if len(targets)-fail < quorum {
					return fmt.Errorf("web quorum failed: %d/%d reachable; failed: %s", ok, len(targets), strings.Join(failures, ", "))
				}
			}
		case <-timer.C:
			return fmt.Errorf("web quorum timeout: %d/%d reachable after %s", ok, len(targets), formatProbeDuration(timeout))
		}
	}
	return fmt.Errorf("web quorum failed: %d/%d reachable", ok, len(targets))
}

func webQuorumTargetHostPort(target webQuorumTarget) (string, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("target host missing")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), nil
}

func fetchURL(proxy *url.URL, target string, timeout time.Duration) (int, string, error) {
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
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
	case "global":
		return a.runHostingShortlist(args[1:], st)
	case "russian":
		return a.runHostingRussian(args[1:], st)
	default:
		return fmt.Errorf("unknown hosting subcommand %q", args[0])
	}
}

func (a app) runHostingCheck(args []string, st *envdState) error {
	verbose := false
	for _, arg := range args {
		switch arg {
		case "--verbose":
			verbose = true
		default:
			return fmt.Errorf("usage: envd hosting check [--verbose]")
		}
	}
	catalog, err := a.loadHostingCatalog()
	if err != nil {
		return err
	}
	russian, err := parseRussianPaymentHostingProvidersTSV(builtInRussianPaymentProvidersTSV)
	if err != nil {
		return err
	}
	catalog = mergeHostingCatalogs(catalog, russian)
	fmt.Fprintf(a.stdout, "Checking: %d providers, parallel=%d, timeout=%s\n", len(catalog.Providers), hostingCheckConcurrency, hostingCheckTimeout)
	checks := checkHostingProviders(catalog.Providers)
	recordHostingChecks(st, checks)
	printHostingCheck(a.stdout, checks, verbose)
	if !verbose {
		freshChecks := hostingChecksByProvider(checks)
		global, err := a.loadHostingCatalog()
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "\nGlobal:")
		printHostingList(a.stdout, global.Providers, freshChecks, hostingGlobalNote)
		fmt.Fprintln(a.stdout, "\nRussian payment:")
		printHostingList(a.stdout, russian.Providers, freshChecks, hostingRussianNote)
	}
	return nil
}

func (a app) runHostingShortlist(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd hosting global")
	}
	catalog, err := a.loadHostingCatalog()
	if err != nil {
		return err
	}
	printHostingList(a.stdout, catalog.Providers, latestHostingChecks(st), hostingGlobalNote)
	return nil
}

func (a app) runHostingRussian(args []string, st *envdState) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: envd hosting russian")
	}
	catalog, err := parseRussianPaymentHostingProvidersTSV(builtInRussianPaymentProvidersTSV)
	if err != nil {
		return err
	}
	printHostingList(a.stdout, catalog.Providers, latestHostingChecks(st), hostingRussianNote)
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

func (a app) loadHostingCatalog() (hostingCatalog, error) {
	raw, err := loadBaseHostingCatalogRaw(a.root)
	if err != nil {
		raw = []byte(builtInHostingCatalogJSON)
	}
	catalog, err := parseHostingCatalog(raw)
	if err != nil {
		return hostingCatalog{}, err
	}
	community, err := parseBuiltInHostingProvidersTSV(builtInHostingProvidersTSV)
	if err != nil {
		return hostingCatalog{}, err
	}
	catalog = mergeHostingCatalogs(community, catalog)
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
	return os.ReadFile(filepath.Join(root, "data", "hosting", "providers.json"))
}

func parseBuiltInHostingProvidersTSV(raw string) (hostingCatalog, error) {
	catalog := hostingCatalog{Version: 1}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNo := 0
	seenIDs := map[string]int{}
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			return hostingCatalog{}, fmt.Errorf("hosting provider table line %d: expected 5 tab-separated fields", lineNo)
		}
		name := strings.TrimSpace(fields[0])
		domain := strings.TrimSpace(fields[1])
		tier := strings.TrimSpace(fields[2])
		regions := strings.TrimSpace(fields[3])
		notes := strings.TrimSpace(fields[4])
		id := providerIDFromNameDomain(name, domain)
		if n := seenIDs[id]; n > 0 {
			seenIDs[id] = n + 1
			id = fmt.Sprintf("%s-%d", id, n+1)
		} else {
			seenIDs[id] = 1
		}
		provider := hostingProvider{
			ID:                id,
			Name:              name,
			Homepage:          "https://" + strings.TrimRight(domain, "/"),
			SignupURL:         "https://" + strings.TrimRight(domain, "/"),
			APIURL:            nil,
			CountriesSoldFrom: countriesFromRegionText(regions),
			Regions:           regionsFromRegionText(regions),
			Payments:          []string{"unknown"},
			MinPlan:           hostingMinPlan{CPU: 1, RAMMB: 1024, DiskGB: 10},
			Notes:             []string{"community dataset", tier, regions, notes},
			Confidence:        "community",
		}
		if strings.Contains(strings.ToLower(tier), "verify") || strings.Contains(strings.ToLower(notes), "verify") {
			provider.Confidence = "unknown"
		}
		catalog.Providers = append(catalog.Providers, provider)
	}
	if err := scanner.Err(); err != nil {
		return hostingCatalog{}, err
	}
	rawJSON, err := json.Marshal(catalog)
	if err != nil {
		return hostingCatalog{}, err
	}
	return parseHostingCatalog(rawJSON)
}

func parseRussianPaymentHostingProvidersTSV(raw string) (hostingCatalog, error) {
	catalog := hostingCatalog{Version: 1}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNo := 0
	seenIDs := map[string]int{}
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 7 {
			return hostingCatalog{}, fmt.Errorf("Russian-payment provider table line %d: expected 7 tab-separated fields", lineNo)
		}
		name := strings.TrimSpace(fields[0])
		domain := strings.TrimSpace(fields[1])
		locations := strings.TrimSpace(fields[2])
		payments := splitProviderList(fields[3])
		strength := strings.TrimSpace(fields[4])
		evidence := strings.TrimSpace(fields[5])
		notes := strings.TrimSpace(fields[6])
		id := providerIDFromNameDomain(name, domain)
		if n := seenIDs[id]; n > 0 {
			seenIDs[id] = n + 1
			id = fmt.Sprintf("%s-%d", id, n+1)
		} else {
			seenIDs[id] = 1
		}
		provider := hostingProvider{
			ID:                id,
			Name:              name,
			Homepage:          "https://" + strings.TrimRight(domain, "/"),
			SignupURL:         "https://" + strings.TrimRight(domain, "/"),
			APIURL:            nil,
			CountriesSoldFrom: []string{"RU"},
			Regions:           regionsFromRegionText(locations),
			Payments:          payments,
			MinPlan:           hostingMinPlan{CPU: 1, RAMMB: 1024, DiskGB: 10},
			Notes:             []string{"ru-payment", locations, strength, evidence, notes},
			Confidence:        russianPaymentConfidence(strength),
		}
		catalog.Providers = append(catalog.Providers, provider)
	}
	if err := scanner.Err(); err != nil {
		return hostingCatalog{}, err
	}
	rawJSON, err := json.Marshal(catalog)
	if err != nil {
		return hostingCatalog{}, err
	}
	return parseHostingCatalog(rawJSON)
}

func splitProviderList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '/'
	})
	out := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{"unknown"}
	}
	return out
}

func russianPaymentConfidence(strength string) string {
	strength = strings.ToLower(strength)
	if strings.Contains(strength, "direct") || strings.Contains(strength, "off") {
		return "verified"
	}
	if strings.Contains(strength, "strong") {
		return "community"
	}
	return "unknown"
}

func providerIDFromNameDomain(name, domain string) string {
	base := strings.ToLower(strings.TrimSpace(domain))
	base = strings.TrimPrefix(base, "www.")
	base = strings.Split(base, "/")[0]
	for _, suffix := range []string{".com", ".net", ".org", ".io", ".eu", ".ru", ".su", ".cloud", ".hosting", ".digital", ".de", ".in", ".jp", ".ua", ".at", ".is", ".ch", ".au", ".br", ".co", ".uk"} {
		base = strings.TrimSuffix(base, suffix)
	}
	if len(base) < 3 {
		base = strings.ToLower(name)
	}
	id := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(base, "-")
	id = strings.Trim(id, "-")
	id = readableNumericProviderID(id)
	if id == "" || id[0] < 'a' || id[0] > 'z' {
		id = "provider-" + id
	}
	if len(id) > 64 {
		id = strings.Trim(id[:64], "-")
	}
	return id
}

func readableNumericProviderID(id string) string {
	if id == "" || id[0] < '0' || id[0] > '9' {
		return id
	}
	words := map[string]string{
		"0":  "zero",
		"1":  "one",
		"2":  "two",
		"4":  "four",
		"23": "twenty-three",
		"62": "sixty-two",
	}
	for digits, word := range words {
		if id == digits {
			return word
		}
		if strings.HasPrefix(id, digits) {
			rest := strings.TrimPrefix(id, digits)
			rest = strings.TrimLeft(rest, "-")
			if rest == "" {
				return word
			}
			return word + "-" + rest
		}
	}
	return "n" + id
}

func countriesFromRegionText(text string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, code := range countryCodesFromRegionText(text) {
		if !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	if len(out) == 0 {
		return []string{"unknown"}
	}
	return out
}

func regionsFromRegionText(text string) []hostingRegion {
	codes := countriesFromRegionText(text)
	regions := make([]hostingRegion, 0, len(codes))
	for _, code := range codes {
		regions = append(regions, hostingRegion{Code: strings.ToLower(code), Country: code, City: "", ASN: "unknown"})
	}
	return regions
}

func countryCodesFromRegionText(text string) []string {
	lower := strings.ToLower(text)
	codes := []string{}
	add := func(code string) { codes = append(codes, code) }
	if strings.Contains(lower, "global") {
		add("global")
	}
	mapping := []struct {
		needle string
		code   string
	}{
		{"south africa", "ZA"}, {"latin america", "LATAM"}, {"united kingdom", "GB"},
		{"europe", "EU"}, {"eu", "EU"}, {"germany", "DE"}, {"finland", "FI"}, {"netherlands", "NL"}, {"lithuania", "LT"},
		{"switzerland", "CH"}, {"austria", "AT"}, {"france", "FR"}, {"poland", "PL"}, {"romania", "RO"}, {"moldova", "MD"},
		{"bulgaria", "BG"}, {"latvia", "LV"}, {"italy", "IT"}, {"norway", "NO"}, {"sweden", "SE"}, {"iceland", "IS"},
		{"uk", "GB"}, {"luxembourg", "LU"}, {"belgium", "BE"}, {"spain", "ES"}, {"us", "US"}, {"usa", "US"}, {"canada", "CA"},
		{"australia", "AU"}, {"india", "IN"}, {"japan", "JP"}, {"korea", "KR"}, {"indonesia", "ID"}, {"singapore", "SG"},
		{"malaysia", "MY"}, {"china", "CN"}, {"asia", "AS"}, {"africa", "AF"}, {"brazil", "BR"}, {"russia", "RU"},
		{"cis", "CIS"}, {"ukraine", "UA"}, {"turkey", "TR"},
	}
	for _, item := range mapping {
		if strings.Contains(lower, item.needle) {
			add(item.code)
		}
	}
	return codes
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

const (
	hostingCheckConcurrency = 32
	hostingCheckTimeout     = 3 * time.Second
)

func checkHostingProviders(providers []hostingProvider) []hostingCheckRecord {
	checks := make([]hostingCheckRecord, len(providers))
	now := time.Now().UTC()
	if len(providers) == 0 {
		return checks
	}
	workers := hostingCheckConcurrency
	if len(providers) < workers {
		workers = len(providers)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				checks[idx] = checkHostingProvider(providers[idx], now)
			}
		}()
	}
	for i := range providers {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return checks
}

func checkHostingProvider(p hostingProvider, now time.Time) hostingCheckRecord {
	homepage := probeDirectURL(p.ID+" homepage", "hosting", p.Homepage, hostingCheckTimeout)
	api := internetProbeRecord{Name: p.ID + " api", Path: "hosting", Status: "skip", Detail: "no api_url"}
	if p.APIURL != nil && *p.APIURL != "" {
		api = probeDirectURL(p.ID+" api", "hosting", *p.APIURL, hostingCheckTimeout)
	}
	return hostingCheckRecord{
		Time:      now,
		Provider:  p.ID,
		Homepage:  homepage,
		API:       api,
		Reachable: homepage.Status == "ok" || api.Status == "ok",
	}
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

func printHostingCheck(w io.Writer, checks []hostingCheckRecord, verbose bool) {
	reachable := 0
	failed := []hostingCheckRecord{}
	for _, c := range checks {
		if c.Reachable {
			reachable++
		} else {
			failed = append(failed, c)
		}
	}
	fmt.Fprintf(w, "Checked: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Reachable: %d/%d\n", reachable, len(checks))
	fmt.Fprintf(w, "Failed or slow: %d/%d\n", len(failed), len(checks))
	fmt.Fprintf(w, "Meaning: this is current website reachability from this network, not permanent provider quality.\n")
	if !verbose {
		if len(failed) > 0 {
			fmt.Fprintf(w, "\nFailures sample:\n")
			fmt.Fprintf(w, "%-18s %s\n", "PROVIDER", "DETAIL")
			limit := 12
			if len(failed) < limit {
				limit = len(failed)
			}
			for _, c := range failed[:limit] {
				fmt.Fprintf(w, "%-18s %s\n", c.Provider, compactField(c.Homepage.Detail, 96))
			}
			if len(failed) > limit {
				fmt.Fprintf(w, "... %d more; run `envd hosting check --verbose` for all rows\n", len(failed)-limit)
			}
		}
		return
	}
	fmt.Fprintf(w, "\nDetails:\n")
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

func hostingChecksByProvider(checks []hostingCheckRecord) map[string]hostingCheckRecord {
	out := map[string]hostingCheckRecord{}
	for _, check := range checks {
		out[check.Provider] = check
	}
	return out
}

func printHostingList(w io.Writer, providers []hostingProvider, checks map[string]hostingCheckRecord, noteFn func(hostingProvider) string) {
	sortHostingProviders(providers, checks)
	fmt.Fprintf(w, "%-18s %-8s %-8s %s\n", "PROVIDER", "REACH", "SOURCE", "NOTE")
	for _, p := range providers {
		fmt.Fprintf(w, "%-18s %-8s %-8s %s\n", p.ID, hostingReachLabel(p.ID, checks), hostingSourceLabel(p.Confidence), compactField(noteFn(p), 58))
	}
}

func hostingReachLabel(id string, checks map[string]hostingCheckRecord) string {
	c, ok := checks[id]
	if !ok {
		return "unknown"
	}
	if c.Reachable {
		return "ok"
	}
	return "fail"
}

func hostingSourceLabel(confidence string) string {
	switch confidence {
	case "verified":
		return "direct"
	case "community":
		return "listed"
	default:
		return "weak"
	}
}

func hostingGlobalNote(p hostingProvider) string {
	if len(p.Notes) == 0 {
		return p.Name
	}
	last := strings.TrimSpace(p.Notes[len(p.Notes)-1])
	if last == "" {
		return p.Name
	}
	return last
}

func hostingRussianNote(p hostingProvider) string {
	location := ""
	if len(p.Notes) > 1 {
		location = strings.TrimSpace(p.Notes[1])
	}
	payments := strings.Join(p.Payments, ",")
	if location == "" {
		return payments
	}
	if payments == "" || payments == "unknown" {
		return location
	}
	return location + "; " + payments
}

func compactField(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	if limit <= 1 {
		return s[:limit]
	}
	return strings.TrimSpace(s[:limit-3]) + "..."
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
		fmt.Fprint(a.stdout, "Usage: envd doctor history [SUBJECT]\n")
		return nil
	}
	if len(st.Events) == 0 {
		fmt.Fprintln(a.stdout, "No events recorded.")
		return nil
	}
	filter := strings.TrimSpace(strings.Join(args, " "))
	matched := false
	for _, ev := range st.Events {
		if filter != "" && ev.Subject != filter && ev.Kind+" "+ev.Subject != filter {
			continue
		}
		matched = true
		subject := ev.Subject
		if subject != "" {
			subject = " " + subject
		}
		fmt.Fprintf(a.stdout, "%s %-12s%s %s\n", ev.Time.Format(time.RFC3339), ev.Kind, subject, ev.Message)
	}
	if filter != "" && !matched {
		fmt.Fprintf(a.stdout, "No events recorded for %s.\n", filter)
	}
	return nil
}

func (a app) runWhy(args []string, st *envdState) error {
	if len(args) != 1 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, "Usage: envd doctor why ENV\n")
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
		if err := ensureEnvContainerAccess(ref); err != nil {
			return err
		}
	}
	return publishRuntimeRoute(ref, networkOrSealed(ref.Network))
}

func repairCreatedEnvAccessForRef(ref envRef) error {
	if err := repairEnvSSHAccess(ref.Name); err != nil {
		return err
	}
	return publishRuntimeRoute(ref, networkOrSealed(ref.Network))
}

func ensureEnvContainerAccess(ref envRef) error {
	authKey, err := ensureEnvdSSHKey()
	if err != nil {
		return err
	}
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
config="${ssh_dir}/config"
touch "${config}"
config_tmp="${config}.envd-tmp.$$"
awk '
  /# --- envd: identity start ---/ {skip=1; next}
  /# --- envd: identity end ---/ {skip=0; next}
  skip != 1 {print}
' "${config}" > "${config_tmp}"
cat >> "${config_tmp}" <<EOF

# --- envd: identity start ---
Host *
  IdentityAgent ${home_dir}/.envd/ssh-agent.sock
  AddKeysToAgent no
# --- envd: identity end ---
EOF
mv "${config_tmp}" "${config}"
chown "${DEV_USER}:${DEV_USER}" "${config}"
chmod 600 "${config}"
mkdir -p "${home_dir}"
mkdir -p "${home_dir}/.local" "${home_dir}/.npm"
npmrc="${home_dir}/.npmrc"
touch "${npmrc}"
npmrc_tmp="${npmrc}.envd-tmp.$$"
grep -v '^prefix=' "${npmrc}" > "${npmrc_tmp}" 2>/dev/null || true
printf 'prefix=%s/.local\n' "${home_dir}" >> "${npmrc_tmp}"
mv "${npmrc_tmp}" "${npmrc}"
bashrc="${home_dir}/.bashrc"
touch "${bashrc}"
tmp="${bashrc}.envd-tmp.$$"
trap 'rm -f "${tmp}"' EXIT INT TERM
awk '
  /# --- envd: user-local bin ---/ {skip_user_local=1; next}
  skip_user_local == 1 && /^esac$/ {skip_user_local=0; next}
  skip_user_local == 1 {next}
  /# --- envd: prompt start ---/ {skip=1; next}
  /# --- envd: prompt end ---/ {skip=0; next}
  /# --- envd: ensure colored prompt ---/ {skip=1; next}
  /^unset color_prompt force_color_prompt$/ && skip == 1 {skip=0; next}
  skip != 1 {print}
' "${bashrc}" > "${tmp}"
cat >> "${tmp}" <<EOF

# --- envd: user-local bin ---
export NPM_CONFIG_PREFIX="\${HOME}/.local"
case ":\${PATH}:" in
  *":\${HOME}/.local/bin:"*) ;;
  *) export PATH="\${HOME}/.local/bin:\${PATH}" ;;
esac

# --- envd: prompt start ---
export ENVD_ENV_NAME="${ENVD_ENV_NAME_VALUE}"
if [ -n "\${BASH_VERSION:-}" ]; then
  if [ -S "\${HOME}/.envd/ssh-agent.sock" ]; then
    export SSH_AUTH_SOCK="\${HOME}/.envd/ssh-agent.sock"
  fi
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
chown -R "${DEV_USER}:${DEV_USER}" "${home_dir}/.local" "${home_dir}/.npm"
chown "${DEV_USER}:${DEV_USER}" "${bashrc}" "${npmrc}"
chmod 600 "${npmrc}"
`
	return dockerRun("exec",
		"-e", "DEV_USER="+userName,
		"-e", "ENVD_AUTHORIZED_KEY="+authKey.PublicKey,
		"-e", "ENVD_ENV_NAME_VALUE="+envName,
		ref.DevName, "sh", "-lc", script)
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
    touch "${dir}/extensions.json"
    chown "${DEV_USER}:${DEV_USER}" "${dir}/extensions.json"
    chmod u+rw "${dir}/extensions.json"
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
			if strings.TrimSpace(egress) == "" {
				return probeResult{Name: "Sealed HTTPS", Detail: env.Name + " DNS/TCP/TLS/DockerHub OK; egress unknown"}
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
	cmd := exec.CommandContext(ctx, dockerBinary(), "inspect", "-f", "{{.State.Status}}", name)
	out, err := cmd.Output()
	if err != nil {
		return "missing"
	}
	return strings.TrimSpace(string(out))
}

func dockerPublishedPort(container, privatePort string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, dockerBinary(), "port", container, privatePort).Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, portText, err := net.SplitHostPort(line)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			continue
		}
		return port, nil
	}
	return 0, fmt.Errorf("no published port for %s %s", container, privatePort)
}

func dockerRun(args ...string) error {
	cmd := exec.Command(dockerBinary(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker %s failed: %w\n%s", strings.Join(redactDockerArgs(args), " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dockerBinary() string {
	if path, err := exec.LookPath("docker"); err == nil {
		return path
	}
	for _, path := range []string{
		"/usr/local/bin/docker",
		"/opt/homebrew/bin/docker",
		"/Applications/Docker.app/Contents/Resources/bin/docker",
	} {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return "docker"
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
	return exec.Command(dockerBinary(), "container", "inspect", name).Run() == nil
}

func volumeExists(name string) bool {
	return exec.Command(dockerBinary(), "volume", "inspect", name).Run() == nil
}

func sealedRuntimeRecreateStatus(ref envRef) (bool, string, error) {
	if !containerExists(ref.DevName) {
		return true, "missing dev container", nil
	}
	if recreate, reason, err := sidecarRecreateReason(ref.NetName); err != nil || recreate {
		return recreate, reason, err
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

func sidecarRecreateReason(netName string) (bool, string, error) {
	if !containerExists(netName) {
		return true, "missing sidecar container", nil
	}
	sidecar, err := inspectContainer(netName)
	if err != nil {
		return false, "", err
	}
	if sidecar.State.Restarting {
		return true, "sidecar restarting", nil
	}
	if sidecar.State.Status != "running" {
		return true, "sidecar " + sidecar.State.Status, nil
	}
	if sidecar.State.Health != nil {
		switch sidecar.State.Health.Status {
		case "unhealthy":
			return true, "sidecar unhealthy", nil
		case "starting":
			if sidecar.RestartCount > 0 {
				return true, "sidecar restart loop", nil
			}
		}
	}
	return false, "", nil
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

func waitForSidecarReady(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := "not running"
	for time.Now().Before(deadline) {
		item, err := inspectContainer(name)
		if err != nil {
			last = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if item.State.Status != "running" {
			last = "state " + item.State.Status
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if _, err := dockerExecOutputQuiet(name, 2*time.Second, "sidecar tun", "sh", "-lc", "ip link show tun0 >/dev/null 2>&1"); err == nil {
			return nil
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("sidecar %s did not become ready: %s", name, last)
}

func sidecarReadyNow(name string) bool {
	item, err := inspectContainer(name)
	if err != nil {
		return false
	}
	if item.State.Status != "running" || item.State.Restarting {
		return false
	}
	if item.State.Health != nil && item.State.Health.Status == "unhealthy" {
		return false
	}
	_, err = dockerExecOutputQuiet(name, 2*time.Second, "sidecar tun", "sh", "-lc", "ip link show tun0 >/dev/null 2>&1")
	return err == nil
}

func verifySealedEnvStartup(name string) error {
	if _, err := dockerExecOutputQuiet(name, 3*time.Second, "sealed startup DNS", "getent", "hosts", "example.com"); err != nil {
		return layerErr("sealed startup", err)
	}
	return nil
}

func verifySealedEnvAgainstGateway(name, gatewayEgress string) (string, error) {
	if _, err := dockerExecOutput(name, 8*time.Second, "getent", "hosts", "example.com"); err != nil {
		return "", layerErr("DNS", err)
	}
	if out, err := dockerExecOutputQuiet(name, 12*time.Second, "sealed HTTPS quorum", "sh", "-lc", sealedWebQuorumScript()); err != nil {
		return "", layerErr("sealed sidecar", fmt.Errorf("HTTPS quorum failed: %w", err))
	} else if strings.TrimSpace(out) != "" && !strings.Contains(out, "ok=") {
		return "", layerErr("sealed sidecar", fmt.Errorf("HTTPS quorum returned unexpected output: %s", strings.TrimSpace(out)))
	}
	egress := ""
	if got, err := dockerExecOutput(name, 8*time.Second, "sh", "-lc", sealedEgressScript()); err == nil {
		egress = strings.TrimSpace(got)
	}
	if gatewayEgress != "" && egress != "" && egress != strings.TrimSpace(gatewayEgress) {
		return egress, layerErr("egress policy", fmt.Errorf("sealed egress %s differs from gateway egress %s", egress, strings.TrimSpace(gatewayEgress)))
	}
	return egress, nil
}

func sealedWebQuorumScript() string {
	return `
set +e
targets='https://www.google.com/generate_204 https://www.cloudflare.com/cdn-cgi/trace https://github.com/ https://registry-1.docker.io/v2/'
ok=0
pids=''
tmp="${TMPDIR:-/tmp}/envd-quorum.$$"
mkdir -p "$tmp"
i=0
for target in $targets; do
  i=$((i + 1))
  (
    code="$(curl -sSIL -o /dev/null -w '%{http_code}' --max-time 8 "$target" 2>/dev/null)"
    case "$code" in
      [1-4][0-9][0-9]) exit 0 ;;
      *) exit 1 ;;
    esac
  ) &
  pids="$pids $!"
done
for pid in $pids; do
  if wait "$pid"; then
    ok=$((ok + 1))
  fi
done
rm -rf "$tmp"
printf 'ok=%s total=4\n' "$ok"
test "$ok" -ge 3
`
}

func sealedEgressScript() string {
	return `
set +e
for target in https://api.ipify.org https://icanhazip.com https://ifconfig.me/ip; do
  ip="$(curl -fsS --max-time 4 "$target" 2>/dev/null | tr -d '\r' | awk 'NF {print; exit}')"
  if [ -n "$ip" ]; then
    printf '%s\n' "$ip"
    exit 0
  fi
done
exit 1
`
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

func dockerExecOutputQuiet(container string, timeout time.Duration, label string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dockerArgs := append([]string{"exec", container}, args...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s timed out after %s", label, timeout)
	}
	if err != nil {
		if text != "" {
			return "", fmt.Errorf("%s failed: %w: %s", label, err, firstLine(text))
		}
		return "", fmt.Errorf("%s failed: %w", label, err)
	}
	return string(out), nil
}

func firstLine(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return strings.TrimSpace(text[:i])
	}
	return text
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
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return fmt.Errorf("invalid env name %q: use lowercase letters, digits, and hyphens only", name)
		}
	}
	if strings.HasSuffix(name, "-") {
		return fmt.Errorf("invalid env name %q: must end with lowercase letter or digit", name)
	}
	return nil
}

func dirHasFiles(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

type dockerInspect struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	Mounts       []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status     string `json:"Status"`
		Restarting bool   `json:"Restarting"`
		Health     *struct {
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
	Image             string
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
	dev, netContainer, err := inspectEnvContainers(ref)
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
	if netContainer != nil {
		env.Net = netContainer
	}
	_ = st
	return env, nil
}

func inspectEnvContainers(ref envRef) (dockerInspect, *dockerInspect, error) {
	if ref.NetName != "" {
		if items, err := inspectContainerMany(ref.DevName, ref.NetName); err == nil {
			var dev dockerInspect
			var netContainer *dockerInspect
			for _, item := range items {
				name := strings.TrimPrefix(item.Name, "/")
				switch name {
				case ref.DevName:
					dev = item
				case ref.NetName:
					copy := item
					netContainer = &copy
				}
			}
			if dev.Name != "" {
				return dev, netContainer, nil
			}
		}
	}
	dev, err := inspectContainer(ref.DevName)
	if err != nil {
		return dockerInspect{}, nil, err
	}
	if ref.NetName == "" {
		return dev, nil, nil
	}
	netContainer, err := inspectContainer(ref.NetName)
	if err != nil {
		return dev, nil, nil
	}
	return dev, &netContainer, nil
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
				Image:             rec.Image,
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
			Image:             rec.Image,
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
	items, err := inspectContainerMany(name)
	if err != nil {
		return dockerInspect{}, err
	}
	if len(items) != 1 {
		return dockerInspect{}, fmt.Errorf("docker inspect %s returned %d items", name, len(items))
	}
	return items[0], nil
}

func inspectContainerMany(names ...string) ([]dockerInspect, error) {
	args := append([]string{"inspect"}, names...)
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect %s failed: %w", strings.Join(names, " "), err)
	}
	var items []dockerInspect
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, err
	}
	return items, nil
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
		return profilePackage{}, fmt.Errorf("package must use apt:PACKAGE, npm:PACKAGE, pip:PACKAGE, or tool:NAME")
	}
	switch source {
	case "apt", "npm", "pip", "tool":
	default:
		return profilePackage{}, fmt.Errorf("unsupported package source %q: use apt, npm, pip, or tool", source)
	}
	if err := validatePackageName(name); err != nil {
		return profilePackage{}, err
	}
	return profilePackage{Source: source, Name: name}, nil
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
	pip := []string{}
	for _, pkg := range profile.Packages {
		switch pkg.Source {
		case "apt":
			aptSet[pkg.Name] = true
		case "npm":
			aptSet["nodejs"] = true
			aptSet["npm"] = true
			npm = append(npm, pkg.Name)
		case "pip":
			aptSet["python3"] = true
			aptSet["python3-pip"] = true
			aptSet["python3-venv"] = true
			pip = append(pip, pkg.Name)
		case "tool":
			for _, aptName := range toolAptPackages(pkg.Name) {
				aptSet[aptName] = true
			}
			for _, npmName := range toolNpmPackages(pkg.Name) {
				aptSet["nodejs"] = true
				aptSet["npm"] = true
				npm = append(npm, npmName)
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
	if len(npm) > 0 || len(pip) > 0 {
		b.WriteString("ENV NPM_CONFIG_PREFIX=/home/dev/.local\n")
		b.WriteString("ENV PATH=/home/dev/.local/bin:${PATH}\n")
	}
	if len(apt) > 0 {
		b.WriteString("RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends")
		for _, name := range apt {
			b.WriteString(" " + shellQuote(name))
		}
		b.WriteString(" && rm -rf /var/lib/apt/lists/*\n")
	}
	if len(npm) > 0 || len(pip) > 0 {
		b.WriteString("RUN install -d -o 1000 -g 1000 /home/dev /home/dev/.local /home/dev/.npm\n")
	}
	if len(npm) > 0 {
		b.WriteString("USER 1000:1000\n")
		b.WriteString("RUN npm install -g")
		for _, name := range npm {
			b.WriteString(" " + shellQuote(name))
		}
		b.WriteString("\n")
		b.WriteString("USER root\n")
	}
	if len(pip) > 0 {
		b.WriteString("USER 1000:1000\n")
		b.WriteString("RUN python3 -m pip install --user --break-system-packages")
		for _, name := range pip {
			b.WriteString(" " + shellQuote(name))
		}
		b.WriteString("\n")
		b.WriteString("USER root\n")
	}
	return b.String()
}

func toolAptPackages(name string) []string {
	switch name {
	case "build-essential":
		return []string{"build-essential"}
	case "codex":
		return []string{"nodejs", "npm"}
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

func toolNpmPackages(name string) []string {
	switch name {
	case "codex":
		return []string{"@openai/codex"}
	default:
		return nil
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
	if err := verifyActiveGatewayRuntime(cfg, 6*time.Second); err == nil {
		return nil
	}
	if err := restartGatewayRuntime(runtimeDir); err != nil {
		return layerErr("local gateway", err)
	}
	if err := verifyActiveGatewayRuntime(cfg, 8*time.Second); err != nil {
		return layerErr("remote gateway", err)
	}
	return nil
}

func (a app) restartActiveGatewayRuntime(st *envdState) error {
	cfg, _, err := a.activeGatewayConfig(st)
	if err != nil {
		return err
	}
	runtimeDir, err := a.materializeGatewayRuntime(cfg)
	if err != nil {
		return layerErr("local gateway", err)
	}
	if err := restartGatewayRuntime(runtimeDir); err != nil {
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

func verifyActiveGatewayRuntime(cfg gatewayConfig, timeout time.Duration) error {
	host := hostForClient(cfg.BindIP)
	socks := net.JoinHostPort(host, strconv.Itoa(cfg.SOCKSPort))
	httpProxy := net.JoinHostPort(host, strconv.Itoa(cfg.HTTPHostPort))
	return verifyGatewayProxyCached(socks, httpProxy, timeout)
}

func restartGatewayRuntime(runtimeDir string) error {
	const containerName = "vpn-gateway-xray-1"
	if dockerContainerStatus(containerName) == "missing" {
		if err := startGatewayRuntime(runtimeDir); err != nil {
			return err
		}
		return waitForDockerContainerRunning(containerName, 10*time.Second)
	}
	if err := dockerRun("restart", "-t", "1", containerName); err != nil {
		return err
	}
	return waitForDockerContainerRunning(containerName, 10*time.Second)
}

func waitForDockerContainerRunning(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := "missing"
	for time.Now().Before(deadline) {
		last = dockerContainerStatus(name)
		if last == "running" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s is %s after %s", name, last, timeout)
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
		return "Run envd status and recreate or restart the affected sealed environment."
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
