package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestVersionDoesNotNeedState(t *testing.T) {
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"version"}); err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "envd "+version {
		t.Fatalf("version output = %q", got)
	}
}

func TestHelpDoesNotNeedState(t *testing.T) {
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"help"}); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("help output missing usage: %q", out.String())
	}
}

func TestHelpUsesStartAndStatusCommands(t *testing.T) {
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"help"}); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{"start                create or start an environment", "status               show access, gateway, and environments"} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q:\n%s", want, got)
		}
	}
	for _, old := range []string{"run                  create", "ps                   list", "list                 list environments"} {
		if strings.Contains(got, old) {
			t.Fatalf("help still contains old command %q:\n%s", old, got)
		}
	}
}

func TestTopLevelListCommandRemoved(t *testing.T) {
	a := app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}

	err := a.run([]string{"list"})
	if err == nil || !strings.Contains(err.Error(), `unknown command "list"`) {
		t.Fatalf("expected list to be removed, got %v", err)
	}
}

func TestRemovedTopLevelCommands(t *testing.T) {
	a := app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}
	for _, cmd := range []string{"internet", "events", "why", "inspect", "supervisor"} {
		err := a.run([]string{cmd})
		if err == nil || !strings.Contains(err.Error(), `unknown command "`+cmd+`"`) {
			t.Fatalf("expected %s to be removed, got %v", cmd, err)
		}
	}
}

func TestDoctorInternetCommandRemoved(t *testing.T) {
	a := app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}
	err := a.runDoctor([]string{"internet"}, &envdState{})
	if err == nil || !strings.Contains(err.Error(), `unknown doctor subcommand "internet"`) {
		t.Fatalf("expected doctor internet to be removed, got %v", err)
	}
}

func TestStatefulCommandRequiresInit(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	err := a.run([]string{"doctor", "history"})
	if err == nil || !strings.Contains(err.Error(), "envd init") {
		t.Fatalf("expected init error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.enc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state.enc should not be created by doctor history before init: %v", err)
	}
}

func TestInitCreatesEncryptedState(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if !strings.Contains(out.String(), "Initialized encrypted envd state") {
		t.Fatalf("init output missing state path: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.enc")); err != nil {
		t.Fatalf("state.enc was not created: %v", err)
	}
	out.Reset()
	if err := a.run([]string{"doctor", "history"}); err != nil {
		t.Fatalf("doctor history after init failed: %v", err)
	}
	if !strings.Contains(out.String(), "encrypted state initialized") {
		t.Fatalf("doctor history output did not include initial state event: %q", out.String())
	}
	if err := a.run([]string{"init"}); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("second init should fail, got %v", err)
	}
}

func TestUnlockValidatesExistingState(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	out.Reset()
	if err := a.run([]string{"unlock"}); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	if !strings.Contains(out.String(), "Unlocked:") {
		t.Fatalf("unlock output = %q", out.String())
	}
}

func TestStateEventsAreBounded(t *testing.T) {
	st := envdState{}
	for i := 0; i < maxStateEvents+25; i++ {
		st.addEvent("test", "", fmt.Sprintf("event-%d", i))
	}
	if len(st.Events) != maxStateEvents {
		t.Fatalf("event history length = %d", len(st.Events))
	}
	if got := st.Events[0].Message; got != "event-25" {
		t.Fatalf("oldest retained event = %q", got)
	}
}

func TestRuntimeAccessPublishAndLock(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	ref := envRef{Name: "books", ID: "abc123", UserName: "dev", DevName: "envd-abc123-dev", Network: "sealed"}
	if _, err := runtimeRoute("books"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("missing runtime access should be locked, got %v", err)
	}
	if err := publishRuntimeRoute(ref, "sealed"); err != nil {
		t.Fatalf("publish runtime route failed: %v", err)
	}
	route, err := runtimeRoute("books")
	if err != nil {
		t.Fatalf("runtime route not readable: %v", err)
	}
	if route.DevName != ref.DevName || route.Network != "sealed" {
		t.Fatalf("unexpected route: %+v", route)
	}
	if err := lockRuntimeAccess(); err != nil {
		t.Fatalf("lock runtime access failed: %v", err)
	}
	if _, err := runtimeRoute("books"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked runtime route should be denied, got %v", err)
	}
}

func TestRuntimeAccessUnpublish(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	ref := envRef{Name: "books", ID: "abc123", UserName: "dev", DevName: "envd-abc123-dev", Network: "sealed"}
	if err := publishRuntimeRoute(ref, "sealed"); err != nil {
		t.Fatalf("publish runtime route failed: %v", err)
	}
	if _, err := runtimeRoute("books"); err != nil {
		t.Fatalf("runtime route missing before unpublish: %v", err)
	}
	if err := unpublishRuntimeRoute("books"); err != nil {
		t.Fatalf("unpublish runtime route failed: %v", err)
	}
	if _, err := runtimeRoute("books"); err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("runtime route should be gone after unpublish, got %v", err)
	}
}

func TestStatusDoesNotNeedEncryptedState(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	if err := saveRuntimeAccess(runtimeAccessState{Locked: false, Routes: map[string]runtimeSSHRoute{
		"books": {Name: "books", ID: "abc123", DevName: "envd-abc123-dev", Network: "sealed", Storage: "protected"},
	}}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.run([]string{"status"}); err != nil {
		t.Fatalf("status without state failed: %v", err)
	}
	if !strings.Contains(out.String(), "Access:") || !strings.Contains(out.String(), "Master cache:") {
		t.Fatalf("status output missing expected fields: %q", out.String())
	}
	for _, want := range []string{"NAME", "books", "sealed", "protected"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("runtime status missing %q:\n%s", want, out.String())
		}
	}
}

func TestDetailRowsAlignLongLabels(t *testing.T) {
	var out bytes.Buffer
	printDetailRows(&out, []detailRow{
		{Label: "Name", Value: "test1"},
		{Label: "Gateway generation", Value: "1"},
		{Label: "Image ID", Value: "sha256:abc"},
	})
	got := out.String()
	for _, want := range []string{
		"Name:                test1\n",
		"Gateway generation:  1\n",
		"Image ID:            sha256:abc\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details alignment missing %q:\n%s", want, got)
		}
	}
}

func TestProbeResultsAlignLongNames(t *testing.T) {
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	ok, failures := a.printProbeResults([]probeResult{
		{Name: "Env bet1", Detail: "sealed running"},
		{Name: "Env sealed-storage-test", Detail: "sealed running"},
	})
	if !ok || len(failures) != 0 {
		t.Fatalf("expected ok probe results, ok=%v failures=%v", ok, failures)
	}
	got := out.String()
	for _, want := range []string{
		"Env bet1                 OK    sealed running\n",
		"Env sealed-storage-test  OK    sealed running\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("probe alignment missing %q:\n%s", want, got)
		}
	}
}

func TestStatusIgnoresObsoleteHostIdentitySocket(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".local", "share", "envd")
	t.Setenv("ENVD_DATA_DIR", dataDir)
	socketPath := filepath.Join(dataDir, "runtime", "identity-agents", "books.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	access := runtimeAccessState{Locked: false, Routes: map[string]runtimeSSHRoute{
		"books": {Name: "books", ID: "abc123", DevName: "envd-abc123-dev", Network: "sealed"},
	}}
	if err := saveRuntimeAccess(access); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.run([]string{"status"}); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(out.String(), "Identity:") || !strings.Contains(out.String(), "missing for books") {
		t.Fatalf("status did not report missing env identity agent: %q", out.String())
	}
}

func TestStatusReportsMissingIdentityAgent(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	access := runtimeAccessState{Locked: false, Routes: map[string]runtimeSSHRoute{
		"books": {Name: "books", ID: "abc123", DevName: "envd-abc123-dev", Network: "sealed"},
	}}
	if err := saveRuntimeAccess(access); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.run([]string{"status"}); err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if !strings.Contains(out.String(), "Identity:") || !strings.Contains(out.String(), "missing for books") {
		t.Fatalf("status did not report missing identity agent: %q", out.String())
	}
}

func TestBrowserLaunchFlagsForceProxyAndLeakMitigations(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	extensionDir := browserExtensionDirForProfile(profile)
	if err := os.MkdirAll(extensionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extensionDir, "manifest.json"), []byte(`{"manifest_version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	webStoreDir := chromiumWebStoreExtensionDir(filepath.Dir(profile))
	if err := os.MkdirAll(webStoreDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webStoreDir, "manifest.json"), []byte(`{"manifest_version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := strings.Join(browserLaunchFlags(profile, "127.0.0.1:11080"), " ")
	for _, want := range []string{
		"--user-data-dir=" + profile,
		"--proxy-server=socks5://127.0.0.1:11080",
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-background-networking",
		"--force-dark-mode",
		"--use-mock-keychain",
		"TabSearch",
		"AvatarToolbarButton",
		"ExtensionsToolbarMenu",
		"ublock-origin-lite",
		"chromium-web-store",
		"--custom-ntp=" + fileURL(browserNewTabPagePath(filepath.Dir(profile))),
		"--extension-mime-request-handling=always-prompt-for-install",
		"--load-extension=",
	} {
		if !strings.Contains(flags, want) {
			t.Fatalf("browser flags missing %q:\n%s", want, flags)
		}
	}
	if strings.Contains(flags, "--host-resolver-rules") {
		t.Fatalf("browser flags should not trigger Chromium unsupported flag warning:\n%s", flags)
	}
	if strings.Contains(flags, "chrome-extension://") {
		t.Fatalf("browser flags should not directly open extension URLs:\n%s", flags)
	}
	if strings.Contains(flags, "--disable-extensions-except") {
		t.Fatalf("browser flags should not block user-installed extensions:\n%s", flags)
	}
	if strings.Contains(flags, "vhrome-new-tab") || strings.Contains(flags, "blank-new-tab-page") {
		t.Fatalf("browser flags should not allow stale Vhrome extensions:\n%s", flags)
	}
}

func TestInstallBrowserNewTabPageIsLocalAndBlank(t *testing.T) {
	root := t.TempDir()
	inst := browserInstall{Root: root}
	if err := installBrowserNewTabPage(inst); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(browserNewTabPagePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "#f1f3f4") || !strings.Contains(string(html), "#3c3c3c") {
		t.Fatalf("blank new tab should use Chromium chrome-like colors:\n%s", html)
	}
	if !strings.Contains(string(html), `<meta name="theme-color" content="#3c3c3c">`) {
		t.Fatalf("blank new tab should declare dark first-paint theme color:\n%s", html)
	}
	if !strings.Contains(string(html), `<link rel="icon" href="empty.png">`) {
		t.Fatalf("blank new tab should use transparent favicon:\n%s", html)
	}
	icon, err := os.ReadFile(filepath.Join(browserNewTabPageDir(root), "empty.png"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(icon, []byte{0x89, 0x50, 0x4e, 0x47}) {
		t.Fatalf("transparent icon should be a PNG, got %x", icon[:min(len(icon), 8)])
	}
}

func TestWriteFileIfChangedReportsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	changed, err := writeFileIfChanged(path, []byte("one"), 0o600)
	if err != nil || !changed {
		t.Fatalf("first write changed=%v err=%v", changed, err)
	}
	changed, err = writeFileIfChanged(path, []byte("one"), 0o600)
	if err != nil || changed {
		t.Fatalf("same write changed=%v err=%v", changed, err)
	}
	changed, err = writeFileIfChanged(path, []byte("two"), 0o600)
	if err != nil || !changed {
		t.Fatalf("different write changed=%v err=%v", changed, err)
	}
}

func TestIdlePreferenceStatusText(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	if !idleSchedulerEnabled() {
		t.Fatal("idle should default on")
	}
	if got := idleStatusText(); !strings.Contains(got, "opportunistic") {
		t.Fatalf("unexpected default idle status: %q", got)
	}
	if err := setIdleSchedulerEnabled(false); err != nil {
		t.Fatal(err)
	}
	if idleSchedulerEnabled() {
		t.Fatal("idle should be disabled")
	}
	if got := idleStatusText(); got != "off" {
		t.Fatalf("unexpected disabled idle status: %q", got)
	}
}

func TestApplyMinimalVSCodeSettingsMergesAndBacksUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := []byte(`{
	// VS Code user settings are JSONC.
	"custom.keep": true,
	"window.title": "old",
}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	changed, backup, err := applyMinimalVSCodeSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || backup == "" {
		t.Fatalf("expected changed with backup, changed=%v backup=%q", changed, backup)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["custom.keep"] != true {
		t.Fatalf("custom setting was not preserved: %+v", settings)
	}
	if settings["window.title"] != " " || settings["workbench.statusBar.visible"] != false {
		t.Fatalf("minimal settings were not applied: %+v", settings)
	}
	backupRaw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(backupRaw) != string(original) {
		t.Fatalf("backup mismatch: %q", string(backupRaw))
	}
	changed, _, err = applyMinimalVSCodeSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second apply should be unchanged")
	}
}

func TestSeedBrowserProfileDoesNotWriteProtectedSearchPrefs(t *testing.T) {
	profile := t.TempDir()
	defaultDir := filepath.Join(profile, "Default")
	if err := os.MkdirAll(filepath.Join(defaultDir, "Sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(defaultDir, "Current Session"),
		filepath.Join(defaultDir, "Last Tabs"),
		filepath.Join(defaultDir, "Sessions", "Session_1"),
		filepath.Join(defaultDir, "Sessions", "Tabs_1"),
		filepath.Join(defaultDir, "Sessions", "Other"),
	} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(profile, "Local State"), []byte(`{"browser":{"enabled_labs_experiments":["custom-ntp"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := seedBrowserProfile(profile); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(profile, "Local State"))
	if err != nil {
		t.Fatal(err)
	}
	var localState map[string]any
	if err := json.Unmarshal(raw, &localState); err != nil {
		t.Fatal(err)
	}
	browser := localState["browser"].(map[string]any)
	experiments := browser["enabled_labs_experiments"].([]any)
	if !containsAnyString(experiments, "disable-top-sites") {
		t.Fatalf("missing top-sites flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "hide-extensions-menu") {
		t.Fatalf("missing extensions menu flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "remove-tabsearch-button") {
		t.Fatalf("missing tab search flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "show-avatar-button@3") {
		t.Fatalf("missing avatar flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "extensions-toolbar-menu@2") {
		t.Fatalf("missing extensions toolbar flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "extension-mime-request-handling@2") {
		t.Fatalf("missing extension MIME flag: %+v", experiments)
	}
	if !containsAnyString(experiments, "custom-ntp") {
		t.Fatalf("missing custom NTP flag: %+v", experiments)
	}
	prefsRaw, err := os.ReadFile(filepath.Join(profile, "Default", "Preferences"))
	if err != nil {
		t.Fatal(err)
	}
	var prefs map[string]any
	if err := json.Unmarshal(prefsRaw, &prefs); err != nil {
		t.Fatal(err)
	}
	ntp := prefs["ntp"].(map[string]any)
	if ntp["shortcust_visible"] != false || ntp["custom_links_visible"] != false || ntp["enterprise_shortcuts_visible"] != false || ntp["use_most_visited_tiles"] != false || ntp["num_personal_suggestions"] != float64(0) || ntp["shortcuts_type"] != float64(0) {
		t.Fatalf("unexpected ntp prefs: %+v", ntp)
	}
	if prefs["default_search_provider_data"] != nil {
		t.Fatalf("seed should not write protected search prefs: %+v", prefs["default_search_provider_data"])
	}
	if _, err := os.Stat(filepath.Join(profile, "Default", "Secure Preferences")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Secure Preferences should not be created by browser seed; err=%v", err)
	}
	for _, path := range []string{
		filepath.Join(defaultDir, "Current Session"),
		filepath.Join(defaultDir, "Last Tabs"),
		filepath.Join(defaultDir, "Sessions", "Session_1"),
		filepath.Join(defaultDir, "Sessions", "Tabs_1"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("startup session file should be removed: %s err=%v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(defaultDir, "Sessions", "Other")); err != nil {
		t.Fatalf("unrelated session dir file should remain: %v", err)
	}
}

func containsAnyString(items []any, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestInstallVhromeLinuxLauncher(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux launcher test")
	}
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	t.Setenv("XDG_DATA_HOME", filepath.Join(dataDir, "xdg"))
	inst, err := browserInstallPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := installVhromeLinuxLauncher(inst); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(inst.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Name=Vhrome") || !strings.Contains(string(raw), "Exec=") || !strings.Contains(string(raw), " browser") {
		t.Fatalf("unexpected launcher:\n%s", raw)
	}
}

func TestSSHProxyUsesRuntimeAccessWithoutUnlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ENVD_DATA_DIR", filepath.Join(home, ".local", "share", "envd"))
	t.Setenv("ENVD_NONINTERACTIVE", "1")
	ref := envRef{Name: "books", ID: "abc123", UserName: "dev", DevName: "envd-abc123-dev", Network: "sealed"}
	if err := publishRuntimeRoute(ref, "sealed"); err != nil {
		t.Fatal(err)
	}
	_, err := prepareSSHProxyDockerArgs([]string{"books"})
	if err == nil || !strings.Contains(err.Error(), `environment "books" is not running`) {
		t.Fatalf("expected runtime-only not-running error, got %v", err)
	}
}

func TestEnvCanBeExposedAfterUnlockSkipsDeadPlainState(t *testing.T) {
	rec := envRecord{ID: "abc123", Storage: "plain", Network: "sealed"}
	ref := envRef{
		DevName: devContainerName(rec.ID),
		NetName: netContainerName(rec.ID),
	}
	if envCanBeExposedAfterUnlock(ref, rec) {
		t.Fatalf("dead plain state should not become visible after unlock")
	}
	rec.Storage = "protected"
	if !envCanBeExposedAfterUnlock(ref, rec) {
		t.Fatalf("protected state should be restorable after unlock")
	}
}

func TestWrongMasterPasswordIsFriendly(t *testing.T) {
	stateDir := t.TempDir()
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.save(initialEnvdState(time.Now().UTC()), []byte("right-password")); err != nil {
		t.Fatalf("save state failed: %v", err)
	}

	_, err := store.loadOrCreate([]byte("wrong-password"))
	if err == nil {
		t.Fatalf("wrong password should fail")
	}
	if !strings.Contains(err.Error(), "wrong master password") {
		t.Fatalf("expected friendly error, got %v", err)
	}
	if strings.Contains(err.Error(), "cipher:") || strings.Contains(err.Error(), "message authentication failed") {
		t.Fatalf("raw crypto error leaked: %v", err)
	}
}

func TestPasswordChangeReencryptsExistingState(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "old-password")
	t.Setenv("ENVD_NEW_MASTER_PASSWORD", "new-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	now := time.Now().UTC()
	st := initialEnvdState(now)
	st.ActiveGateway = "ams1"
	st.Gateways["ams1"] = gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "203.0.113.10", ServerPort: "443"}, now)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.save(st, []byte("old-password")); err != nil {
		t.Fatalf("save old state failed: %v", err)
	}

	if err := a.run([]string{"password", "change"}); err != nil {
		t.Fatalf("password change failed: %v", err)
	}
	if !strings.Contains(out.String(), "Changed envd master password") {
		t.Fatalf("password change output = %q", out.String())
	}
	if _, err := store.loadOrCreate([]byte("old-password")); err == nil {
		t.Fatalf("old password should not unlock state after password change")
	}
	loaded, err := store.loadOrCreate([]byte("new-password"))
	if err != nil {
		t.Fatalf("new password did not unlock state: %v", err)
	}
	if loaded.ActiveGateway != "ams1" || loaded.Gateways["ams1"].ServerIP != "203.0.113.10" {
		t.Fatalf("state was not preserved after password change: %+v", loaded)
	}
	if len(loaded.Events) == 0 || !strings.Contains(loaded.Events[len(loaded.Events)-1].Message, "master password changed") {
		t.Fatalf("password change event missing: %+v", loaded.Events)
	}
}

func TestPasswordChangeRequiresDifferentPassword(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "same-password")
	t.Setenv("ENVD_NEW_MASTER_PASSWORD", "same-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	err := a.run([]string{"password", "change"})
	if err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("expected different-password error, got %v", err)
	}
}

func TestPasswordChangeRequiresInit(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "old-password")
	t.Setenv("ENVD_NEW_MASTER_PASSWORD", "new-password")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	err := a.run([]string{"password", "change"})
	if err == nil || !strings.Contains(err.Error(), "envd init") {
		t.Fatalf("expected init error, got %v", err)
	}
}

func TestResetStateMovesStateToBackup(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	t.Setenv("ENVD_NONINTERACTIVE", "1")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "state.lock"), []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.run([]string{"reset-state", "--delete", "--i-understand-this-deletes-envd-state", "--yes"}); err != nil {
		t.Fatalf("reset-state failed: %v", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir should have moved, stat err=%v", err)
	}
	line := strings.TrimSpace(out.String())
	if !strings.Contains(line, "Moved envd state to backup:") || !strings.Contains(line, "Next: envd init") {
		t.Fatalf("unexpected reset output: %q", out.String())
	}
	backup := ""
	for _, part := range strings.Fields(out.String()) {
		if strings.Contains(part, ".backup.") {
			backup = part
			break
		}
	}
	if backup == "" {
		t.Fatalf("backup path not found in output: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(backup, "state.enc")); err != nil {
		t.Fatalf("backup state.enc missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backup, "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should not keep stale lock, stat err=%v", err)
	}
}

func TestResetStateRequiresFullConfirmation(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	t.Setenv("ENVD_NONINTERACTIVE", "1")
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if err := a.run([]string{"reset-state"}); err == nil || !strings.Contains(err.Error(), "--delete --i-understand-this-deletes-envd-state --yes") {
		t.Fatalf("reset-state without --yes should fail, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.enc")); err != nil {
		t.Fatalf("state should remain after refused reset: %v", err)
	}
	if err := a.run([]string{"reset-state", "--delete", "--yes"}); err == nil || !strings.Contains(err.Error(), "--i-understand-this-deletes-envd-state") {
		t.Fatalf("reset-state without phrase should fail, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.enc")); err != nil {
		t.Fatalf("state should remain after refused reset: %v", err)
	}
}

func TestConfirmResetStateRequiresTypedPhrase(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	if err := withStdinText("wrong\n", func() error {
		return confirmResetState(io.Discard)
	}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected cancellation on wrong phrase, got %v", err)
	}
	if err := withStdinText("Remove envd state\n", func() error {
		return confirmResetState(io.Discard)
	}); err != nil {
		t.Fatalf("expected exact phrase to confirm, got %v", err)
	}
}

func withStdinText(text string, fn func() error) error {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	if _, err := w.WriteString(text); err != nil {
		_ = r.Close()
		_ = w.Close()
		return err
	}
	_ = w.Close()
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()
	return fn()
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestStateLockReclaimsDeadPID(t *testing.T) {
	stateDir := t.TempDir()
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stateDir, "state.lock")
	if err := os.WriteFile(lockPath, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	unlock, err := store.lock()
	if err != nil {
		t.Fatalf("stale lock was not reclaimed: %v", err)
	}
	defer unlock()

	raw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("lock file missing after reclaim: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != strconv.Itoa(os.Getpid()) {
		t.Fatalf("lock pid = %q, want current pid", got)
	}
}

func TestStateLockDoesNotStealLivePID(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stateDir, "state.lock")
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stale, err := staleStateLock(lockPath)
	if err != nil {
		t.Fatalf("live lock check failed: %v", err)
	}
	if stale {
		t.Fatalf("current process lock was treated as stale")
	}
}

func TestEncryptedStateDoesNotLeakSensitiveValues(t *testing.T) {
	stateDir := t.TempDir()
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	password := []byte("test-password")
	now := time.Now().UTC()
	st := envdState{
		SchemaVersion:     stateSchemaVersion,
		CreatedAt:         now,
		ActiveGateway:     "ams1",
		GatewayGeneration: 1,
		Gateways: map[string]gatewayRecord{
			"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{
				ServerIP:   "203.0.113.44",
				ServerPort: "443",
				Raw:        map[string]string{"XRAY_UUID": "00000000-0000-0000-0000-000000000000"},
			}, now),
		},
		Environments: map[string]envRecord{
			"books": {ID: "abc123def456", Network: "sealed", Storage: "plain", CreatedAt: now, UpdatedAt: now},
		},
		Identities: map[string]identityRecord{
			"github": {
				Name:       "github",
				Type:       "ssh",
				PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key\n-----END OPENSSH PRIVATE KEY-----",
				Policy:     defaultIdentityPolicy(),
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
		Events: []stateEvent{{Time: now, Kind: "env", Subject: "books", Message: "created sealed plain environment"}},
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.save(st, password); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("read state failed: %v", err)
	}
	for _, leaked := range []string{"books", "ams1", "203.0.113.44", "00000000-0000-0000-0000-000000000000", "created sealed", "github", "secret-key"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("encrypted state leaked %q in %s", leaked, raw)
		}
	}
	loaded, err := store.loadOrCreate(password)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.ActiveGateway != "ams1" || loaded.Gateways["ams1"].ServerIP != "203.0.113.44" || loaded.Environments["books"].Storage != "plain" || loaded.Identities["github"].PrivateKey == "" {
		t.Fatalf("state did not round trip: %+v", loaded)
	}
}

func validTestGatewayConfig(serverIP string) gatewayConfig {
	return gatewayConfig{
		BindIP:       "127.0.0.1",
		SOCKSPort:    11080,
		HTTPHostPort: 11081,
		SOCKSInner:   2088,
		HTTPInner:    2089,
		ServerIP:     serverIP,
		ServerPort:   "443",
		Raw: map[string]string{
			"XRAY_UUID":       "00000000-0000-0000-0000-000000000000",
			"XRAY_PUBLIC_KEY": "pub",
			"XRAY_SNI":        "example.com",
			"XRAY_SHORT_ID":   "abcd",
		},
	}
}

func TestProxyPrintsEffectivePorts(t *testing.T) {
	var out bytes.Buffer
	st := envdState{
		ActiveGateway: "ams1",
		Gateways: map[string]gatewayRecord{
			"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{
				BindIP:       "127.0.0.1",
				SOCKSPort:    11080,
				HTTPHostPort: 11081,
				ServerIP:     "1.2.3.4",
				ServerPort:   "443",
				Raw:          map[string]string{},
			}, time.Now().UTC()),
		},
	}
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runProxy(nil, &st); err != nil {
		t.Fatalf("proxy failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{"SOCKS: 127.0.0.1:11080", "HTTP:  127.0.0.1:11081"} {
		if !strings.Contains(got, want) {
			t.Fatalf("proxy output missing %q: %q", want, got)
		}
	}
}

func TestXrayProviderRender(t *testing.T) {
	root := t.TempDir()
	gwDir := filepath.Join(root, "deploy", "gateway")
	if err := os.MkdirAll(gwDir, 0o755); err != nil {
		t.Fatal(err)
	}
	template := `{"inbounds":[{"port":${XRAY_INBOUND_PORT}},{"port":${XRAY_HTTP_PROXY_PORT}}],"outbounds":[{"settings":{"vnext":[{"address":"${XRAY_SERVER_IP}","port":${XRAY_SERVER_PORT},"users":[{"id":"${XRAY_UUID}"}]}]},"streamSettings":{"realitySettings":{"publicKey":"${XRAY_PUBLIC_KEY}","serverName":"${XRAY_SNI}","shortId":"${XRAY_SHORT_ID}","fingerprint":"${XRAY_FINGERPRINT}"}}}]}`
	if err := os.WriteFile(filepath.Join(gwDir, "config.template.json"), []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := gatewayConfig{
		SOCKSInner: 2088,
		HTTPInner:  2089,
		ServerIP:   "1.2.3.4",
		ServerPort: "443",
		Raw: map[string]string{
			"XRAY_UUID":       "00000000-0000-0000-0000-000000000000",
			"XRAY_PUBLIC_KEY": "pub",
			"XRAY_SNI":        "example.com",
			"XRAY_SHORT_ID":   "abcd",
		},
	}

	rendered, err := (xrayProvider{}).Render(app{root: root}, cfg)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	if !json.Valid(rendered) {
		t.Fatalf("rendered config is invalid JSON: %s", rendered)
	}
	if strings.Contains(string(rendered), "${") {
		t.Fatalf("render left unresolved template variable: %s", rendered)
	}
	if !strings.Contains(string(rendered), `"fingerprint": "firefox"`) {
		t.Fatalf("render did not apply fingerprint default: %s", rendered)
	}
}

func TestXrayProviderRenderUsesEmbeddedTemplateWithoutRepo(t *testing.T) {
	cfg := gatewayConfig{
		SOCKSInner: 2088,
		HTTPInner:  2089,
		ServerIP:   "1.2.3.4",
		ServerPort: "443",
		Raw: map[string]string{
			"XRAY_UUID":       "00000000-0000-0000-0000-000000000000",
			"XRAY_PUBLIC_KEY": "pub",
			"XRAY_SNI":        "example.com",
			"XRAY_SHORT_ID":   "abcd",
		},
	}
	rendered, err := (xrayProvider{}).Render(app{root: t.TempDir()}, cfg)
	if err != nil {
		t.Fatalf("embedded render failed: %v", err)
	}
	if !json.Valid(rendered) {
		t.Fatalf("embedded rendered config is invalid JSON: %s", rendered)
	}
	if strings.Contains(string(rendered), "${") {
		t.Fatalf("embedded render left unresolved template variable: %s", rendered)
	}
}

func TestXrayProviderRenderMissingRequiredValue(t *testing.T) {
	root := t.TempDir()
	gwDir := filepath.Join(root, "deploy", "gateway")
	if err := os.MkdirAll(gwDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gwDir, "config.template.json"), []byte(`{"id":"${XRAY_UUID}"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (xrayProvider{}).Render(app{root: root}, gatewayConfig{Raw: map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "missing XRAY_SERVER_IP") {
		t.Fatalf("unexpected render error: %v", err)
	}
}

func TestGatewayRuntimeMaterializesWithoutEnvFile(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	cfg := gatewayConfig{
		BindIP:       "127.0.0.1",
		SOCKSPort:    11080,
		HTTPHostPort: 11081,
		SOCKSInner:   2088,
		HTTPInner:    2089,
		ServerIP:     "1.2.3.4",
		ServerPort:   "443",
		Raw: map[string]string{
			"XRAY_UUID":       "00000000-0000-0000-0000-000000000000",
			"XRAY_PUBLIC_KEY": "pub",
			"XRAY_SNI":        "example.com",
			"XRAY_SHORT_ID":   "abcd",
		},
	}
	dir, err := (app{root: t.TempDir()}).materializeGatewayRuntime(cfg)
	if err != nil {
		t.Fatalf("materialize gateway runtime failed: %v", err)
	}
	if !strings.HasPrefix(dir, dataDir) {
		t.Fatalf("runtime dir %q outside data dir %q", dir, dataDir)
	}
	configRaw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if !json.Valid(configRaw) {
		t.Fatalf("materialized config invalid JSON: %s", configRaw)
	}
	composeRaw, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatalf("compose not written: %v", err)
	}
	compose := string(composeRaw)
	for _, forbidden := range []string{"env_file", ".env", "${"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("compose contains manual env dependency %q:\n%s", forbidden, compose)
		}
	}
	for _, want := range []string{"name: vpn-gateway", "127.0.0.1:11080:2088", "127.0.0.1:11081:2089", "./config.json:/etc/xray/config.json:ro"} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose missing %q:\n%s", want, compose)
		}
	}
}

func TestActiveGatewayConfigRequiresEncryptedState(t *testing.T) {
	st := envdState{Gateways: map[string]gatewayRecord{}}
	_, _, err := (app{root: t.TempDir()}).activeGatewayConfig(&st)
	if err == nil || !strings.Contains(err.Error(), "no active gateway") {
		t.Fatalf("expected active gateway error, got %v", err)
	}
	if strings.ContainsAny(err.Error(), "`<>") {
		t.Fatalf("active gateway error is not paste-safe: %q", err.Error())
	}
}

func TestActiveGatewayConfigSuggestsReadyGateway(t *testing.T) {
	st := envdState{
		Gateways: map[string]gatewayRecord{
			"frankfurt2": {Name: "frankfurt2", ServerIP: "150.241.79.37", ServerPort: "443"},
		},
	}
	_, _, err := (app{root: t.TempDir()}).activeGatewayConfig(&st)
	if err == nil || !strings.Contains(err.Error(), "envd gateway use frankfurt2") {
		t.Fatalf("expected active gateway suggestion, got %v", err)
	}
}

func TestActiveGatewayConfigUsesEncryptedStateWithoutRepo(t *testing.T) {
	now := time.Now().UTC()
	cfg := gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{"XRAY_UUID": "uuid"}}
	st := envdState{
		ActiveGateway: "ams1",
		Gateways:      map[string]gatewayRecord{"ams1": gatewayRecordFromConfig("ams1", cfg, now)},
	}
	got, source, err := (app{root: t.TempDir()}).activeGatewayConfig(&st)
	if err != nil {
		t.Fatalf("active gateway from encrypted state failed: %v", err)
	}
	if source != "encrypted state" || got.ServerIP != "1.2.3.4" {
		t.Fatalf("unexpected active gateway: source=%q cfg=%+v", source, got)
	}
}

func TestPublishedPortMatches(t *testing.T) {
	if !publishedPortMatches("127.0.0.1:11080\n", 11080) {
		t.Fatal("expected localhost mapping to match")
	}
	if !publishedPortMatches("0.0.0.0:11080\n[::]:11080\n", 11080) {
		t.Fatal("expected wildcard mapping to match")
	}
	if publishedPortMatches("127.0.0.1:1080\n", 11080) {
		t.Fatal("unexpected stale mapping match")
	}
}

func TestNextActionForError(t *testing.T) {
	err := layerErr("local gateway", os.ErrNotExist)
	got := nextActionForError(err)
	if !strings.Contains(got, "envd gateway render") {
		t.Fatalf("unexpected next action: %q", got)
	}
}

func TestDiagnosticLayerMapping(t *testing.T) {
	cases := map[string]error{
		"host Docker":    errors.New("docker daemon unavailable: test"),
		"asset cache":    layerErr("asset cache", errors.New("missing image")),
		"local gateway":  layerErr("local gateway", errors.New("bad render")),
		"local proxy":    layerErr("local proxy", errors.New("bad socks")),
		"remote gateway": layerErr("remote gateway", errors.New("handshake failed")),
		"sealed sidecar": layerErr("sealed sidecar", errors.New("route failed")),
		"DNS":            layerErr("DNS", errors.New("lookup failed")),
		"egress policy":  layerErr("egress policy", errors.New("direct egress")),
		"state":          layerErr("state", errors.New("locked")),
	}
	for want, err := range cases {
		if got := diagnosticLayer(err); got != want {
			t.Fatalf("diagnosticLayer(%v) = %q, want %q", err, got, want)
		}
		if got := nextActionForError(err); got == "" && want != "state" {
			t.Fatalf("missing next action for %q", want)
		}
	}
}

func TestDiagnosticReleaseGateMappings(t *testing.T) {
	gates := map[string]error{
		"Broken Docker daemon":                 errors.New("docker daemon unavailable: test"),
		"Missing runtime image":                layerErr("asset cache", errors.New("cannot restore required image")),
		"Wrong SOCKS port":                     layerErr("local proxy", errors.New("cannot connect to 127.0.0.1:11080")),
		"TCP-open but bad SOCKS/HTTP protocol": layerErr("local proxy", errors.New("unexpected SOCKS greeting response")),
		"Remote server down":                   layerErr("remote gateway", errors.New("connect failed")),
		"Sidecar route failure":                layerErr("sealed sidecar", errors.New("HTTPS probe failed")),
		"DNS failure":                          layerErr("DNS", errors.New("lookup failed")),
		"Direct egress":                        layerErr("egress policy", errors.New("sealed egress differs from gateway egress")),
	}
	for name, err := range gates {
		layer := diagnosticLayer(err)
		if layer == "unknown" {
			t.Fatalf("%s mapped to unknown layer", name)
		}
		if nextActionForError(err) == "" {
			t.Fatalf("%s has no next action", name)
		}
	}
}

func TestRedactSensitive(t *testing.T) {
	input := strings.Join([]string{
		`uuid=00000000-0000-0000-0000-000000000000`,
		`password=hunter2`,
		`Authorization: Bearer abc.def.ghi`,
		"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
	}, "\n")
	got := redactSensitive(input)
	for _, leaked := range []string{
		"00000000-0000-0000-0000-000000000000",
		"hunter2",
		"abc.def.ghi",
		"secret\n-----END PRIVATE KEY-----",
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redaction leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "password=<redacted>") {
		t.Fatalf("redaction did not preserve key context: %q", got)
	}
}

func TestRedactDockerArgsHidesAuthorizedKey(t *testing.T) {
	args := []string{
		"run",
		"-e", "ENVD_AUTHORIZED_KEY=ssh-ed25519 AAAATEST envd",
		"-e", "DEV_USER=dev",
	}
	got := strings.Join(redactDockerArgs(args), " ")
	if strings.Contains(got, "AAAATEST") {
		t.Fatalf("authorized key leaked in docker args: %q", got)
	}
	if !strings.Contains(got, "ENVD_AUTHORIZED_KEY=<redacted>") {
		t.Fatalf("authorized key was not redacted: %q", got)
	}
	if !strings.Contains(got, "DEV_USER=dev") {
		t.Fatalf("non-sensitive arg was redacted: %q", got)
	}
}

func TestRecordAssetMetadataEvents(t *testing.T) {
	st := envdState{Assets: map[string]assetRecord{}}
	meta := assetRecord{Image: "sshdev:24.04", ImageID: "sha256:aaaaaaaaaaaa1111", UpdatedAt: time.Now().UTC()}

	recordAssetMetadata(&st, meta.Image, meta, false)
	if got := st.Assets[meta.Image].ImageID; got != meta.ImageID {
		t.Fatalf("asset image ID = %q", got)
	}
	if len(st.Events) != 1 || !strings.Contains(st.Events[0].Message, "restored sshdev:24.04") {
		t.Fatalf("missing restore event: %+v", st.Events)
	}

	recordAssetMetadata(&st, meta.Image, meta, true)
	if len(st.Events) != 1 {
		t.Fatalf("unchanged asset should not add event: %+v", st.Events)
	}

	updated := assetRecord{Image: meta.Image, ImageID: "sha256:bbbbbbbbbbbb2222", UpdatedAt: time.Now().UTC()}
	recordAssetMetadata(&st, updated.Image, updated, true)
	if len(st.Events) != 2 || !strings.Contains(st.Events[1].Message, "image drift") {
		t.Fatalf("missing drift event: %+v", st.Events)
	}
}

func TestAssetImagePathUsesEnvdDataDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dir)

	path, err := assetImagePath("registry.example.com/ns/image:1.2@sha256:abcd")
	if err != nil {
		t.Fatalf("assetImagePath failed: %v", err)
	}
	want := filepath.Join(dir, "assets", "images", "registry.example.com_ns_image_1.2_sha256_abcd.tar")
	if path != want {
		t.Fatalf("asset path = %q, want %q", path, want)
	}
}

func TestSafeAssetName(t *testing.T) {
	cases := map[string]string{
		"sshdev:24.04":                       "sshdev_24.04",
		"devnet-sidecar:1":                   "devnet-sidecar_1",
		"repo/image@sha256:abcdef":           "repo_image_sha256_abcdef",
		"  ../../weird image:tag with space": "weird_image_tag_with_space",
		"":                                   "image",
	}
	for input, want := range cases {
		if got := safeAssetName(input); got != want {
			t.Fatalf("safeAssetName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseProfilePackage(t *testing.T) {
	pkg, err := parseProfilePackage("apt:ffmpeg")
	if err != nil {
		t.Fatalf("parseProfilePackage failed: %v", err)
	}
	if pkg.Source != "apt" || pkg.Name != "ffmpeg" {
		t.Fatalf("unexpected package: %+v", pkg)
	}
	pkg, err = parseProfilePackage("pip:poetry")
	if err != nil {
		t.Fatalf("parse pip package failed: %v", err)
	}
	if pkg.Source != "pip" || pkg.Name != "poetry" {
		t.Fatalf("unexpected pip package: %+v", pkg)
	}
	if _, err := parseProfilePackage("gem:rails"); err == nil {
		t.Fatal("unsupported source accepted")
	}
	if _, err := parseProfilePackage("apt:bad package"); err == nil {
		t.Fatal("invalid package name accepted")
	}
}

func TestRunPkgAddCreatesProfileGeneration(t *testing.T) {
	st := envdState{Profiles: map[string]profileRecord{}}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.runPkgAdd([]string{"web", "apt:ffmpeg"}, &st); err != nil {
		t.Fatalf("pkg add failed: %v", err)
	}
	profile := st.Profiles["web"]
	if profile.ID == "" || profile.Generation != 1 || len(profile.Packages) != 1 || profile.Packages[0].Name != "ffmpeg" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if !strings.Contains(out.String(), "deferred until first use") {
		t.Fatalf("output missing lazy build note: %q", out.String())
	}
	if err := a.runPkgAdd([]string{"web", "apt:ffmpeg"}, &st); err != nil {
		t.Fatalf("duplicate pkg add failed: %v", err)
	}
	if st.Profiles["web"].Generation != 1 {
		t.Fatalf("duplicate package changed generation: %+v", st.Profiles["web"])
	}
}

func TestRunPkgListShowAndRemove(t *testing.T) {
	st := envdState{Profiles: map[string]profileRecord{}}
	a := app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runPkgAdd([]string{"web", "apt:ffmpeg"}, &st); err != nil {
		t.Fatal(err)
	}
	if err := a.runPkgAdd([]string{"web", "npm:pnpm"}, &st); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a.stdout = &out
	if err := a.runPkgList(nil, &st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PROFILE") || !strings.Contains(out.String(), "web") || !strings.Contains(out.String(), "apt:1,npm:1") {
		t.Fatalf("unexpected list output: %q", out.String())
	}
	out.Reset()
	if err := a.runPkgShow([]string{"web"}, &st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "apt:ffmpeg") || !strings.Contains(out.String(), "npm:pnpm") {
		t.Fatalf("unexpected show output: %q", out.String())
	}
	out.Reset()
	if err := a.runPkgRemove([]string{"web", "--yes"}, &st); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Profiles["web"]; ok {
		t.Fatalf("profile was not removed: %+v", st.Profiles)
	}
	if !strings.Contains(out.String(), "Removed profile: web") {
		t.Fatalf("unexpected remove output: %q", out.String())
	}
}

func TestPkgHelpShowsSingleApplyPath(t *testing.T) {
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	a.printPkgHelp()
	if !strings.Contains(out.String(), "envd start ENV --profile PROFILE") {
		t.Fatalf("pkg help should show start --profile apply flow: %q", out.String())
	}
	for _, forbidden := range []string{"envd pkg use", "envd pkg suggest", "envd pkg promote", "best-effort"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("pkg help should not show redundant command %q: %q", forbidden, out.String())
		}
	}
}

func TestRunPkgRemoveRefusesProfileInUse(t *testing.T) {
	st := envdState{
		Profiles:     map[string]profileRecord{"web": {Name: "web", ID: "abc123", Generation: 1}},
		Environments: map[string]envRecord{"books": {Profile: "web"}},
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	err := a.runPkgRemove([]string{"web", "--yes"}, &st)
	if err == nil || !strings.Contains(err.Error(), "used by env: books") {
		t.Fatalf("expected in-use error, got %v", err)
	}
	if _, ok := st.Profiles["web"]; !ok {
		t.Fatal("profile should not be removed while in use")
	}
}

func TestAddPackageToProfileDeduplicates(t *testing.T) {
	st := envdState{Profiles: map[string]profileRecord{}}
	pkg := profilePackage{Source: "apt", Name: "sl"}
	profile, changed, err := addPackageToProfile(&st, "tiny", pkg)
	if err != nil || !changed {
		t.Fatalf("addPackageToProfile = %+v %v %v", profile, changed, err)
	}
	profile, changed, err = addPackageToProfile(&st, "tiny", pkg)
	if err != nil {
		t.Fatalf("duplicate add failed: %v", err)
	}
	if changed || profile.Generation != 1 {
		t.Fatalf("duplicate changed profile: %+v changed=%v", profile, changed)
	}
}

func TestProfileImageNameUsesOpaqueID(t *testing.T) {
	got := profileImageName("abc123def456", 4)
	if got != "envd-profile-abc123def456:4" {
		t.Fatalf("profile image = %q", got)
	}
	if strings.Contains(got, "web") {
		t.Fatalf("profile image leaked human profile name: %q", got)
	}
}

func TestProfileDockerfile(t *testing.T) {
	profile := profileRecord{Packages: []profilePackage{
		{Source: "npm", Name: "pnpm"},
		{Source: "tool", Name: "rg"},
		{Source: "tool", Name: "codex"},
		{Source: "pip", Name: "poetry"},
		{Source: "apt", Name: "ffmpeg"},
	}}
	got := profileDockerfile(profile)
	for _, want := range []string{
		"FROM " + devImage,
		"apt-get install",
		"'ffmpeg'",
		"'nodejs'",
		"'npm'",
		"'ripgrep'",
		"'python3'",
		"'python3-pip'",
		"'python3-venv'",
		"npm install -g 'pnpm'",
		"'@openai/codex'",
		"python3 -m pip install --break-system-packages 'poetry'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Dockerfile missing %q:\n%s", want, got)
		}
	}
}

func TestDevContainerArgsBlockHostDockerAndHostAccessByDefault(t *testing.T) {
	t.Setenv("ENVD_DOCKER_SOCKET", "none")
	args, err := devContainerRunArgs("books", "dev", "abc123", "envd-abc123-dev", "envd-abc123-net", "plain", "envd-abc123-home", "envd-abc123-repo", "sealed", devImage, "ssh-ed25519 AAAATEST envd")
	if err != nil {
		t.Fatalf("devContainerRunArgs failed: %v", err)
	}
	got := strings.Join(args, " ")
	for _, forbidden := range []string{
		"/var/run/docker.sock",
		"--privileged",
		"--network host",
		"--pid host",
		"--ipc host",
		"--mount type=bind",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("dev container args include forbidden host access %q: %q", forbidden, got)
		}
	}
	for _, want := range []string{
		"--network container:envd-abc123-net",
		"-v envd-abc123-home:/home/dev",
		"-v envd-abc123-repo:/home/dev/repo",
		"-e ENVD_SEALED_DNS=1",
		"-e ENVD_ENV_NAME=books",
		"-e ENVD_ENV_ID=abc123",
		"-e ENVD_AUTHORIZED_KEY=ssh-ed25519 AAAATEST envd",
		"--label envd.name=books",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("dev container args missing %q: %q", want, got)
		}
	}
	args, err = devContainerRunArgs("books", "dev", "abc123", "envd-abc123-dev", "envd-abc123-net", "plain", "envd-abc123-home", "envd-abc123-repo", "direct", devImage, "")
	if err != nil {
		t.Fatalf("direct devContainerRunArgs failed: %v", err)
	}
	directArgs := strings.Join(args, " ")
	if strings.Contains(directArgs, "--network host") {
		t.Fatalf("direct mode used host networking: %q", directArgs)
	}
	if strings.Contains(directArgs, "ENVD_SEALED_DNS=1") {
		t.Fatalf("direct mode enabled sealed DNS rewrite: %q", directArgs)
	}
	if strings.Contains(directArgs, "DOCKER_HOST=") {
		t.Fatalf("direct mode enabled Docker socket despite opt-out: %q", directArgs)
	}
}

func TestDevContainerArgsExposeHostDockerSocketWhenAvailable(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()
	t.Setenv("ENVD_DOCKER_SOCKET", socketPath)

	args, err := devContainerRunArgs("books", "dev", "abc123", "envd-abc123-dev", "envd-abc123-net", "plain", "envd-abc123-home", "envd-abc123-repo", "sealed", devImage, "")
	if err != nil {
		t.Fatalf("devContainerRunArgs failed: %v", err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-v " + socketPath + ":/var/run/docker.sock",
		"-e DOCKER_HOST=unix:///var/run/docker.sock",
		"-e DOCKER_TLS_VERIFY=",
		"-e DOCKER_CERT_PATH=",
		"-e COMPOSE_PROJECT_NAME=envd_books",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("dev container args missing %q: %q", want, got)
		}
	}
}

func TestSidecarKillSwitchPinsPreTunnelGateway(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "assets", "containers", "net-sidecar", "entrypoint.sh"))
	if err != nil {
		t.Fatalf("read sidecar entrypoint: %v", err)
	}
	got := string(raw)
	for _, want := range []string{
		`XRAY_ADDR_FILE="/run/envd-xray-addr"`,
		`printf '%s\n' "${XRAY_ADDR}" >"${XRAY_ADDR_FILE}"`,
		`-d "${XRAY_ADDR}" --dport "${XRAY_PORT}"`,
		`-d "${XRAY_ADDR}" --dport "${XRAY_HTTP_PORT}"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sidecar entrypoint missing %q", want)
		}
	}
	if strings.Contains(got, `-o "${uplink_dev}" -p tcp --dport "${XRAY_PORT}"`) {
		t.Fatalf("sidecar kill-switch allows pre-tunnel port without destination pin")
	}
}

func TestSidecarHealthcheckUsesResolvedGatewayIP(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "assets", "containers", "net-sidecar", "Dockerfile"))
	if err != nil {
		t.Fatalf("read sidecar Dockerfile: %v", err)
	}
	got := string(raw)
	for _, want := range []string{
		"--interval=5s",
		"--retries=2",
		`test -s /run/envd-xray-addr`,
		`nc -z -w 2 "$(cat /run/envd-xray-addr)" "${XRAY_PORT:-2088}"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sidecar Dockerfile missing %q", want)
		}
	}
	if strings.Contains(got, `"${XRAY_HOST:-xray}" "${XRAY_PORT:-2088}"`) {
		t.Fatalf("sidecar healthcheck resolves Docker DNS after resolv.conf is sealed")
	}
}

func TestSSHDevEntrypointInstallsEnvdAuthorizedKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "assets", "containers", "sshdev", "entrypoint.sh"))
	if err != nil {
		t.Fatalf("read sshdev entrypoint: %v", err)
	}
	got := string(raw)
	for _, want := range []string{
		`ENVD_AUTHORIZED_KEY="${ENVD_AUTHORIZED_KEY:-}"`,
		`AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"`,
		`grep -qxF "$ENVD_AUTHORIZED_KEY" "$AUTHORIZED_KEYS"`,
		`chmod 600 "$AUTHORIZED_KEYS"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sshdev entrypoint missing %q", want)
		}
	}
}

func TestEmbeddedAssetContextMaterializesWithoutRepo(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	dir, err := materializeEmbeddedAssetContext(sidecarImage, "containers/net-sidecar")
	if err != nil {
		t.Fatalf("materialize embedded context failed: %v", err)
	}
	if !strings.HasPrefix(dir, dataDir) {
		t.Fatalf("context dir %q outside data dir %q", dir, dataDir)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("embedded Dockerfile missing: %v", err)
	}
	if !strings.Contains(string(raw), "sing-box") || !strings.Contains(string(raw), "ENTRYPOINT") {
		t.Fatalf("unexpected embedded Dockerfile: %s", raw)
	}
}

func TestParseRunArgsProfile(t *testing.T) {
	opts, err := parseRunArgs([]string{"books", "--profile", "web", "--network=direct"})
	if err != nil {
		t.Fatalf("parseRunArgs failed: %v", err)
	}
	if opts.Name != "books" || opts.Network != "direct" || opts.Storage != "plain" || opts.Profile != "web" {
		t.Fatalf("unexpected args: %+v", opts)
	}
	if !opts.NetworkExplicit || !opts.ProfileExplicit || opts.StorageExplicit {
		t.Fatalf("unexpected explicit flags: %+v", opts)
	}
}

func TestDevContainerArgsProtectedStorageUsesEnvdVolumes(t *testing.T) {
	args, err := devContainerRunArgs("books", "dev", "abc123", "envd-abc123-dev", "envd-abc123-net", "protected", "envd-abc123-home", "envd-abc123-repo", "offline", devImage, "")
	if err != nil {
		t.Fatalf("protected devContainerRunArgs failed: %v", err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"--label envd.storage=protected",
		"-v envd-abc123-home:/home/dev",
		"-v envd-abc123-repo:/home/dev/repo",
		"--network none",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("protected dev container args missing %q: %q", want, got)
		}
	}
	for _, forbidden := range []string{"/var/run/docker.sock", "--privileged", "--network host"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("protected dev container args include forbidden host access %q: %q", forbidden, got)
		}
	}
}

func TestProtectedStorageBackendSelection(t *testing.T) {
	rec, err := newProtectedStorageRecord("abc123")
	if err != nil {
		t.Fatalf("newProtectedStorageRecord failed: %v", err)
	}
	switch runtime.GOOS {
	case "darwin":
		if rec.Backend != "apfs-sparseimage" || !strings.HasSuffix(rec.ImagePath, "storage.sparseimage") {
			t.Fatalf("unexpected darwin protected backend: %+v", rec)
		}
	case "linux":
		if rec.Backend != "luks2-dmcrypt" || !strings.HasSuffix(rec.ImagePath, "storage.luks") {
			t.Fatalf("unexpected linux protected backend: %+v", rec)
		}
	default:
		if rec.Backend == "" {
			t.Fatalf("backend should be explicit even when unsupported: %+v", rec)
		}
	}
}

func TestValidateEnvNameAllowsHyphens(t *testing.T) {
	for _, name := range []string{"books", "sealed-storage-test", "dev1-test2"} {
		if err := validateEnvName(name); err != nil {
			t.Fatalf("valid env name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"-bad", "bad-", "Bad", "bad_name", "bad.name"} {
		if err := validateEnvName(name); err == nil {
			t.Fatalf("invalid env name %q accepted", name)
		}
	}
}

func TestParseProjectManifest(t *testing.T) {
	manifest, err := parseProjectManifest([]byte("network: direct\nstorage: plain\nprofile: web\n"))
	if err != nil {
		t.Fatalf("parseProjectManifest failed: %v", err)
	}
	if manifest.Network != "direct" || manifest.Storage != "plain" || manifest.Profile != "web" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if _, err := parseProjectManifest([]byte("network: leaked\n")); err == nil {
		t.Fatal("invalid network accepted")
	}
	if _, err := parseProjectManifest([]byte("unknown: value\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestApplyProjectManifestDefaults(t *testing.T) {
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	if err := os.WriteFile(filepath.Join(dir, ".envd.yaml"), []byte("network: direct\nprofile: web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	opts := runOptions{Name: "books", Network: "sealed", Storage: "plain"}
	if err := applyProjectManifestDefaults(&opts); err != nil {
		t.Fatalf("applyProjectManifestDefaults failed: %v", err)
	}
	if opts.Network != "direct" || opts.Profile != "web" {
		t.Fatalf("manifest defaults not applied: %+v", opts)
	}
	opts = runOptions{Name: "books", Network: "offline", Storage: "plain", NetworkExplicit: true}
	if err := applyProjectManifestDefaults(&opts); err != nil {
		t.Fatalf("applyProjectManifestDefaults explicit failed: %v", err)
	}
	if opts.Network != "offline" || opts.Profile != "web" {
		t.Fatalf("explicit network was not preserved: %+v", opts)
	}
}

func TestParseMigrateProfileArgs(t *testing.T) {
	name, profile, err := parseMigrateProfileArgs([]string{"books", "--profile", "web"})
	if err != nil {
		t.Fatalf("parseMigrateProfileArgs failed: %v", err)
	}
	if name != "books" || profile != "web" {
		t.Fatalf("unexpected migrate args: %q %q", name, profile)
	}
	if _, _, err := parseMigrateProfileArgs([]string{"books", "web"}); err == nil {
		t.Fatal("invalid migrate args accepted")
	}
}

func TestEnvIssueGatewayGenerationMismatch(t *testing.T) {
	env := envInspect{GatewayGeneration: 1}
	if got := env.issue(2); got != "gateway generation mismatch" {
		t.Fatalf("issue = %q", got)
	}
}

func TestSortedEnvNames(t *testing.T) {
	st := envdState{Environments: map[string]envRecord{
		"zeta":  {},
		"alpha": {},
	}}
	got := sortedEnvNames(&st)
	if strings.Join(got, ",") != "alpha,zeta" {
		t.Fatalf("sorted env names = %+v", got)
	}
}

func TestLegacyEnvironmentRecordStaysPlainStorage(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Environments: map[string]envRecord{
		"books": {
			ID:        "books",
			Network:   "sealed",
			Storage:   "plain",
			Legacy:    true,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}}
	ref, err := resolveEnvRef(&st, "books")
	if err != nil {
		t.Fatalf("resolve legacy env failed: %v", err)
	}
	if !ref.Legacy || ref.HomeVol != "books-home" || ref.RepoVol != "books-repo" {
		t.Fatalf("unexpected legacy ref: %+v", ref)
	}
	if st.Environments["books"].Storage != "plain" {
		t.Fatalf("legacy storage changed: %+v", st.Environments["books"])
	}
}

func TestLockStopsAllRecordedWorkloads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	socket := filepath.Join(t.TempDir(), "unlock.sock")
	t.Setenv("ENVD_UNLOCK_SOCKET", socket)
	done := make(chan error, 1)
	go func() { done <- serveUnlockAgent(socket) }()
	waitForFile(t, socket)
	if err := cacheMasterPassword([]byte("cached-password"), time.Minute); err != nil {
		t.Fatalf("cache password failed: %v", err)
	}
	if got, ok := cachedMasterPassword(); !ok || string(got) != "cached-password" {
		t.Fatalf("expected cached password before lock, ok=%v got=%q", ok, string(got))
	}

	now := time.Now().UTC()
	st := envdState{Environments: map[string]envRecord{
		"books": {ID: "abc123", Network: "sealed", Storage: "plain", CreatedAt: now, UpdatedAt: now},
		"apps":  {ID: "def456", Network: "direct", Storage: "plain", CreatedAt: now, UpdatedAt: now},
	}}
	var stopped []string
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	err := a.lockEnvdWithStopper(nil, &st, func(ref envRef) error {
		stopped = append(stopped, ref.DevName+"/"+ref.NetName)
		return nil
	})
	if err != nil {
		t.Fatalf("lock failed: %v", err)
	}
	if strings.Join(stopped, ",") != "envd-def456-dev/envd-def456-net,envd-abc123-dev/envd-abc123-net" {
		t.Fatalf("unexpected stop order/refs: %+v", stopped)
	}
	if !strings.Contains(out.String(), "Locked: 2 envs") {
		t.Fatalf("unexpected lock output: %q", out.String())
	}
	if len(st.Events) != 3 || !strings.Contains(st.Events[2].Message, "completed: stopped 2 workloads; failed 0") {
		t.Fatalf("missing lock completion event: %+v", st.Events)
	}
	if got, ok := cachedMasterPassword(); ok {
		t.Fatalf("lock should clear cached password, got %q", string(got))
	}
	envdConfig := filepath.Join(home, ".ssh", "envd_config")
	raw, err := os.ReadFile(envdConfig)
	if err != nil {
		t.Fatalf("read hidden envd ssh config: %v", err)
	}
	if strings.Contains(string(raw), "Host books") || strings.Contains(string(raw), "Host apps") {
		t.Fatalf("lock should hide envd SSH hosts:\n%s", raw)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unlock agent failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("unlock agent did not exit after lock cleared cache")
	}
}

func TestLockReportsFailedWorkloadAndKeepsGoing(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Environments: map[string]envRecord{
		"books": {ID: "abc123", Network: "sealed", Storage: "plain", CreatedAt: now, UpdatedAt: now},
		"apps":  {ID: "def456", Network: "direct", Storage: "plain", CreatedAt: now, UpdatedAt: now},
	}}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	err := a.lockEnvdWithStopper(nil, &st, func(ref envRef) error {
		if ref.Name == "books" {
			return errors.New("simulated stop failure")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "lock completed with 1 failures") {
		t.Fatalf("expected lock failure, got %v", err)
	}
	if !strings.Contains(out.String(), "Failed: 1") {
		t.Fatalf("unexpected lock output: %q", out.String())
	}
	if len(st.Events) != 3 || !strings.Contains(st.Events[1].Message, "failed to stop workload") {
		t.Fatalf("missing failed lock event: %+v", st.Events)
	}
}

func TestDevStartCommandsRestartSealedDevAfterSidecar(t *testing.T) {
	sealed := devStartCommandsForMode("sealed", "envd-abc-dev")
	if got := fmt.Sprint(sealed); got != "[[start envd-abc-dev] [restart -t 1 envd-abc-dev]]" {
		t.Fatalf("sealed start commands = %s", got)
	}
	direct := devStartCommandsForMode("direct", "envd-abc-dev")
	if got := fmt.Sprint(direct); got != "[[start envd-abc-dev]]" {
		t.Fatalf("direct start commands = %s", got)
	}
}

func TestRecoveryPointPruningKeepsLatestPerEnv(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.enc")
	newPath := filepath.Join(dir, "new.enc")
	otherPath := filepath.Join(dir, "other.enc")
	for _, path := range []string{oldPath, newPath, otherPath} {
		if err := os.WriteFile(path, []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	st := envdState{RecoveryPoints: []recoveryPointRecord{
		{ID: "old", EnvID: "env1", Path: oldPath, CreatedAt: now.Add(-time.Hour)},
		{ID: "new", EnvID: "env1", Path: newPath, CreatedAt: now},
		{ID: "other", EnvID: "env2", Path: otherPath, CreatedAt: now.Add(-2 * time.Hour)},
	}}
	pruneRecoveryPoints(&st)
	if len(st.RecoveryPoints) != 2 {
		t.Fatalf("recovery point count = %d", len(st.RecoveryPoints))
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old recovery point was not removed: %v", err)
	}
	for _, path := range []string{newPath, otherPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("kept recovery point missing %s: %v", path, err)
		}
	}
}

func TestRemoveRecoveryPointsForEnvDeletesFiles(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	envDir := filepath.Join(dataDir, "recovery", "env1")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	removePath := filepath.Join(envDir, "remove.enc")
	keepPath := filepath.Join(dataDir, "keep.enc")
	if err := os.WriteFile(removePath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keepPath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := envdState{RecoveryPoints: []recoveryPointRecord{
		{ID: "remove", EnvID: "env1", Path: removePath},
		{ID: "keep", EnvID: "env2", Path: keepPath},
	}}
	removeRecoveryPointsForEnv(&st, "env1")
	if len(st.RecoveryPoints) != 1 || st.RecoveryPoints[0].ID != "keep" {
		t.Fatalf("unexpected recovery points after removal: %+v", st.RecoveryPoints)
	}
	if _, err := os.Stat(removePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("env recovery point file was not removed: %v", err)
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("unrelated recovery point removed: %v", err)
	}
}

func TestSupervisorIdleParsingAndNextDelay(t *testing.T) {
	idle, err := parseSupervisorIdle([]string{"--idle", "4h"})
	if err != nil {
		t.Fatalf("parse idle failed: %v", err)
	}
	if idle != 4*time.Hour {
		t.Fatalf("idle = %s", idle)
	}
	if _, err := parseSupervisorIdle([]string{"--idle", "10m"}); err == nil {
		t.Fatal("accepted unsafe short idle duration")
	}
	now := time.Unix(10000, 0).UTC()
	st := envdState{Environments: map[string]envRecord{
		"soon": {LastUsedAt: now.Add(-2*time.Hour - 50*time.Minute)},
		"late": {LastUsedAt: now.Add(-time.Hour)},
	}}
	if got := supervisorNextDelay(&st, 3*time.Hour, now); got != 10*time.Minute {
		t.Fatalf("next delay = %s", got)
	}
	st.Environments["overdue"] = envRecord{LastUsedAt: now.Add(-4 * time.Hour)}
	if got := supervisorNextDelay(&st, 3*time.Hour, now); got > time.Millisecond {
		t.Fatalf("overdue delay should wake immediately, got %s", got)
	}
	if got := supervisorNextDelay(&envdState{}, 3*time.Hour, now); got != time.Hour {
		t.Fatalf("empty state delay = %s", got)
	}
}

func TestSupervisorTickStopsOnlyIdleRunningWorkloads(t *testing.T) {
	now := time.Unix(10000, 0).UTC()
	st := envdState{Environments: map[string]envRecord{
		"idle":   {ID: "aaa111", Network: "sealed", Storage: "plain", LastUsedAt: now.Add(-4 * time.Hour)},
		"active": {ID: "bbb222", Network: "sealed", Storage: "plain", LastUsedAt: now.Add(-time.Hour)},
		"stopped": {ID: "ccc333", Network: "sealed", Storage: "plain",
			LastUsedAt: now.Add(-5 * time.Hour)},
	}}
	var stopped []string
	count, err := supervisorTick(&st, 3*time.Hour, now, func(ref envRef) (bool, error) {
		return ref.Name != "stopped", nil
	}, func(ref envRef) error {
		stopped = append(stopped, ref.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("supervisor tick failed: %v", err)
	}
	if count != 1 || strings.Join(stopped, ",") != "idle" {
		t.Fatalf("unexpected stopped workloads count=%d stopped=%+v", count, stopped)
	}
	if st.Environments["active"].UpdatedAt.Equal(now) {
		t.Fatal("active env was updated unexpectedly")
	}
	if !st.Environments["idle"].UpdatedAt.Equal(now) {
		t.Fatalf("idle env was not touched: %+v", st.Environments["idle"])
	}
	if len(st.Events) != 1 || !strings.Contains(st.Events[0].Message, "idle auto-stopped") {
		t.Fatalf("missing supervisor event: %+v", st.Events)
	}
}

func TestRuntimeIdleTickDoesNotStopActiveSession(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	now := time.Unix(10000, 0).UTC()
	if err := saveRuntimeAccess(runtimeAccessState{Routes: map[string]runtimeSSHRoute{
		"books": {Name: "books", ID: "abc123", DevName: "envd-abc123-dev", UserName: "dev", Network: "sealed", Storage: "plain", UpdatedAt: now.Add(-3 * time.Hour)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := touchRuntimeActivity("books", now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stopSession, err := startRuntimeSession("books", "ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer stopSession()
	var stopped []string
	count, err := runtimeIdleTick(defaultIdleTimeout, now, func(runtimeSSHRoute) bool {
		return true
	}, func(route runtimeSSHRoute) error {
		stopped = append(stopped, route.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("idle tick failed: %v", err)
	}
	if count != 0 || len(stopped) != 0 {
		t.Fatalf("active session was stopped: count=%d stopped=%v", count, stopped)
	}
}

func TestRuntimeIdleTickStopsDisconnectedOldEnv(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	now := time.Unix(10000, 0).UTC()
	if err := saveRuntimeAccess(runtimeAccessState{Routes: map[string]runtimeSSHRoute{
		"idle":   {Name: "idle", ID: "aaa111", DevName: "envd-aaa111-dev", UserName: "dev", Network: "sealed", Storage: "plain", UpdatedAt: now.Add(-3 * time.Hour)},
		"recent": {Name: "recent", ID: "bbb222", DevName: "envd-bbb222-dev", UserName: "dev", Network: "sealed", Storage: "plain", UpdatedAt: now.Add(-time.Hour)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := touchRuntimeActivity("idle", now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := touchRuntimeActivity("recent", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var stopped []string
	count, err := runtimeIdleTick(defaultIdleTimeout, now, func(runtimeSSHRoute) bool {
		return true
	}, func(route runtimeSSHRoute) error {
		stopped = append(stopped, route.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("idle tick failed: %v", err)
	}
	if count != 1 || strings.Join(stopped, ",") != "idle" {
		t.Fatalf("unexpected idle stops: count=%d stopped=%v", count, stopped)
	}
}

func TestOpportunisticIdleSweepHonorsPreference(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ENVD_DATA_DIR", dataDir)
	now := time.Unix(10000, 0).UTC()
	if err := saveRuntimeAccess(runtimeAccessState{Routes: map[string]runtimeSSHRoute{
		"idle": {Name: "idle", ID: "aaa111", DevName: "envd-aaa111-dev", UserName: "dev", Network: "sealed", Storage: "plain", UpdatedAt: now.Add(-3 * time.Hour)},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := touchRuntimeActivity("idle", now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := setIdleSchedulerEnabled(false); err != nil {
		t.Fatal(err)
	}
	count, err := opportunisticIdleSweep(now, func(runtimeSSHRoute) bool {
		return true
	}, func(runtimeSSHRoute) error {
		t.Fatal("disabled idle sweep stopped an env")
		return nil
	})
	if err != nil || count != 0 {
		t.Fatalf("disabled sweep count=%d err=%v", count, err)
	}
	if err := setIdleSchedulerEnabled(true); err != nil {
		t.Fatal(err)
	}
	var stopped []string
	count, err = opportunisticIdleSweep(now, func(runtimeSSHRoute) bool {
		return true
	}, func(route runtimeSSHRoute) error {
		stopped = append(stopped, route.Name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || strings.Join(stopped, ",") != "idle" {
		t.Fatalf("enabled sweep did not stop idle env: count=%d stopped=%v", count, stopped)
	}
}

func TestTouchEnvUsed(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Environments: map[string]envRecord{"books": {ID: "abc123"}}}
	touchEnvUsed(&st, "books", now)
	if !st.Environments["books"].LastUsedAt.Equal(now) || !st.Environments["books"].UpdatedAt.Equal(now) {
		t.Fatalf("env not touched: %+v", st.Environments["books"])
	}
	touchEnvUsed(&st, "missing", now.Add(time.Hour))
	if len(st.Environments) != 1 {
		t.Fatalf("missing env touch created a record: %+v", st.Environments)
	}
}

func TestPrepareShellDockerArgs(t *testing.T) {
	st := envdState{Environments: map[string]envRecord{
		"books":  {ID: "abc123", Network: "direct"},
		"sealed": {ID: "def456", Network: "sealed"},
	}}
	args, err := prepareShellDockerArgs([]string{"books", "whoami"}, &st)
	if err != nil {
		t.Fatalf("prepareShellDockerArgs failed: %v", err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{"exec", "-u dev", "-w /home/dev/repo", "envd-abc123-dev", "whoami"} {
		if !strings.Contains(got, want) {
			t.Fatalf("docker args missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "DOCKER_HOST=") {
		t.Fatalf("direct shell received managed Docker endpoint: %q", got)
	}

	args, err = prepareShellDockerArgs([]string{"sealed", "docker", "info"}, &st)
	if err != nil {
		t.Fatalf("prepareShellDockerArgs sealed failed: %v", err)
	}
	got = strings.Join(args, " ")
	for _, want := range []string{
		"envd-def456-dev",
		"docker info",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sealed docker args missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "DOCKER_HOST=") || strings.Contains(got, "COMPOSE_PROJECT_NAME=") {
		t.Fatalf("shell exec should not inject Docker endpoint envs: %q", got)
	}
}

func TestShellCommandWithEphemeralSSHAgent(t *testing.T) {
	command := shellCommandWithEphemeralSSHAgent([]string{"git", "clone", "git@github.com:owner/repo.git", "."})
	got := strings.Join(command, " ")
	for _, want := range []string{"sh -lc", "ssh-agent -s", "ssh-add -", "unset ENVD_IDENTITY_KEY_B64", "exec 'git' 'clone'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("wrapped shell command missing %q:\n%s", want, got)
		}
	}
}

func TestShellCommandWithEphemeralGitHTTPSHelper(t *testing.T) {
	command := shellCommandWithEphemeralGitHTTPSHelper([]string{"git", "clone", "https://github.com/owner/repo.git", "."})
	got := strings.Join(command, " ")
	for _, want := range []string{"sh -lc", "GIT_CONFIG_KEY_0=credential.helper", "ENVD_GIT_HTTPS_USERNAME", "ENVD_GIT_HTTPS_PASSWORD_B64", "exec 'git' 'clone'"} {
		if !strings.Contains(got, want) {
			t.Fatalf("wrapped git https command missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret-token") {
		t.Fatalf("wrapped git https command leaked token: %s", got)
	}
}

func TestPrepareShellDockerArgsInjectsGitHTTPSIdentity(t *testing.T) {
	oldHealth := shellIdentityBrokerHealth
	shellIdentityBrokerHealth = func(*envdState, string) identityBrokerHealth {
		return func() error { return nil }
	}
	defer func() { shellIdentityBrokerHealth = oldHealth }()
	st := envdState{
		GatewayGeneration: 1,
		Environments: map[string]envRecord{
			"books": {ID: "abc123", Network: "sealed", GatewayGeneration: 1},
		},
		Identities: map[string]identityRecord{
			"githubhttps": {
				Name:     "githubhttps",
				Type:     "git-https",
				Username: "alice",
				Password: "secret-token",
				Policy:   defaultIdentityPolicy(),
			},
		},
	}
	args, err := prepareShellDockerArgs([]string{"books", "git", "clone", "https://github.com/owner/repo.git", "."}, &st)
	if err != nil {
		t.Fatalf("prepareShellDockerArgs failed: %v", err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{"ENVD_GIT_HTTPS_USERNAME=alice", "ENVD_GIT_HTTPS_PASSWORD_B64=", "credential.helper"} {
		if !strings.Contains(got, want) {
			t.Fatalf("git https shell args missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret-token") {
		t.Fatalf("git https shell args leaked token: %s", got)
	}
}

func TestGatewayRecordRoundTrip(t *testing.T) {
	cfg := gatewayConfig{
		BindIP:       "127.0.0.1",
		SOCKSPort:    11080,
		HTTPHostPort: 11081,
		SOCKSInner:   2088,
		HTTPInner:    2089,
		ServerIP:     "1.2.3.4",
		ServerPort:   "443",
		Raw:          map[string]string{"XRAY_UUID": "00000000-0000-0000-0000-000000000000"},
	}
	rec := gatewayRecordFromConfig("ams1", cfg, time.Now().UTC())
	got := rec.toConfig()
	if got.ServerIP != cfg.ServerIP || got.SOCKSPort != cfg.SOCKSPort || got.Raw["XRAY_UUID"] != cfg.Raw["XRAY_UUID"] {
		t.Fatalf("gateway config did not round trip: %+v", got)
	}
	got.Raw["XRAY_UUID"] = "changed"
	if rec.Raw["XRAY_UUID"] == "changed" {
		t.Fatal("gateway raw map was not copied")
	}
}

func TestGatewayUserURI(t *testing.T) {
	cfg := gatewayConfig{
		ServerIP:   "1.2.3.4",
		ServerPort: "443",
		Raw: map[string]string{
			"XRAY_UUID":        "00000000-0000-0000-0000-000000000000",
			"XRAY_PUBLIC_KEY":  "pub",
			"XRAY_SNI":         "www.example.com",
			"XRAY_SHORT_ID":    "abcd",
			"XRAY_FINGERPRINT": "firefox",
		},
	}
	uri, err := gatewayUserURI("ams1", cfg)
	if err != nil {
		t.Fatalf("gatewayUserURI failed: %v", err)
	}
	for _, want := range []string{
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?",
		"security=reality",
		"type=tcp",
		"encryption=none",
		"flow=xtls-rprx-vision",
		"sni=www.example.com",
		"fp=firefox",
		"pbk=pub",
		"sid=abcd",
		"#ams1",
	} {
		if !strings.Contains(uri, want) {
			t.Fatalf("URI missing %q: %s", want, uri)
		}
	}
}

func TestGatewayShareURILabelUsesHyphen(t *testing.T) {
	cfg := gatewayConfig{
		ServerIP:   "1.2.3.4",
		ServerPort: "443",
		Raw: map[string]string{
			"XRAY_PUBLIC_KEY": "pub",
			"XRAY_SNI":        "www.example.com",
			"XRAY_SHORT_ID":   "abcd",
		},
	}
	uri, err := gatewayUserURIForUUID(gatewayShareURILabel("frankfurt2", "mac"), cfg, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("gatewayUserURIForUUID failed: %v", err)
	}
	if !strings.Contains(uri, "#frankfurt2-mac") {
		t.Fatalf("share URI should use hyphen label: %s", uri)
	}
	if strings.Contains(uri, "%2F") {
		t.Fatalf("share URI should not encode slash in label: %s", uri)
	}
}

func TestGatewayShareURIReprintsExistingShare(t *testing.T) {
	st := &envdState{
		Gateways: map[string]gatewayRecord{
			"frankfurt2": {
				Name:       "frankfurt2",
				ServerIP:   "1.2.3.4",
				ServerPort: "443",
				Raw: map[string]string{
					"XRAY_UUID":        "00000000-0000-4000-8000-000000000000",
					"XRAY_PUBLIC_KEY":  "pub",
					"XRAY_SNI":         "www.example.com",
					"XRAY_SHORT_ID":    "abcd",
					"XRAY_FINGERPRINT": "firefox",
				},
			},
		},
		GatewayShares: map[string][]gatewayShareRecord{
			"frankfurt2": {
				{Name: "mac", UUID: "11111111-1111-4111-8111-111111111111"},
			},
		},
	}
	uri, err := gatewayShareURI(st, "frankfurt2", "mac")
	if err != nil {
		t.Fatalf("gatewayShareURI failed: %v", err)
	}
	if !strings.Contains(uri, "vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?") {
		t.Fatalf("share URI used wrong UUID or address: %s", uri)
	}
	if !strings.Contains(uri, "#frankfurt2-mac") {
		t.Fatalf("share URI used wrong label: %s", uri)
	}
}

func TestGatewayShareURIReprintsDefaultShare(t *testing.T) {
	st := &envdState{
		Gateways: map[string]gatewayRecord{
			"frankfurt2": {
				Name:       "frankfurt2",
				ServerIP:   "1.2.3.4",
				ServerPort: "443",
				Raw: map[string]string{
					"XRAY_UUID":        "00000000-0000-4000-8000-000000000000",
					"XRAY_PUBLIC_KEY":  "pub",
					"XRAY_SNI":         "www.example.com",
					"XRAY_SHORT_ID":    "abcd",
					"XRAY_FINGERPRINT": "firefox",
				},
			},
		},
	}
	uri, err := gatewayShareURI(st, "frankfurt2", "default")
	if err != nil {
		t.Fatalf("gatewayShareURI failed: %v", err)
	}
	if !strings.Contains(uri, "vless://00000000-0000-4000-8000-000000000000@1.2.3.4:443?") {
		t.Fatalf("default URI used wrong UUID or address: %s", uri)
	}
	if !strings.Contains(uri, "#frankfurt2") {
		t.Fatalf("default URI used wrong label: %s", uri)
	}
}

func TestGatewayUserURIMissingRequiredValue(t *testing.T) {
	_, err := gatewayUserURI("ams1", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "missing XRAY_PUBLIC_KEY") {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = gatewayUserURIForUUID("ams1", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{
		"XRAY_PUBLIC_KEY": "pub",
		"XRAY_SNI":        "www.example.com",
		"XRAY_SHORT_ID":   "abcd",
	}}, "")
	if err == nil || !strings.Contains(err.Error(), "missing user UUID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoteGatewayConfigWithShares(t *testing.T) {
	material, err := generateRemoteGatewayMaterial(gatewayInstallPlan{Name: "ams1"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := remoteGatewayConfigWithShares(material.ConfigJSON, []gatewayShareRecord{
		{Name: "phone", UUID: "11111111-1111-4111-8111-111111111111"},
		{Name: "tablet", UUID: "22222222-2222-4222-8222-222222222222"},
	})
	if err != nil {
		t.Fatalf("remoteGatewayConfigWithShares failed: %v", err)
	}
	for _, want := range []string{material.UUID, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		if !strings.Contains(updated, want) {
			t.Fatalf("updated config missing %q:\n%s", want, updated)
		}
	}
	if strings.Count(updated, `"flow": "xtls-rprx-vision"`) != 3 {
		t.Fatalf("expected three VLESS clients:\n%s", updated)
	}
}

func TestRunGatewayViewDefaultShare(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Gateways: map[string]gatewayRecord{
		"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{
			ServerIP:   "1.2.3.4",
			ServerPort: "443",
			Raw: map[string]string{
				"XRAY_UUID":       "00000000-0000-0000-0000-000000000000",
				"XRAY_PUBLIC_KEY": "pub",
				"XRAY_SNI":        "www.example.com",
				"XRAY_SHORT_ID":   "abcd",
			},
		}, now),
	}}
	var out bytes.Buffer
	if err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayView([]string{"ams1", "default"}, &st); err != nil {
		t.Fatalf("runGatewayView failed: %v", err)
	}
	if !strings.HasPrefix(out.String(), "vless://") {
		t.Fatalf("unexpected URI output: %q", out.String())
	}
}

func TestGatewayRiskReport(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		Gateways: map[string]gatewayRecord{
			"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{"XRAY_HOSTING_PROVIDER": "hetzner"}}, now),
			"hel1": gatewayRecordFromConfig("hel1", gatewayConfig{ServerIP: "5.6.7.8", ServerPort: "443", Raw: map[string]string{"XRAY_HOSTING_PROVIDER": "ovhcloud"}}, now),
		},
		HostingChecks: []hostingCheckRecord{{Provider: "hetzner", Reachable: true}},
	}
	report := gatewayRiskReport("ams1", st.Gateways["ams1"], &st)
	if report.Level != "low" || report.ProviderReach != "ok" {
		t.Fatalf("unexpected low risk report: %+v", report)
	}
}

func TestGatewayRiskReportUnknownProviderAndSingleGateway(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Gateways: map[string]gatewayRecord{
		"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{}}, now),
	}}
	report := gatewayRiskReport("ams1", st.Gateways["ams1"], &st)
	if report.Level != "elevated" || report.Provider != "unknown" {
		t.Fatalf("unexpected unknown provider risk report: %+v", report)
	}
	if len(report.Actions) == 0 {
		t.Fatalf("expected actions for unknown provider risk: %+v", report)
	}
}

func TestRunGatewayRisk(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{Gateways: map[string]gatewayRecord{
		"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{}}, now),
	}}
	var out bytes.Buffer
	if err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayRisk([]string{"ams1"}, &st); err != nil {
		t.Fatalf("runGatewayRisk failed: %v", err)
	}
	if !strings.Contains(out.String(), "Risk:") {
		t.Fatalf("risk output missing risk: %q", out.String())
	}
	if len(st.Events) != 1 || !strings.Contains(st.Events[0].Message, "risk checked") {
		t.Fatalf("missing risk event: %+v", st.Events)
	}
}

func TestGatewayInstallPlanParsingAndOutput(t *testing.T) {
	plan, err := parseGatewayInstallPlan([]string{"ams1", "--host", "1.2.3.4", "--user", "root", "--password", "--dry-run", "--adopt"})
	if err != nil {
		t.Fatalf("parse gateway install plan failed: %v", err)
	}
	if plan.Name != "ams1" || plan.Host != "1.2.3.4" || plan.User != "root" || !plan.Password || !plan.DryRun || plan.Mode != "adopt" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	var out bytes.Buffer
	printGatewayInstallPlan(&out, plan)
	got := out.String()
	for _, want := range []string{
		"Name:     ams1",
		"Remote:   root@1.2.3.4",
		"Gateway:  xray (censorship-resistant)",
		"Action:   adopt",
		"Password: requested",
		"Apply:    no",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("install plan output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Step 01") {
		t.Fatalf("default install plan should be compact:\n%s", got)
	}
	plan.Verbose = true
	out.Reset()
	printGatewayInstallPlan(&out, plan)
	if !strings.Contains(out.String(), "Step 01") {
		t.Fatalf("verbose install plan missing detailed steps:\n%s", out.String())
	}
	if _, err := parseGatewayInstallPlan([]string{"ams1", "--user", "root"}); err == nil {
		t.Fatal("accepted install plan without host")
	}
	if _, err := parseGatewayInstallPlan([]string{"ams1", "--host", "1.2.3.4", "--adopt", "--replace"}); err == nil {
		t.Fatal("accepted mutually exclusive adopt/replace")
	}
}

func TestRunGatewayInstallDryRunRecordsPlanOnly(t *testing.T) {
	st := envdState{}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{"ams1", "--host", "1.2.3.4", "--dry-run"}, &st)
	if err != nil {
		t.Fatalf("gateway install dry-run failed: %v", err)
	}
	if len(st.Gateways) != 0 {
		t.Fatalf("dry-run created gateway: %+v", st.Gateways)
	}
	if len(st.Events) != 1 || !strings.Contains(st.Events[0].Message, "planned remote install") {
		t.Fatalf("dry-run did not record plan event: %+v", st.Events)
	}
	if !strings.Contains(out.String(), "Apply:    no") {
		t.Fatalf("dry-run output missing non-apply note: %q", out.String())
	}
}

func TestRunGatewayInstallPreviewWithoutYesSucceeds(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	st := envdState{}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
	}, &st)
	if err != nil {
		t.Fatalf("gateway install preview should not fail: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"Probe:    ok", "Ready:    verified; no remote changes applied", "Next:     envd gateway install ams1 --host " + server.addr + " --user root --yes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("preview output missing %q:\n%s", want, got)
		}
	}
	if _, ok := st.Gateways["ams1"]; ok {
		t.Fatalf("preview created usable gateway profile before apply: %+v", st.Gateways["ams1"])
	}
	if st.RemoteGateways["ams1"].Password != "secret" {
		t.Fatalf("preview did not keep verified remote credentials for apply: %+v", st.RemoteGateways["ams1"])
	}
}

func TestRunGatewayInstallExistingEnvdConfigRequiresReplace(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	server.setHandler(func(command string) (string, uint32) {
		if strings.Contains(command, "envd_owned_service") {
			return "envd_owned_service=true\nenvd_owned_config=true\nxray_binary=/usr/local/bin/xray\nxray_version=Xray 26.2.6\n", 0
		}
		return defaultTestSSHResponse(command)
	})
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	st := envdState{}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"frankfurt2",
		"--host", server.addr,
		"--user", "root",
		"--password",
	}, &st)
	if err != nil {
		t.Fatalf("existing envd-owned preview should not fail: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"existing envd-owned gateway config found", "--replace --yes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("existing envd preview output missing %q:\n%s", want, got)
		}
	}
	out.Reset()
	err = (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"frankfurt2",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--yes",
	}, &st)
	if err == nil || !strings.Contains(err.Error(), "rerun with --replace") {
		t.Fatalf("apply over existing envd config without replace should fail, got %v\n%s", err, out.String())
	}
}

func TestRunGatewayInstallApplyUnsupported(t *testing.T) {
	st := envdState{}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{"ams1", "--host", "1.2.3.4", "--yes"}, &st)
	if err == nil || !strings.Contains(err.Error(), "requires --password") {
		t.Fatalf("expected apply password requirement, got %v", err)
	}
	if len(st.Gateways) != 0 {
		t.Fatalf("failed apply created gateway: %+v", st.Gateways)
	}
}

func TestRunGatewayInstallProbeStoresEncryptedRemoteInspection(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)

	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.run([]string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	out.Reset()
	err := a.run([]string{
		"gateway", "install", "ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--probe",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("gateway install probe failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{"Probe:    ok", "ubuntu 24.04 aarch64", "existing non-envd Xray config found", "Config:   generated"} {
		if !strings.Contains(got, want) {
			t.Fatalf("probe output missing %q:\n%s", want, got)
		}
	}

	raw, err := os.ReadFile(filepath.Join(stateDir, "state.enc"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte(server.addr)) {
		t.Fatalf("remote secret or host leaked outside encrypted state: %s", raw)
	}
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	st, err := store.loadOrCreate([]byte("test-password"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	rec := st.RemoteGateways["ams1"]
	if rec.Password != "secret" || rec.Host != server.addr || rec.Inspection.OS != "ubuntu" || rec.Inspection.Arch != "aarch64" {
		t.Fatalf("remote probe record not stored correctly: %+v", rec)
	}
	if rec.HostKeySHA256 == "" || rec.ProviderState.XrayBinary != "/usr/local/bin/xray" || len(rec.ProviderState.UnknownConfigs) != 1 {
		t.Fatalf("remote provider inspection not stored correctly: %+v", rec)
	}
	if rec.Material.UUID == "" || rec.Material.RealityPrivateKey == "" || !strings.Contains(rec.Material.ConfigJSON, rec.Material.UUID) {
		t.Fatalf("remote install material not stored correctly: %+v", rec.Material)
	}
}

func TestRunGatewayInstallProbeRejectsHostKeyMismatch(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	st := envdState{
		RemoteGateways: map[string]remoteGatewayRecord{
			"ams1": {Name: "ams1", HostKeySHA256: "SHA256:mismatch"},
		},
	}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--probe",
		"--dry-run",
	}, &st)
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("expected host key mismatch, got %v", err)
	}
	if st.RemoteGateways["ams1"].Password != "" {
		t.Fatalf("stored password after failed probe: %+v", st.RemoteGateways["ams1"])
	}
}

func TestGenerateRemoteGatewayMaterial(t *testing.T) {
	plan, err := parseGatewayInstallPlan([]string{"ams1", "--host", "1.2.3.4", "--strategy", "censorship-resistant"})
	if err != nil {
		t.Fatalf("parse plan: %v", err)
	}
	material, err := generateRemoteGatewayMaterial(plan)
	if err != nil {
		t.Fatalf("generate material failed: %v", err)
	}
	if material.XrayVersion != remoteXrayVersion || material.Port != 443 || material.UUID == "" || material.ShortID == "" {
		t.Fatalf("material missing core values: %+v", material)
	}
	if material.RealityPrivateKey == "" || material.RealityPublicKey == "" || material.RealityPrivateKey == material.RealityPublicKey {
		t.Fatalf("material missing reality keys: %+v", material)
	}
	for _, want := range []string{`"protocol": "vless"`, material.UUID, material.RealityPrivateKey, material.ShortID, "envd Xray Reality gateway"} {
		if !strings.Contains(material.ConfigJSON+material.ServiceUnit, want) {
			t.Fatalf("material missing %q:\nconfig=%s\nunit=%s", want, material.ConfigJSON, material.ServiceUnit)
		}
	}
	if strings.Contains(material.ConfigJSON, `"encryption"`) {
		t.Fatalf("server inbound config must not contain VLESS client encryption:\n%s", material.ConfigJSON)
	}
	if !strings.Contains(material.ConfigJSON, `"decryption": "none"`) {
		t.Fatalf("server inbound config missing VLESS decryption setting:\n%s", material.ConfigJSON)
	}
}

func TestRemoteInstallXrayScriptBootstrapsRequiredTools(t *testing.T) {
	material := remoteGatewayMaterial{
		XrayVersion: remoteXrayVersion,
		ConfigJSON:  "{}",
	}
	script := remoteInstallXrayScript(material)
	for _, want := range []string{
		"command -v unzip",
		"apt-get install -y --no-install-recommends $need_pkgs",
		"dnf install -y $need_pkgs",
		"yum install -y $need_pkgs",
		"apk add --no-cache $need_pkgs",
		"missing required install tools",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("remote install script missing %q:\n%s", want, script)
		}
	}
}

func TestExtractLastIPLineIgnoresDockerPullNoise(t *testing.T) {
	raw := strings.Join([]string{
		"Unable to find image 'alpine:3.21' locally",
		"3.21: Pulling from library/alpine",
		"Status: Downloaded newer image for alpine:3.21",
		"150.241.79.37",
		"",
	}, "\n")
	if got := extractLastIPLine(raw); got != "150.241.79.37" {
		t.Fatalf("extractLastIPLine = %q", got)
	}
	if got := extractLastIPLine("no ip here"); got != "" {
		t.Fatalf("unexpected IP from noisy output: %q", got)
	}
}

func TestRunGatewayInstallApplyInstallsVerifiesAndStoresProfile(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway reachability target: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, portRaw, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	plan, err := parseGatewayInstallPlan([]string{"ams1", "--host", server.addr})
	if err != nil {
		t.Fatal(err)
	}
	material, err := generateRemoteGatewayMaterial(plan)
	if err != nil {
		t.Fatal(err)
	}
	material.Port = port
	st := envdState{RemoteGateways: map[string]remoteGatewayRecord{
		"ams1": {
			Name:     "ams1",
			Host:     server.addr,
			User:     "root",
			Password: "secret",
			Material: material,
		},
	}}
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	var out bytes.Buffer
	err = (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--yes",
	}, &st)
	if err != nil {
		t.Fatalf("gateway install apply failed: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"Apply:    ok", "Verify:   remote process ok", "Stored:   gateway profile", "Next:     envd gateway use ams1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("apply output missing %q:\n%s", want, got)
		}
	}
	commands := server.commands()
	for _, want := range []string{
		"Xray-linux-${xray_arch}.zip",
		"/usr/local/etc/envd/xray/config.json",
		"systemctl enable envd-xray.service",
		"ufw allow",
		"systemctl is-active --quiet envd-xray.service",
	} {
		if !containsCommand(commands, want) {
			t.Fatalf("remote commands missing %q:\n%s", want, strings.Join(commands, "\n---\n"))
		}
	}
	rec := st.Gateways["ams1"]
	if rec.ServerPort != strconv.Itoa(port) || rec.Raw["XRAY_UUID"] != material.UUID || rec.Raw["XRAY_PUBLIC_KEY"] != material.RealityPublicKey {
		t.Fatalf("local gateway profile not stored from remote material: %+v", rec)
	}
	if !st.RemoteGateways["ams1"].ProviderState.EnvdOwnedConfig {
		t.Fatalf("remote provider state not marked envd-owned after apply: %+v", st.RemoteGateways["ams1"].ProviderState)
	}
}

func TestRunGatewayInstallReplaceRegeneratesMaterial(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	oldMaterial := remoteGatewayMaterial{
		XrayVersion:       remoteXrayVersion,
		Port:              443,
		UUID:              "old-uuid",
		RealityPrivateKey: "old-private",
		RealityPublicKey:  "old-public",
		ShortID:           "old-short",
		SNI:               "old.example",
		ConfigJSON:        `{"old":true}`,
		ServiceUnit:       remoteXrayServiceUnit(),
	}
	st := envdState{RemoteGateways: map[string]remoteGatewayRecord{
		"ams1": {
			Name:     "ams1",
			Host:     server.addr,
			User:     "root",
			Password: "secret",
			Material: oldMaterial,
		},
	}}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--replace",
		"--probe",
		"--dry-run",
	}, &st)
	if err != nil {
		t.Fatalf("replace probe failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Config:   regenerated") {
		t.Fatalf("replace output did not report regenerated material:\n%s", out.String())
	}
	got := st.RemoteGateways["ams1"].Material
	if got.UUID == oldMaterial.UUID || got.ConfigJSON == oldMaterial.ConfigJSON || got.RealityPrivateKey == oldMaterial.RealityPrivateKey {
		t.Fatalf("replace reused old material: %+v", got)
	}
}

func TestRunGatewayInstallApplyRollsBackEnvdOwnedConfigOnVerifyFailure(t *testing.T) {
	server := startTestSSHServer(t, "root", "secret")
	server.setHandler(func(command string) (string, uint32) {
		if strings.Contains(command, "envd_owned_service") {
			return "envd_owned_service=true\nenvd_owned_config=true\nxray_binary=/usr/local/bin/xray\nxray_version=Xray 25.1.1\n", 0
		}
		if strings.Contains(command, "systemctl is-active --quiet envd-xray.service") {
			return "inactive\n", 1
		}
		return defaultTestSSHResponse(command)
	})
	plan, err := parseGatewayInstallPlan([]string{"ams1", "--host", server.addr})
	if err != nil {
		t.Fatal(err)
	}
	material, err := generateRemoteGatewayMaterial(plan)
	if err != nil {
		t.Fatal(err)
	}
	material.Port = 1
	st := envdState{RemoteGateways: map[string]remoteGatewayRecord{
		"ams1": {
			Name:          "ams1",
			Host:          server.addr,
			User:          "root",
			Password:      "secret",
			Material:      material,
			ProviderState: remoteProviderInspection{EnvdOwnedConfig: true},
		},
	}}
	t.Setenv("ENVD_GATEWAY_PASSWORD", "secret")
	var out bytes.Buffer
	err = (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayInstall([]string{
		"ams1",
		"--host", server.addr,
		"--user", "root",
		"--password",
		"--replace",
		"--yes",
	}, &st)
	if err == nil || !strings.Contains(err.Error(), "remote provider process verification failed") {
		t.Fatalf("expected verification failure, got %v", err)
	}
	if _, ok := st.Gateways["ams1"]; ok {
		t.Fatalf("failed apply stored usable gateway: %+v", st.Gateways["ams1"])
	}
	if !containsCommand(server.commands(), "config.json.envd-rollback") {
		t.Fatalf("rollback command was not executed:\n%s", strings.Join(server.commands(), "\n---\n"))
	}
}

func TestEnsureEnvSSHConfigWritesStandardSSHHost(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := ensureEnvSSHConfig("books", "/tmp/envd tool/envd"); err != nil {
		t.Fatalf("ensure SSH config failed: %v", err)
	}
	mainRaw, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		t.Fatalf("read main ssh config: %v", err)
	}
	if !strings.Contains(string(mainRaw), "Include "+filepath.Join(home, ".ssh", "envd_config")) {
		t.Fatalf("main ssh config missing envd include:\n%s", mainRaw)
	}
	envdRaw, err := os.ReadFile(filepath.Join(home, ".ssh", "envd_config"))
	if err != nil {
		t.Fatalf("read envd ssh config: %v", err)
	}
	got := string(envdRaw)
	for _, want := range []string{
		"# envd managed: books",
		"Host books",
		"ProxyCommand '/tmp/envd tool/envd' ssh-proxy books",
		"IdentityFile " + shellWords(filepath.Join(home, ".ssh", "envd_ed25519")),
		"IdentitiesOnly yes",
		"PubkeyAuthentication unbound",
		"ForwardAgent yes",
		"IdentityAgent " + shellWords(filepath.Join(home, ".local", "share", "envd", "runtime", "identity-agents", "books.sock")),
		"HostKeyAlias envd-books",
		"StrictHostKeyChecking accept-new",
		"UserKnownHostsFile " + shellWords(filepath.Join(home, ".ssh", "envd_known_hosts")),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("envd ssh config missing %q:\n%s", want, got)
		}
	}
	if err := ensureEnvSSHConfig("books", "/opt/envd"); err != nil {
		t.Fatalf("second ensure SSH config failed: %v", err)
	}
	updatedRaw, err := os.ReadFile(filepath.Join(home, ".ssh", "envd_config"))
	if err != nil {
		t.Fatalf("read updated envd ssh config: %v", err)
	}
	if strings.Count(string(updatedRaw), "# envd managed: books") != 1 {
		t.Fatalf("envd ssh config duplicated managed block:\n%s", updatedRaw)
	}
	if !strings.Contains(string(updatedRaw), "ProxyCommand /opt/envd ssh-proxy books") {
		t.Fatalf("envd ssh config did not update block:\n%s", updatedRaw)
	}
	if !fileExists(filepath.Join(home, ".ssh", "envd_ed25519")) || !fileExists(filepath.Join(home, ".ssh", "envd_ed25519.pub")) {
		t.Fatalf("envd SSH keypair was not generated")
	}
}

func TestSyncEnvSSHConfigPrunesStaleManagedHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envdConfig := filepath.Join(sshDir, "envd_config")
	old := `Host personal
  HostName example.com

# envd managed: old
Host old
  HostName envd
# envd managed end: old

# envd managed: books
Host books
  HostName stale
# envd managed end: books
`
	if err := os.WriteFile(envdConfig, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := syncEnvSSHConfigNames([]string{"books"}, "/opt/envd"); err != nil {
		t.Fatalf("sync SSH config failed: %v", err)
	}
	raw, err := os.ReadFile(envdConfig)
	if err != nil {
		t.Fatalf("read envd config: %v", err)
	}
	got := string(raw)
	if strings.Contains(got, "envd-old") || strings.Contains(got, "# envd managed: old") {
		t.Fatalf("stale envd SSH block was not pruned:\n%s", got)
	}
	if !strings.Contains(got, "Host personal") {
		t.Fatalf("user SSH block was not preserved:\n%s", got)
	}
	if strings.Count(got, "# envd managed: books") != 1 {
		t.Fatalf("books block missing or duplicated:\n%s", got)
	}
	if !strings.Contains(got, "ProxyCommand /opt/envd ssh-proxy books") {
		t.Fatalf("books block was not refreshed:\n%s", got)
	}
}

func TestEnsureSSHIncludePrunesLegacyInlineEnvdHosts(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mainConfig := filepath.Join(sshDir, "config")
	envdConfig := filepath.Join(sshDir, "envd_config")
	raw := `Include /Users/c/.colima/ssh_config

Host github.com
  HostName github.com
  User git

Host books
  HostName 127.0.0.1
  Port 2230
  User books
  IdentityFile /Users/c/.ssh/id_ed25519
  IdentitiesOnly yes
  ForwardAgent yes
  UserKnownHostsFile /Users/c/.ssh/known_hosts_envd
  StrictHostKeyChecking accept-new

Host local-db
  HostName 127.0.0.1
  Port 2222
  User me
`
	if err := os.WriteFile(mainConfig, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSSHInclude(mainConfig, envdConfig); err != nil {
		t.Fatalf("ensure include failed: %v", err)
	}
	updated, err := os.ReadFile(mainConfig)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	got := string(updated)
	if strings.Contains(got, "Host books") || strings.Contains(got, "known_hosts_envd") {
		t.Fatalf("legacy envd host was not removed:\n%s", got)
	}
	for _, want := range []string{
		"Include " + envdConfig,
		"Include /Users/c/.colima/ssh_config",
		"Host github.com",
		"Host local-db",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("config missing preserved entry %q:\n%s", want, got)
		}
	}
}

func TestGatewayChainCreateStatusAndUseFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		Gateways: map[string]gatewayRecord{
			"entry": gatewayRecordFromConfig("entry", gatewayConfig{ServerIP: "1.2.3.4", ServerPort: "443", Raw: map[string]string{}}, now),
			"exit":  gatewayRecordFromConfig("exit", gatewayConfig{ServerIP: "5.6.7.8", ServerPort: "443", Raw: map[string]string{}}, now),
		},
		GatewayChains: map[string]gatewayChainRecord{},
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runGatewayChainCreate([]string{"work", "--entry", "entry", "--exit", "exit"}, &st); err != nil {
		t.Fatalf("chain create failed: %v", err)
	}
	if st.GatewayChains["work"].Entry != "entry" || st.GatewayChains["work"].Exit != "exit" {
		t.Fatalf("chain was not stored: %+v", st.GatewayChains["work"])
	}
	if !strings.Contains(out.String(), "Activation: disabled fail-closed") {
		t.Fatalf("chain create did not describe fail-closed activation: %q", out.String())
	}
	out.Reset()
	if err := a.runGatewayChainStatus([]string{"work"}, &st); err != nil {
		t.Fatalf("chain status failed: %v", err)
	}
	if !strings.Contains(out.String(), "Degrade:") || !strings.Contains(out.String(), "single-hop fallback denied") {
		t.Fatalf("chain status missing no-degrade status: %q", out.String())
	}
	err := a.runGatewayUse([]string{"work"}, &st)
	if err == nil || !strings.Contains(err.Error(), "refusing to degrade") {
		t.Fatalf("chain activation did not fail closed: %v", err)
	}
	if st.ActiveGateway != "" {
		t.Fatalf("chain activation changed active gateway: %q", st.ActiveGateway)
	}
}

func TestParseGatewayChainCreateArgs(t *testing.T) {
	name, entry, exit, err := parseGatewayChainCreateArgs([]string{"work", "--exit", "exit", "--entry", "entry"})
	if err != nil {
		t.Fatalf("parse chain args failed: %v", err)
	}
	if name != "work" || entry != "entry" || exit != "exit" {
		t.Fatalf("unexpected chain args: %q %q %q", name, entry, exit)
	}
	if _, _, _, err := parseGatewayChainCreateArgs([]string{"work", "--entry", "entry", "--exit", "entry"}); err == nil {
		t.Fatal("accepted same entry and exit gateway")
	}
}

func TestRunIdentityAddStoresMaterialAndListRedacts(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	privateKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-material\n-----END OPENSSH PRIVATE KEY-----\n"
	publicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example"
	if err := os.WriteFile(keyPath, []byte(privateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	st := envdState{Identities: map[string]identityRecord{}}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}

	if err := a.runIdentityAdd([]string{"github", "--ssh-key", keyPath}, &st); err != nil {
		t.Fatalf("identity add failed: %v", err)
	}
	rec := st.Identities["github"]
	if rec.PrivateKey != privateKey || rec.PublicKey != publicKey || rec.Type != "ssh" {
		t.Fatalf("identity not stored correctly: %+v", rec)
	}
	if !identityPolicyAllowsSealedOnly(rec.Policy) {
		t.Fatalf("identity policy is not sealed-only: %+v", rec.Policy)
	}
	if strings.Contains(out.String(), "secret-key-material") {
		t.Fatalf("identity add leaked private key: %q", out.String())
	}
	out.Reset()
	if err := a.runIdentityList(nil, &st); err != nil {
		t.Fatalf("identity list failed: %v", err)
	}
	if !strings.Contains(out.String(), "github") || strings.Contains(out.String(), "secret-key-material") || strings.Contains(out.String(), publicKey) {
		t.Fatalf("identity list output leaked or omitted data: %q", out.String())
	}
}

func TestRunIdentityAddGitHTTPSAndCredentialHelper(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("ghp_secret_token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := envdState{
		GatewayGeneration: 3,
		Environments: map[string]envRecord{
			"books": {ID: "env1", Network: "sealed", GatewayGeneration: 3},
		},
		Identities: map[string]identityRecord{},
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runIdentityAdd([]string{"githubhttps", "--git-https", "--username", "alice", "--token-file", tokenPath}, &st); err != nil {
		t.Fatalf("git https identity add failed: %v", err)
	}
	rec := st.Identities["githubhttps"]
	if rec.Type != "git-https" || rec.Username != "alice" || rec.Password != "ghp_secret_token" {
		t.Fatalf("git https identity not stored correctly: %+v", rec)
	}
	if strings.Contains(out.String(), "ghp_secret_token") {
		t.Fatalf("git https add leaked token: %q", out.String())
	}
	out.Reset()
	if err := a.runIdentityList(nil, &st); err != nil {
		t.Fatalf("identity list failed: %v", err)
	}
	if strings.Contains(out.String(), "ghp_secret_token") || strings.Contains(out.String(), "alice") {
		t.Fatalf("identity list leaked git credential data: %q", out.String())
	}
	response, err := gitCredentialHelperResponse(&st, "books", "githubhttps", "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), func() error { return nil })
	if err != nil {
		t.Fatalf("credential helper failed: %v", err)
	}
	if response != "username=alice\npassword=ghp_secret_token\n\n" {
		t.Fatalf("unexpected credential helper response: %q", response)
	}
	if response, err := gitCredentialHelperResponse(&st, "books", "githubhttps", "store", strings.NewReader("\n"), func() error { return nil }); err != nil || response != "" {
		t.Fatalf("store operation should be ignored, response=%q err=%v", response, err)
	}
}

func TestGitCredentialHelperDeniesUnsafeOrWrongType(t *testing.T) {
	st := envdState{
		GatewayGeneration: 1,
		Environments: map[string]envRecord{
			"direct": {ID: "env1", Network: "direct", GatewayGeneration: 1},
			"sealed": {ID: "env2", Network: "sealed", GatewayGeneration: 1},
		},
		Identities: map[string]identityRecord{
			"githubhttps": {Name: "githubhttps", Type: "git-https", Username: "alice", Password: "token", Policy: defaultIdentityPolicy()},
			"githubssh":   {Name: "githubssh", Type: "ssh", PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----", Policy: defaultIdentityPolicy()},
		},
	}
	if _, err := gitCredentialHelperResponse(&st, "direct", "githubhttps", "get", strings.NewReader("\n"), func() error { return nil }); err == nil || !strings.Contains(err.Error(), "requires sealed") {
		t.Fatalf("direct env was not denied: %v", err)
	}
	if _, err := gitCredentialHelperResponse(&st, "sealed", "githubssh", "get", strings.NewReader("\n"), func() error { return nil }); err == nil || !strings.Contains(err.Error(), "cannot satisfy git-https") {
		t.Fatalf("ssh identity was not denied for git https: %v", err)
	}
}

func TestIdentityWrappersWriteConvenienceScripts(t *testing.T) {
	st := envdState{
		Environments: map[string]envRecord{
			"books": {ID: "env1", Network: "sealed"},
		},
		Identities: map[string]identityRecord{
			"github": {Name: "github", Type: "ssh", Policy: defaultIdentityPolicy()},
		},
	}
	dir := t.TempDir()
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runIdentityWrappers([]string{"books", "github", "--dir", dir}, &st)
	if err != nil {
		t.Fatalf("identity wrappers failed: %v", err)
	}
	for _, name := range []string{"ssh", "git"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("wrapper %s was not written: %v", name, err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("wrapper %s is not executable: %v", name, info.Mode())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "identity broker check books github") {
			t.Fatalf("wrapper %s missing broker check:\n%s", name, text)
		}
	}
	if !strings.Contains(out.String(), "convenience only") {
		t.Fatalf("wrapper output did not state convenience boundary: %q", out.String())
	}
	if len(st.Events) != 1 || !strings.Contains(st.Events[0].Message, "convenience wrappers") {
		t.Fatalf("wrapper event missing: %+v", st.Events)
	}
}

func TestIdentityWrappersPrintAndValidateTargets(t *testing.T) {
	st := envdState{
		Environments: map[string]envRecord{"books": {ID: "env1", Network: "sealed"}},
		Identities:   map[string]identityRecord{"github": {Name: "github", Type: "ssh", Policy: defaultIdentityPolicy()}},
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runIdentityWrappers([]string{"books", "github"}, &st); err != nil {
		t.Fatalf("identity wrappers print failed: %v", err)
	}
	if !strings.Contains(out.String(), "Broker policy remains the security boundary") || !strings.Contains(out.String(), "# ssh") {
		t.Fatalf("wrapper print output missing boundary/scripts: %q", out.String())
	}
	if err := a.runIdentityWrappers([]string{"missing", "github"}, &st); err == nil {
		t.Fatal("accepted missing environment")
	}
	if err := a.runIdentityWrappers([]string{"books", "missing"}, &st); err == nil {
		t.Fatal("accepted missing identity")
	}
}

func TestProbeIdentityRecords(t *testing.T) {
	goodKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
	st := envdState{Identities: map[string]identityRecord{
		"github": {
			Name:        "github",
			Type:        "ssh",
			PrivateKey:  goodKey,
			Fingerprint: identityFingerprint([]byte(goodKey), nil),
			Policy:      defaultIdentityPolicy(),
		},
		"unsafe": {
			Name:       "unsafe",
			Type:       "ssh",
			PrivateKey: goodKey,
			Policy: identityPolicy{
				AllowedNetworks:       []string{"direct"},
				RequireHealthySealed:  false,
				RequireGatewayCurrent: false,
			},
		},
	}}
	results := probeIdentityRecords(&st)
	if len(results) != 2 {
		t.Fatalf("identity probe count = %d", len(results))
	}
	if results[0].Err != nil || !strings.Contains(results[0].Detail, "sha256:") {
		t.Fatalf("good identity probe failed: %+v", results[0])
	}
	if results[1].Err == nil || !strings.Contains(results[1].Err.Error(), "not sealed-only") {
		t.Fatalf("unsafe identity probe did not fail: %+v", results[1])
	}
}

func TestIdentityBrokerGrantPolicy(t *testing.T) {
	goodKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
	st := envdState{
		GatewayGeneration: 5,
		Environments: map[string]envRecord{
			"sealed": {ID: "env1", Network: "sealed", GatewayGeneration: 5},
			"direct": {ID: "env2", Network: "direct", GatewayGeneration: 5},
			"stale":  {ID: "env3", Network: "sealed", GatewayGeneration: 4},
		},
		Identities: map[string]identityRecord{
			"github": {Name: "github", Type: "ssh", PrivateKey: goodKey, Policy: defaultIdentityPolicy()},
		},
	}
	allow := evaluateIdentityBrokerGrant(&st, "sealed", "github", "ssh", func() error { return nil })
	if !allow.Allow || allow.EnvID != "env1" || allow.GatewayGeneration != 5 {
		t.Fatalf("expected broker grant to allow: %+v", allow)
	}
	direct := evaluateIdentityBrokerGrant(&st, "direct", "github", "ssh", func() error { return nil })
	if direct.Allow || !strings.Contains(direct.Reason, "requires sealed") {
		t.Fatalf("direct network was not denied: %+v", direct)
	}
	stale := evaluateIdentityBrokerGrant(&st, "stale", "github", "ssh", func() error { return nil })
	if stale.Allow || !strings.Contains(stale.Reason, "revalidation required") {
		t.Fatalf("stale gateway was not denied: %+v", stale)
	}
	unhealthy := evaluateIdentityBrokerGrant(&st, "sealed", "github", "ssh", func() error { return errors.New("sidecar stopped") })
	if unhealthy.Allow || !strings.Contains(unhealthy.Reason, "sealed route unhealthy") {
		t.Fatalf("unhealthy sealed route was not denied: %+v", unhealthy)
	}
}

func TestPolicySSHAgentListsAndSignsAfterBrokerAllow(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privatePEM := string(pem.EncodeToMemory(block))
	rec := identityRecord{Name: "github", Type: "ssh", PrivateKey: privatePEM, Policy: defaultIdentityPolicy()}
	agent := policySSHAgent{check: func() (*identityRecord, error) { return &rec, nil }}
	keys, err := agent.List()
	if err != nil {
		t.Fatalf("agent list failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("agent key count = %d", len(keys))
	}
	sig, err := agent.Sign(keys[0], []byte("payload"))
	if err != nil {
		t.Fatalf("agent sign failed: %v", err)
	}
	if sig == nil || len(sig.Blob) == 0 {
		t.Fatalf("empty signature: %+v", sig)
	}
}

func TestPolicySSHAgentDeniesWhenBrokerDenies(t *testing.T) {
	agent := policySSHAgent{check: func() (*identityRecord, error) {
		return nil, fmt.Errorf("identity broker denied: identity requires sealed networking")
	}}
	if _, err := agent.List(); err == nil || !strings.Contains(err.Error(), "requires sealed") {
		t.Fatalf("agent did not deny list: %v", err)
	}
	if _, err := agent.Sign(nil, []byte("payload")); err == nil || !strings.Contains(err.Error(), "requires sealed") {
		t.Fatalf("agent did not deny sign: %v", err)
	}
}

func TestIdentityBrokerSocketDeniesUnsafeDirectEnv(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("ENVD_STATE_DIR", stateDir)
	t.Setenv("ENVD_MASTER_PASSWORD", "test-password")
	store := stateStore{dir: stateDir, path: filepath.Join(stateDir, "state.enc")}
	now := time.Now().UTC()
	goodKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
	st := envdState{
		SchemaVersion:     stateSchemaVersion,
		CreatedAt:         now,
		GatewayGeneration: 1,
		Environments: map[string]envRecord{
			"direct": {ID: "env1", Network: "direct", GatewayGeneration: 1},
		},
		Identities: map[string]identityRecord{
			"github": {Name: "github", Type: "ssh", PrivateKey: goodKey, Policy: defaultIdentityPolicy()},
		},
		Events: []stateEvent{},
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.save(st, []byte("test-password")); err != nil {
		t.Fatalf("save state: %v", err)
	}
	server, client := net.Pipe()
	defer client.Close()
	var stderr bytes.Buffer
	go (app{stdout: &bytes.Buffer{}, stderr: &stderr, root: t.TempDir()}).handleIdentityBrokerConn(server, "direct", "github", "ssh")
	raw, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read broker response: %v", err)
	}
	if !strings.Contains(string(raw), "DENY") || !strings.Contains(string(raw), "requires sealed") {
		t.Fatalf("unexpected broker response: %q stderr=%q", string(raw), stderr.String())
	}
}

func TestParseIdentityBrokerArgs(t *testing.T) {
	envName, identityName, class, err := parseIdentityBrokerTargetArgs([]string{"books", "github", "--class", "ssh"})
	if err != nil {
		t.Fatalf("parse broker check args failed: %v", err)
	}
	if envName != "books" || identityName != "github" || class != "ssh" {
		t.Fatalf("unexpected broker check args: %q %q %q", envName, identityName, class)
	}
	_, _, _, socketPath, err := parseIdentityBrokerServeArgs([]string{"books", "github", "--class", "git-https", "--socket", "/tmp/envd.sock"})
	if err != nil {
		t.Fatalf("parse broker serve args failed: %v", err)
	}
	if socketPath != "/tmp/envd.sock" {
		t.Fatalf("unexpected socket path: %q", socketPath)
	}
	if _, _, _, err := parseIdentityBrokerTargetArgs([]string{"books", "github", "--class", "raw"}); err == nil {
		t.Fatal("accepted invalid broker class")
	}
}

func TestRunDoctorIdentityOnlySkipsGateway(t *testing.T) {
	goodKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
	st := envdState{Identities: map[string]identityRecord{
		"github": {
			Name:        "github",
			Type:        "ssh",
			PrivateKey:  goodKey,
			Fingerprint: identityFingerprint([]byte(goodKey), nil),
			Policy:      defaultIdentityPolicy(),
		},
	}}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	if err := a.runDoctor([]string{"--identity"}, &st); err != nil {
		t.Fatalf("doctor --identity failed: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Identity github") || strings.Contains(got, "Gateway config") || strings.Contains(got, "secret") {
		t.Fatalf("unexpected identity doctor output: %q", got)
	}
}

func TestNetworkSummaryAndHistoryPruning(t *testing.T) {
	results := []internetProbeRecord{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "fail"},
		{Name: "c", Status: "skip"},
	}
	summary := summarizeInternetResults(results)
	if summary.OK != 1 || summary.Fail != 1 || summary.Skip != 1 || summary.Total != 3 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	st := envdState{}
	for i := 0; i < 55; i++ {
		recordNetworkCheck(&st, internetCheckRecord{
			Time:    time.Unix(int64(i), 0).UTC(),
			Results: results,
			Summary: summary,
		})
	}
	if len(st.InternetChecks) != 50 {
		t.Fatalf("history length = %d", len(st.InternetChecks))
	}
	if got := st.InternetChecks[0].Time.Unix(); got != 5 {
		t.Fatalf("oldest retained check = %d", got)
	}
}

func TestHTTPStatusDetail(t *testing.T) {
	if got := httpStatusDetail(200, "1.2.3.4\n"); got != "egress 1.2.3.4" {
		t.Fatalf("ip detail = %q", got)
	}
	if got := httpStatusDetail(401, ""); got != "HTTP 401" {
		t.Fatalf("status detail = %q", got)
	}
}

func TestPrintNetworkCheck(t *testing.T) {
	check := internetCheckRecord{
		Time: time.Unix(0, 0).UTC(),
		Results: []internetProbeRecord{{
			Name:   "Direct HTTPS",
			Path:   "direct",
			Status: "ok",
			Detail: "egress 1.2.3.4",
		}},
		Summary: internetCheckSummary{OK: 1, Total: 1},
	}
	var out bytes.Buffer
	printNetworkCheck(&out, check)
	got := out.String()
	if !strings.Contains(got, "Checked: 1970-01-01T00:00:00Z ok=1 fail=0 skip=0 total=1") || !strings.Contains(got, "Direct HTTPS  OK    egress 1.2.3.4") {
		t.Fatalf("unexpected network check output: %q", got)
	}
}

func TestNetworkCheckProbeResultsUseDoctorStyle(t *testing.T) {
	results := networkCheckProbeResults(internetCheckRecord{Results: []internetProbeRecord{
		{Name: "Direct HTTPS", Status: "ok", Detail: "egress 1.2.3.4"},
		{Name: "Gateway HTTPS", Status: "fail", Detail: "timeout"},
		{Name: "Gateway Docker Hub", Status: "skip", Detail: "gateway unavailable"},
	}})
	if len(results) != 3 {
		t.Fatalf("results len = %d", len(results))
	}
	if results[0].Err != nil || results[0].Detail != "egress 1.2.3.4" {
		t.Fatalf("unexpected ok result: %+v", results[0])
	}
	if results[1].Err == nil || !strings.Contains(results[1].Err.Error(), "timeout") {
		t.Fatalf("unexpected fail result: %+v", results[1])
	}
	if results[2].Err != nil || !strings.Contains(results[2].Detail, "skipped: gateway unavailable") {
		t.Fatalf("unexpected skip result: %+v", results[2])
	}
}

func TestProbeDurationFormatting(t *testing.T) {
	if got := appendDuration("egress 1.2.3.4", 420*time.Millisecond); got != "egress 1.2.3.4 (420ms)" {
		t.Fatalf("unexpected millisecond duration detail: %q", got)
	}
	if got := appendDuration("timeout", 1500*time.Millisecond); got != "timeout (1.5s)" {
		t.Fatalf("unexpected second duration detail: %q", got)
	}
}

func TestProbeWebQuorumStatus(t *testing.T) {
	targets := []webQuorumTarget{
		{Label: "one", URL: "ok"},
		{Label: "two", URL: "ok"},
		{Label: "three", URL: "ok"},
		{Label: "four", URL: "fail"},
	}
	oldFetchURL := fetchURLFunc
	defer func() { fetchURLFunc = oldFetchURL }()
	fetchURLFunc = func(_ *url.URL, target string, _ time.Duration) (int, string, error) {
		if target == "fail" {
			return 0, "", errors.New("blocked")
		}
		return 204, "", nil
	}
	results := probeWebQuorumTargets(nil, targets, time.Millisecond, time.Millisecond)
	ok := 0
	for _, result := range results {
		if result.Err == nil {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("expected 3 reachable targets, got %+v", results)
	}
}

func TestProbeFastQuorumAllowsOneFailedTarget(t *testing.T) {
	targets := []webQuorumTarget{
		{Label: "one", URL: "https://one.example/"},
		{Label: "two", URL: "https://two.example/"},
		{Label: "three", URL: "https://three.example/"},
		{Label: "four", URL: "https://four.example/"},
	}
	err := probeFastQuorum(targets, 3, time.Second, func(target webQuorumTarget) error {
		if target.Label == "four" {
			return errors.New("down")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("one failed target should still pass quorum: %v", err)
	}
}

func TestProbeFastQuorumFailsWhenQuorumImpossible(t *testing.T) {
	targets := []webQuorumTarget{
		{Label: "one", URL: "https://one.example/"},
		{Label: "two", URL: "https://two.example/"},
		{Label: "three", URL: "https://three.example/"},
		{Label: "four", URL: "https://four.example/"},
	}
	err := probeFastQuorum(targets, 3, time.Second, func(target webQuorumTarget) error {
		if target.Label == "one" {
			return nil
		}
		return errors.New("down")
	})
	if err == nil || !strings.Contains(err.Error(), "web quorum failed") {
		t.Fatalf("expected quorum failure, got %v", err)
	}
}

func TestGatewayHealthCacheValidity(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	now := time.Unix(1000, 0).UTC()
	if gatewayHealthCacheValid("127.0.0.1:11080", "127.0.0.1:11081", now) {
		t.Fatalf("missing cache should not be valid")
	}
	if err := saveGatewayHealthCache("127.0.0.1:11080", "127.0.0.1:11081", now); err != nil {
		t.Fatalf("save cache failed: %v", err)
	}
	if !gatewayHealthCacheValid("127.0.0.1:11080", "127.0.0.1:11081", now.Add(5*time.Second)) {
		t.Fatalf("fresh matching cache should be valid")
	}
	if gatewayHealthCacheValid("127.0.0.1:11082", "127.0.0.1:11081", now.Add(5*time.Second)) {
		t.Fatalf("endpoint mismatch should invalidate cache")
	}
	if gatewayHealthCacheValid("127.0.0.1:11080", "127.0.0.1:11081", now.Add(gatewayHealthCacheTTL+time.Second)) {
		t.Fatalf("expired cache should not be valid")
	}
}

func TestGatewayRecoveryNeededOnlyForGatewayFailures(t *testing.T) {
	checks := []probeResult{
		{Name: "Direct HTTPS", Err: errors.New("offline")},
		{Name: "Gateway SOCKS HTTPS", Detail: "ok"},
	}
	if gatewayRecoveryNeeded(checks) {
		t.Fatalf("direct internet failure should not restart gateway")
	}
	checks = append(checks, probeResult{Name: "Gateway egress IP", Err: errors.New("timeout")})
	if !gatewayRecoveryNeeded(checks) {
		t.Fatalf("gateway egress failure should restart gateway")
	}
}

func TestGatewayQuorumSuppressesSingleSourceFailures(t *testing.T) {
	checks := []probeResult{
		{Name: "Gateway HTTP HTTPS", Err: errors.New("ipify timeout")},
		{Name: "Gateway web quorum", Detail: "4/4 ok"},
	}
	if gatewayRecoveryNeeded(checks) {
		t.Fatalf("healthy gateway quorum should not trigger recovery for single-source failure")
	}
	if latestProbeFailures(checks) {
		t.Fatalf("healthy gateway quorum should suppress single-source failure")
	}
}

func TestLatestProbeFailuresUsesRecoveredProbeState(t *testing.T) {
	checks := []probeResult{
		{Name: "Gateway HTTPS", Err: errors.New("timeout")},
		{Name: "Gateway recovery", Detail: "restarted local gateway"},
		{Name: "Gateway HTTPS", Detail: "egress 1.2.3.4"},
	}
	if latestProbeFailures(checks) {
		t.Fatalf("latest successful gateway probe should clear earlier failure")
	}
	checks = append(checks, probeResult{Name: "Direct HTTPS", Err: errors.New("offline")})
	if !latestProbeFailures(checks) {
		t.Fatalf("unrecovered direct failure should still fail")
	}
}

func TestParseHostingCatalog(t *testing.T) {
	catalog, err := parseHostingCatalog([]byte(builtInHostingCatalogJSON))
	if err != nil {
		t.Fatalf("built-in hosting catalog failed validation: %v", err)
	}
	if len(catalog.Providers) == 0 {
		t.Fatal("built-in catalog has no providers")
	}
	if _, err := parseHostingCatalog([]byte(`{"version":1,"providers":[{"id":"bad id"}]}`)); err == nil {
		t.Fatal("invalid hosting catalog accepted")
	}
}

func TestBuiltInHostingProviderTable(t *testing.T) {
	catalog, err := parseBuiltInHostingProvidersTSV(builtInHostingProvidersTSV)
	if err != nil {
		t.Fatalf("built-in hosting provider table invalid: %v", err)
	}
	if len(catalog.Providers) < 240 {
		t.Fatalf("provider table too small: %d", len(catalog.Providers))
	}
	ids := map[string]bool{}
	for _, p := range catalog.Providers {
		ids[p.ID] = true
	}
	for _, id := range []string{"aws-amazon", "lightsail-aws-amazon", "vultr", "clouding", "racknerd", "donweb"} {
		if !ids[id] {
			t.Fatalf("provider table missing %s", id)
		}
	}
}

func TestRussianPaymentHostingProviderTable(t *testing.T) {
	catalog, err := parseRussianPaymentHostingProvidersTSV(builtInRussianPaymentProvidersTSV)
	if err != nil {
		t.Fatalf("Russian-payment hosting provider table invalid: %v", err)
	}
	if len(catalog.Providers) < 75 {
		t.Fatalf("Russian-payment provider table too small: %d", len(catalog.Providers))
	}
	ids := map[string]hostingProvider{}
	for _, p := range catalog.Providers {
		ids[p.ID] = p
	}
	for _, id := range []string{"timeweb", "hostkey", "ruvds", "vdsina", "litnets", "four-vps", "neironvps", "reg"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("Russian-payment provider table missing %s", id)
		}
	}
	if got := ids["timeweb"].Confidence; got != "verified" {
		t.Fatalf("timeweb confidence = %q", got)
	}
	if got := ids["litnets"].CountriesSoldFrom; len(got) != 1 || got[0] != "RU" {
		t.Fatalf("litnets countries sold from = %+v", got)
	}
}

func TestPrintHostingCheckConciseAndVerbose(t *testing.T) {
	checks := []hostingCheckRecord{
		{Provider: "ok", Homepage: internetProbeRecord{Status: "ok", Detail: "HTTP 200"}, API: internetProbeRecord{Status: "skip", Detail: "no api_url"}, Reachable: true},
		{Provider: "slow", Homepage: internetProbeRecord{Status: "fail", Detail: "context deadline exceeded"}, API: internetProbeRecord{Status: "skip", Detail: "no api_url"}, Reachable: false},
	}
	var concise bytes.Buffer
	printHostingCheck(&concise, checks, false)
	if got := concise.String(); !strings.Contains(got, "Reachable: 1/2") || !strings.Contains(got, "Failures sample") || strings.Contains(got, "Details:") {
		t.Fatalf("unexpected concise output: %q", got)
	}
	var verbose bytes.Buffer
	printHostingCheck(&verbose, checks, true)
	if got := verbose.String(); !strings.Contains(got, "Details:") || !strings.Contains(got, "slow") {
		t.Fatalf("unexpected verbose output: %q", got)
	}
}

func TestMergeHostingCatalogs(t *testing.T) {
	base := hostingCatalog{Version: 1, Providers: []hostingProvider{{ID: "base", Name: "Base", Homepage: "https://base.test", Regions: []hostingRegion{{Code: "a", Country: "AA"}}, Confidence: "community"}}}
	overlay := hostingCatalog{Version: 1, Providers: []hostingProvider{
		{ID: "base", Name: "Override", Homepage: "https://override.test", Regions: []hostingRegion{{Code: "b", Country: "BB"}}, Confidence: "user"},
		{ID: "local", Name: "Local", Homepage: "https://local.test", Regions: []hostingRegion{{Code: "c", Country: "CC"}}, Confidence: "user"},
	}}
	got := mergeHostingCatalogs(base, overlay)
	if len(got.Providers) != 2 {
		t.Fatalf("merged provider count = %d", len(got.Providers))
	}
	if got.Providers[0].Name != "Override" || got.Providers[1].ID != "local" {
		t.Fatalf("unexpected merged catalog: %+v", got.Providers)
	}
}

func TestHostingHistoryPruning(t *testing.T) {
	st := envdState{}
	check := hostingCheckRecord{Provider: "p", Homepage: internetProbeRecord{Status: "ok"}, API: internetProbeRecord{Status: "skip"}, Reachable: true}
	for i := 0; i < 260; i++ {
		check.Time = time.Unix(int64(i), 0).UTC()
		recordHostingChecks(&st, []hostingCheckRecord{check})
	}
	if len(st.HostingChecks) != 250 {
		t.Fatalf("hosting history length = %d", len(st.HostingChecks))
	}
	if got := st.HostingChecks[0].Time.Unix(); got != 10 {
		t.Fatalf("oldest retained hosting check = %d", got)
	}
}

func TestHostingShortlistRanking(t *testing.T) {
	providers := []hostingProvider{
		{ID: "fail", Confidence: "verified", Regions: []hostingRegion{{Code: "a", Country: "AA"}}},
		{ID: "ok", Confidence: "community", Regions: []hostingRegion{{Code: "a", Country: "AA"}}},
	}
	checks := map[string]hostingCheckRecord{
		"fail": {Provider: "fail", Reachable: false},
		"ok":   {Provider: "ok", Reachable: true},
	}
	sortHostingProviders(providers, checks)
	if providers[0].ID != "ok" {
		t.Fatalf("reachable provider was not ranked first: %+v", providers)
	}
}

func TestReconcileSealedEnvGenerations(t *testing.T) {
	st := envdState{
		GatewayGeneration: 3,
		Environments: map[string]envRecord{
			"sealed": {Network: "sealed", GatewayGeneration: 1},
			"direct": {Network: "direct", GatewayGeneration: 1},
		},
	}
	if got := reconcileSealedEnvGenerations(&st); got != 1 {
		t.Fatalf("reconciled = %d", got)
	}
	if st.Environments["sealed"].GatewayGeneration != 3 {
		t.Fatalf("sealed generation not updated: %+v", st.Environments["sealed"])
	}
	if st.Environments["direct"].GatewayGeneration != 1 {
		t.Fatalf("direct generation should not change: %+v", st.Environments["direct"])
	}
}

func TestReconcileFailureBlocksAndStopsFailClosed(t *testing.T) {
	st := envdState{
		GatewayGeneration: 4,
		Environments: map[string]envRecord{
			"sealed": {ID: "abc123", Network: "sealed", GatewayGeneration: 3},
			"direct": {ID: "def456", Network: "direct", GatewayGeneration: 3},
		},
	}
	var stopped []string
	result := reconcileSealedEnvGenerationsWith(&st, func(ref envRef) error {
		return errors.New("probe failed")
	}, func(ref envRef) error {
		stopped = append(stopped, ref.DevName)
		return nil
	})
	if result.Reconciled != 0 || result.Blocked != 1 {
		t.Fatalf("unexpected reconcile result: %+v", result)
	}
	if strings.Join(stopped, ",") != "envd-abc123-dev" {
		t.Fatalf("unexpected stopped refs: %+v", stopped)
	}
	rec := st.Environments["sealed"]
	if rec.BlockedReason == "" || !strings.Contains(rec.BlockedReason, "probe failed") {
		t.Fatalf("missing blocked reason: %+v", rec)
	}
	if rec.GatewayGeneration != 3 {
		t.Fatalf("failed reconcile should not advance generation: %+v", rec)
	}
	if got := (envInspect{GatewayGeneration: rec.GatewayGeneration, BlockedReason: rec.BlockedReason}).issue(st.GatewayGeneration); !strings.Contains(got, "blocked:") {
		t.Fatalf("blocked issue not surfaced: %q", got)
	}
}

func TestReconcileSuccessClearsBlockedReason(t *testing.T) {
	st := envdState{
		GatewayGeneration: 4,
		Environments: map[string]envRecord{
			"sealed": {ID: "abc123", Network: "sealed", GatewayGeneration: 3, BlockedReason: "old failure"},
		},
	}
	result := reconcileSealedEnvGenerationsWith(&st, func(envRef) error { return nil }, func(envRef) error { return nil })
	if result.Reconciled != 1 || result.Blocked != 0 {
		t.Fatalf("unexpected reconcile result: %+v", result)
	}
	rec := st.Environments["sealed"]
	if rec.BlockedReason != "" || rec.GatewayGeneration != 4 {
		t.Fatalf("blocked reason not cleared: %+v", rec)
	}
}

func TestSealedRuntimeRecreateReason(t *testing.T) {
	recreate, reason, err := sealedRuntimeRecreateReason("sha256:aaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("sealedRuntimeRecreateReason failed: %v", err)
	}
	if !recreate || !strings.Contains(reason, "sidecar image drift") {
		t.Fatalf("expected image drift recreate, got recreate=%v reason=%q", recreate, reason)
	}
	recreate, reason, err = sealedRuntimeRecreateReason("sha256:aaaaaaaaaaaaaaaa", "sha256:aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("same image failed: %v", err)
	}
	if recreate || reason != "" {
		t.Fatalf("same image should not recreate, got recreate=%v reason=%q", recreate, reason)
	}
	if _, _, err := sealedRuntimeRecreateReason("", "sha256:aaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("empty image ID accepted")
	}
}

func TestGatewayActivationTracksPreviousAndRollbackEvents(t *testing.T) {
	t.Setenv("ENVD_DATA_DIR", t.TempDir())
	now := time.Now().UTC()
	oldCfg := validTestGatewayConfig("1.1.1.1")
	newCfg := validTestGatewayConfig("2.2.2.2")
	st := envdState{
		GatewayGeneration: 2,
		ActiveGateway:     "old",
		Gateways: map[string]gatewayRecord{
			"old": gatewayRecordFromConfig("old", oldCfg, now),
			"new": gatewayRecordFromConfig("new", newCfg, now),
		},
		Environments: map[string]envRecord{},
	}
	var out bytes.Buffer
	a := app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}
	verify := func(gatewayConfig) (string, error) { return "203.0.113.10", nil }
	stop := func(envRef) error { return nil }
	if err := a.activateGateway("new", &st, "use", verify, stop); err != nil {
		t.Fatalf("activate gateway failed: %v", err)
	}
	if st.ActiveGateway != "new" || st.PreviousGateway != "old" || st.GatewayGeneration != 3 {
		t.Fatalf("unexpected activation state: active=%q previous=%q generation=%d", st.ActiveGateway, st.PreviousGateway, st.GatewayGeneration)
	}
	if len(st.Events) == 0 || !strings.Contains(st.Events[len(st.Events)-1].Message, "use activated generation 3") {
		t.Fatalf("activation event missing: %+v", st.Events)
	}
	if !strings.Contains(st.Events[len(st.Events)-1].Message, "reconciled 0") {
		t.Fatalf("activation event missing reconciliation count: %+v", st.Events[len(st.Events)-1])
	}
	out.Reset()
	if err := a.activateGateway(st.PreviousGateway, &st, "rollback", verify, stop); err != nil {
		t.Fatalf("rollback activation failed: %v", err)
	}
	if st.ActiveGateway != "old" || st.PreviousGateway != "new" || st.GatewayGeneration != 4 {
		t.Fatalf("unexpected rollback state: active=%q previous=%q generation=%d", st.ActiveGateway, st.PreviousGateway, st.GatewayGeneration)
	}
	if !strings.Contains(out.String(), "Rollback:") {
		t.Fatalf("rollback output missing status: %q", out.String())
	}
	if len(st.Events) == 0 || !strings.Contains(st.Events[len(st.Events)-1].Message, "rollback activated generation 4") {
		t.Fatalf("rollback event missing: %+v", st.Events)
	}
}

func TestGatewayListShowsRemoteLocalAndChains(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		ActiveGateway:   "ams1",
		PreviousGateway: "local1",
		Gateways: map[string]gatewayRecord{
			"ams1":   gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "150.241.79.37", ServerPort: "443", Raw: map[string]string{}}, now),
			"local1": {Name: "local1", ServerIP: "203.0.113.10", ServerPort: "443", ImportedFromLocal: true},
		},
		RemoteGateways: map[string]remoteGatewayRecord{
			"ams1":  {Name: "ams1", Host: "150.241.79.37", Provider: "xray", Strategy: "censorship-resistant", Mode: "replace"},
			"draft": {Name: "draft", Host: "198.51.100.20", Provider: "xray", Strategy: "fast", Mode: "install"},
		},
		GatewayChains: map[string]gatewayChainRecord{
			"chain1": {Name: "chain1", Entry: "ams1", Exit: "local1"},
		},
	}
	var out bytes.Buffer
	if err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayList(nil, &st); err != nil {
		t.Fatalf("gateway list failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"NAME",
		"ams1",
		"active",
		"remote",
		"150.241.79.37",
		"censorship-resistant",
		"draft",
		"fast",
		"chain1",
		"ams1->local1",
		"local1",
		"previous",
		"imported",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("gateway list missing %q:\n%s", want, got)
		}
	}
}

func TestGatewayRemoveDeletesInactiveGatewayMetadata(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		ActiveGateway:   "active",
		PreviousGateway: "old",
		Gateways: map[string]gatewayRecord{
			"active": gatewayRecordFromConfig("active", gatewayConfig{ServerIP: "150.241.79.37", ServerPort: "443", Raw: map[string]string{}}, now),
			"old":    gatewayRecordFromConfig("old", gatewayConfig{ServerIP: "198.51.100.20", ServerPort: "443", Raw: map[string]string{}}, now),
		},
		RemoteGateways: map[string]remoteGatewayRecord{
			"old": {Name: "old", Host: "198.51.100.20", Provider: "xray"},
		},
		GatewayShares: map[string][]gatewayShareRecord{
			"old": {{Name: "phone", UUID: "share-uuid", CreatedAt: now, UpdatedAt: now}},
		},
	}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayRemove([]string{"old", "--yes"}, &st)
	if err != nil {
		t.Fatalf("gateway remove failed: %v", err)
	}
	if _, ok := st.Gateways["old"]; ok {
		t.Fatal("local gateway metadata was not removed")
	}
	if _, ok := st.RemoteGateways["old"]; ok {
		t.Fatal("remote gateway metadata was not removed")
	}
	if _, ok := st.GatewayShares["old"]; ok {
		t.Fatal("gateway shares were not removed")
	}
	if st.PreviousGateway != "" {
		t.Fatalf("previous gateway was not cleared: %q", st.PreviousGateway)
	}
	if !strings.Contains(out.String(), "Removed gateway: old") {
		t.Fatalf("remove output missing confirmation: %q", out.String())
	}
	if len(st.Events) == 0 || !strings.Contains(st.Events[len(st.Events)-1].Message, "removed local gateway metadata") {
		t.Fatalf("remove event missing: %+v", st.Events)
	}
}

func TestGatewayRemoveRefusesActiveGateway(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		ActiveGateway: "ams1",
		Gateways: map[string]gatewayRecord{
			"ams1": gatewayRecordFromConfig("ams1", gatewayConfig{ServerIP: "150.241.79.37", ServerPort: "443", Raw: map[string]string{}}, now),
		},
	}
	err := (app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayRemove([]string{"ams1", "--yes"}, &st)
	if err == nil || !strings.Contains(err.Error(), "cannot remove active gateway") {
		t.Fatalf("expected active gateway refusal, got %v", err)
	}
	if _, ok := st.Gateways["ams1"]; !ok {
		t.Fatal("active gateway was removed")
	}
}

func TestGatewayRemoveRefusesGatewayUsedByChain(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		ActiveGateway: "exit",
		Gateways: map[string]gatewayRecord{
			"entry": gatewayRecordFromConfig("entry", gatewayConfig{ServerIP: "198.51.100.10", ServerPort: "443", Raw: map[string]string{}}, now),
			"exit":  gatewayRecordFromConfig("exit", gatewayConfig{ServerIP: "203.0.113.10", ServerPort: "443", Raw: map[string]string{}}, now),
		},
		GatewayChains: map[string]gatewayChainRecord{
			"work": {Name: "work", Entry: "entry", Exit: "exit", CreatedAt: now, UpdatedAt: now},
		},
	}
	err := (app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayRemove([]string{"entry", "--yes"}, &st)
	if err == nil || !strings.Contains(err.Error(), "chain \"work\" still uses it") {
		t.Fatalf("expected chain reference refusal, got %v", err)
	}
	if _, ok := st.Gateways["entry"]; !ok {
		t.Fatal("gateway used by chain was removed")
	}
}

func TestGatewayRemoveDeletesChainRecord(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		ActiveGateway: "exit",
		Gateways: map[string]gatewayRecord{
			"entry": gatewayRecordFromConfig("entry", gatewayConfig{ServerIP: "198.51.100.10", ServerPort: "443", Raw: map[string]string{}}, now),
			"exit":  gatewayRecordFromConfig("exit", gatewayConfig{ServerIP: "203.0.113.10", ServerPort: "443", Raw: map[string]string{}}, now),
		},
		GatewayChains: map[string]gatewayChainRecord{
			"work": {Name: "work", Entry: "entry", Exit: "exit", CreatedAt: now, UpdatedAt: now},
		},
	}
	var out bytes.Buffer
	err := (app{stdout: &out, stderr: &bytes.Buffer{}, root: t.TempDir()}).runGatewayRemove([]string{"work", "--yes"}, &st)
	if err != nil {
		t.Fatalf("gateway chain remove failed: %v", err)
	}
	if _, ok := st.GatewayChains["work"]; ok {
		t.Fatal("gateway chain metadata was not removed")
	}
	if _, ok := st.Gateways["entry"]; !ok {
		t.Fatal("chain endpoint gateway was removed")
	}
	if !strings.Contains(out.String(), "Removed gateway: work") {
		t.Fatalf("remove output missing confirmation: %q", out.String())
	}
}

func TestGatewayActivationFailureDoesNotMutateState(t *testing.T) {
	now := time.Now().UTC()
	st := envdState{
		GatewayGeneration: 7,
		ActiveGateway:     "old",
		PreviousGateway:   "older",
		Gateways: map[string]gatewayRecord{
			"old": gatewayRecordFromConfig("old", gatewayConfig{ServerIP: "1.1.1.1", ServerPort: "443", Raw: map[string]string{}}, now),
			"new": gatewayRecordFromConfig("new", gatewayConfig{ServerIP: "2.2.2.2", ServerPort: "443", Raw: map[string]string{}}, now),
		},
	}
	err := (app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, root: t.TempDir()}).activateGateway("new", &st, "use", func(gatewayConfig) (string, error) {
		return "", errors.New("verification failed")
	}, func(envRef) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected verification failure, got %v", err)
	}
	if st.ActiveGateway != "old" || st.PreviousGateway != "older" || st.GatewayGeneration != 7 {
		t.Fatalf("failed activation mutated state: active=%q previous=%q generation=%d", st.ActiveGateway, st.PreviousGateway, st.GatewayGeneration)
	}
	if len(st.Events) == 0 || !strings.Contains(st.Events[len(st.Events)-1].Message, "activation failed") {
		t.Fatalf("failed activation event missing: %+v", st.Events)
	}
}

func TestGatewayUseFailedRenderKeepsPreviousActive(t *testing.T) {
	root := t.TempDir()
	gwDir := filepath.Join(root, "deploy", "gateway")
	if err := os.MkdirAll(gwDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gwDir, "config.template.json"), []byte(`{"id":"${XRAY_UUID}"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st := envdState{
		ActiveGateway:     "good",
		GatewayGeneration: 7,
		Gateways: map[string]gatewayRecord{
			"good": {Name: "good", Raw: map[string]string{}},
			"bad":  {Name: "bad", Raw: map[string]string{}},
		},
	}
	var out bytes.Buffer
	err := (app{root: root, stdout: &out, stderr: &bytes.Buffer{}}).runGatewayUse([]string{"bad"}, &st)
	if err == nil {
		t.Fatal("expected gateway use to fail")
	}
	if st.ActiveGateway != "good" {
		t.Fatalf("active gateway changed on failure: %q", st.ActiveGateway)
	}
	if st.GatewayGeneration != 7 {
		t.Fatalf("generation changed on failure: %d", st.GatewayGeneration)
	}
}

type testSSHServer struct {
	addr  string
	state *testSSHServerState
}

type testSSHServerState struct {
	mu       sync.Mutex
	commands []string
	handler  func(string) (string, uint32)
}

func startTestSSHServer(t *testing.T, user, password string) testSSHServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ssh host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("create ssh signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh: %v", err)
	}
	state := &testSSHServerState{handler: defaultTestSSHResponse}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, cfg, state)
		}
	}()
	return testSSHServer{addr: ln.Addr().String(), state: state}
}

func (s testSSHServer) commands() []string {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return append([]string(nil), s.state.commands...)
}

func (s testSSHServer) setHandler(handler func(string) (string, uint32)) {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	s.state.handler = handler
}

func serveTestSSHConn(conn net.Conn, cfg *ssh.ServerConfig, state *testSSHServerState) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go serveTestSSHSession(channel, requests, state)
	}
}

func serveTestSSHSession(channel ssh.Channel, requests <-chan *ssh.Request, state *testSSHServerState) {
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct {
			Command string
		}
		ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)
		state.mu.Lock()
		state.commands = append(state.commands, payload.Command)
		handler := state.handler
		state.mu.Unlock()
		out, status := handler(payload.Command)
		_, _ = io.WriteString(channel, out)
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

func defaultTestSSHResponse(command string) (string, uint32) {
	if strings.Contains(command, "os-release") {
		return "os=ubuntu\nversion=24.04\narch=aarch64\nmemory_mb=2048\ndisk_mb=20480\ninit_system=systemd\nfirewall=ufw\n", 0
	}
	if strings.Contains(command, "envd_owned_service") {
		return "envd_owned_service=true\nenvd_owned_config=false\nunknown_config=/etc/xray/config.json\nxray_binary=/usr/local/bin/xray\nxray_version=Xray 25.1.1\n", 0
	}
	return "", 0
}

func containsCommand(commands []string, substr string) bool {
	for _, command := range commands {
		if strings.Contains(command, substr) {
			return true
		}
	}
	return false
}
