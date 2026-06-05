package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const stateSchemaVersion = 1

type encryptedEnvelope struct {
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	Salt        string `json:"salt"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}

type envdState struct {
	SchemaVersion     int                            `json:"schema_version"`
	CreatedAt         time.Time                      `json:"created_at"`
	GatewayGeneration int                            `json:"gateway_generation"`
	ActiveGateway     string                         `json:"active_gateway,omitempty"`
	PreviousGateway   string                         `json:"previous_gateway,omitempty"`
	Gateways          map[string]gatewayRecord       `json:"gateways,omitempty"`
	RemoteGateways    map[string]remoteGatewayRecord `json:"remote_gateways,omitempty"`
	GatewayChains     map[string]gatewayChainRecord  `json:"gateway_chains,omitempty"`
	Events            []stateEvent                   `json:"events"`
	Environments      map[string]envRecord           `json:"environments,omitempty"`
	Profiles          map[string]profileRecord       `json:"profiles,omitempty"`
	Identities        map[string]identityRecord      `json:"identities,omitempty"`
	RecoveryPoints    []recoveryPointRecord          `json:"recovery_points,omitempty"`
	Assets            map[string]assetRecord         `json:"assets,omitempty"`
	DoctorFailures    map[string]string              `json:"doctor_failures,omitempty"`
	InternetChecks    []internetCheckRecord          `json:"internet_checks,omitempty"`
	HostingChecks     []hostingCheckRecord           `json:"hosting_checks,omitempty"`
}

type stateEvent struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Subject string    `json:"subject,omitempty"`
	Message string    `json:"message"`
}

type internetCheckRecord struct {
	Time    time.Time             `json:"time"`
	Results []internetProbeRecord `json:"results"`
	Summary internetCheckSummary  `json:"summary"`
}

type internetProbeRecord struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type internetCheckSummary struct {
	OK    int `json:"ok"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Total int `json:"total"`
}

type hostingCheckRecord struct {
	Time      time.Time           `json:"time"`
	Provider  string              `json:"provider"`
	Homepage  internetProbeRecord `json:"homepage"`
	API       internetProbeRecord `json:"api"`
	Reachable bool                `json:"reachable"`
}

type envRecord struct {
	ID                string    `json:"id"`
	Network           string    `json:"network"`
	Storage           string    `json:"storage"`
	StorageBackend    string    `json:"storage_backend,omitempty"`
	StorageImagePath  string    `json:"storage_image_path,omitempty"`
	StorageMountPath  string    `json:"storage_mount_path,omitempty"`
	StorageKey        string    `json:"storage_key,omitempty"`
	Image             string    `json:"image"`
	Profile           string    `json:"profile,omitempty"`
	ProfileGeneration int       `json:"profile_generation,omitempty"`
	GatewayGeneration int       `json:"gateway_generation"`
	Legacy            bool      `json:"legacy,omitempty"`
	BlockedReason     string    `json:"blocked_reason,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastUsedAt        time.Time `json:"last_used_at,omitempty"`
}

type profileRecord struct {
	Name       string           `json:"name"`
	ID         string           `json:"id"`
	Generation int              `json:"generation"`
	Image      string           `json:"image,omitempty"`
	Packages   []profilePackage `json:"packages,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

type profilePackage struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

type identityRecord struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	PrivateKey  string         `json:"private_key,omitempty"`
	PublicKey   string         `json:"public_key,omitempty"`
	Username    string         `json:"username,omitempty"`
	Password    string         `json:"password,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Policy      identityPolicy `json:"policy"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type identityPolicy struct {
	AllowedNetworks       []string `json:"allowed_networks"`
	RequireHealthySealed  bool     `json:"require_healthy_sealed"`
	RequireGatewayCurrent bool     `json:"require_gateway_current"`
}

type recoveryPointRecord struct {
	ID        string    `json:"id"`
	EnvID     string    `json:"env_id"`
	EnvName   string    `json:"env_name"`
	Reason    string    `json:"reason"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

type assetRecord struct {
	Image      string    `json:"image"`
	ImageID    string    `json:"image_id"`
	RepoDigest string    `json:"repo_digest,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type gatewayRecord struct {
	Name              string            `json:"name"`
	Provider          string            `json:"provider"`
	BindIP            string            `json:"bind_ip"`
	SOCKSPort         int               `json:"socks_port"`
	HTTPHostPort      int               `json:"http_host_port"`
	SOCKSInner        int               `json:"socks_inner"`
	HTTPInner         int               `json:"http_inner"`
	ServerIP          string            `json:"server_ip"`
	ServerPort        string            `json:"server_port"`
	Raw               map[string]string `json:"raw"`
	ImportedFromLocal bool              `json:"imported_from_local"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type remoteGatewayRecord struct {
	Name          string                   `json:"name"`
	Host          string                   `json:"host"`
	User          string                   `json:"user"`
	Provider      string                   `json:"provider"`
	Strategy      string                   `json:"strategy"`
	Mode          string                   `json:"mode"`
	Password      string                   `json:"password,omitempty"`
	HostKeySHA256 string                   `json:"host_key_sha256,omitempty"`
	Inspection    remoteGatewayInspection  `json:"inspection"`
	ProviderState remoteProviderInspection `json:"provider_state"`
	Material      remoteGatewayMaterial    `json:"material,omitempty"`
	LastProbeAt   time.Time                `json:"last_probe_at"`
	CreatedAt     time.Time                `json:"created_at"`
	UpdatedAt     time.Time                `json:"updated_at"`
}

type remoteGatewayMaterial struct {
	XrayVersion       string `json:"xray_version,omitempty"`
	Port              int    `json:"port,omitempty"`
	UUID              string `json:"uuid,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	ShortID           string `json:"short_id,omitempty"`
	SNI               string `json:"sni,omitempty"`
	ConfigJSON        string `json:"config_json,omitempty"`
	ServiceUnit       string `json:"service_unit,omitempty"`
}

type remoteGatewayInspection struct {
	OS         string `json:"os,omitempty"`
	Version    string `json:"version,omitempty"`
	Arch       string `json:"arch,omitempty"`
	MemoryMB   int    `json:"memory_mb,omitempty"`
	DiskMB     int    `json:"disk_mb,omitempty"`
	InitSystem string `json:"init_system,omitempty"`
	Firewall   string `json:"firewall,omitempty"`
}

type remoteProviderInspection struct {
	EnvdOwnedService bool     `json:"envd_owned_service"`
	EnvdOwnedConfig  bool     `json:"envd_owned_config"`
	UnknownConfigs   []string `json:"unknown_configs,omitempty"`
	XrayBinary       string   `json:"xray_binary,omitempty"`
	XrayVersion      string   `json:"xray_version,omitempty"`
}

type gatewayChainRecord struct {
	Name      string    `json:"name"`
	Entry     string    `json:"entry"`
	Exit      string    `json:"exit"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type stateStore struct {
	dir  string
	path string
}

func newStateStore() (stateStore, error) {
	dir := os.Getenv("ENVD_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return stateStore{}, err
		}
		dir = filepath.Join(home, ".local", "state", "envd")
	}
	return stateStore{dir: dir, path: filepath.Join(dir, "state.enc")}, nil
}

func (s stateStore) withState(stderr io.Writer, fn func(*envdState) error) error {
	return s.withStateMode(stderr, false, fn)
}

func (s stateStore) withStateSaveOnError(stderr io.Writer, fn func(*envdState) error) error {
	return s.withStateMode(stderr, true, fn)
}

func (s stateStore) withStateMode(stderr io.Writer, saveOnFnErr bool, fn func(*envdState) error) error {
	return s.withStatePasswordMode(stderr, saveOnFnErr, func(st *envdState, _ []byte) error {
		return fn(st)
	})
}

func (s stateStore) withStatePasswordSaveOnError(stderr io.Writer, fn func(*envdState, []byte) error) error {
	return s.withStatePasswordMode(stderr, true, fn)
}

func (s stateStore) withStatePasswordMode(stderr io.Writer, saveOnFnErr bool, fn func(*envdState, []byte) error) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	password, err := readMasterPassword(stderr, !fileExists(s.path))
	if err != nil {
		return err
	}
	clear := func() {
		for i := range password {
			password[i] = 0
		}
	}
	defer clear()

	st, err := s.loadOrCreate(password)
	if err != nil {
		return err
	}
	if err := fn(&st, password); err != nil {
		if saveOnFnErr {
			if saveErr := s.save(st, password); saveErr != nil {
				return fmt.Errorf("%w; additionally failed to save state: %v", err, saveErr)
			}
		}
		return err
	}
	return s.save(st, password)
}

func (s stateStore) loadOrCreate(password []byte) (envdState, error) {
	if !fileExists(s.path) {
		now := time.Now().UTC()
		return envdState{
			SchemaVersion:  stateSchemaVersion,
			CreatedAt:      now,
			Gateways:       map[string]gatewayRecord{},
			RemoteGateways: map[string]remoteGatewayRecord{},
			GatewayChains:  map[string]gatewayChainRecord{},
			Environments:   map[string]envRecord{},
			Profiles:       map[string]profileRecord{},
			Identities:     map[string]identityRecord{},
			RecoveryPoints: []recoveryPointRecord{},
			Assets:         map[string]assetRecord{},
			DoctorFailures: map[string]string{},
			Events: []stateEvent{{
				Time:    now,
				Kind:    "state",
				Message: "encrypted state initialized",
			}},
		}, nil
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		return envdState{}, err
	}
	var env encryptedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envdState{}, fmt.Errorf("state envelope is corrupt: %w", err)
	}
	plain, err := decryptEnvelope(env, password)
	if err != nil {
		return envdState{}, fmt.Errorf("cannot unlock encrypted state: %w", err)
	}
	var st envdState
	if err := json.Unmarshal(plain, &st); err != nil {
		return envdState{}, fmt.Errorf("state payload is corrupt: %w", err)
	}
	if st.SchemaVersion != stateSchemaVersion {
		return envdState{}, fmt.Errorf("unsupported state schema %d", st.SchemaVersion)
	}
	st.ensureDefaults()
	return st, nil
}

func (s stateStore) save(st envdState, password []byte) error {
	raw, err := json.Marshal(st)
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
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s stateStore) lock() (func(), error) {
	lockPath := filepath.Join(s.dir, "state.lock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("state is locked by another envd process: %s", lockPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func encryptEnvelope(plain, password []byte) (encryptedEnvelope, error) {
	salt := randomBytes(16)
	nonce := randomBytes(12)
	params := kdfParams()
	key := deriveKey(password, salt, params)
	block, err := aes.NewCipher(key)
	if err != nil {
		return encryptedEnvelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedEnvelope{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	return encryptedEnvelope{
		Version:     1,
		KDF:         "argon2id",
		Time:        params.time,
		MemoryKiB:   params.memoryKiB,
		Parallelism: params.parallelism,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptEnvelope(env encryptedEnvelope, password []byte) ([]byte, error) {
	if env.Version != 1 || env.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported envelope version or kdf")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	key := deriveKey(password, salt, kdfParam{time: env.Time, memoryKiB: env.MemoryKiB, parallelism: env.Parallelism})
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

type kdfParam struct {
	time        uint32
	memoryKiB   uint32
	parallelism uint8
}

func kdfParams() kdfParam {
	p := uint8(runtime.NumCPU())
	if p > 4 {
		p = 4
	}
	if p < 1 {
		p = 1
	}
	return kdfParam{time: 3, memoryKiB: 64 * 1024, parallelism: p}
}

func deriveKey(password, salt []byte, p kdfParam) []byte {
	return argon2.IDKey(password, salt, p.time, p.memoryKiB, p.parallelism, 32)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func readMasterPassword(stderr io.Writer, create bool) ([]byte, error) {
	if v := os.Getenv("ENVD_MASTER_PASSWORD"); v != "" {
		return []byte(v), nil
	}
	prompt := "Master password: "
	if create {
		prompt = "Create envd master password: "
	}
	fmt.Fprint(stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(stderr)
		if err != nil {
			return nil, err
		}
		if len(pw) == 0 {
			return nil, errors.New("empty master password is not allowed")
		}
		return pw, nil
	}
	var pw string
	if _, err := fmt.Fscan(os.Stdin, &pw); err != nil {
		return nil, err
	}
	pw = strings.TrimSpace(pw)
	if pw == "" {
		return nil, errors.New("empty master password is not allowed")
	}
	return []byte(pw), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *envdState) ensureDefaults() {
	if s.Environments == nil {
		s.Environments = map[string]envRecord{}
	}
	if s.Gateways == nil {
		s.Gateways = map[string]gatewayRecord{}
	}
	if s.RemoteGateways == nil {
		s.RemoteGateways = map[string]remoteGatewayRecord{}
	}
	if s.GatewayChains == nil {
		s.GatewayChains = map[string]gatewayChainRecord{}
	}
	if s.Profiles == nil {
		s.Profiles = map[string]profileRecord{}
	}
	if s.Identities == nil {
		s.Identities = map[string]identityRecord{}
	}
	if s.RecoveryPoints == nil {
		s.RecoveryPoints = []recoveryPointRecord{}
	}
	if s.Assets == nil {
		s.Assets = map[string]assetRecord{}
	}
	if s.DoctorFailures == nil {
		s.DoctorFailures = map[string]string{}
	}
	if s.InternetChecks == nil {
		s.InternetChecks = []internetCheckRecord{}
	}
	if s.HostingChecks == nil {
		s.HostingChecks = []hostingCheckRecord{}
	}
	if s.Events == nil {
		s.Events = []stateEvent{}
	}
}

func (s *envdState) addEvent(kind, subject, message string) {
	s.ensureDefaults()
	s.Events = append(s.Events, stateEvent{
		Time:    time.Now().UTC(),
		Kind:    kind,
		Subject: subject,
		Message: message,
	})
}
