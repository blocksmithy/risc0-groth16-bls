// Package keys resolves the active Groth16 key-set.
//
// The verifying key is committed (embedded into the binary), so verification needs
// nothing else. The large proving key and constraint system are fetched from the
// ceremony release on first use, SHA-256-verified against the manifest, and cached,
// so prove works from a fresh clone with no manual key handling and no dev key.
//
// The manifest lists named key-sets (e.g. small-ceremony-2026-06, and later mainnet)
// with one active default; the prover's --key flag selects another.
package keys

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed manifest.json
var manifestJSON []byte

// The verifying key is embedded so the binary is self-contained. (vk.cardano.bin is committed
// next to it for the on-chain and native verifiers; the binary re-derives that encoding from vk.bin.)
// Add one line per additional key-set.
//
//go:embed small-ceremony-2026-06/vk.bin
var vkFS embed.FS

// Ceremony records the provenance of a key-set (for transparency; not security-critical).
type Ceremony struct {
	Participants  int    `json:"participants"`
	Contributions string `json:"contributions"`
	Finalized     string `json:"finalized"`
	Beacon        string `json:"beacon"`
	BeaconSource  string `json:"beacon_source"`
	Release       string `json:"release"`
}

// KeySet is one set of Groth16 keys produced by a ceremony.
type KeySet struct {
	Name                string   `json:"-"`
	Description         string   `json:"description"`
	VKGateSHA256        string   `json:"vk_gate_sha256"`        // sha256(vk.cardano.bin) - the prover's pinned gate value
	VKFingerprintSHA256 string   `json:"vk_fingerprint_sha256"` // sha256(vk.bin) - the ceremony record fingerprint
	CCSSHA256           string   `json:"ccs_sha256"`
	PKSHA256            string   `json:"pk_sha256"`
	PKURL               string   `json:"pk_url"`
	CCSURL              string   `json:"ccs_url"`
	Ceremony            Ceremony `json:"ceremony"`
}

// Manifest is the committed key registry.
type Manifest struct {
	Active  string            `json:"active"`
	KeySets map[string]KeySet `json:"keysets"`
}

// Load parses the embedded manifest.
func Load() (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("parse key manifest: %w", err)
	}
	for name, ks := range m.KeySets {
		ks.Name = name
		m.KeySets[name] = ks
	}
	return &m, nil
}

// Resolve returns the named key-set, or the manifest's active one if name is empty.
func (m *Manifest) Resolve(name string) (KeySet, error) {
	if name == "" {
		name = m.Active
	}
	ks, ok := m.KeySets[name]
	if !ok {
		return KeySet{}, fmt.Errorf("unknown key-set %q (available: %s)", name, m.Names())
	}
	return ks, nil
}

// Names lists the available key-set names, sorted.
func (m *Manifest) Names() string {
	ns := make([]string, 0, len(m.KeySets))
	for n := range m.KeySets {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return strings.Join(ns, ", ")
}

// VKBytes returns the committed (embedded) gnark verifying key.
func (ks KeySet) VKBytes() ([]byte, error) { return vkFS.ReadFile(ks.Name + "/vk.bin") }

// CacheDir is where the fetched pk/ccs are stored for this key-set.
// Override wins; else $RISC0_GROTH16_BLS_HOME/<name>; else ~/.risc0/groth16-bls/<name>.
func (ks KeySet) CacheDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if e := os.Getenv("RISC0_GROTH16_BLS_HOME"); e != "" {
		return filepath.Join(e, ks.Name), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for key cache: %w", err)
	}
	return filepath.Join(home, ".risc0", "groth16-bls", ks.Name), nil
}

// EnsurePK returns a local path to the proving key, fetching + verifying it if absent.
func (ks KeySet) EnsurePK(cacheDir string, logf func(string, ...any)) (string, error) {
	return ensureAsset(filepath.Join(cacheDir, "pk.bin"), ks.PKURL, ks.PKSHA256, "proving key", logf)
}

// EnsureCCS returns a local path to the constraint system, fetching + verifying it if absent.
func (ks KeySet) EnsureCCS(cacheDir string, logf func(string, ...any)) (string, error) {
	return ensureAsset(filepath.Join(cacheDir, "ccs.bin"), ks.CCSURL, ks.CCSSHA256, "constraint system", logf)
}

func ensureAsset(path, url, wantSHA, label string, logf func(string, ...any)) (string, error) {
	if FileSHA256(path) == wantSHA {
		return path, nil // cached and intact
	}
	if url == "" {
		return "", fmt.Errorf("%s not cached at %s and no download URL in manifest", label, path)
	}
	logf("fetching %s from %s", label, url)
	if err := download(url, path); err != nil {
		return "", fmt.Errorf("download %s: %w", label, err)
	}
	if got := FileSHA256(path); got != wantSHA {
		_ = os.Remove(path)
		return "", fmt.Errorf("%s SHA-256 mismatch after download:\n  want %s\n  got  %s", label, wantSHA, got)
	}
	logf("  cached %s at %s", label, path)
	return path, nil
}

// FileSHA256 returns the hex SHA-256 of a file, or "" if it cannot be read.
func FileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func download(url, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	c := &http.Client{Timeout: 30 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
