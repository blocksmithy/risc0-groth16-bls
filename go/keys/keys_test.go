package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestActiveKeySetConsistent checks that the manifest's active key-set resolves and that the
// committed (embedded) verifying key matches the fingerprint the manifest declares for it.
// This is what binds the binary to the published key: if the committed vk.bin were swapped, or
// the manifest fingerprint edited, this fails.
func TestActiveKeySetConsistent(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if m.Active == "" {
		t.Fatal("manifest has no active key-set")
	}
	ks, err := m.Resolve("")
	if err != nil {
		t.Fatalf("resolve active: %v", err)
	}

	vk, err := ks.VKBytes()
	if err != nil {
		t.Fatalf("read embedded vk for %q: %v", ks.Name, err)
	}
	sum := sha256.Sum256(vk)
	if got := hex.EncodeToString(sum[:]); got != ks.VKFingerprintSHA256 {
		t.Fatalf("committed vk for %q does not match manifest fingerprint:\n  vk.bin sha256 = %s\n  manifest      = %s",
			ks.Name, got, ks.VKFingerprintSHA256)
	}

	// Every key-set must carry the metadata a consumer relies on.
	for name, k := range m.KeySets {
		for field, v := range map[string]string{
			"vk_gate_sha256": k.VKGateSHA256, "ccs_sha256": k.CCSSHA256, "pk_sha256": k.PKSHA256, "pk_url": k.PKURL, "ccs_url": k.CCSURL,
		} {
			if v == "" {
				t.Errorf("key-set %q is missing %s", name, field)
			}
		}
	}
}

// TestResolveUnknown reports unknown key-sets rather than silently falling back.
func TestResolveUnknown(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve("does-not-exist"); err == nil {
		t.Fatal("expected an error resolving an unknown key-set")
	}
}
