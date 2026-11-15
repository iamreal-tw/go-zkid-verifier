package keymanager

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Upstream release. Its cert-chain keys are for the upstream circuit and fail
// the expectedSHA256 check below: the keys for the validity-check circuit are
// not published yet. Generate them with `cert-chain setup` from
// iamreal-tw/zkID at 85b8156 (the setup is deterministic) and place them in
// KEYS_DIR. The user-sig key is unchanged and still downloads from here.
const releaseURL = "https://github.com/privacy-ethereum/zkID/releases/download/RSA-X.509-Cert-latest"

// maxKeySize caps decompressed input as a gzip-bomb defense.
const maxKeySize = 2 * 1024 * 1024 * 1024

var (
	errTruncated  = errors.New("decompressed size exceeds cap")
	errSkipVerify = errors.New("no recorded checksum")
)

var RequiredKeys = []string{
	"cert_chain_rs2048_verifying.key",
	"cert_chain_rs4096_verifying.key",
	"user_sig_rs2048_verifying.key",
}

// expectedSHA256 pins each key's hex SHA-256. Empty string disables verification
// for that key. releaseURL is a moving "latest" tag; when upstream rotates keys,
// these hashes must be bumped in the same commit, and deployed caches must be
// cleared (or rely on the verifyFile mismatch path) to pick up the new release.
var expectedSHA256 = map[string]string{
	"cert_chain_rs2048_verifying.key": "0ba468bb63cc095f312e2316ff580481b985a55ef86b6fb0a5498ef061deff41",
	"cert_chain_rs4096_verifying.key": "3050b9b07dea498faad0184a9032213280a4f5e032434f3cb900917633da3724",
	"user_sig_rs2048_verifying.key":   "d85d0738827dcdfe13dc5fbf0ce8cddab5cbef3d55e6bf02c9c749190bdc3091",
}

var httpClient = &http.Client{Timeout: 10 * time.Minute}

// EnsureKeys verifies each RequiredKey in keysDir, re-downloading any that
// are missing or fail the expectedSHA256 check. Keys are processed in parallel.
func EnsureKeys(keysDir string) error {
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}

	errs := make([]error, len(RequiredKeys))
	var wg sync.WaitGroup
	for i, key := range RequiredKeys {
		wg.Add(1)
		go func(i int, key string) {
			defer wg.Done()
			if err := ensureOne(key, filepath.Join(keysDir, key)); err != nil {
				errs[i] = fmt.Errorf("ensure %s: %w", key, err)
			}
		}(i, key)
	}
	wg.Wait()
	return errors.Join(errs...)
}

func ensureOne(key, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		switch err := verifyFile(key, dest); {
		case err == nil:
			log.Printf("  %s present and verified", key)
			return nil
		case errors.Is(err, errSkipVerify):
			log.Printf("  %s exists, no checksum recorded; skipping verification", key)
			return nil
		default:
			log.Printf("  %s checksum mismatch (%v); re-downloading", key, err)
			if rmErr := os.Remove(dest); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return fmt.Errorf("remove stale %s: %w", key, rmErr)
			}
		}
	}

	if err := downloadAndDecompress(key, dest); err != nil {
		return err
	}
	log.Printf("  %s downloaded", key)
	return nil
}

func downloadAndDecompress(key, dest string) error {
	url := fmt.Sprintf("%s/%s.gz", releaseURL, key)

	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	// Unique tmp path: cross-process EnsureKeys against the same KEYS_DIR must
	// not clobber each other's in-flight writes.
	f, err := os.CreateTemp(filepath.Dir(dest), filepath.Base(dest)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp for %s: %w", key, err)
	}
	tmpFile := f.Name()

	sum, err := writeBoundedAndHash(f, gz, maxKeySize)
	closeErr := f.Close()
	if err != nil {
		os.Remove(tmpFile)
		if errors.Is(err, errTruncated) {
			return fmt.Errorf("decompressed %s exceeds %d byte cap", key, maxKeySize)
		}
		return fmt.Errorf("decompress %s: %w", key, err)
	}
	if closeErr != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close %s: %w", tmpFile, closeErr)
	}

	switch err := compareHash(key, hex.EncodeToString(sum.Sum(nil))); {
	case err == nil:
	case errors.Is(err, errSkipVerify):
		log.Printf("  %s: no recorded checksum, accepting download", key)
	default:
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, dest); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("rename %s: %w", key, err)
	}
	return nil
}

// writeBoundedAndHash copies r into w with a SHA-256 side-channel and returns
// errTruncated if r had more than limit bytes of payload. io.LimitReader alone
// is unsuitable here: it returns EOF at the cap, indistinguishable from a clean
// end of stream, so a too-large input would silently truncate.
func writeBoundedAndHash(w io.Writer, r io.Reader, limit int64) (hash.Hash, error) {
	h := sha256.New()
	mw := io.MultiWriter(w, h)
	if _, err := io.CopyN(mw, r, limit); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	var probe [1]byte
	switch n, err := r.Read(probe[:]); {
	case n > 0:
		return nil, errTruncated
	case err != nil && !errors.Is(err, io.EOF):
		return nil, err
	}
	return h, nil
}

func verifyFile(key, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return compareHash(key, hex.EncodeToString(h.Sum(nil)))
}

func compareHash(key, got string) error {
	want, ok := expectedSHA256[key]
	if !ok || want == "" {
		return errSkipVerify
	}
	if got != want {
		return fmt.Errorf("sha256 mismatch for %s: got %s want %s", key, got, want)
	}
	return nil
}
