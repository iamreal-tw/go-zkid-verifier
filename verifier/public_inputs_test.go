package verifier

import (
	"testing"
	"time"
)

func TestParseUserSig(t *testing.T) {
	const pkCommit = "0xdeadbeef"
	const nullifier = "0xfeedface"
	const challenge = "1234567890"

	// Pack 0x01..0x1f (31 bytes) little-endian into a field element.
	bytes := make([]byte, AppIDLen)
	for i := 0; i < AppIDLen; i++ {
		bytes[i] = byte(i + 1)
	}
	packed, err := PackAppIDLE(bytes)
	if err != nil {
		t.Fatalf("PackAppIDLE: %v", err)
	}

	ds, err := ParseUserSig([]string{pkCommit, nullifier, packed, challenge})
	if err != nil {
		t.Fatalf("ParseUserSig: %v", err)
	}
	if ds.PkCommit != pkCommit {
		t.Errorf("PkCommit: got %s, want %s", ds.PkCommit, pkCommit)
	}
	if ds.Nullifier != nullifier {
		t.Errorf("Nullifier: got %s, want %s", ds.Nullifier, nullifier)
	}
	if ds.AppIDPacked != packed {
		t.Errorf("AppIDPacked: got %s, want %s", ds.AppIDPacked, packed)
	}
	if ds.Challenge != challenge {
		t.Errorf("Challenge: got %s, want %s", ds.Challenge, challenge)
	}
}

func TestParseUserSigStrictLength(t *testing.T) {
	if _, err := ParseUserSig(make([]string, 3)); err == nil {
		t.Error("expected error for 3 signals (need 4)")
	}
	if _, err := ParseUserSig(make([]string, 5)); err == nil {
		t.Error("expected error for 5 signals (need 4)")
	}
}

func TestPackUnpackAppIDRoundTrip(t *testing.T) {
	cases := [][]byte{
		bytesIota(AppIDLen),
		bytesAll(0xff),
		append([]byte{0x00, 0x00}, bytesIota(AppIDLen-2)...),
	}
	for _, b := range cases {
		packed, err := PackAppIDLE(b)
		if err != nil {
			t.Fatalf("PackAppIDLE: %v", err)
		}
		got, err := UnpackAppID(packed)
		if err != nil {
			t.Fatalf("UnpackAppID: %v", err)
		}
		if got != string(b) {
			t.Errorf("round-trip mismatch: got %q, want %q", got, string(b))
		}
	}
}

func TestPackUnpackAppIDKnownValue(t *testing.T) {
	appID := "7a635353567978587232424230694e7"
	packed, err := PackAppIDLE([]byte(appID))
	if err != nil {
		t.Fatalf("PackAppIDLE: %v", err)
	}
	got, err := UnpackAppID(packed)
	if err != nil {
		t.Fatalf("UnpackAppID: %v", err)
	}
	if got != appID {
		t.Errorf("got %q, want %q", got, appID)
	}
}

func TestUnpackAppIDRejectsOversize(t *testing.T) {
	// 32-byte value (overflows the 31-byte budget for app_id).
	tooBig := "0x" + "01" + repeat("00", 31)
	if _, err := UnpackAppID(tooBig); err == nil {
		t.Error("expected error for >31-byte packed value")
	}
}

func bytesIota(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(i + 1)
	}
	return out
}

func bytesAll(v byte) []byte {
	out := make([]byte, AppIDLen)
	for i := range out {
		out[i] = v
	}
	return out
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestParseCertChainRS2048(t *testing.T) {
	signals := make([]string, 20)
	signals[0] = "0xpk"
	for i := 1; i < 18; i++ {
		signals[i] = "0xlimb"
	}
	signals[18] = "0xroot"
	signals[19] = "0xtime"

	cc, err := ParseCertChainRS2048(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS2048: %v", err)
	}
	if cc.PkCommit != "0xpk" {
		t.Errorf("PkCommit: got %q", cc.PkCommit)
	}
	if len(cc.IssuerRSAModulus) != 17 {
		t.Errorf("IssuerRSAModulus length: got %d, want 17", len(cc.IssuerRSAModulus))
	}
	if cc.SmtRoot != "0xroot" {
		t.Errorf("SmtRoot: got %q", cc.SmtRoot)
	}
	if cc.CurrentTime != "0xtime" {
		t.Errorf("CurrentTime: got %q", cc.CurrentTime)
	}
}

func TestParseCertChainRS2048StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS2048(make([]string, 19)); err == nil {
		t.Error("expected error for 19 signals (need exactly 20)")
	}
	if _, err := ParseCertChainRS2048(make([]string, 21)); err == nil {
		t.Error("expected error for 21 signals (need exactly 20)")
	}
}

func TestParseCertChainRS4096(t *testing.T) {
	signals := make([]string, 37)
	signals[0] = "0xpk"
	for i := 1; i < 35; i++ {
		signals[i] = "0xlimb"
	}
	signals[35] = "0xroot"
	signals[36] = "0xtime"

	cc, err := ParseCertChainRS4096(signals)
	if err != nil {
		t.Fatalf("ParseCertChainRS4096: %v", err)
	}
	if cc.PkCommit != "0xpk" {
		t.Errorf("PkCommit: got %q", cc.PkCommit)
	}
	if len(cc.IssuerRSAModulus) != 34 {
		t.Errorf("IssuerRSAModulus length: got %d, want 34", len(cc.IssuerRSAModulus))
	}
	if cc.SmtRoot != "0xroot" {
		t.Errorf("SmtRoot: got %q", cc.SmtRoot)
	}
	if cc.CurrentTime != "0xtime" {
		t.Errorf("CurrentTime: got %q", cc.CurrentTime)
	}
}

func TestParseCertChainRS4096StrictLength(t *testing.T) {
	if _, err := ParseCertChainRS4096(make([]string, 36)); err == nil {
		t.Error("expected error for 36 signals (need exactly 37)")
	}
	if _, err := ParseCertChainRS4096(make([]string, 38)); err == nil {
		t.Error("expected error for 38 signals (need exactly 37)")
	}
}

func TestParseCurrentTime(t *testing.T) {
	want := time.Date(2026, 11, 14, 15, 59, 59, 0, time.UTC)
	for _, in := range []string{"261114155959", "0x3ccb9dd3b7", " 261114155959 "} {
		got, err := ParseCurrentTime(in)
		if err != nil {
			t.Fatalf("ParseCurrentTime(%q): %v", in, err)
		}
		if !got.Equal(want) {
			t.Errorf("ParseCurrentTime(%q) = %s, want %s", in, got, want)
		}
	}

	// Years 2000-2009 drop the leading zeros of YY.
	got, err := ParseCurrentTime("90102030405")
	if err != nil {
		t.Fatalf("ParseCurrentTime(short): %v", err)
	}
	if want := time.Date(2009, 1, 2, 3, 4, 5, 0, time.UTC); !got.Equal(want) {
		t.Errorf("short = %s, want %s", got, want)
	}
}

func TestParseCurrentTimeRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"abc",
		"-1",
		"261314155959",  // month 13
		"260230000000",  // 30 February
		"261114245959",  // hour 24
		"261114156059",  // minute 60
		"1261114155959", // 13 digits
		"0xzz",
		// A full-width field element must not wrap into a plausible time.
		"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	} {
		if got, err := ParseCurrentTime(in); err == nil {
			t.Errorf("ParseCurrentTime(%q) = %s, want error", in, got)
		}
	}
}
