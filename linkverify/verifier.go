package linkverify

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/privacy-ethereum/go-zkid-verifier/issuercert"
	"github.com/privacy-ethereum/go-zkid-verifier/smtroot"
	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
)

// Bounds on the cert-chain proof's `currentTime` relative to the verifier's
// clock. The circuit proves the certificate was valid at `currentTime`; these
// bounds are what make that mean "valid now".
//
// MaxAge is the security-relevant side: a certificate that expired less than
// MaxAge ago can still pass, so keep it close to the challenge TTL. MaxAhead
// only makes the proof stricter about expiry (the certificate must stay valid
// until then), so it can be generous; it lets a prover use a coarse value such
// as the end of the current day instead of revealing its exact clock.
const (
	DefaultCurrentTimeMaxAge   = 10 * time.Minute
	DefaultCurrentTimeMaxAhead = 24 * time.Hour
)

type Verifier struct {
	KeysDir       string
	SmtRoot       *smtroot.Provider
	IssuerCert    *issuercert.Provider
	ExpectedAppID string // 31-char UTF-8 string; compared constant-time against parsed proof
	Logger        smtroot.Logger

	// The currentTime check always runs; zero values select the defaults.
	CurrentTimeMaxAge   time.Duration
	CurrentTimeMaxAhead time.Duration
	Now                 func() time.Time // nil → time.Now
}

// Result holds everything the handler needs to respond.
type Result struct {
	Verified      bool
	Reason        string
	Signals       *PublicSignals
	Parsed        *verifier.ParsedInputs
	SmtRoot       *SmtRootOutcome
	IssuerModulus *IssuerModulusOutcome
	AppID         *AppIDOutcome
	Challenge     *ChallengeOutcome
	CurrentTime   *CurrentTimeOutcome
}

// CurrentTimeOutcome reports whether the cert-chain proof's `currentTime`
// falls inside [Earliest, Latest], the window around the verifier's clock.
type CurrentTimeOutcome struct {
	Match    bool      `json:"match"`
	Observed time.Time `json:"observed"`
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`
}

// SmtRootOutcome is the outcome of the proof-vs-trusted-root comparison.
type SmtRootOutcome struct {
	Issuer      smtroot.IssuerID `json:"-"`
	IssuerName  string           `json:"issuer"`
	Match       bool             `json:"match"`
	Expected    string           `json:"expected"`
	Observed    string           `json:"observed"`
	TrustSource string           `json:"trust_source,omitempty"`
	TrustedAt   time.Time        `json:"trusted_at,omitempty"`
}

type IssuerModulusOutcome struct {
	Issuer         smtroot.IssuerID `json:"-"`
	IssuerName     string           `json:"issuer"`
	Match          bool             `json:"match"`
	ExpectedSHA256 string           `json:"expected_sha256"`
	TrustSource    string           `json:"trust_source,omitempty"`
	TrustedAt      time.Time        `json:"trusted_at,omitempty"`
}

type AppIDOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

// ChallengeOutcome reports whether the per-session challenge in the user-sig
// proof matches the value the verifier issued for this challenge.
type ChallengeOutcome struct {
	Match    bool   `json:"match"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

func (v *Verifier) Verify(req Request) (*Result, error) {
	ffiVerified, signals, err := Verify(req, v.KeysDir)
	if err != nil {
		return nil, err
	}
	if !ffiVerified {
		return &Result{Verified: false, Reason: ReasonProofInvalid, Signals: signals}, nil
	}

	certChainType := verifier.CertChainRS2048
	if req.ProofType == ProofTypeRS4096 {
		certChainType = verifier.CertChainRS4096
	}
	parsed, err := verifier.ParsePublicInputs(signals, certChainType)
	if err != nil {
		return nil, fmt.Errorf("parse public inputs: %w", err)
	}

	res := &Result{Verified: true, Signals: signals, Parsed: parsed}

	ctOutcome, err := v.checkCurrentTime(parsed)
	if err != nil {
		return nil, err
	}
	res.CurrentTime = ctOutcome
	if !ctOutcome.Match {
		res.Verified = false
		res.Reason = ReasonCurrentTimeOutOfRange
	}

	if v.SmtRoot != nil {
		outcome, err := checkSmtRoot(req.ProofType, parsed, v.SmtRoot, v.Logger)
		if err != nil {
			return nil, err
		}
		res.SmtRoot = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonSmtRootMismatch
		}
	}

	if v.IssuerCert != nil {
		outcome, err := checkIssuerModulus(req.ProofType, parsed, v.IssuerCert, v.Logger)
		if err != nil {
			return nil, err
		}
		res.IssuerModulus = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonIssuerModulusMismatch
		}
	}

	if v.ExpectedAppID != "" {
		outcome := checkAppID(parsed, v.ExpectedAppID, v.Logger)
		res.AppID = outcome
		if !outcome.Match && res.Reason == "" {
			res.Verified = false
			res.Reason = ReasonAppIDMismatch
		}
	}
	return res, nil
}

// CheckChallenge compares the per-session challenge in the proof against the
// value issued for this challenge (constant-time). Lives on Verifier so
// the service layer can reuse it after the FFI verify completes.
func (v *Verifier) CheckChallenge(parsed *verifier.ParsedInputs, expected string) *ChallengeOutcome {
	// Normalise the proof's challenge signal (may be 0x-prefixed hex) to
	// decimal before comparing with the decimal store key.
	observed, err := verifier.NormalizeDecimal(parsed.Challenge)
	if err != nil {
		observed = parsed.Challenge
	}
	match := subtle.ConstantTimeCompare([]byte(observed), []byte(expected)) == 1
	outcome := &ChallengeOutcome{
		Match:    match,
		Expected: expected,
		Observed: observed,
	}
	level, event := "info", "challenge_check"
	if !match {
		level, event = "warn", "challenge_mismatch"
	}
	v.Logger.Event(level, event,
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
	)
	return outcome
}

func (v *Verifier) checkCurrentTime(parsed *verifier.ParsedInputs) (*CurrentTimeOutcome, error) {
	observed, err := verifier.ParseCurrentTime(parsed.CurrentTime)
	if err != nil {
		return nil, fmt.Errorf("parse proof current_time: %w", err)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	maxAge, maxAhead := v.CurrentTimeMaxAge, v.CurrentTimeMaxAhead
	if maxAge <= 0 {
		maxAge = DefaultCurrentTimeMaxAge
	}
	if maxAhead <= 0 {
		maxAhead = DefaultCurrentTimeMaxAhead
	}
	t := now().UTC()
	outcome := &CurrentTimeOutcome{
		Observed: observed,
		Earliest: t.Add(-maxAge),
		Latest:   t.Add(maxAhead),
	}
	outcome.Match = !observed.Before(outcome.Earliest) && !observed.After(outcome.Latest)
	level, event := "info", "current_time_check"
	if !outcome.Match {
		level, event = "warn", "current_time_out_of_range"
	}
	if v.Logger != nil {
		v.Logger.Event(level, event,
			"observed", outcome.Observed.Format(time.RFC3339),
			"earliest", outcome.Earliest.Format(time.RFC3339),
			"latest", outcome.Latest.Format(time.RFC3339),
			"match", outcome.Match,
		)
	}
	return outcome, nil
}

func checkSmtRoot(pt ProofType, parsed *verifier.ParsedInputs, provider *smtroot.Provider, logger smtroot.Logger) (*SmtRootOutcome, error) {
	issuer := issuerForProofType(pt)
	observed, err := smtroot.ParseRoot(parsed.SmtRoot)
	if err != nil {
		return nil, fmt.Errorf("parse proof smt_root %q: %w", parsed.SmtRoot, err)
	}
	trusted, ok := provider.Trusted(issuer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSmtRootUnavailable, issuer.LongName())
	}
	meta := provider.Meta()
	outcome := &SmtRootOutcome{
		Issuer:      issuer,
		IssuerName:  issuer.ShortName(),
		Match:       observed.Equal(trusted),
		Expected:    trusted.Hex(),
		Observed:    observed.Hex(),
		TrustSource: meta.SourceUsed,
		TrustedAt:   meta.UpdatedAt,
	}
	level, event := "info", "smt_root_check"
	if !outcome.Match {
		level, event = "warn", "smt_root_mismatch"
	}
	logger.Event(level, event,
		"issuer", issuer.LongName(),
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
		"trust_source", outcome.TrustSource,
		"cache_age_s", meta.CacheAgeSeconds,
	)
	return outcome, nil
}

func checkIssuerModulus(pt ProofType, parsed *verifier.ParsedInputs, provider *issuercert.Provider, logger smtroot.Logger) (*IssuerModulusOutcome, error) {
	issuer := issuerForProofType(pt)
	rec, meta, ok := provider.TrustedWithMeta(issuer)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrIssuerCertUnavailable, issuer.LongName())
	}
	if got, want := len(parsed.IssuerRSAModulus), len(rec.Limbs); got != want {
		return nil, fmt.Errorf("issuer modulus limb count: got %d, want %d for %s", got, want, issuer.LongName())
	}
	match := issuercert.LimbsEqual(rec.Limbs, parsed.IssuerRSAModulus)
	outcome := &IssuerModulusOutcome{
		Issuer:         issuer,
		IssuerName:     issuer.ShortName(),
		Match:          match,
		ExpectedSHA256: rec.SHA256Hex,
		TrustSource:    rec.Source,
		TrustedAt:      meta.UpdatedAt,
	}
	level, event := "info", "issuer_modulus_check"
	if !match {
		level, event = "warn", "issuer_modulus_mismatch"
	}
	logger.Event(level, event,
		"issuer", issuer.LongName(),
		"expected_sha256", outcome.ExpectedSHA256,
		"match", match,
		"trust_source", outcome.TrustSource,
		"cache_age_s", meta.CacheAgeSeconds,
	)
	return outcome, nil
}

func checkAppID(parsed *verifier.ParsedInputs, expected string, logger smtroot.Logger) *AppIDOutcome {
	match := subtle.ConstantTimeCompare([]byte(parsed.AppID), []byte(expected)) == 1
	outcome := &AppIDOutcome{
		Match:    match,
		Expected: expected,
		Observed: parsed.AppID,
	}
	level, event := "info", "app_id_check"
	if !match {
		level, event = "warn", "app_id_mismatch"
	}
	logger.Event(level, event,
		"expected", outcome.Expected,
		"observed", outcome.Observed,
		"match", outcome.Match,
	)
	return outcome
}

// RS2048 → G2, RS4096 → G3.
func issuerForProofType(pt ProofType) smtroot.IssuerID {
	if pt == ProofTypeRS4096 {
		return smtroot.IssuerG3
	}
	return smtroot.IssuerG2
}
