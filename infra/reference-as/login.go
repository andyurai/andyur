package main

// The login page for STANDALONE Andyur -- a deployment with no enterprise SSO in
// front of it.
//
// The important property is what is NOT here: Andyur never renders a password
// box and never sees a password. `andyur auth login` is an ordinary OIDC client.
// It discovers whichever authorization server is configured and opens THAT
// server's login page. Standalone gets this one; an enterprise gets Okta's or
// Entra's, with no different code path on Andyur's side.
//
// This is the AS's page, not Andyur's, and it lives here because the reference
// AS is the default Andyur starts for you when you have none of your own
// (docs/replaceable-components.md: complete out of the box, every part
// swappable).

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

//go:embed login.html
var loginHTML string

// Set by main() so the form can name its own continuation URL.
var issuerURL string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// The standalone user store. Seeded from ANDYUR_REFAS_USERS as
// "alice:password,bob:password", defaulting to the demo users the SRE demo uses.
//
// Deliberately tiny and deliberately NOT a feature: a deployment with real users
// points Andyur at a real identity provider. This exists so someone with no
// infrastructure can still log in as a real subject rather than asserting one,
// which is what ANDYUR_ASSERTED_USER used to be for and is why that flag can go.
func users() map[string]string {
	raw := os.Getenv("ANDYUR_REFAS_USERS")
	if raw == "" {
		raw = "alice:alice-password,bob:bob-password"
	}
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		name, pass, ok := strings.Cut(strings.TrimSpace(pair), ":")
		if ok && name != "" {
			out[name] = pass
		}
	}
	return out
}

type pageData struct {
	Error  string
	Client string
	// Action is where the form posts. go-oidc resumes an authentication session
	// at /authorize/<session id>/login, NOT at /authorize -- posting back to the
	// original URL starts a new authorization request and 401s.
	Action string
}

// loginPolicy renders a form, and on POST authenticates against the store.
func loginPolicy() goidc.AuthnPolicy {
	store := users()
	log.Printf("standalone login enabled for %d user(s)", len(store))

	return goidc.NewPolicy(
		"standalone-login",
		// Applies to every request; there is only one way to log in here.
		func(r *http.Request, as *goidc.AuthnSession, c *goidc.Client) bool {
			return true
		},
		func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession,
			c *goidc.Client) (goidc.Status, error) {

			action := issuerURL + "/authorize/" + as.ID + "/login"
			if r.Method != http.MethodPost {
				render(w, pageData{Client: c.ID, Action: action})
				return goidc.StatusPending, nil
			}

			username := strings.TrimSpace(r.PostFormValue("username"))
			password := r.PostFormValue("password")
			want, known := store[username]

			// Hash BOTH sides before comparing. The previous version compared the
			// raw strings and claimed an unknown user cost the same as a known
			// one; ConstantTimeCompare returns 0 immediately on a length mismatch,
			// and `want` is "" for an unknown user, so the unknown-user path was
			// measurably cheaper and the comment asserted a property the code did
			// not have. Fixed-length digests make the comparison actually uniform.
			gotSum := sha256.Sum256([]byte(password))
			wantSum := sha256.Sum256([]byte(want))
			ok := subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
			if !known || !ok {
				// One message for both cases, for the same reason.
				log.Printf("login refused for %q", truncate(username, 64))
				render(w, pageData{Error: "Incorrect username or password.",
					Client: c.ID, Action: action})
				return goidc.StatusPending, nil
			}

			as.Subject = username
			as.Username = username
			// Grant exactly what was asked for. The AS is not where Andyur's
			// narrowing happens -- that is the four-term intersection, before
			// the exchange -- but nothing here should widen it either.
			as.GrantedScopes = as.Scopes
			// Resources must be GRANTED, not only validated. The token endpoint
			// checks the requested resource against what this session granted, so
			// a policy that sets scopes and forgets resources produces a
			// successful /authorize followed by invalid_target at /token -- which
			// reads like a misconfigured allow-list rather than a missing grant.
			as.GrantedResources = as.Resources
			log.Printf("login ok: sub=%s client=%s", username, c.ID)
			return goidc.StatusSuccess, nil
		},
	)
}

func render(w http.ResponseWriter, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// This page takes a password. Caching it, framing it, or letting a sniffed
	// content type change its meaning are all avoidable.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := loginTmpl.Execute(w, d); err != nil {
		log.Printf("login page render failed: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
