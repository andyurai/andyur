package policy

// Where an agent's ceiling comes from.
//
// THE CEILING IS REGISTRY DATA. `andyur/server/registry.py` opens with "The
// agent registry ceiling ... This module owns it: agents.ceiling_actions /
// agents.ceiling_audiences". An agent's ceiling is defined when the agent is
// defined, so the registry is the source and this server READS it rather than
// keeping a parallel copy that will drift.
//
// The split, stated once so it is not re-derived:
//
//	agent ceilings  -> Andyur's agent registry. Andyur is where agents exist.
//	user entitlements -> this server's own store. That is the enterprise's
//	                     directory, and Andyur has no business holding it.
//
// AND THE LIMIT THIS CREATES, which is easy to overstate the other way: when the
// ceiling is fetched FROM Andyur, the AS's refusal is a second opinion against a
// BUGGY Andyur, not a containment boundary against a COMPROMISED one -- a
// compromised Andyur would serve the bound it is about to be judged against. In
// the current threat model the harness is trusted and the agent is not, so this
// is the right trade. An adopter who does not trust the harness configures
// static ceilings here instead, and StaticCeilings is that configuration.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CeilingSource answers "what may this agent EVER hold".
type CeilingSource interface {
	Ceiling(agent string) (Ceiling, bool, error)
}

// StaticCeilings is the configured form: ceilings.json, for a deployment that
// does not want the AS depending on the harness.
type StaticCeilings map[string]Ceiling

func (s StaticCeilings) Ceiling(agent string) (Ceiling, bool, error) {
	c, ok := s[agent]
	return c, ok, nil
}

// RegistryCeilings reads GET /agents/{name}/ceiling from Andyur's registry.
type RegistryCeilings struct {
	BaseURL string
	// Operator credential. The endpoint is operator-gated, because the ceiling
	// tells you exactly how far an agent can go.
	Token string
	TTL   time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
	// Client is bounded: this call sits on the authorization path, and an
	// unbounded one turns a slow registry into a stalled AS.
	Client *http.Client
}

// Enough for any plausible agent population, small enough that a flood of
// forged names cannot grow the process without bound.
const maxCachedCeilings = 4096

type cacheEntry struct {
	ceiling Ceiling
	known   bool
	at      time.Time
}

func NewRegistryCeilings(baseURL, token string, ttl time.Duration) *RegistryCeilings {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &RegistryCeilings{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		TTL:     ttl,
		cache:   map[string]cacheEntry{},
		Client:  &http.Client{Timeout: 3 * time.Second},
	}
}

func (r *RegistryCeilings) Ceiling(agent string) (Ceiling, bool, error) {
	r.mu.Lock()
	if e, ok := r.cache[agent]; ok && time.Since(e.at) < r.TTL {
		r.mu.Unlock()
		return e.ceiling, e.known, nil
	}
	r.mu.Unlock()

	c, known, err := r.fetch(agent)
	if err != nil {
		// On ERROR, nothing is served from cache: a ceiling that may have been
		// TIGHTENED while the registry was unreachable must not keep authorising
		// at its old width. Note this is weaker than "a stale ceiling is never
		// served" -- inside the TTL an ordinary hit does serve one, so a
		// tightening takes up to TTL to apply. That is the cost of caching at
		// all, and it is bounded rather than absent.
		return Ceiling{}, false, err
	}
	r.mu.Lock()
	// BOUNDED. The key is an agent name taken from an actor token this fixture
	// does not verify, so it is caller-chosen, and 404s were cached too -- a
	// flood of forged names grew the map from 13MB to 46MB with no plateau while
	// firing one registry request per distinct name. At the cap the map is
	// dropped wholesale: the next lookups re-fetch, which is correct, where
	// serving an unbounded map is not.
	if len(r.cache) >= maxCachedCeilings {
		r.cache = map[string]cacheEntry{}
	}
	r.cache[agent] = cacheEntry{ceiling: c, known: known, at: time.Now()}
	r.mu.Unlock()
	return c, known, nil
}

func (r *RegistryCeilings) fetch(agent string) (Ceiling, bool, error) {
	// The agent name goes in a path segment. Anything that could escape it is
	// refused rather than escaped, because the registry's own NAME_RE is the
	// authority on what a name may be and this is not the place to re-implement it.
	if agent == "" || strings.ContainsAny(agent, "/?#%.") {
		return Ceiling{}, false, fmt.Errorf("implausible agent name %q", agent)
	}
	req, err := http.NewRequest("GET", r.BaseURL+"/agents/"+agent+"/ceiling", nil)
	if err != nil {
		return Ceiling{}, false, err
	}
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return Ceiling{}, false, fmt.Errorf("the agent registry did not answer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain before returning, or Go discards the connection instead of
		// pooling it and every 404 costs a fresh connect.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode == http.StatusNotFound {
			return Ceiling{}, false, nil // no such agent: a DENIAL upstream, not an error
		}
		return Ceiling{}, false, fmt.Errorf(
			"the agent registry answered %d for %q", resp.StatusCode, agent)
	}
	// Bounded read: the registry is another service and its body is not something
	// this process should size-trust.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return Ceiling{}, false, err
	}
	var out struct {
		Actions   []string `json:"actions"`
		Audiences []string `json:"audiences"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Ceiling{}, false, fmt.Errorf("unreadable ceiling for %q: %w", agent, err)
	}
	// A NULL ceiling in the registry means "unrestricted" there. It must NOT mean
	// unrestricted here: this server's job is to bound, and an absent bound is
	// exactly the composition that made two "unrestricted" sentinels permit every
	// action (docs/reviews/2026-08-06-open-findings.md #1).
	if out.Actions == nil && out.Audiences == nil {
		return Ceiling{}, false, fmt.Errorf(
			"agent %q has no ceiling set in the registry; this server will not "+
				"treat an unset ceiling as an unlimited one", agent)
	}
	return Ceiling{Actions: out.Actions, Audiences: out.Audiences}, true, nil
}
