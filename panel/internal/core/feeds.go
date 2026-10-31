package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/iprange"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// FeedPreset is a well-known public IP blocklist.
type FeedPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	IntervalMin int    `json:"interval_min"`
}

// FeedPresets are offered in the UI. Licences/terms of the providers apply.
var FeedPresets = []FeedPreset{
	{"firehol-level1", "FireHOL Level 1", "https://iplists.firehol.org/files/firehol_level1.netset", "Bösartige Netze aus vielen Quellen, sehr wenige Fehlalarme. Gut als Blockliste.", 720},
	{"spamhaus-drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "Gekaperte und von Kriminellen kontrollierte Netze (Don't Route Or Peer).", 720},
	{"feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Botnetz-Command-and-Control-Server (Dridex, Emotet, QakBot …).", 360},
	{"blocklist-de", "blocklist.de (alle)", "https://lists.blocklist.de/lists/all.txt", "In den letzten 48 h gemeldete Angreifer (SSH, Mail, Web). Eher für Challenge statt Block.", 240},
	{"et-compromised", "Emerging Threats: kompromittiert", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "Bekannte kompromittierte Hosts.", 720},
	{"tor-exit", "Tor-Exit-Knoten", "https://check.torproject.org/torbulkexitlist", "Ausgangsknoten des Tor-Netzwerks. Eher für Challenge oder Protokollierung.", 120},
}

type feedManager struct {
	e      *Engine
	mu     sync.RWMutex
	sets   map[string]*iprange.Set
	client *http.Client
	kick   chan string
}

func newFeedManager(e *Engine) *feedManager {
	return &feedManager{e: e, sets: map[string]*iprange.Set{}, client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: guardedProxy, DialContext: noMetadataDialer().DialContext, TLSHandshakeTimeout: 15 * time.Second}}, kick: make(chan string, 16)}
}

func feedHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:8])
}

// load compiles all stored feeds (at startup).
func (m *feedManager) load() {
	feeds, err := m.e.Store.ListFeeds()
	if err != nil {
		return
	}
	for _, f := range feeds {
		full, err := m.e.Store.GetFeed(f.ID, true)
		if err != nil {
			continue
		}
		set, _ := iprange.Parse(strings.NewReader(full.Content))
		m.mu.Lock()
		m.sets[f.ID] = set
		m.mu.Unlock()
	}
}

// Refs lists enabled feeds for the agent state.
func (m *feedManager) Refs() []protocol.FeedRef {
	feeds, _ := m.e.Store.ListFeeds()
	var out []protocol.FeedRef
	for _, f := range feeds {
		if f.Enabled && f.Hash != "" {
			out = append(out, protocol.FeedRef{ID: f.ID, Name: f.Name, Hash: f.Hash, Count: f.Count})
		}
	}
	return out
}

// Match returns the feeds containing ip.
func (m *feedManager) Match(ip string) []string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for id, s := range m.sets {
		if s.Contains(a) {
			out = append(out, id)
		}
	}
	return out
}

// SetContent stores manually maintained feed content.
func (m *feedManager) SetContent(id, content string) (int, error) {
	set, n := iprange.Parse(strings.NewReader(content))
	if err := m.e.Store.SetFeedContent(id, content, feedHash(content), n, ""); err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.sets[id] = set
	m.mu.Unlock()
	m.e.Rebuild("feed " + id)
	return n, nil
}

func (m *feedManager) Delete(id string) {
	m.mu.Lock()
	delete(m.sets, id)
	m.mu.Unlock()
}

// Refresh downloads a feed now.
func (m *feedManager) Refresh(ctx context.Context, id string) error {
	f, err := m.e.Store.GetFeed(id, true)
	if err != nil {
		return err
	}
	if f.URL == "" {
		return fmt.Errorf("Feed hat keine URL (manuell gepflegt)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "caddy-sentinel/"+Version+" (+feed updater)")
	resp, err := m.client.Do(req)
	if err != nil {
		_ = m.e.Store.SetFeedError(id, err.Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("HTTP %d", resp.StatusCode)
		_ = m.e.Store.SetFeedError(id, err.Error())
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		_ = m.e.Store.SetFeedError(id, err.Error())
		return err
	}
	content := string(body)
	set, n := iprange.Parse(strings.NewReader(content))
	if n == 0 {
		err := fmt.Errorf("keine gültigen IP-Adressen in der Antwort")
		_ = m.e.Store.SetFeedError(id, err.Error())
		return err
	}
	hash := feedHash(content)
	changed := hash != f.Hash
	if err := m.e.Store.SetFeedContent(id, content, hash, n, ""); err != nil {
		return err
	}
	m.mu.Lock()
	m.sets[id] = set
	m.mu.Unlock()
	if changed && f.Enabled {
		m.e.Rebuild("feed " + id)
	}
	return nil
}

func (m *feedManager) run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	check := func() {
		feeds, err := m.e.Store.ListFeeds()
		if err != nil {
			return
		}
		now := time.Now().Unix()
		for _, f := range feeds {
			if !f.Enabled || f.URL == "" {
				continue
			}
			iv := int64(f.IntervalMin)
			if iv < 15 {
				iv = 15
			}
			if f.Hash != "" && now-f.Updated < iv*60 {
				continue
			}
			if f.Hash == "" && f.LastError != "" && now-f.Updated < 600 {
				continue // retry failed initial downloads every 10 min
			}
			if err := m.Refresh(ctx, f.ID); err != nil {
				m.e.log.Warn("feed update failed", "feed", f.ID, "err", err)
			}
		}
	}
	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		case id := <-m.kick:
			_ = m.Refresh(ctx, id)
		}
	}
}

// feedFromPreset creates a feed record from a preset.
func feedFromPreset(p FeedPreset) *store.Feed {
	return &store.Feed{ID: p.ID, Name: p.Name, URL: p.URL, Description: p.Description, IntervalMin: p.IntervalMin, Enabled: true}
}
