package core

// Validation of the newer policy parts: instance scope, maintenance window,
// bot settings, WAF exclusions with end date and notes on rules.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

func (e *Engine) normalizePolicyExtras(p *PolicyDoc) error {
	// instances
	var insts []string
	known := map[string]bool{}
	for _, i := range e.Instances() {
		known[i.ID] = true
	}
	for _, id := range p.Instances {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if !known[id] {
			return fmt.Errorf("Caddy-Instanz %q existiert nicht", id)
		}
		insts = append(insts, id)
	}
	if len(insts) == len(known) {
		insts = nil // all instances = no restriction
	}
	if insts == nil {
		insts = []string{}
	}
	p.Instances = insts
	if len(p.Instances) > 0 && p.ID == e.Settings().DefaultPolicy {
		return fmt.Errorf("die Standard-Policy gilt immer auf allen Caddy-Instanzen")
	}

	// maintenance
	p.MaintenanceAllow = cleanList(p.MaintenanceAllow)
	for _, n := range p.MaintenanceAllow {
		if !validIPOrCIDR(n) {
			return fmt.Errorf("Wartung: ungültiges Netz %s", n)
		}
	}
	if p.MaintenanceUntil > 0 && p.MaintenanceFrom > 0 && p.MaintenanceUntil <= p.MaintenanceFrom {
		return fmt.Errorf("Wartung: das Ende muss nach dem Beginn liegen")
	}
	if p.Maintenance && p.MaintenanceUntil > 0 && p.MaintenanceUntil <= time.Now().Unix() {
		return fmt.Errorf("Wartung: das geplante Ende liegt in der Vergangenheit")
	}

	// bots
	for _, v := range []string{p.Bots.AI, p.Bots.SEO} {
		switch v {
		case "", "allow", "block", "limit":
		default:
			return fmt.Errorf("Bots: unbekannte Aktion %q", v)
		}
	}
	if p.Bots.LimitPerMinute < 0 || p.Bots.LimitPerMinute > 10000 {
		return fmt.Errorf("Bots: Grenze pro Minute zwischen 1 und 10000")
	}

	// WAF exclusions with end date
	for _, x := range p.WAF.Exclusions {
		if x.Until > 0 && x.Until <= time.Now().Unix() {
			return fmt.Errorf("WAF-Ausnahme %v: das Ablaufdatum liegt in der Vergangenheit", x.Rules)
		}
	}
	for i := range p.RateLimits {
		p.RateLimits[i].Note = strings.TrimSpace(p.RateLimits[i].Note)
	}
	for i := range p.PathRules {
		p.PathRules[i].Note = strings.TrimSpace(p.PathRules[i].Note)
	}
	return nil
}

// stampAuthors records who last changed a path rule or rate limit (only
// rules whose content changed get a new stamp).
func stampAuthors(old, p *PolicyDoc, user string) {
	now := time.Now().Unix()
	oldRules := map[string]protocol.PathRule{}
	oldRL := map[string]protocol.RateLimit{}
	if old != nil {
		for _, r := range old.PathRules {
			oldRules[r.ID] = r
		}
		for _, r := range old.RateLimits {
			oldRL[r.ID] = r
		}
	}
	for i := range p.PathRules {
		r := &p.PathRules[i]
		o, ok := oldRules[r.ID]
		if ok && sameRule(o, *r) {
			r.Author, r.Updated = o.Author, o.Updated
			continue
		}
		r.Author, r.Updated = user, now
	}
	for i := range p.RateLimits {
		r := &p.RateLimits[i]
		o, ok := oldRL[r.ID]
		if ok && sameJSON(stripRL(o), stripRL(*r)) {
			r.Author, r.Updated = o.Author, o.Updated
			continue
		}
		r.Author, r.Updated = user, now
	}
}

func sameRule(a, b protocol.PathRule) bool {
	a.Author, a.Updated, b.Author, b.Updated = "", 0, "", 0
	return sameJSON(a, b)
}

func stripRL(r protocol.RateLimit) protocol.RateLimit {
	r.Author, r.Updated = "", 0
	return r
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
