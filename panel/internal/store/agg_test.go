package store

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// seed writes n requests spread over the last span.
func seed(t *testing.T, st *Store, n int, span time.Duration, ips int) {
	t.Helper()
	r := rand.New(rand.NewSource(7))
	now := time.Now()
	hosts := []string{"a.example", "b.example", "c.example"}
	actions := []string{"", "", "", "", "", "", "waf_block", "rate_limit", "geo_block", "waf_detect", "banned"}
	batch := []protocol.Request{}
	for i := 0; i < n; i++ {
		ts := now.Add(-span).UnixMilli() + int64(float64(span.Milliseconds())*float64(i)/float64(n))
		a := actions[r.Intn(len(actions))]
		status := 200
		if isBlocking(a) {
			status = 403
		} else if r.Intn(10) == 0 {
			status = 404 + r.Intn(2)*98
		}
		det := ""
		if a == "waf_block" {
			det = fmt.Sprintf("94%d", r.Intn(5))
		}
		if a == "banned" {
			det = fmt.Sprintf("ban %d", r.Intn(3))
		}
		batch = append(batch, protocol.Request{T: ts, Host: hosts[r.Intn(3)], Method: []string{"GET", "POST"}[r.Intn(2)], Path: fmt.Sprintf("/p/%d", r.Intn(40)),
			IP: fmt.Sprintf("10.0.%d.%d", r.Intn(4), r.Intn(ips)), UA: []string{"curl", "Firefox", "Chrome"}[r.Intn(3)], Status: status, Bytes: int64(r.Intn(5000)),
			Dur: float64(r.Intn(100)), Policy: "p", Action: a, Detail: det, Country: []string{"DE", "FR", ""}[r.Intn(3)], ASN: r.Intn(3), ASOrg: "Org",
			Port: 443, Inst: []string{"local", "b"}[r.Intn(2)]})
		if len(batch) == 1000 {
			if err := st.InsertRequests(batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := st.InsertRequests(batch); err != nil {
		t.Fatal(err)
	}
}

func TestAggregatesMatchRaw(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed(t, st, 30000, 7*time.Hour, 60)
	pending, err := st.PendingHours(72)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range pending {
		if _, err := st.RollupHour(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	if hrs, _ := st.AggStatus(); hrs < 5 {
		t.Fatalf("only %d hours condensed", hrs)
	}
	now := time.Now()
	for _, f := range []RequestFilter{
		{From: now.Add(-6*time.Hour - 17*time.Minute).UnixMilli(), To: now.UnixMilli()},
		{From: now.Add(-5 * time.Hour).UnixMilli(), To: now.Add(-73 * time.Minute).UnixMilli(), Host: "b.example"},
		{From: now.Add(-8 * time.Hour).UnixMilli(), To: now.UnixMilli(), Inst: "b"},
	} {
		for dim := range topDims {
			agg, used, err := st.topAgg(dim, f, 1000)
			if err != nil || !used {
				t.Fatalf("%s: used=%v err=%v", dim, used, err)
			}
			raw, err := st.topRaw(dim, f, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for i := range raw { // AvgMs: float sums in a different order
				raw[i].AvgMs, agg[i].AvgMs = 0, 0
			}
			sortTop(raw)
			sortTop(agg)
			if !reflect.DeepEqual(agg, raw) {
				t.Errorf("%s %+v:\nagg %v\nraw %v", dim, f, agg[:min(3, len(agg))], raw[:min(3, len(raw))])
			}
		}
		fa, used, err := st.failuresAgg(f.From, f.To, f.Inst, f.Host, 500)
		if err != nil || !used {
			t.Fatalf("failures used=%v err=%v", used, err)
		}
		fr, err := st.failuresRaw(f.From, f.To, f.Inst, f.Host, 500)
		if err != nil {
			t.Fatal(err)
		}
		if len(fa) != len(fr) {
			t.Fatalf("failure groups: agg %d raw %d", len(fa), len(fr))
		}
		key := func(g FailureGroup) string {
			return fmt.Sprint(g.Host, g.Policy, g.Action, g.Detail, g.Rule, g.Port, g.Status, g.Inst)
		}
		rm := map[string]FailureGroup{}
		for _, g := range fr {
			rm[key(g)] = g
		}
		for _, g := range fa {
			r, ok := rm[key(g)]
			if !ok {
				t.Fatalf("group %s missing in raw", key(g))
			}
			if g.Count != r.Count || g.First != r.First || g.Last != r.Last || g.SampleID != r.SampleID {
				t.Errorf("group %s: agg %+v raw %+v", key(g), g, r)
			}
			if d := g.IPs - r.IPs; d*d > (r.IPs/10+2)*(r.IPs/10+2) {
				t.Errorf("group %s: ips agg %d raw %d", key(g), g.IPs, r.IPs)
			}
			if d := g.Paths - r.Paths; d*d > (r.Paths/10+2)*(r.Paths/10+2) {
				t.Errorf("group %s: paths agg %d raw %d", key(g), g.Paths, r.Paths)
			}
		}
	}
	// filters the aggregates cannot answer fall back to raw
	if _, used, _ := st.topAgg("ip", RequestFilter{From: 1, Status: "404"}, 10); used {
		t.Error("status filter must not use aggregates")
	}
	// late rows re-open a condensed hour
	old := now.Add(-4 * time.Hour).UnixMilli()
	if err := st.InsertRequests([]protocol.Request{{T: old, Host: "late.example", Status: 200, Inst: "local"}}); err != nil {
		t.Fatal(err)
	}
	if !contains64(mustPending(t, st), old/hourMs*hourMs) {
		t.Error("late request did not re-open its hour")
	}
}

func sortTop(es []TopEntry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && (es[j].Count > es[j-1].Count || (es[j].Count == es[j-1].Count && es[j].Key < es[j-1].Key)); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

func mustPending(t *testing.T, st *Store) []int64 {
	p, err := st.PendingHours(72)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func contains64(l []int64, v int64) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func TestHLL(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000, 20000} {
		var h hll
		for i := 0; i < n; i++ {
			h.add(fmt.Sprintf("192.0.2.%d/%d", i%251, i))
		}
		e := h.estimate()
		if d := float64(e-n) / float64(n); d > 0.15 || d < -0.15 {
			t.Errorf("n=%d estimate %d", n, e)
		}
	}
}

func TestRequestsWindow(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed(t, st, 5000, 3*time.Hour, 30)
	now := time.Now()
	for _, f := range []RequestFilter{
		{From: now.Add(-time.Hour).UnixMilli(), To: now.UnixMilli(), Limit: 100},
		{From: now.Add(-150 * time.Minute).UnixMilli(), To: now.Add(-100 * time.Minute).UnixMilli(), Limit: 1000},
		{From: now.Add(-3 * time.Hour).UnixMilli(), To: now.UnixMilli(), Host: "a.example", Limit: 50},
		{From: now.Add(time.Hour).UnixMilli(), To: now.Add(2 * time.Hour).UnixMilli(), Limit: 50},
	} {
		got, err := st.Requests(f)
		if err != nil {
			t.Fatal(err)
		}
		where, args := f.where()
		var want int
		_ = st.DB.QueryRow(`SELECT COUNT(*) FROM (SELECT id FROM requests WHERE `+where+` LIMIT ?)`, append(args, f.Limit)...).Scan(&want)
		if len(got) != want {
			t.Errorf("%+v: got %d rows, want %d", f, len(got), want)
		}
		for i := 1; i < len(got); i++ {
			if got[i].ID >= got[i-1].ID || got[i].T < f.From || got[i].T > f.To {
				t.Fatalf("order/window broken at %d", i)
			}
		}
	}
}
