package store

// Hourly aggregates keep the analytics fast with millions of stored
// requests: once an hour is over, a background job condenses its requests
// into top lists per dimension (agg_top) and failure groups (agg_fail).
// Queries combine the aggregates of full hours with the raw requests of the
// partial hours at the edges of the window, so results stay exact for short
// windows and current data. High-cardinality dimensions (path, IP, user
// agent, referer) keep the 500 most frequent values per hour, host and
// instance; distinct IPs/paths of failure groups use a small HyperLogLog
// sketch (about ±6 % above a few hundred values, near exact below).

import (
	"context"
	"database/sql"
	"hash/fnv"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	hourMs = int64(3600 * 1000)
	// aggTopK: values kept per hour, host and instance for the
	// high-cardinality dimensions.
	aggTopK = 500
	// aggGrace: an hour is condensed this long after it ended, so late
	// telemetry batches are included.
	aggGrace = 3 * time.Minute
)

// aggHighCard dimensions are truncated to aggTopK values per hour.
var aggHighCard = map[string]bool{"path": true, "ip": true, "ua": true, "referer": true, "asn": true, "rule": true}

func (s *Store) migrateAgg() error {
	_, err := s.DB.Exec(`
CREATE TABLE IF NOT EXISTS agg_top (
	hour    INTEGER NOT NULL,
	inst    TEXT NOT NULL,
	host    TEXT NOT NULL,
	dim     TEXT NOT NULL,
	key     TEXT NOT NULL,
	count   INTEGER NOT NULL,
	errors  INTEGER NOT NULL,
	blocked INTEGER NOT NULL,
	bytes   INTEGER NOT NULL,
	dur_sum REAL NOT NULL,
	last_ts INTEGER NOT NULL,
	PRIMARY KEY (dim, inst, host, hour, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_fail (
	hour    INTEGER NOT NULL,
	inst    TEXT NOT NULL,
	host    TEXT NOT NULL,
	policy  TEXT NOT NULL,
	action  TEXT NOT NULL,
	detail  TEXT NOT NULL,
	rule    TEXT NOT NULL,
	port    INTEGER NOT NULL,
	status  INTEGER NOT NULL,
	count   INTEGER NOT NULL,
	first   INTEGER NOT NULL,
	last    INTEGER NOT NULL,
	max_id  INTEGER NOT NULL,
	ips     BLOB NOT NULL,
	paths   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS agg_fail_hour ON agg_fail(hour);
CREATE TABLE IF NOT EXISTS ingest_batches (
	id TEXT PRIMARY KEY,
	ts INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_done (
	hour INTEGER PRIMARY KEY,
	rows INTEGER NOT NULL,
	at   INTEGER NOT NULL
);
`)
	return err
}

// ---------------------------------------------------------------- HyperLogLog

const hllRegs = 256

type hll [hllRegs]byte

func hashStr(v string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(v))
	x := h.Sum64()
	// splitmix finaliser: FNV alone is not uniform enough in the high bits
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func (h *hll) add(v string) {
	x := hashStr(v)
	idx := x >> 56
	rho := byte(bits.LeadingZeros64(x<<8|0xff)) + 1
	if rho > h[idx] {
		h[idx] = rho
	}
}

func (h *hll) merge(b []byte) {
	if len(b) != hllRegs {
		return
	}
	for i, v := range b {
		if v > h[i] {
			h[i] = v
		}
	}
}

func (h *hll) estimate() int {
	m := float64(hllRegs)
	var sum float64
	zeros := 0
	for _, v := range h {
		sum += math.Ldexp(1, -int(v))
		if v == 0 {
			zeros++
		}
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros)) // linear counting for small sets
	}
	return int(math.Round(e))
}

// ---------------------------------------------------------------- rollup

type aggRow struct {
	count, errors, blocked, bytes int64
	dur                           float64
	last                          int64
}

type aggKey struct{ inst, host, dim, key string }

type failKey struct {
	inst, host, policy, action, detail, rule string
	port, status                             int
}

type failAgg struct {
	count, first, last, maxID int64
	ips, paths                hll
}

// isBlocking mirrors blockingSQL.
func isBlocking(action string) bool {
	if strings.HasPrefix(action, "test:") {
		return false
	}
	switch action {
	case "", "waf_detect", "feed_match", "challenge_pass", "auth_login", "auth_required", "redirect":
		return false
	}
	return true
}

func asnKey(asn int64, aso string) string {
	if asn <= 0 {
		return ""
	}
	return "AS" + strconv.FormatInt(asn, 10) + " " + aso
}

// failKeyOf groups like the SQL in failuresRaw.
func failKeyOf(inst, host, policy, action, detail, rule string, port, status int) failKey {
	blocking := isBlocking(action)
	d := detail
	if !blocking || action == "banned" {
		d = ""
	}
	st := status
	if blocking {
		st = 0
	}
	return failKey{inst: inst, host: host, policy: policy, action: action, detail: d, rule: rule, port: port, status: st}
}

// rawAggregate condenses the requests in [from, to) (unix ms).
func (s *Store) rawAggregate(ctx context.Context, from, to int64, wantTop, wantFail bool) (map[aggKey]*aggRow, map[failKey]*failAgg, int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, COALESCE(inst,'local'), COALESCE(host,''), COALESCE(method,''), COALESCE(path,''), COALESCE(ip,''), COALESCE(ua,''), COALESCE(ref,''),
		COALESCE(status,0), COALESCE(bytes,0), COALESCE(dur,0), COALESCE(policy,''), COALESCE(action,''), COALESCE(detail,''), COALESCE(rule,''), COALESCE(port,0),
		COALESCE(cc,''), COALESCE(asn,0), COALESCE(aso,'')
		FROM requests WHERE ts>=? AND ts<?`, from, to)
	if err != nil {
		return nil, nil, 0, err
	}
	defer rows.Close()
	top := map[aggKey]*aggRow{}
	fail := map[failKey]*failAgg{}
	n := 0
	pruneAt := 400000 // map size that triggers trimming the long tails
	var (
		id, ts, bytes, asn                                                           int64
		inst, host, method, path, ip, ua, ref, policy, action, detail, rule, cc, aso string
		status, port                                                                 int
		dur                                                                          float64
	)
	add := func(k aggKey, isErr, isBlk bool) {
		r := top[k]
		if r == nil {
			r = &aggRow{}
			top[k] = r
		}
		r.count++
		if isErr {
			r.errors++
		}
		if isBlk {
			r.blocked++
		}
		r.bytes += bytes
		r.dur += dur
		if ts > r.last {
			r.last = ts
		}
	}
	for rows.Next() {
		if err := rows.Scan(&id, &ts, &inst, &host, &method, &path, &ip, &ua, &ref, &status, &bytes, &dur, &policy, &action, &detail, &rule, &port, &cc, &asn, &aso); err != nil {
			return nil, nil, 0, err
		}
		n++
		blk := isBlocking(action)
		if wantTop {
			isErr := status >= 400
			vals := [][2]string{{"path", path}, {"ip", ip}, {"ua", ua}, {"referer", ref}, {"status", strconv.Itoa(status)}, {"method", method},
				{"host", host}, {"action", action}, {"policy", policy}, {"country", cc}, {"asn", asnKey(asn, aso)}}
			if action == "waf_block" {
				vals = append(vals, [2]string{"rule", detail})
			}
			for _, v := range vals {
				for _, ih := range [4][2]string{{inst, host}, {inst, "*"}, {"*", host}, {"*", "*"}} {
					add(aggKey{ih[0], ih[1], v[0], v[1]}, isErr, blk)
				}
			}
			if len(top) > pruneAt {
				pruneTop(top, 50000) // keep memory bounded on very busy hours
				pruneAt = max(400000, 2*len(top))
			}
		}
		if wantFail && (status >= 400 || blk) {
			k := failKeyOf(inst, host, policy, action, detail, rule, port, status)
			f := fail[k]
			if f == nil {
				f = &failAgg{first: ts}
				fail[k] = f
			}
			f.count++
			if ts < f.first {
				f.first = ts
			}
			if ts > f.last {
				f.last = ts
			}
			if id > f.maxID {
				f.maxID = id
			}
			f.ips.add(ip)
			f.paths.add(path)
		}
	}
	return top, fail, n, rows.Err()
}

// pruneTop keeps the keep most frequent values per high-cardinality group.
func pruneTop(top map[aggKey]*aggRow, keep int) {
	groups := map[[3]string][]aggKey{}
	for k := range top {
		if aggHighCard[k.dim] {
			g := [3]string{k.inst, k.host, k.dim}
			groups[g] = append(groups[g], k)
		}
	}
	for _, ks := range groups {
		if len(ks) <= keep {
			continue
		}
		sort.Slice(ks, func(i, j int) bool { return top[ks[i]].count > top[ks[j]].count })
		for _, k := range ks[keep:] {
			delete(top, k)
		}
	}
}

// RollupHour condenses one hour (start in unix ms) into the aggregates.
func (s *Store) RollupHour(ctx context.Context, hour int64) (int, error) {
	top, fail, n, err := s.rawAggregate(ctx, hour, hour+hourMs, true, true)
	if err != nil {
		return 0, err
	}
	pruneTop(top, aggTopK)
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM agg_top WHERE hour=?`, hour); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM agg_fail WHERE hour=?`, hour); err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT INTO agg_top(hour,inst,host,dim,key,count,errors,blocked,bytes,dur_sum,last_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for k, r := range top {
			if _, err := st.Exec(hour, k.inst, k.host, k.dim, k.key, r.count, r.errors, r.blocked, r.bytes, r.dur, r.last); err != nil {
				return err
			}
		}
		sf, err := tx.Prepare(`INSERT INTO agg_fail(hour,inst,host,policy,action,detail,rule,port,status,count,first,last,max_id,ips,paths) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer sf.Close()
		for k, f := range fail {
			if _, err := sf.Exec(hour, k.inst, k.host, k.policy, k.action, k.detail, k.rule, k.port, k.status, f.count, f.first, f.last, f.maxID, f.ips[:], f.paths[:]); err != nil {
				return err
			}
		}
		// Rows that arrived while the hour was being read (late agent
		// batches) are not in this result: leave the hour pending so the next
		// round includes them.
		var now int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM requests WHERE ts>=? AND ts<?`, hour, hour+hourMs).Scan(&now); err != nil {
			return err
		}
		if now != n {
			return nil
		}
		_, err = tx.Exec(`INSERT INTO agg_done(hour,rows,at) VALUES(?,?,?) ON CONFLICT(hour) DO UPDATE SET rows=excluded.rows, at=excluded.at`, hour, n, time.Now().Unix())
		return err
	})
	return n, err
}

// PendingHours lists finished hours within the retention that are not
// condensed yet (newest first, so recent data gets fast first).
func (s *Store) PendingHours(retentionHours int) ([]int64, error) {
	now := time.Now()
	last := now.Add(-aggGrace).UnixMilli()/hourMs*hourMs - hourMs // newest finished hour
	first := (now.Add(-time.Duration(retentionHours)*time.Hour).UnixMilli()/hourMs + 1) * hourMs
	done := map[int64]bool{}
	rows, err := s.DB.Query(`SELECT hour FROM agg_done WHERE hour>=?`, first)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h int64
		if rows.Scan(&h) == nil {
			done[h] = true
		}
	}
	rows.Close()
	var out []int64
	for h := last; h >= first; h -= hourMs {
		if !done[h] {
			out = append(out, h)
		}
	}
	return out, nil
}

// markLate re-opens condensed hours that received late requests.
func (s *Store) markLate(tx *sql.Tx, hours map[int64]bool) {
	for h := range hours {
		_, _ = tx.Exec(`DELETE FROM agg_done WHERE hour=?`, h)
	}
}

// doneHours returns which hours in [from, to) are condensed.
func (s *Store) doneHours(from, to int64) map[int64]bool {
	out := map[int64]bool{}
	rows, err := s.DB.Query(`SELECT hour FROM agg_done WHERE hour>=? AND hour<?`, from, to)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var h int64
		if rows.Scan(&h) == nil {
			out[h] = true
		}
	}
	return out
}

// splitWindow divides [from, to] into condensed hours (aggregates) and raw
// segments. ok=false when the aggregates bring nothing (short window).
func (s *Store) splitWindow(from, to int64) (aggFrom, aggTo int64, hours []int64, raw [][2]int64, ok bool) {
	if from <= 0 {
		from = 1
	}
	if to <= 0 {
		to = time.Now().UnixMilli()
	}
	h0 := (from + hourMs - 1) / hourMs * hourMs
	h1 := (to + 1) / hourMs * hourMs // first hour not fully inside
	if h1-h0 < 2*hourMs {
		return 0, 0, nil, nil, false
	}
	done := s.doneHours(h0, h1)
	if len(done) < 2 {
		return 0, 0, nil, nil, false
	}
	if from < h0 {
		raw = append(raw, [2]int64{from, h0})
	}
	for h := h0; h < h1; h += hourMs {
		if done[h] {
			hours = append(hours, h)
			continue
		}
		if n := len(raw); n > 0 && raw[n-1][1] == h {
			raw[n-1][1] = h + hourMs
		} else {
			raw = append(raw, [2]int64{h, h + hourMs})
		}
	}
	if n := len(raw); n > 0 && raw[n-1][1] == h1 && h1 <= to {
		raw[n-1][1] = to + 1
	} else if h1 <= to {
		raw = append(raw, [2]int64{h1, to + 1})
	}
	return h0, h1, hours, raw, true
}

// aggEligible: filters the aggregates can answer.
func (f RequestFilter) aggEligible() bool {
	g := f
	g.From, g.To, g.Host, g.Inst, g.Limit, g.BeforeID = 0, 0, "", "", 0, 0
	return g == RequestFilter{}
}

// topAgg answers Top from the aggregates plus raw edge segments.
func (s *Store) topAgg(dim string, f RequestFilter, limit int) ([]TopEntry, bool, error) {
	if !f.aggEligible() {
		return nil, false, nil
	}
	_, _, hours, raw, ok := s.splitWindow(f.From, f.To)
	if !ok {
		return nil, false, nil
	}
	inst, host := f.Inst, f.Host
	if inst == "" {
		inst = "*"
	}
	if host == "" {
		host = "*"
	}
	m := map[string]*TopEntry{}
	acc := map[string]float64{}
	merge := func(key string, count, errs, blk, bytes int64, dur float64, last int64) {
		e := m[key]
		if e == nil {
			e = &TopEntry{Key: key}
			m[key] = e
		}
		e.Count += count
		e.Errors += errs
		e.Blocked += blk
		e.Bytes += bytes
		acc[key] += dur
		if last > e.LastSeen {
			e.LastSeen = last
		}
	}
	// condensed hours (contiguous ranges keep the query on the primary key)
	for _, rg := range hourRanges(hours) {
		rows, err := s.DB.Query(`SELECT key, SUM(count), SUM(errors), SUM(blocked), SUM(bytes), SUM(dur_sum), MAX(last_ts) FROM agg_top
			WHERE dim=? AND inst=? AND host=? AND hour>=? AND hour<? GROUP BY key`, dim, inst, host, rg[0], rg[1])
		if err != nil {
			return nil, true, err
		}
		for rows.Next() {
			var k string
			var c, e, b, by, last int64
			var d float64
			if err := rows.Scan(&k, &c, &e, &b, &by, &d, &last); err != nil {
				rows.Close()
				return nil, true, err
			}
			merge(k, c, e, b, by, d, last)
		}
		rows.Close()
	}
	// raw edges
	col := topDims[dim]
	for _, seg := range raw {
		g := f
		g.From, g.To = seg[0], seg[1]-1
		where, args := g.where()
		if dim == "rule" {
			where += " AND action='waf_block'"
		}
		rows, err := s.DB.Query(`SELECT COALESCE(`+col+`,'') AS k, COUNT(*), SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),
			SUM(CASE WHEN `+blockingSQL+` THEN 1 ELSE 0 END), COALESCE(SUM(bytes),0), COALESCE(SUM(dur),0), MAX(ts)
			FROM requests WHERE `+where+` GROUP BY k`, args...)
		if err != nil {
			return nil, true, err
		}
		for rows.Next() {
			var k string
			var c, e, b, by, last int64
			var d float64
			if err := rows.Scan(&k, &c, &e, &b, &by, &d, &last); err != nil {
				rows.Close()
				return nil, true, err
			}
			merge(k, c, e, b, by, d, last)
		}
		rows.Close()
	}
	out := make([]TopEntry, 0, len(m))
	for k, e := range m {
		if e.Count > 0 {
			e.AvgMs = acc[k] / float64(e.Count)
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, true, nil
}

// hourRanges merges sorted hours into [from, to) ranges.
func hourRanges(hours []int64) [][2]int64 {
	var out [][2]int64
	for _, h := range hours {
		if n := len(out); n > 0 && out[n-1][1] == h {
			out[n-1][1] = h + hourMs
		} else {
			out = append(out, [2]int64{h, h + hourMs})
		}
	}
	return out
}

// failuresAgg answers Failures from the aggregates plus raw edges.
func (s *Store) failuresAgg(from, to int64, inst, host string, limit int) ([]FailureGroup, bool, error) {
	_, _, hours, raw, ok := s.splitWindow(from, to)
	if !ok {
		return nil, false, nil
	}
	groups := map[failKey]*failAgg{}
	get := func(k failKey) *failAgg {
		g := groups[k]
		if g == nil {
			g = &failAgg{first: math.MaxInt64}
			groups[k] = g
		}
		return g
	}
	for _, rg := range hourRanges(hours) {
		q := `SELECT inst,host,policy,action,detail,rule,port,status,count,first,last,max_id,ips,paths FROM agg_fail WHERE hour>=? AND hour<?`
		args := []any{rg[0], rg[1]}
		if inst != "" {
			q += " AND inst=?"
			args = append(args, inst)
		}
		if host != "" {
			q += " AND host=?"
			args = append(args, host)
		}
		rows, err := s.DB.Query(q, args...)
		if err != nil {
			return nil, true, err
		}
		for rows.Next() {
			var k failKey
			var c, fi, la, mx int64
			var ips, paths []byte
			if err := rows.Scan(&k.inst, &k.host, &k.policy, &k.action, &k.detail, &k.rule, &k.port, &k.status, &c, &fi, &la, &mx, &ips, &paths); err != nil {
				rows.Close()
				return nil, true, err
			}
			g := get(k)
			g.count += c
			g.first = min(g.first, fi)
			g.last = max(g.last, la)
			g.maxID = max(g.maxID, mx)
			g.ips.merge(ips)
			g.paths.merge(paths)
		}
		rows.Close()
	}
	for _, seg := range raw {
		_, fail, _, err := s.rawAggregate(context.Background(), seg[0], seg[1], false, true)
		if err != nil {
			return nil, true, err
		}
		for k, f := range fail {
			if (inst != "" && k.inst != inst) || (host != "" && k.host != host) {
				continue
			}
			g := get(k)
			g.count += f.count
			g.first = min(g.first, f.first)
			g.last = max(g.last, f.last)
			g.maxID = max(g.maxID, f.maxID)
			g.ips.merge(f.ips[:])
			g.paths.merge(f.paths[:])
		}
	}
	out := make([]FailureGroup, 0, len(groups))
	for k, g := range groups {
		out = append(out, FailureGroup{Host: k.host, Policy: k.policy, Action: k.action, Detail: k.detail, Rule: k.rule, Port: k.port, Status: k.status,
			Inst: k.inst, Count: int(g.count), IPs: g.ips.estimate(), Paths: g.paths.estimate(), First: g.first, Last: g.last, SampleID: g.maxID})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Last > out[j].Last
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, true, nil
}

// PruneAgg drops aggregates older than before.
func (s *Store) PruneAgg(before int64) {
	h := before / hourMs * hourMs
	_, _ = s.Exec(`DELETE FROM agg_top WHERE hour<?`, h)
	_, _ = s.Exec(`DELETE FROM agg_fail WHERE hour<?`, h)
	_, _ = s.Exec(`DELETE FROM agg_done WHERE hour<?`, h)
}

// AggStatus reports how many hours are condensed (for diagnostics).
func (s *Store) AggStatus() (hours int, rows int64) {
	_ = s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(rows),0) FROM agg_done`).Scan(&hours, &rows)
	return
}
