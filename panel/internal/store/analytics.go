package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// InsertRequests stores raw request records.
func (s *Store) InsertRequests(reqs []protocol.Request) error {
	if len(reqs) == 0 {
		return nil
	}
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT INTO requests(ts,host,method,path,query,ip,ua,ref,proto,status,bytes,dur,policy,action,detail,waf_score,hits,sampled,cc,asn,aso,usr,sref,why,rule,port,inst)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		// requests for an hour that is already condensed (agent was offline
		// and sends late): re-open that hour
		late := map[int64]bool{}
		cutoff := time.Now().Add(-aggGrace).UnixMilli()/hourMs*hourMs - hourMs
		for _, r := range reqs {
			if h := r.T / hourMs * hourMs; h <= cutoff {
				late[h] = true
			}
		}
		if len(late) > 0 {
			s.markLate(tx, late)
		}
		for _, r := range reqs {
			var hits any
			if len(r.Hits) > 0 {
				b, _ := json.Marshal(r.Hits)
				hits = string(b)
			}
			smp := 0
			if r.Sampled {
				smp = 1
			}
			if _, err := st.Exec(r.T, r.Host, r.Method, r.Path, r.Query, r.IP, r.UA, r.Referer, r.Proto, r.Status, r.Bytes, r.Dur,
				r.Policy, r.Action, r.Detail, r.WAFScore, hits, smp, r.Country, r.ASN, r.ASOrg, nullStr(r.User), nullStr(r.Ref), nullStr(r.Why), nullStr(r.Rule), r.Port, instOr(r.Inst)); err != nil {
				return err
			}
		}
		return nil
	})
}

// AddRollups adds counters to the minute rollup table.
func (s *Store) AddRollups(minute int64, cs []protocol.Counter) error {
	if len(cs) == 0 {
		return nil
	}
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		for _, c := range cs {
			var existing string
			err := tx.QueryRow(`SELECT buckets FROM rollups WHERE minute=? AND inst=? AND host=? AND policy=? AND status=? AND action=?`,
				minute, instOr(c.Inst), c.Host, c.Policy, c.Status, c.Action).Scan(&existing)
			buckets := c.Buckets
			if err == nil {
				var old []int64
				_ = json.Unmarshal([]byte(existing), &old)
				buckets = addBuckets(old, c.Buckets)
			}
			b, _ := json.Marshal(buckets)
			if _, err := tx.Exec(`INSERT INTO rollups(minute,inst,host,policy,status,action,count,bytes,dur_sum,dur_max,buckets) VALUES(?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(minute,inst,host,policy,status,action) DO UPDATE SET
					count=count+excluded.count, bytes=bytes+excluded.bytes, dur_sum=dur_sum+excluded.dur_sum,
					dur_max=MAX(dur_max,excluded.dur_max), buckets=excluded.buckets`,
				minute, instOr(c.Inst), c.Host, c.Policy, c.Status, c.Action, c.Count, c.Bytes, c.DurSum, c.DurMax, string(b)); err != nil {
				return err
			}
		}
		return nil
	})
}

func addBuckets(a, b []int64) []int64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]int64, n)
	for i := range out {
		if i < len(a) {
			out[i] += a[i]
		}
		if i < len(b) {
			out[i] += b[i]
		}
	}
	return out
}

// ---------------------------------------------------------------- queries

type Range struct {
	From, To int64 // unix seconds
	Host     string
	Policy   string
	Inst     string // Caddy instance ("" = all)
}

type SeriesPoint struct {
	T        int64   `json:"t"` // unix seconds (bucket start)
	Requests int64   `json:"req"`
	S2       int64   `json:"s2"`
	S3       int64   `json:"s3"`
	S4       int64   `json:"s4"`
	S5       int64   `json:"s5"`
	Blocked  int64   `json:"blocked"`
	Bytes    int64   `json:"bytes"`
	AvgMs    float64 `json:"avg"`
	P95Ms    float64 `json:"p95"`
	MaxMs    float64 `json:"max"`
}

type Overview struct {
	Requests   int64            `json:"requests"`
	Bytes      int64            `json:"bytes"`
	Blocked    int64            `json:"blocked"`
	Errors4xx  int64            `json:"errors_4xx"`
	Errors5xx  int64            `json:"errors_5xx"`
	AvgMs      float64          `json:"avg_ms"`
	P50Ms      float64          `json:"p50_ms"`
	P95Ms      float64          `json:"p95_ms"`
	P99Ms      float64          `json:"p99_ms"`
	MaxMs      float64          `json:"max_ms"`
	ByAction   map[string]int64 `json:"by_action"`
	ByStatus   map[int]int64    `json:"by_status"`
	Histogram  []int64          `json:"histogram"`
	HistBounds []float64        `json:"hist_bounds"`
	Series     []SeriesPoint    `json:"series"`
	Step       int64            `json:"step"`
	Hosts      []HostStat       `json:"hosts"`
}

type HostStat struct {
	Host     string  `json:"host"`
	Requests int64   `json:"requests"`
	Bytes    int64   `json:"bytes"`
	Errors   int64   `json:"errors"`
	Blocked  int64   `json:"blocked"`
	AvgMs    float64 `json:"avg_ms"`
}

func rangeWhere(r Range) (string, []any) {
	w := []string{"minute>=?", "minute<=?"}
	args := []any{r.From / 60, r.To / 60}
	if r.Host != "" {
		w = append(w, "host=?")
		args = append(args, r.Host)
	}
	if r.Policy != "" {
		w = append(w, "policy=?")
		args = append(args, r.Policy)
	}
	if r.Inst != "" {
		w = append(w, "inst=?")
		args = append(args, r.Inst)
	}
	return strings.Join(w, " AND "), args
}

// isBlocked reports whether an agent action means the request was stopped.
func isBlocked(action string) bool { return protocol.IsBlocking(action) }

// Overview aggregates the rollups for the range with the given step (seconds).
func (s *Store) Overview(r Range, step int64) (*Overview, error) {
	if step < 60 {
		step = 60
	}
	where, args := rangeWhere(r)
	rows, err := s.DB.Query(`SELECT minute,host,status,action,count,bytes,dur_sum,dur_max,buckets FROM rollups WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ov := &Overview{ByAction: map[string]int64{}, ByStatus: map[int]int64{}, HistBounds: protocol.LatencyBuckets, Step: step}
	nb := len(protocol.LatencyBuckets) + 1
	ov.Histogram = make([]int64, nb)
	type agg struct {
		p    SeriesPoint
		dur  float64
		hist []int64
	}
	series := map[int64]*agg{}
	hosts := map[string]*HostStat{}
	hostDur := map[string]float64{}
	var durSum float64
	for rows.Next() {
		var minute, count, bytes int64
		var host, action, bucketsRaw string
		var status int
		var dsum, dmax float64
		if err := rows.Scan(&minute, &host, &status, &action, &count, &bytes, &dsum, &dmax, &bucketsRaw); err != nil {
			return nil, err
		}
		var buckets []int64
		_ = json.Unmarshal([]byte(bucketsRaw), &buckets)
		ts := minute * 60
		base := r.From - r.From%60
		key := base + ((ts-base)/step)*step
		a := series[key]
		if a == nil {
			a = &agg{p: SeriesPoint{T: key}, hist: make([]int64, nb)}
			series[key] = a
		}
		a.p.Requests += count
		a.p.Bytes += bytes
		a.dur += dsum
		if dmax > a.p.MaxMs {
			a.p.MaxMs = dmax
		}
		for i := 0; i < nb && i < len(buckets); i++ {
			a.hist[i] += buckets[i]
			ov.Histogram[i] += buckets[i]
		}
		switch status / 100 {
		case 2:
			a.p.S2 += count
		case 3:
			a.p.S3 += count
		case 4:
			a.p.S4 += count
			ov.Errors4xx += count
		case 5:
			a.p.S5 += count
			ov.Errors5xx += count
		}
		blocked := isBlocked(action)
		if blocked {
			a.p.Blocked += count
			ov.Blocked += count
		}
		if action != "" {
			ov.ByAction[action] += count
		}
		ov.ByStatus[status] += count
		ov.Requests += count
		ov.Bytes += bytes
		durSum += dsum
		if dmax > ov.MaxMs {
			ov.MaxMs = dmax
		}
		hs := hosts[host]
		if hs == nil {
			hs = &HostStat{Host: host}
			hosts[host] = hs
		}
		hs.Requests += count
		hs.Bytes += bytes
		hostDur[host] += dsum
		if status >= 500 {
			hs.Errors += count
		}
		if blocked {
			hs.Blocked += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ov.Requests > 0 {
		ov.AvgMs = durSum / float64(ov.Requests)
	}
	ov.P50Ms = histQuantile(ov.Histogram, 0.50, ov.MaxMs)
	ov.P95Ms = histQuantile(ov.Histogram, 0.95, ov.MaxMs)
	ov.P99Ms = histQuantile(ov.Histogram, 0.99, ov.MaxMs)

	// dense series
	start := r.From - (r.From % 60)
	for t := start; t <= r.To; t += step {
		a := series[t]
		if a == nil {
			ov.Series = append(ov.Series, SeriesPoint{T: t})
			continue
		}
		if a.p.Requests > 0 {
			a.p.AvgMs = a.dur / float64(a.p.Requests)
		}
		a.p.P95Ms = histQuantile(a.hist, 0.95, a.p.MaxMs)
		ov.Series = append(ov.Series, a.p)
	}
	for h, hs := range hosts {
		if hs.Requests > 0 {
			hs.AvgMs = hostDur[h] / float64(hs.Requests)
		}
		ov.Hosts = append(ov.Hosts, *hs)
	}
	sort.Slice(ov.Hosts, func(i, j int) bool { return ov.Hosts[i].Requests > ov.Hosts[j].Requests })
	return ov, nil
}

// histQuantile estimates a quantile from the latency histogram by linear
// interpolation inside the bucket.
func histQuantile(h []int64, q float64, max float64) float64 {
	var total int64
	for _, v := range h {
		total += v
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	bounds := protocol.LatencyBuckets
	for i, v := range h {
		prev := cum
		cum += float64(v)
		if cum >= target && v > 0 {
			lo := 0.0
			if i > 0 {
				lo = bounds[i-1]
			}
			hi := max
			if i < len(bounds) {
				hi = bounds[i]
			}
			if hi < lo {
				hi = lo
			}
			frac := (target - prev) / float64(v)
			val := lo + (hi-lo)*frac
			if max > 0 {
				val = math.Min(val, max)
			}
			return math.Round(val*100) / 100
		}
	}
	return max
}

// ---------------------------------------------------------------- raw request queries

type RequestFilter struct {
	From, To int64 // unix ms
	Host     string
	IP       string
	Path     string // substring
	Status   string // "4xx", "404", ...
	Method   string
	Action   string // specific, "blocked", "any"
	UA       string
	Policy   string
	Search   string
	User     string
	Country  string
	ASN      int
	Ref      string // reference from Sentinel's error page
	Detail   string // exact detail (grouping in the failure analysis)
	Rule     string // path rule ID
	Port     int
	Errors   bool   // only failed requests (status >= 400 or blocking action)
	Inst     string // Caddy instance
	BeforeID int64
	Limit    int
}

func (f RequestFilter) where() (string, []any) {
	w := []string{"1=1"}
	var args []any
	if f.From > 0 {
		w = append(w, "ts>=?")
		args = append(args, f.From)
	}
	if f.To > 0 {
		w = append(w, "ts<=?")
		args = append(args, f.To)
	}
	if f.Host != "" {
		w = append(w, "host=?")
		args = append(args, f.Host)
	}
	if f.User != "" {
		w = append(w, "usr=?")
		args = append(args, f.User)
	}
	if f.IP != "" {
		if strings.HasSuffix(f.IP, "*") {
			w = append(w, "ip LIKE ?")
			args = append(args, strings.TrimSuffix(f.IP, "*")+"%")
		} else {
			w = append(w, "ip=?")
			args = append(args, f.IP)
		}
	}
	if f.Path != "" {
		w = append(w, "path LIKE ?")
		args = append(args, "%"+f.Path+"%")
	}
	if f.Method != "" {
		w = append(w, "method=?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.UA != "" {
		w = append(w, "ua LIKE ?")
		args = append(args, "%"+f.UA+"%")
	}
	if f.Policy != "" {
		w = append(w, "policy=?")
		args = append(args, f.Policy)
	}
	if f.Status != "" {
		st := strings.ToLower(f.Status)
		if len(st) == 3 && strings.HasSuffix(st, "xx") {
			var c int
			fmt.Sscanf(st[:1], "%d", &c)
			w = append(w, "status>=? AND status<?")
			args = append(args, c*100, c*100+100)
		} else {
			var c int
			fmt.Sscanf(st, "%d", &c)
			w = append(w, "status=?")
			args = append(args, c)
		}
	}
	switch f.Action {
	case "":
	case "any":
		w = append(w, "action<>''")
	case "blocked":
		w = append(w, blockingSQL)
	case "none":
		w = append(w, "action=''")
	default:
		w = append(w, "action=?")
		args = append(args, f.Action)
	}
	if f.Search != "" {
		w = append(w, "(path LIKE ? OR query LIKE ? OR ua LIKE ? OR detail LIKE ? OR ip LIKE ? OR usr LIKE ? OR sref=? OR why LIKE ?)")
		q := "%" + f.Search + "%"
		args = append(args, q, q, q, q, q, q, normRef(f.Search), q)
	}
	if f.Inst != "" {
		w = append(w, "inst=?")
		args = append(args, f.Inst)
	}
	if f.Ref != "" {
		w = append(w, "sref=?")
		args = append(args, normRef(f.Ref))
	}
	if f.Detail != "" {
		w = append(w, "detail=?")
		args = append(args, f.Detail)
	}
	if f.Rule != "" {
		w = append(w, "rule=?")
		args = append(args, f.Rule)
	}
	if f.Port > 0 {
		w = append(w, "port=?")
		args = append(args, f.Port)
	}
	if f.Errors {
		w = append(w, "(status>=400 OR "+blockingSQL+")")
	}
	if f.Country != "" {
		if f.Country == "-" {
			w = append(w, "COALESCE(cc,'')=''")
		} else {
			w = append(w, "cc=?")
			args = append(args, strings.ToUpper(f.Country))
		}
	}
	if f.ASN > 0 {
		w = append(w, "asn=?")
		args = append(args, f.ASN)
	}
	if f.BeforeID > 0 {
		w = append(w, "id<?")
		args = append(args, f.BeforeID)
	}
	return strings.Join(w, " AND "), args
}

// requestsWhere builds the explorer condition. Rows are listed newest
// first by id; with only a time window SQLite would read the whole window
// through the ts index and sort it. Translating the window into an id range
// (two index lookups) lets it walk the primary key backwards and stop after
// LIMIT rows. The ts condition stays for exactness ("+ts" keeps SQLite
// from choosing the ts index again).
func (f RequestFilter) requestsWhere(s *Store) (string, []any) {
	if f.From <= 0 && f.To <= 0 {
		return f.where()
	}
	g := f
	g.From, g.To = 0, 0
	where, args := g.where()
	var lo, hi int64
	if f.From > 0 {
		if err := s.DB.QueryRow(`SELECT id FROM requests WHERE ts>=? ORDER BY ts LIMIT 1`, f.From).Scan(&lo); err != nil {
			return "0", nil // nothing in the window
		}
		// late batches can carry older timestamps than their id suggests
		lo -= 50000
		where += " AND id>=? AND +ts>=?"
		args = append(args, lo, f.From)
	}
	if f.To > 0 {
		if f.To < time.Now().Add(-time.Minute).UnixMilli() {
			if err := s.DB.QueryRow(`SELECT id FROM requests WHERE ts>? ORDER BY ts LIMIT 1`, f.To).Scan(&hi); err == nil {
				hi += 50000
				where += " AND id<=?"
				args = append(args, hi)
			}
		}
		where += " AND +ts<=?"
		args = append(args, f.To)
	}
	return where, args
}

type RequestRow struct {
	ID int64 `json:"id"`
	protocol.Request
}

func (s *Store) Requests(f RequestFilter) ([]RequestRow, error) {
	where, args := f.requestsWhere(s)
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	args = append(args, f.Limit)
	rows, err := s.DB.Query(`SELECT id,ts,COALESCE(host,''),COALESCE(method,''),COALESCE(path,''),COALESCE(query,''),COALESCE(ip,''),COALESCE(ua,''),COALESCE(ref,''),COALESCE(proto,''),
		COALESCE(status,0),COALESCE(bytes,0),COALESCE(dur,0),COALESCE(policy,''),COALESCE(action,''),COALESCE(detail,''),COALESCE(waf_score,0),COALESCE(hits,''),COALESCE(sampled,0),
		COALESCE(cc,''),COALESCE(asn,0),COALESCE(aso,''),COALESCE(usr,''),COALESCE(sref,''),COALESCE(why,''),COALESCE(rule,''),COALESCE(port,0),COALESCE(inst,'local')
		FROM requests WHERE `+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RequestRow{}
	for rows.Next() {
		var r RequestRow
		var hits string
		var smp int
		if err := rows.Scan(&r.ID, &r.T, &r.Host, &r.Method, &r.Path, &r.Query, &r.IP, &r.UA, &r.Referer, &r.Proto,
			&r.Status, &r.Bytes, &r.Dur, &r.Policy, &r.Action, &r.Detail, &r.WAFScore, &hits, &smp, &r.Country, &r.ASN, &r.ASOrg, &r.User, &r.Ref, &r.Why, &r.Rule, &r.Port, &r.Inst); err != nil {
			return nil, err
		}
		if hits != "" {
			_ = json.Unmarshal([]byte(hits), &r.Hits)
		}
		r.Sampled = smp == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

type TopEntry struct {
	Key      string  `json:"key"`
	Count    int64   `json:"count"`
	Errors   int64   `json:"errors"`
	Blocked  int64   `json:"blocked"`
	Bytes    int64   `json:"bytes"`
	AvgMs    float64 `json:"avg_ms"`
	LastSeen int64   `json:"last_seen"`
}

var topDims = map[string]string{
	"path":    "path",
	"ip":      "ip",
	"ua":      "ua",
	"referer": "ref",
	"status":  "CAST(status AS TEXT)",
	"method":  "method",
	"host":    "host",
	"action":  "action",
	"policy":  "policy",
	"rule":    "detail",
	"country": "cc",
	"asn":     "CASE WHEN asn>0 THEN 'AS' || asn || ' ' || COALESCE(aso,'') ELSE '' END",
}

// Top returns the top values of a dimension within the filter.
func (s *Store) Top(dim string, f RequestFilter, limit int) ([]TopEntry, error) {
	if _, ok := topDims[dim]; !ok {
		return nil, fmt.Errorf("unknown dimension %q", dim)
	}
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	if out, used, err := s.topAgg(dim, f, limit); used {
		return out, err
	}
	return s.topRaw(dim, f, limit)
}

func (s *Store) topRaw(dim string, f RequestFilter, limit int) ([]TopEntry, error) {
	col := topDims[dim]
	where, args := f.where()
	if dim == "rule" {
		where += " AND action='waf_block'"
	}
	args = append(args, limit)
	rows, err := s.DB.Query(`SELECT COALESCE(`+col+`,'') AS k, COUNT(*), SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),
		SUM(CASE WHEN `+blockingSQL+` THEN 1 ELSE 0 END), COALESCE(SUM(bytes),0), COALESCE(AVG(dur),0), MAX(ts)
		FROM requests WHERE `+where+` GROUP BY k ORDER BY COUNT(*) DESC, k LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopEntry{}
	for rows.Next() {
		var e TopEntry
		if err := rows.Scan(&e.Key, &e.Count, &e.Errors, &e.Blocked, &e.Bytes, &e.AvgMs, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type RuleStat struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Count    int64    `json:"count"`
	Blocked  int64    `json:"blocked"`
	LastSeen int64    `json:"last_seen"`
	Tags     []string `json:"tags"`
}

// TopRules aggregates WAF hits from requests in the window.
func (s *Store) TopRules(f RequestFilter, limit int) ([]RuleStat, error) {
	where, args := f.where()
	rows, err := s.DB.Query(`SELECT ts, action, hits FROM requests WHERE `+where+` AND hits IS NOT NULL AND hits<>'' ORDER BY id DESC LIMIT 20000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int]*RuleStat{}
	for rows.Next() {
		var ts int64
		var action, hitsRaw string
		if err := rows.Scan(&ts, &action, &hitsRaw); err != nil {
			return nil, err
		}
		var hits []protocol.Hit
		_ = json.Unmarshal([]byte(hitsRaw), &hits)
		for _, h := range hits {
			if h.ID == 949110 || h.ID == 980170 || h.ID == 980130 || (h.ID >= 900000 && h.ID < 902000) {
				continue // anomaly evaluation / correlation, not interesting by itself
			}
			rs := m[h.ID]
			if rs == nil {
				rs = &RuleStat{ID: h.ID, Msg: h.Msg, Tags: h.Tags}
				m[h.ID] = rs
			}
			rs.Count++
			if action == protocol.ActionWAFBlock {
				rs.Blocked++
			}
			if ts > rs.LastSeen {
				rs.LastSeen = ts
			}
		}
	}
	out := make([]RuleStat, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// HostsSeen lists hosts that have rollups in the last days.
func (s *Store) HostsSeen(sinceMinute int64, inst string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT DISTINCT host FROM rollups WHERE minute>=? AND (?='' OR inst=?) ORDER BY host`, sinceMinute, inst, inst)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		rows.Scan(&h)
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostSparks returns per-host request counts per bucket for sparklines.
func (s *Store) HostSparks(fromMinute, toMinute, stepMin int64, inst string) (map[string][]int64, error) {
	rows, err := s.DB.Query(`SELECT host, minute, SUM(count) FROM rollups WHERE minute>=? AND minute<=? AND (?='' OR inst=?) GROUP BY host, minute`, fromMinute, toMinute, inst, inst)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := (toMinute-fromMinute)/stepMin + 1
	out := map[string][]int64{}
	for rows.Next() {
		var h string
		var m, c int64
		rows.Scan(&h, &m, &c)
		if out[h] == nil {
			out[h] = make([]int64, n)
		}
		i := (m - fromMinute) / stepMin
		if i >= 0 && i < n {
			out[h][i] += c
		}
	}
	return out, rows.Err()
}

// IPSummary aggregates stats for one IP from raw requests.
type IPSummary struct {
	Requests  int64            `json:"requests"`
	Errors    int64            `json:"errors"`
	Blocked   int64            `json:"blocked"`
	FirstSeen int64            `json:"first_seen"`
	LastSeen  int64            `json:"last_seen"`
	Hosts     []TopEntry       `json:"hosts"`
	Paths     []TopEntry       `json:"paths"`
	UAs       []TopEntry       `json:"uas"`
	Actions   map[string]int64 `json:"actions"`
}

func (s *Store) IPSummary(ip string) (*IPSummary, error) {
	sum := &IPSummary{Actions: map[string]int64{}}
	err := s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN `+blockingSQL+` THEN 1 ELSE 0 END),0), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0)
		FROM requests WHERE ip=?`, ip).Scan(&sum.Requests, &sum.Errors, &sum.Blocked, &sum.FirstSeen, &sum.LastSeen)
	if err != nil {
		return nil, err
	}
	f := RequestFilter{IP: ip}
	sum.Hosts, _ = s.Top("host", f, 10)
	sum.Paths, _ = s.Top("path", f, 15)
	sum.UAs, _ = s.Top("ua", f, 5)
	acts, _ := s.Top("action", f, 20)
	for _, a := range acts {
		if a.Key != "" {
			sum.Actions[a.Key] = a.Count
		}
	}
	return sum, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nonBlockingSQL lists actions after which the request was still served.
const nonBlockingSQL = "'','waf_detect','feed_match','challenge_pass','auth_login','auth_required','redirect'"

// blockingSQL is true for requests Sentinel stopped (test-mode decisions
// "test:…" let the request through).
const blockingSQL = "(action NOT IN (" + nonBlockingSQL + ") AND action NOT LIKE 'test:%')"

// normRef normalises a user-typed reference ("abcd efgh", "ABCDEFGH").
func normRef(s string) string {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "Ref:", "", "REF:", "").Replace(strings.TrimSpace(s)))
	if len(s) == 8 {
		return s[:4] + "-" + s[4:]
	}
	return s
}

// RequestByID returns one stored request.
func (s *Store) RequestByID(id int64) (*RequestRow, error) {
	rows, err := s.Requests(RequestFilter{BeforeID: id + 1, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || rows[0].ID != id {
		return nil, sql.ErrNoRows
	}
	return &rows[0], nil
}

// FailureGroup aggregates failed requests with the same cause.
type FailureGroup struct {
	Host     string `json:"host"`
	Policy   string `json:"policy"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	Rule     string `json:"rule"`
	Port     int    `json:"port"`
	Status   int    `json:"status"`
	Inst     string `json:"inst"`
	Count    int    `json:"count"`
	IPs      int    `json:"ips"`
	Paths    int    `json:"paths"`
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
	SampleID int64  `json:"sample_id"`
}

// Failures groups failed requests (blocked by Sentinel or answered with an
// error status) by host and cause.
func (s *Store) Failures(from, to int64, inst, host string, limit int) ([]FailureGroup, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if out, used, err := s.failuresAgg(from, to, inst, host, limit); used {
		return out, err
	}
	return s.failuresRaw(from, to, inst, host, limit)
}

func (s *Store) failuresRaw(from, to int64, inst, host string, limit int) ([]FailureGroup, error) {
	w := "ts>=? AND ts<=? AND (status>=400 OR " + blockingSQL + ")"
	args := []any{from, to}
	if inst != "" {
		w += " AND inst=?"
		args = append(args, inst)
	}
	if host != "" {
		w += " AND host=?"
		args = append(args, host)
	}
	// Sentinel decisions group by action+detail+rule; other errors by status.
	// The detail of rate bans carries the ban duration ("name|600").
	q := `SELECT COALESCE(host,''), COALESCE(policy,''), COALESCE(action,''),
		CASE WHEN NOT ` + blockingSQL + ` OR action='banned' THEN '' ELSE COALESCE(detail,'') END AS d,
		COALESCE(rule,''), COALESCE(port,0),
		CASE WHEN NOT ` + blockingSQL + ` THEN status ELSE 0 END AS st, COALESCE(inst,'local'),
		COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT path), MIN(ts), MAX(ts), MAX(id)
		FROM requests WHERE ` + w + `
		GROUP BY 1,2,3,4,5,6,7,8 ORDER BY COUNT(*) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailureGroup{}
	for rows.Next() {
		var g FailureGroup
		if err := rows.Scan(&g.Host, &g.Policy, &g.Action, &g.Detail, &g.Rule, &g.Port, &g.Status, &g.Inst, &g.Count, &g.IPs, &g.Paths, &g.First, &g.Last, &g.SampleID); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// instOr maps an empty instance to the local one (older agents/rows).
func instOr(s string) string {
	if s == "" {
		return "local"
	}
	return s
}
