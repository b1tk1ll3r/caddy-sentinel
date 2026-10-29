package core

// Weekly report by e-mail: traffic, blocks, the main failure causes,
// certificates, Caddy instances and open warnings – as HTML with a plain
// text alternative.

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

type reportSection struct {
	Title string
	Rows  [][]string // first row = header
	Lines []string
}

type Report struct {
	Subject  string
	From, To time.Time
	KPIs     [][2]string
	Sections []reportSection
	Link     string
}

func (e *Engine) BuildReport(ctx context.Context, days int) *Report {
	if days <= 0 {
		days = 7
	}
	to := time.Now()
	from := to.Add(-time.Duration(days) * 24 * time.Hour)
	rep := &Report{From: from, To: to, Link: strings.TrimRight(e.Settings().PanelURL, "/")}
	rep.Subject = fmt.Sprintf("Caddy Sentinel – Wochenbericht %s – %s", from.Format("02.01."), to.Format("02.01.2006"))

	ov, _ := e.Store.Overview(store.Range{From: from.Unix(), To: to.Unix()}, int64(days)*86400)
	if ov != nil {
		errRate := 0.0
		if ov.Requests > 0 {
			errRate = float64(ov.Errors4xx+ov.Errors5xx) / float64(ov.Requests) * 100
		}
		rep.KPIs = [][2]string{
			{"Anfragen", fmtNum(ov.Requests)},
			{"Blockiert", fmtNum(ov.Blocked)},
			{"Fehlerquote", fmt.Sprintf("%.1f %%", errRate)},
			{"Antwortzeit Ø / p95", fmt.Sprintf("%.0f ms / %.0f ms", ov.AvgMs, ov.P95Ms)},
		}
	}

	// per instance
	if e.multiInstance() {
		sec := reportSection{Title: "Caddy-Instanzen", Rows: [][]string{{"Instanz", "Status", "Anfragen", "Blockiert", "5xx"}}}
		for _, iv := range e.Instances() {
			o, _ := e.Store.Overview(store.Range{From: from.Unix(), To: to.Unix(), Inst: iv.ID}, int64(days)*86400)
			status := "verbunden"
			if !iv.Online {
				status = "OFFLINE"
			}
			row := []string{iv.Name, status, "–", "–", "–"}
			if o != nil {
				row[2], row[3], row[4] = fmtNum(o.Requests), fmtNum(o.Blocked), fmtNum(o.Errors5xx)
			}
			sec.Rows = append(sec.Rows, row)
		}
		rep.Sections = append(rep.Sections, sec)
	}

	// main failure causes
	if groups, err := e.Failures(ctx, from.UnixMilli(), to.UnixMilli(), "", ""); err == nil && len(groups) > 0 {
		sec := reportSection{Title: "Häufigste Fehlerursachen", Rows: [][]string{{"Ursache", "Wer", "Host", "Anzahl", "Clients"}}}
		for i, g := range groups {
			if i >= 10 {
				break
			}
			host := g.Host
			if g.Port != 0 && g.Port != 80 && g.Port != 443 {
				host = fmt.Sprintf("%s:%d", host, g.Port)
			}
			if e.multiInstance() {
				host = e.InstanceName(g.Inst) + " · " + host
			}
			sec.Rows = append(sec.Rows, []string{g.Headline, g.WhoLabel, host, fmtNum(int64(g.Count)), fmtNum(int64(g.IPs))})
		}
		rep.Sections = append(rep.Sections, sec)
	}

	// blocked clients
	f := store.RequestFilter{From: from.UnixMilli(), To: to.UnixMilli(), Action: "blocked"}
	if top, err := e.Store.Top("ip", f, 8); err == nil && len(top) > 0 {
		sec := reportSection{Title: "Am häufigsten blockierte Clients", Rows: [][]string{{"IP", "Blockiert", "Anfragen"}}}
		for _, t := range top {
			sec.Rows = append(sec.Rows, []string{t.Key, fmtNum(t.Blocked), fmtNum(t.Count)})
		}
		rep.Sections = append(rep.Sections, sec)
	}
	if bans, err := e.Store.ActiveBans(); err == nil {
		rep.KPIs = append(rep.KPIs, [2]string{"Aktive Sperren", fmtNum(int64(len(bans)))})
	}

	// changes
	if evs, err := e.Store.Events(store.EventFilter{Types: []string{"audit", "config"}, Since: from.UnixMilli(), Limit: 500}); err == nil {
		n := 0
		var lines []string
		for _, ev := range evs {
			if strings.Contains(ev.Title, "Anmeldung") || strings.Contains(ev.Title, "Sitzung") {
				continue
			}
			n++
			if len(lines) < 12 {
				lines = append(lines, time.UnixMilli(ev.TS).Format("02.01. 15:04")+" – "+ev.Title)
			}
		}
		if n > 0 {
			rep.Sections = append(rep.Sections, reportSection{Title: fmt.Sprintf("Änderungen (%d)", n), Lines: lines})
		}
	}

	// warnings (certificates, backends, offline instances, test mode …)
	if ws := e.Warnings(ctx, ""); len(ws) > 0 {
		sec := reportSection{Title: "Offene Hinweise"}
		for _, w := range ws {
			l := w.Title
			if w.Detail != "" {
				l += " – " + w.Detail
			}
			sec.Lines = append(sec.Lines, l)
		}
		rep.Sections = append(rep.Sections, sec)
	} else {
		rep.Sections = append(rep.Sections, reportSection{Title: "Offene Hinweise", Lines: []string{"Keine – alle Zertifikate, Backends und Instanzen in Ordnung."}})
	}
	return rep
}

var numCell = regexp.MustCompile(`^[0-9.,–-]+$`)

func fmtNum(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	r := strings.Join(out, ".")
	if neg {
		r = "-" + r
	}
	return r
}

func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", r.Subject, strings.Repeat("=", len([]rune(r.Subject))))
	for _, k := range r.KPIs {
		fmt.Fprintf(&b, "%-22s %s\n", k[0]+":", k[1])
	}
	for _, s := range r.Sections {
		fmt.Fprintf(&b, "\n%s\n%s\n", s.Title, strings.Repeat("-", len([]rune(s.Title))))
		for i, row := range s.Rows {
			if i == 0 {
				continue
			}
			fmt.Fprintf(&b, "- %s\n", strings.Join(row, " · "))
		}
		for _, l := range s.Lines {
			fmt.Fprintf(&b, "- %s\n", l)
		}
	}
	if r.Link != "" {
		fmt.Fprintf(&b, "\nPanel: %s\n", r.Link)
	}
	return b.String()
}

func (r *Report) HTML() string {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>` + esc(r.Subject) + `</title></head>
<body style="margin:0;background:#eef1f4;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#1d2330">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f4;padding:20px 0"><tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border:1px solid #d5dbe2;border-radius:8px">
<tr><td style="padding:22px 26px;border-bottom:4px solid #2d47c9"><div style="font-size:12px;color:#5a6573;text-transform:uppercase;letter-spacing:.06em">Caddy Sentinel · Wochenbericht</div>
<div style="font-size:20px;font-weight:700;margin-top:4px">` + esc(r.From.Format("02.01.")+" – "+r.To.Format("02.01.2006")) + `</div></td></tr>
<tr><td style="padding:18px 26px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>`)
	for i, k := range r.KPIs {
		if i > 0 && i%3 == 0 {
			b.WriteString(`</tr><tr>`)
		}
		b.WriteString(`<td style="padding:8px 8px 8px 0;vertical-align:top"><div style="font-size:12px;color:#5a6573">` + esc(k[0]) + `</div><div style="font-size:19px;font-weight:700">` + esc(k[1]) + `</div></td>`)
	}
	b.WriteString(`</tr></table></td></tr>`)
	for _, s := range r.Sections {
		b.WriteString(`<tr><td style="padding:6px 26px 16px"><div style="font-size:15px;font-weight:700;margin:6px 0 8px">` + esc(s.Title) + `</div>`)
		if len(s.Rows) > 0 {
			b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border-collapse:collapse">`)
			for i, row := range s.Rows {
				b.WriteString(`<tr>`)
				for j, c := range row {
					align := "left"
					if j > 0 && numCell.MatchString(c) {
						align = "right"
					}
					if i == 0 {
						b.WriteString(`<th style="text-align:` + align + `;padding:5px 6px;border-bottom:1px solid #d5dbe2;color:#5a6573;font-weight:600">` + esc(c) + `</th>`)
					} else {
						color := ""
						if c == "OFFLINE" {
							color = "color:#c22f2f;font-weight:700;"
						}
						b.WriteString(`<td style="` + color + `text-align:` + align + `;padding:5px 6px;border-bottom:1px solid #e4e8ed">` + esc(c) + `</td>`)
					}
				}
				b.WriteString(`</tr>`)
			}
			b.WriteString(`</table>`)
		}
		if len(s.Lines) > 0 {
			b.WriteString(`<ul style="margin:0;padding-left:18px;font-size:13px;line-height:1.55">`)
			for _, l := range s.Lines {
				b.WriteString(`<li>` + esc(l) + `</li>`)
			}
			b.WriteString(`</ul>`)
		}
		b.WriteString(`</td></tr>`)
	}
	if r.Link != "" {
		b.WriteString(`<tr><td style="padding:10px 26px 24px"><a href="` + esc(r.Link) + `/#/failures" style="display:inline-block;background:#2d47c9;color:#fff;text-decoration:none;padding:9px 16px;border-radius:6px;font-weight:600">Im Panel ansehen</a></td></tr>`)
	}
	b.WriteString(`</table><div style="font-size:11px;color:#5a6573;margin-top:10px">Einstellbar unter Einstellungen › Benachrichtigungen › Wochenbericht.</div></td></tr></table></body></html>`)
	return b.String()
}

// reportLoop sends the weekly report at the configured weekday and hour.
func (e *Engine) reportLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cfg := e.Settings().Report
			if !cfg.Enabled || len(cfg.Recipients) == 0 || int(now.Weekday()) != cfg.Weekday || now.Hour() != cfg.Hour {
				continue
			}
			var last int64
			_, _ = e.Store.GetSetting("report_last", &last)
			if time.Since(time.Unix(last, 0)) < 6*24*time.Hour {
				continue
			}
			if err := e.SendReport(ctx, cfg.Recipients); err != nil {
				e.AddEvent(store.Event{Type: "alert", Severity: 2, Title: "Wochenbericht konnte nicht gesendet werden: " + err.Error()}, false)
				continue
			}
			_ = e.Store.SetSetting("report_last", now.Unix())
		}
	}
}

func (e *Engine) SendReport(ctx context.Context, to []string) error {
	rep := e.BuildReport(ctx, 7)
	return sendMailParts(e.Settings().SMTP, to, rep.Subject, rep.Text(), rep.HTML())
}

func (s *Server) handleReportPreview(w http.ResponseWriter, r *http.Request) {
	rep := s.e.BuildReport(r.Context(), 7)
	writeJSON(w, 200, map[string]any{"subject": rep.Subject, "html": rep.HTML(), "text": rep.Text()})
}

func (s *Server) handleReportSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	_ = readJSON(r, &req)
	to := splitRecipients(req.To)
	if len(to) == 0 {
		to = s.e.Settings().Report.Recipients
	}
	if len(to) == 0 {
		writeErr(w, 400, "keine Empfänger angegeben")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	if err := s.e.SendReport(ctx, to); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "to": to})
}
