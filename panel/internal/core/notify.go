package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// Notifier delivers events to webhooks.
type Notifier struct {
	e     *Engine
	queue chan store.Event
	// urgent holds events of severity >= 3 (agent offline, attack wave,
	// certificates …): a flood of lower-severity events cannot push them out
	// and they are delivered first.
	urgent chan store.Event
	client *http.Client
}

func newNotifier(e *Engine) *Notifier {
	return &Notifier{e: e, queue: make(chan store.Event, 500), urgent: make(chan store.Event, 200), client: &http.Client{Timeout: 10 * time.Second}}
}

func (n *Notifier) Send(ev store.Event) {
	ch := n.queue
	if ev.Severity >= 3 {
		ch = n.urgent
	}
	select {
	case ch <- ev:
	default:
		n.e.log.Warn("notification queue full, event dropped", "title", truncateStr(ev.Title, 120), "severity", ev.Severity)
	}
}

func (n *Notifier) run(ctx context.Context) {
	for {
		var ev store.Event
		select {
		case ev = <-n.urgent:
		default:
			select {
			case <-ctx.Done():
				return
			case ev = <-n.urgent:
			case ev = <-n.queue:
			}
		}
		if n.e.muted(ev) {
			continue
		}
		for _, wh := range n.e.Settings().Webhooks {
			if !wh.Enabled || ev.Severity < wh.MinSeverity || !typeMatch(wh.Types, ev.Type) {
				continue
			}
			if err := n.deliver(ctx, wh, ev); err != nil {
				n.e.log.Warn("webhook failed", "webhook", wh.Name, "err", err)
			}
		}
	}
}

// mdEscape neutralises Markdown (Discord, Teams, Gotify) in text from
// outside: links, emphasis, code and mentions show up literally.
func mdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '_', '~', '`', '[', ']', '(', ')', '<', '>', '@', '#', '|', '!':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// slackEscape escapes the characters Slack's mrkdwn treats as control
// sequences (<!channel>, <https://x|label>).
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func typeMatch(types []string, t string) bool {
	if len(types) == 0 {
		return true
	}
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

var sevNames = []string{"Info", "Niedrig", "Mittel", "Hoch", "Kritisch"}

func SeverityName(s int) string {
	if s < 0 || s >= len(sevNames) {
		return "?"
	}
	return sevNames[s]
}

// Test sends a test notification.
func (n *Notifier) Test(ctx context.Context, wh Webhook) error {
	return n.deliver(ctx, wh, store.Event{TS: time.Now().UnixMilli(), Type: "test", Severity: 1, Title: "Testnachricht von Caddy Sentinel"})
}

func (n *Notifier) deliver(ctx context.Context, wh Webhook, ev store.Event) error {
	text := truncateStr(ev.Title, 300)
	var lines []string
	if ev.Host != "" {
		lines = append(lines, "Host: "+ev.Host)
	}
	if ev.IP != "" {
		lines = append(lines, "IP: "+ev.IP)
	}
	if inst := ev.Inst; inst != "" && len(n.e.Instances()) > 1 {
		lines = append(lines, "Caddy: "+n.e.InstanceName(inst))
	}
	body := strings.Join(lines, "\n")
	links := n.e.actionLinks(ev)
	sev := SeverityName(ev.Severity)
	var payload []byte
	method, target := http.MethodPost, wh.URL
	headers := map[string]string{"Content-Type": "application/json"}
	if wh.Format == "email" {
		to := splitRecipients(wh.URL)
		if len(to) == 0 {
			return fmt.Errorf("keine gültigen Empfänger")
		}
		mail := fmt.Sprintf("%s\n\nSchwere: %s\nArt: %s\nZeit: %s\n", text, sev, ev.Type, time.UnixMilli(ev.TS).Format("02.01.2006 15:04:05"))
		if body != "" {
			mail += body + "\n"
		}
		for _, l := range links {
			mail += "\n" + l.Label + ": " + l.URL
		}
		if d := eventJSON(ev); d != "" {
			mail += "\n\nDetails:\n" + d + "\n"
		}
		return sendMail(n.e.Settings().SMTP, to, "[Sentinel] "+text, mail)
	}
	mdLinks := func(f func(l actionLink) string) string {
		var parts []string
		for _, l := range links {
			parts = append(parts, f(l))
		}
		return strings.Join(parts, " · ")
	}
	switch wh.Format {
	case "discord":
		// title and lines carry attacker-controlled text (paths, Host
		// headers): escaped, and mentions are never resolved
		msg := fmt.Sprintf("**[%s] %s**\n%s", sev, mdEscape(text), mdEscape(body))
		if len(links) > 0 {
			msg += "\n" + mdLinks(func(l actionLink) string { return "[" + l.Label + "](<" + l.URL + ">)" })
		}
		payload, _ = json.Marshal(map[string]any{"username": "Caddy Sentinel", "content": msg, "allowed_mentions": map[string]any{"parse": []string{}}})
	case "slack":
		blocks := []any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*[%s] %s*\n%s", sev, slackEscape(text), slackEscape(body))}}}
		if len(links) > 0 {
			var els []any
			for _, l := range links {
				els = append(els, map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": l.Label}, "url": l.URL})
			}
			blocks = append(blocks, map[string]any{"type": "actions", "elements": els})
		}
		payload, _ = json.Marshal(map[string]any{"text": fmt.Sprintf("[%s] %s", sev, slackEscape(text)), "blocks": blocks})
	case "teams":
		// Teams "Workflows" webhook (the old Office 365 connectors are retired):
		// an Adaptive Card with link buttons.
		var facts []any
		for _, l := range lines {
			k, v, _ := strings.Cut(l, ": ")
			facts = append(facts, map[string]any{"title": k, "value": mdEscape(v)})
		}
		var acts []any
		for _, l := range links {
			acts = append(acts, map[string]any{"type": "Action.OpenUrl", "title": l.Label, "url": l.URL})
		}
		card := map[string]any{
			"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4",
			"body": []any{
				map[string]any{"type": "TextBlock", "text": "Caddy Sentinel · " + sev, "isSubtle": true, "size": "Small"},
				map[string]any{"type": "TextBlock", "text": mdEscape(text), "weight": "Bolder", "wrap": true},
				map[string]any{"type": "FactSet", "facts": facts},
			},
			"actions": acts,
		}
		payload, _ = json.Marshal(map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
	case "ntfy":
		// JSON publishing (UTF-8 labels and action buttons without header encoding)
		u, err := url.Parse(wh.URL)
		if err != nil {
			return err
		}
		topic := strings.Trim(u.Path, "/")
		if i := strings.LastIndexByte(topic, '/'); i >= 0 {
			topic = topic[i+1:]
		}
		u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), topic)
		target = strings.TrimRight(u.String(), "/") + "/"
		msg := body
		if msg == "" {
			msg = text
		}
		var acts []any
		click := ""
		for i, l := range links {
			if i == 3 {
				break // ntfy shows at most three actions
			}
			if strings.Contains(l.URL, "/act/") {
				acts = append(acts, map[string]any{"action": "http", "label": l.Label, "url": l.URL, "method": "POST", "clear": true})
			} else {
				acts = append(acts, map[string]any{"action": "view", "label": l.Label, "url": l.URL})
				click = l.URL
			}
		}
		pl := map[string]any{"topic": topic, "title": text, "message": msg, "priority": min(ev.Severity+1, 5), "tags": []string{"shield"}}
		if len(acts) > 0 {
			pl["actions"] = acts
		}
		if click != "" {
			pl["click"] = click
		}
		payload, _ = json.Marshal(pl)
		if wh.Token != "" {
			headers["Authorization"] = "Bearer " + wh.Token
		}
	case "gotify":
		msg := mdEscape(body)
		if len(links) > 0 {
			msg += "\n\n" + mdLinks(func(l actionLink) string { return "[" + l.Label + "](" + l.URL + ")" })
		}
		extras := map[string]any{"client::display": map[string]any{"contentType": "text/markdown"}}
		for _, l := range links {
			if !strings.Contains(l.URL, "/act/") {
				extras["client::notification"] = map[string]any{"click": map[string]any{"url": l.URL}}
			}
		}
		payload, _ = json.Marshal(map[string]any{"title": text, "message": msg + " ", "priority": ev.Severity * 2, "extras": extras})
		if wh.Token != "" {
			headers["X-Gotify-Key"] = wh.Token
		}
	case "matrix":
		// URL = homeserver, Room = room ID (!abc:example.org), Token = access token
		if wh.Room == "" || wh.Token == "" {
			return fmt.Errorf("Matrix braucht Raum-ID und Access-Token")
		}
		htmlBody := "<b>[" + htmlEsc(sev) + "] " + htmlEsc(text) + "</b>"
		if body != "" {
			htmlBody += "<br>" + strings.ReplaceAll(htmlEsc(body), "\n", "<br>")
		}
		plain := "[" + sev + "] " + text + "\n" + body
		if len(links) > 0 {
			htmlBody += "<br>" + mdLinks(func(l actionLink) string { return `<a href="` + htmlEsc(l.URL) + `">` + htmlEsc(l.Label) + `</a>` })
			plain += "\n" + mdLinks(func(l actionLink) string { return l.Label + ": " + l.URL })
		}
		payload, _ = json.Marshal(map[string]any{"msgtype": "m.text", "body": plain, "format": "org.matrix.custom.html", "formatted_body": htmlBody})
		method = http.MethodPut
		target = strings.TrimRight(wh.URL, "/") + "/_matrix/client/v3/rooms/" + url.PathEscape(wh.Room) + "/send/m.room.message/sentinel-" + RandomToken(8)
		headers["Authorization"] = "Bearer " + wh.Token
	case "telegram":
		// Token = bot token, Room = chat ID
		if wh.Room == "" || wh.Token == "" {
			return fmt.Errorf("Telegram braucht Bot-Token und Chat-ID")
		}
		msg := "<b>[" + htmlEsc(sev) + "] " + htmlEsc(text) + "</b>"
		if body != "" {
			msg += "\n" + htmlEsc(body)
		}
		req := map[string]any{"chat_id": wh.Room, "text": msg, "parse_mode": "HTML", "disable_web_page_preview": true}
		if len(links) > 0 {
			var row []any
			for _, l := range links {
				row = append(row, map[string]any{"text": l.Label, "url": l.URL})
			}
			req["reply_markup"] = map[string]any{"inline_keyboard": []any{row}}
		}
		payload, _ = json.Marshal(req)
		base := strings.TrimRight(wh.URL, "/")
		if base == "" {
			base = "https://api.telegram.org"
		}
		target = base + "/bot" + wh.Token + "/sendMessage"
	default:
		payload, _ = json.Marshal(map[string]any{"source": "caddy-sentinel", "event": ev, "severity_name": SeverityName(ev.Severity), "actions": links})
		if wh.Token != "" {
			headers["Authorization"] = "Bearer " + wh.Token
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		if wh.Format == "telegram" {
			return fmt.Errorf("Telegram nicht erreichbar")
		}
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func htmlEsc(s string) string { return html.EscapeString(s) }

// encodeHeader keeps HTTP header values ASCII (ntfy supports RFC 2047).
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + b64(s) + "?="
		}
	}
	return s
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
