package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/panel/internal/store"
)

// Notifier delivers events to webhooks.
type Notifier struct {
	e      *Engine
	queue  chan store.Event
	client *http.Client
}

func newNotifier(e *Engine) *Notifier {
	return &Notifier{e: e, queue: make(chan store.Event, 500), client: &http.Client{Timeout: 10 * time.Second}}
}

func (n *Notifier) Send(ev store.Event) {
	select {
	case n.queue <- ev:
	default:
	}
}

func (n *Notifier) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.queue:
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
	base := strings.TrimRight(n.e.Settings().PanelURL, "/")
	text := ev.Title
	var lines []string
	if ev.Host != "" {
		lines = append(lines, "Host: "+ev.Host)
	}
	if ev.IP != "" {
		lines = append(lines, "IP: "+ev.IP)
		if base != "" {
			lines = append(lines, base+"/#/ip/"+ev.IP)
		}
	}
	body := strings.Join(lines, "\n")
	var payload []byte
	headers := map[string]string{"Content-Type": "application/json"}
	if wh.Format == "email" {
		to := splitRecipients(wh.URL)
		if len(to) == 0 {
			return fmt.Errorf("keine gültigen Empfänger")
		}
		mail := fmt.Sprintf("%s\n\nSchwere: %s\nArt: %s\nZeit: %s\n", text, SeverityName(ev.Severity), ev.Type, time.UnixMilli(ev.TS).Format("02.01.2006 15:04:05"))
		if body != "" {
			mail += body + "\n"
		}
		if d := eventJSON(ev); d != "" {
			mail += "\nDetails:\n" + d + "\n"
		}
		return sendMail(n.e.Settings().SMTP, to, "[Sentinel] "+text, mail)
	}
	switch wh.Format {
	case "discord":
		payload, _ = json.Marshal(map[string]any{"username": "Caddy Sentinel", "content": fmt.Sprintf("**[%s] %s**\n%s", SeverityName(ev.Severity), text, body)})
	case "slack":
		payload, _ = json.Marshal(map[string]any{"text": fmt.Sprintf("*[%s] %s*\n%s", SeverityName(ev.Severity), text, body)})
	case "teams":
		payload, _ = json.Marshal(map[string]any{"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": text, "title": text, "text": strings.ReplaceAll(body, "\n", "<br>")})
	case "ntfy":
		payload = []byte(body)
		if body == "" {
			payload = []byte(text)
		}
		headers = map[string]string{"Content-Type": "text/plain; charset=utf-8", "Title": encodeHeader(text), "Priority": fmt.Sprint(min(ev.Severity+1, 5)), "Tags": "shield"}
		if wh.Token != "" {
			headers["Authorization"] = "Bearer " + wh.Token
		}
	case "gotify":
		payload, _ = json.Marshal(map[string]any{"title": text, "message": body + " ", "priority": ev.Severity * 2})
		if wh.Token != "" {
			headers["X-Gotify-Key"] = wh.Token
		}
	default:
		payload, _ = json.Marshal(map[string]any{"source": "caddy-sentinel", "event": ev, "severity_name": SeverityName(ev.Severity)})
		if wh.Token != "" {
			headers["Authorization"] = "Bearer " + wh.Token
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

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
