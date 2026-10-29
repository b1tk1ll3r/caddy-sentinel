package core

// Update check against the GitHub releases of the project (cached; disable
// with SENTINEL_UPDATE_CHECK=0). The panel runs unprivileged and does not
// update itself – it shows the command instead.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const releaseRepo = "b1tk1ll3r/caddy-sentinel"

type UpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	URL       string `json:"url,omitempty"`
	Published string `json:"published,omitempty"`
	Available bool   `json:"available"`
	Checked   int64  `json:"checked,omitempty"`
	Error     string `json:"error,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
	Docker    bool   `json:"docker"`
}

var updCache struct {
	sync.Mutex
	info UpdateInfo
	at   time.Time
}

func (e *Engine) UpdateCheck(ctx context.Context, force bool) UpdateInfo {
	_, docker := os.LookupEnv("SENTINEL_CADDY_DATA")
	base := UpdateInfo{Current: Version, Docker: docker}
	if v := os.Getenv("SENTINEL_UPDATE_CHECK"); v == "0" || v == "false" {
		base.Disabled = true
		return base
	}
	updCache.Lock()
	defer updCache.Unlock()
	if !force && !updCache.at.IsZero() && time.Since(updCache.at) < 6*time.Hour {
		i := updCache.info
		i.Current, i.Docker = Version, docker
		i.Available = i.Latest != "" && newerVersion(i.Latest, Version)
		return i
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	info := base
	info.Checked = time.Now().Unix()
	// VERSION asset of the latest release: no API rate limit; the GitHub API
	// is only the fallback for releases published before that asset existed.
	if tag, err := latestFromAsset(ctx); err == nil {
		info.Latest, info.URL = tag, "https://github.com/"+releaseRepo+"/releases/tag/"+tag
		info.Available = newerVersion(tag, Version)
	} else if rel, err := latestFromAPI(ctx); err != nil {
		info.Error = err.Error()
	} else {
		info.Latest, info.URL, info.Published = rel.Tag, rel.URL, rel.Published
		info.Available = newerVersion(rel.Tag, Version)
	}
	updCache.info, updCache.at = info, time.Now()
	if info.Error != "" {
		updCache.at = time.Now().Add(-5 * time.Hour) // retry in an hour
	}
	return info
}

// newerVersion compares "v1.2.3" style versions; dev builds never get hints.
func newerVersion(latest, current string) bool {
	if current == "dev" || current == "" || strings.HasPrefix(current, "ci-") {
		return false
	}
	pa, pb := parseSemver(latest), parseSemver(current)
	if pa == nil || pb == nil {
		return latest != current
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	// same core version: a release beats a pre-release
	return !strings.Contains(latest, "-") && strings.Contains(current, "-")
}

func parseSemver(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.e.UpdateCheck(r.Context(), r.URL.Query().Get("force") == "1"))
}

func latestFromAsset(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/"+releaseRepo+"/releases/latest/download/VERSION", nil)
	req.Header.Set("User-Agent", "caddy-sentinel/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	tag := strings.TrimSpace(string(b))
	if parseSemver(tag) == nil {
		return "", fmt.Errorf("ungültige Version %q", tag)
	}
	return tag, nil
}

type ghRelease struct {
	Tag       string `json:"tag_name"`
	URL       string `json:"html_url"`
	Published string `json:"published_at"`
}

func latestFromAPI(ctx context.Context) (ghRelease, error) {
	var rel ghRelease
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+releaseRepo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "caddy-sentinel/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("GitHub: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&rel)
	return rel, err
}
