package sentinel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.uber.org/zap"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/geoip"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/iprange"
	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

type loadedFeed struct {
	hash string
	set  *iprange.Set
}

var feedIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

func (c *core) feedFile(id string) string {
	return filepath.Join(filepath.Dir(c.cacheFile), "sentinel-feed-"+id+".txt")
}

func (c *core) feedSet(id string) *iprange.Set {
	if fm := c.feeds.Load(); fm != nil {
		if f := (*fm)[id]; f != nil {
			return f.set
		}
	}
	return nil
}

// syncFeeds downloads feeds whose hash changed. Failures keep the previous
// version of the feed.
func (c *core) syncFeeds(ctx context.Context, s *protocol.State) {
	old := map[string]*loadedFeed{}
	if fm := c.feeds.Load(); fm != nil {
		old = *fm
	}
	next := make(map[string]*loadedFeed, len(s.Feeds))
	for _, ref := range s.Feeds {
		if !feedIDRe.MatchString(ref.ID) {
			continue
		}
		if f := old[ref.ID]; f != nil && f.hash == ref.Hash {
			next[ref.ID] = f
			continue
		}
		data, err := c.downloadFeed(ctx, ref.ID)
		if err != nil {
			c.log.Warn("sentinel: feed download failed", zap.String("feed", ref.ID), zap.Error(err))
			if f := old[ref.ID]; f != nil {
				next[ref.ID] = f
			}
			continue
		}
		set, n := iprange.Parse(bytes.NewReader(data))
		next[ref.ID] = &loadedFeed{hash: ref.Hash, set: set}
		_ = os.WriteFile(c.feedFile(ref.ID), append([]byte("# hash "+ref.Hash+"\n"), data...), 0o600)
		c.log.Info("sentinel: feed loaded", zap.String("feed", ref.ID), zap.Int("entries", n), zap.Int("ranges", set.Size()))
	}
	c.feeds.Store(&next)
}

func (c *core) downloadFeed(ctx context.Context, id string) ([]byte, error) {
	req, err := c.newReq(ctx, http.MethodGet, "/api/agent/feed?id="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("panel returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// loadCachedFeeds restores feeds from disk (used when the panel is down at start).
func (c *core) loadCachedFeeds(s *protocol.State) {
	next := map[string]*loadedFeed{}
	for _, ref := range s.Feeds {
		if !feedIDRe.MatchString(ref.ID) {
			continue
		}
		b, err := os.ReadFile(c.feedFile(ref.ID))
		if err != nil {
			continue
		}
		set, _ := iprange.Parse(bytes.NewReader(b))
		hash := ""
		if line, _, ok := bytes.Cut(b, []byte("\n")); ok && bytes.HasPrefix(line, []byte("# hash ")) {
			hash = string(line[7:])
		}
		next[ref.ID] = &loadedFeed{hash: hash, set: set}
	}
	c.feeds.Store(&next)
}

// updateGeo (re)opens the GeoIP databases if the configured paths changed.
func (c *core) updateGeo(cfg protocol.GeoIP) {
	if c.geoOverride.CountryDB != "" {
		cfg.CountryDB = c.geoOverride.CountryDB
	}
	if c.geoOverride.ASNDB != "" {
		cfg.ASNDB = c.geoOverride.ASNDB
	}
	cur := c.geo.Load()
	if cur != nil && cur.CountryPath == cfg.CountryDB && cur.ASNPath == cfg.ASNDB {
		return
	}
	if cur == nil && cfg.CountryDB == "" && cfg.ASNDB == "" {
		return
	}
	g := geoip.Open(cfg.CountryDB, cfg.ASNDB)
	c.geo.Store(g)
	c.geoCache.Reset()
	if g.Status != "" {
		c.log.Info("sentinel: geoip", zap.String("status", g.Status))
	}
	// old readers are memory-mapped; close them after in-flight lookups finished
	if cur != nil {
		go func() {
			time.Sleep(30 * time.Second)
			cur.Close()
		}()
	}
}
