package protocol

// Known crawlers: AI crawlers and assistants, SEO tools and search engines
// (with the reverse DNS domains they document for verification).

import "strings"

// BotClass describes a known crawler.
type BotClass struct {
	Class string // ai | seo | search
	Name  string
	// suffixes of the reverse DNS name for verifiable search engines
	Domains []string
}

// order matters: specific names before generic ones
var knownBots = []struct {
	needle string
	bot    BotClass
}{
	// search engines (verifiable)
	{"googlebot", BotClass{"search", "Googlebot", []string{".googlebot.com", ".google.com"}}},
	{"google-inspectiontool", BotClass{"search", "Google-InspectionTool", []string{".googlebot.com", ".google.com"}}},
	{"storebot-google", BotClass{"search", "Storebot-Google", []string{".googlebot.com", ".google.com"}}},
	{"adsbot-google", BotClass{"search", "AdsBot-Google", []string{".googlebot.com", ".google.com"}}},
	{"bingbot", BotClass{"search", "Bingbot", []string{".search.msn.com"}}},
	{"bingpreview", BotClass{"search", "BingPreview", []string{".search.msn.com"}}},
	{"msnbot", BotClass{"search", "msnbot", []string{".search.msn.com"}}},
	{"applebot-extended", BotClass{"ai", "Applebot-Extended", nil}},
	{"applebot", BotClass{"search", "Applebot", []string{".applebot.apple.com"}}},
	{"yandexbot", BotClass{"search", "YandexBot", []string{".yandex.ru", ".yandex.net", ".yandex.com"}}},
	{"baiduspider", BotClass{"search", "Baiduspider", []string{".baidu.com", ".baidu.jp"}}},
	{"yahoo! slurp", BotClass{"search", "Yahoo Slurp", []string{".crawl.yahoo.net"}}},
	{"petalbot", BotClass{"search", "PetalBot", []string{".petalsearch.com"}}},
	{"duckduckbot", BotClass{"search", "DuckDuckBot", nil}},
	// AI crawlers and assistants
	{"gptbot", BotClass{"ai", "GPTBot", nil}},
	{"chatgpt-user", BotClass{"ai", "ChatGPT-User", nil}},
	{"oai-searchbot", BotClass{"ai", "OAI-SearchBot", nil}},
	{"claudebot", BotClass{"ai", "ClaudeBot", nil}},
	{"claude-web", BotClass{"ai", "Claude-Web", nil}},
	{"claude-user", BotClass{"ai", "Claude-User", nil}},
	{"claude-searchbot", BotClass{"ai", "Claude-SearchBot", nil}},
	{"anthropic-ai", BotClass{"ai", "anthropic-ai", nil}},
	{"ccbot", BotClass{"ai", "CCBot", nil}},
	{"perplexitybot", BotClass{"ai", "PerplexityBot", nil}},
	{"perplexity-user", BotClass{"ai", "Perplexity-User", nil}},
	{"bytespider", BotClass{"ai", "Bytespider", nil}},
	{"amazonbot", BotClass{"ai", "Amazonbot", nil}},
	{"meta-externalagent", BotClass{"ai", "meta-externalagent", nil}},
	{"meta-externalfetcher", BotClass{"ai", "meta-externalfetcher", nil}},
	{"facebookbot", BotClass{"ai", "FacebookBot", nil}},
	{"diffbot", BotClass{"ai", "Diffbot", nil}},
	{"cohere-ai", BotClass{"ai", "cohere-ai", nil}},
	{"cohere-training-data-crawler", BotClass{"ai", "cohere-training-data-crawler", nil}},
	{"imagesiftbot", BotClass{"ai", "ImagesiftBot", nil}},
	{"omgilibot", BotClass{"ai", "Omgilibot", nil}},
	{"youbot", BotClass{"ai", "YouBot", nil}},
	{"timpibot", BotClass{"ai", "Timpibot", nil}},
	{"ai2bot", BotClass{"ai", "AI2Bot", nil}},
	{"duckassistbot", BotClass{"ai", "DuckAssistBot", nil}},
	{"mistralai-user", BotClass{"ai", "MistralAI-User", nil}},
	{"google-cloudvertexbot", BotClass{"ai", "Google-CloudVertexBot", nil}},
	{"iaskspider", BotClass{"ai", "iAskSpider", nil}},
	{"kangaroo bot", BotClass{"ai", "Kangaroo Bot", nil}},
	{"panscient", BotClass{"ai", "panscient", nil}},
	{"velenpublicwebcrawler", BotClass{"ai", "VelenPublicWebCrawler", nil}},
	// SEO tools
	{"ahrefsbot", BotClass{"seo", "AhrefsBot", nil}},
	{"ahrefssiteaudit", BotClass{"seo", "AhrefsSiteAudit", nil}},
	{"semrushbot", BotClass{"seo", "SemrushBot", nil}},
	{"siteauditbot", BotClass{"seo", "SiteAuditBot", nil}},
	{"mj12bot", BotClass{"seo", "MJ12bot", nil}},
	{"dotbot", BotClass{"seo", "DotBot", nil}},
	{"blexbot", BotClass{"seo", "BLEXBot", nil}},
	{"dataforseobot", BotClass{"seo", "DataForSeoBot", nil}},
	{"serpstatbot", BotClass{"seo", "serpstatbot", nil}},
	{"barkrowler", BotClass{"seo", "Barkrowler", nil}},
	{"seekportbot", BotClass{"seo", "SeekportBot", nil}},
	{"megaindex", BotClass{"seo", "MegaIndex", nil}},
	{"linkpadbot", BotClass{"seo", "LinkpadBot", nil}},
	{"rogerbot", BotClass{"seo", "rogerbot", nil}},
	{"screaming frog", BotClass{"seo", "Screaming Frog", nil}},
	{"sistrix", BotClass{"seo", "SISTRIX", nil}},
	{"seokicks", BotClass{"seo", "SEOkicks", nil}},
	{"backlinkcrawler", BotClass{"seo", "BacklinkCrawler", nil}},
}

// ClassifyBot returns the crawler class of a user agent (nil = no known bot).
func ClassifyBot(ua string) *BotClass {
	if ua == "" {
		return nil
	}
	l := strings.ToLower(ua)
	for i := range knownBots {
		if strings.Contains(l, knownBots[i].needle) {
			return &knownBots[i].bot
		}
	}
	return nil
}
