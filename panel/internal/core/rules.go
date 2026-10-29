package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type fieldDef struct {
	Var       string // SecLang variable (may contain %s for name)
	NeedsName bool
	Phase     int
	Label     string
}

// Fields available in the rule builder.
var Fields = map[string]fieldDef{
	"path":         {"REQUEST_FILENAME", false, 1, "Pfad"},
	"uri":          {"REQUEST_URI", false, 1, "URI (Pfad + Query)"},
	"query":        {"QUERY_STRING", false, 1, "Query-String"},
	"method":       {"REQUEST_METHOD", false, 1, "Methode"},
	"host":         {"SERVER_NAME", false, 1, "Host"},
	"ip":           {"REMOTE_ADDR", false, 1, "Client-IP"},
	"user_agent":   {"REQUEST_HEADERS:User-Agent", false, 1, "User-Agent"},
	"referer":      {"REQUEST_HEADERS:Referer", false, 1, "Referer"},
	"content_type": {"REQUEST_HEADERS:Content-Type", false, 1, "Content-Type"},
	"header":       {"REQUEST_HEADERS:%s", true, 1, "Header"},
	"header_names": {"REQUEST_HEADERS_NAMES", false, 1, "Header-Namen"},
	"cookie":       {"REQUEST_COOKIES:%s", true, 1, "Cookie"},
	"arg":          {"ARGS:%s", true, 2, "Parameter"},
	"args":         {"ARGS", false, 2, "Alle Parameter"},
	"arg_names":    {"ARGS_NAMES", false, 2, "Parameter-Namen"},
	"query_arg":    {"ARGS_GET:%s", true, 1, "Query-Parameter"},
	"body":         {"REQUEST_BODY", false, 2, "Request-Body"},
	"file_name":    {"REQUEST_BASENAME", false, 1, "Dateiname"},
	"protocol":     {"REQUEST_PROTOCOL", false, 1, "Protokoll"},
	"files":        {"FILES", false, 2, "Upload-Dateinamen"},
}

type opDef struct {
	Op    string
	Label string
}

var Ops = map[string]opDef{
	"contains":    {"@contains", "enthält"},
	"equals":      {"@streq", "ist gleich"},
	"begins":      {"@beginsWith", "beginnt mit"},
	"ends":        {"@endsWith", "endet mit"},
	"regex":       {"@rx", "Regex"},
	"words":       {"@pm", "enthält eines der Wörter"},
	"within":      {"@within", "ist einer von"},
	"ip":          {"@ipMatch", "IP/CIDR in"},
	"eq":          {"@eq", "= (Zahl)"},
	"gt":          {"@gt", "> (Zahl)"},
	"lt":          {"@lt", "< (Zahl)"},
	"exists":      {"", "existiert"},
	"detect_sqli": {"@detectSQLi", "SQL-Injection (libinjection)"},
	"detect_xss":  {"@detectXSS", "XSS (libinjection)"},
	"length_gt":   {"@gt", "Länge >"},
}

var validTransforms = map[string]bool{
	"lowercase": true, "urlDecodeUni": true, "urlDecode": true, "trim": true, "normalizePath": true,
	"removeWhitespace": true, "compressWhitespace": true, "htmlEntityDecode": true, "base64Decode": true,
	"removeNulls": true, "cmdLine": true, "jsDecode": true,
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_\-.\[\]]+$`)
var excludeRe = regexp.MustCompile(`^(\d+(-\d+)?|tag:[A-Za-z0-9_\-/.]+|\d+;[A-Z_]+(:[A-Za-z0-9_\-.\[\]]+)?)$`)

func escapeArg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func escapeRegexArg(s string) string {
	// keep regex backslashes intact, only escape quotes
	return strings.ReplaceAll(s, `"`, `\"`)
}

func escapeMsg(s string) string {
	s = strings.ReplaceAll(s, `'`, "’")
	s = strings.ReplaceAll(s, `"`, "”")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// CompileRule renders one rule as SecLang.
func CompileRule(r Rule) (string, error) {
	if !r.Enabled {
		return "", nil
	}
	if r.Mode == "raw" {
		raw := strings.TrimSpace(r.Raw)
		if raw == "" {
			return "", nil
		}
		return raw + "\n", nil
	}
	if r.ID <= 0 {
		return "", fmt.Errorf("Regel %q hat keine ID", r.Name)
	}
	if len(r.Conditions) == 0 {
		return "", fmt.Errorf("Regel %q hat keine Bedingung", r.Name)
	}
	phase := 1
	type line struct{ variable, op, transforms string }
	var lines []line
	for i, c := range r.Conditions {
		fd, ok := Fields[c.Field]
		if !ok {
			return "", fmt.Errorf("Regel %q, Bedingung %d: unbekanntes Feld %q", r.Name, i+1, c.Field)
		}
		od, ok := Ops[c.Op]
		if !ok {
			return "", fmt.Errorf("Regel %q, Bedingung %d: unbekannter Operator %q", r.Name, i+1, c.Op)
		}
		if strings.ContainsAny(c.Value, "\n\r") {
			return "", fmt.Errorf("Regel %q, Bedingung %d: Wert darf keine Zeilenumbrüche enthalten", r.Name, i+1)
		}
		v := fd.Var
		if fd.NeedsName {
			if !nameRe.MatchString(c.Name) {
				return "", fmt.Errorf("Regel %q, Bedingung %d: ungültiger Name %q", r.Name, i+1, c.Name)
			}
			v = fmt.Sprintf(fd.Var, c.Name)
		}
		if fd.Phase > phase {
			phase = fd.Phase
		}
		var opStr string
		neg := ""
		if c.Negate {
			neg = "!"
		}
		switch c.Op {
		case "exists":
			v = "&" + v
			if c.Negate {
				opStr = `"@eq 0"`
			} else {
				opStr = `"@gt 0"`
			}
		case "length_gt":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil {
				return "", fmt.Errorf("Regel %q: Länge muss eine Zahl sein", r.Name)
			}
			opStr = fmt.Sprintf(`"%s@gt %d"`, neg, n)
			c.Transform = append([]string{"length"}, c.Transform...)
		case "detect_sqli", "detect_xss":
			opStr = fmt.Sprintf(`"%s%s"`, neg, od.Op)
		case "eq", "gt", "lt":
			if _, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64); err != nil {
				return "", fmt.Errorf("Regel %q: %q ist keine Zahl", r.Name, c.Value)
			}
			opStr = fmt.Sprintf(`"%s%s %s"`, neg, od.Op, strings.TrimSpace(c.Value))
		case "regex":
			if _, err := regexp.Compile(c.Value); err != nil {
				return "", fmt.Errorf("Regel %q: ungültige Regex: %v", r.Name, err)
			}
			opStr = fmt.Sprintf(`"%s%s %s"`, neg, od.Op, escapeRegexArg(c.Value))
		case "ip":
			opStr = fmt.Sprintf(`"%s%s %s"`, neg, od.Op, escapeArg(strings.Join(strings.Fields(strings.ReplaceAll(c.Value, ",", " ")), ",")))
		default:
			if c.Value == "" {
				return "", fmt.Errorf("Regel %q, Bedingung %d: Wert fehlt", r.Name, i+1)
			}
			opStr = fmt.Sprintf(`"%s%s %s"`, neg, od.Op, escapeArg(c.Value))
		}
		tf := "t:none"
		for _, t := range c.Transform {
			if t == "length" || validTransforms[t] {
				tf += ",t:" + t
			}
		}
		lines = append(lines, line{v, opStr, tf})
	}

	sev := strings.ToUpper(r.Severity)
	switch sev {
	case "CRITICAL", "ERROR", "WARNING", "NOTICE":
	default:
		sev = "CRITICAL"
	}
	var actions []string
	actions = append(actions, fmt.Sprintf("id:%d", r.ID), fmt.Sprintf("phase:%d", phase))
	switch r.Action {
	case "block", "":
		st := r.Status
		if st < 400 || st > 599 {
			st = 403
		}
		actions = append(actions, "deny", fmt.Sprintf("status:%d", st), "log")
	case "allow":
		actions = append(actions, "allow", "nolog")
	case "log":
		actions = append(actions, "pass", "log")
	case "score":
		n := r.Score
		if n <= 0 {
			n = 5
		}
		actions = append(actions, "pass", "log", fmt.Sprintf("setvar:'tx.inbound_anomaly_score_pl1=+%d'", n))
	case "exclude":
		if phase != 1 {
			return "", fmt.Errorf("Regel %q: Ausnahmen müssen in Phase 1 greifen – Body/Parameter-Bedingungen sind hier nicht möglich", r.Name)
		}
		actions = append(actions, "pass", "nolog")
		if len(r.Exclude) == 0 {
			return "", fmt.Errorf("Regel %q: keine auszuschließenden Regeln angegeben", r.Name)
		}
		for _, e := range r.Exclude {
			e = strings.TrimSpace(e)
			if !excludeRe.MatchString(e) {
				return "", fmt.Errorf("Regel %q: ungültige Ausnahme %q", r.Name, e)
			}
			switch {
			case strings.HasPrefix(e, "tag:"):
				actions = append(actions, "ctl:ruleRemoveByTag="+strings.TrimPrefix(e, "tag:"))
			case strings.Contains(e, ";"):
				actions = append(actions, "ctl:ruleRemoveTargetById="+e)
			default:
				actions = append(actions, "ctl:ruleRemoveById="+e)
			}
		}
	default:
		return "", fmt.Errorf("Regel %q: unbekannte Aktion %q", r.Name, r.Action)
	}
	name := r.Name
	if name == "" {
		name = fmt.Sprintf("Regel %d", r.ID)
	}
	if r.Action != "allow" && r.Action != "exclude" {
		actions = append(actions, fmt.Sprintf("msg:'%s'", escapeMsg(name)), fmt.Sprintf("severity:'%s'", sev))
	}
	actions = append(actions, "tag:'sentinel'", "tag:'custom'")

	var b strings.Builder
	if r.Note != "" {
		fmt.Fprintf(&b, "# %s\n", strings.ReplaceAll(r.Note, "\n", " "))
	}
	for i, l := range lines {
		acts := l.transforms
		if i == 0 {
			acts = strings.Join(actions, ",") + "," + l.transforms
		}
		if i < len(lines)-1 {
			acts += ",chain"
		}
		indent := ""
		if i > 0 {
			indent = "    "
		}
		fmt.Fprintf(&b, "%sSecRule %s %s \"%s\"\n", indent, l.variable, l.op, acts)
	}
	return b.String(), nil
}

// CompileRules renders a list of rules and collects errors.
func CompileRules(rules []Rule) (string, []string) {
	var b strings.Builder
	var errs []string
	for _, r := range rules {
		s, err := CompileRule(r)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if s != "" {
			b.WriteString(s)
		}
	}
	return b.String(), errs
}

// ---------------------------------------------------------------- presets

type Preset struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
}

func cond(field, op, value string) Cond { return Cond{Field: field, Op: op, Value: value} }

// Presets returns ruleset templates. Rule IDs are assigned when a preset is
// instantiated.
func Presets() []Preset {
	return []Preset{
		{
			Key:         "exploit-paths",
			Name:        "Exploit-Pfade & Scanner",
			Description: "Blockiert typische Sondierungs-Pfade (.env, .git, phpinfo, Router-Exploits …) und Angriffstools.",
			Rules: []Rule{
				{Name: "Geheime Dateien (.env, .git, .aws …)", Enabled: true, Mode: "builder", Action: "block", Status: 404,
					Conditions: []Cond{{Field: "path", Op: "regex", Value: `(?i)/\.(env|git|svn|hg|aws|ssh|docker|DS_Store|htpasswd|htaccess)(/|$)`}}},
				{Name: "Exploit-Sonden", Enabled: true, Mode: "builder", Action: "block", Status: 404,
					Conditions: []Cond{{Field: "path", Op: "regex", Value: `(?i)(phpinfo\.php|/vendor/phpunit/|/cgi-bin/|/boaform/|/HNAP1|/GponForm|/setup\.cgi|/shell\?|/actuator/|/\.well-known/security\.txt\.bak|/wp-config\.php|/xmlrpc\.php\.bak|/config\.json\.bak|/server-status)`}}},
				{Name: "Angriffstools (User-Agent)", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{{Field: "user_agent", Op: "words", Value: "sqlmap nikto masscan zgrab nuclei wpscan gobuster dirbuster feroxbuster wfuzz commix", Transform: []string{"lowercase"}}}},
				{Name: "Leerer User-Agent", Enabled: false, Mode: "builder", Action: "score", Score: 3,
					Conditions: []Cond{{Field: "user_agent", Op: "exists", Negate: true}}},
			},
		},
		{
			Key:         "wordpress",
			Name:        "WordPress-Härtung",
			Description: "Sperrt xmlrpc.php, PHP in Uploads und Benutzer-Enumeration.",
			Rules: []Rule{
				{Name: "xmlrpc.php sperren", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{cond("path", "ends", "/xmlrpc.php")}},
				{Name: "PHP in wp-content/uploads", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{{Field: "path", Op: "regex", Value: `(?i)/wp-content/uploads/.*\.ph(p\d?|tml|ar)$`}}},
				{Name: "Autoren-Enumeration (?author=)", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{{Field: "query_arg", Name: "author", Op: "regex", Value: `^\d+$`}}},
				{Name: "REST-Benutzerliste", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{{Field: "path", Op: "begins", Value: "/wp-json/wp/v2/users"}}},
			},
		},
		{
			Key:         "admin-internal",
			Name:        "Admin nur aus internen Netzen",
			Description: "Pfade unter /admin nur aus privaten Netzen erreichbar. Pfad und Netze anpassen.",
			Rules: []Rule{
				{Name: "/admin von extern sperren", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{
						cond("path", "begins", "/admin"),
						{Field: "ip", Op: "ip", Value: "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1, ::1, fc00::/7", Negate: true},
					}},
			},
		},
		{
			Key:         "api-json",
			Name:        "API: nur JSON",
			Description: "Schreibende Requests auf /api/ müssen JSON senden.",
			Rules: []Rule{
				{Name: "Nicht-JSON auf /api/ ablehnen", Enabled: true, Mode: "builder", Action: "block", Status: 415,
					Conditions: []Cond{
						cond("path", "begins", "/api/"),
						cond("method", "within", "POST PUT PATCH"),
						{Field: "content_type", Op: "contains", Value: "application/json", Negate: true, Transform: []string{"lowercase"}},
					}},
			},
		},
		{
			Key:         "nextcloud",
			Name:        "Nextcloud / WebDAV",
			Description: "Typische CRS-Fehlalarme für WebDAV-Methoden und Sync-Clients ausnehmen (Ausgangspunkt, bei Bedarf erweitern).",
			Rules: []Rule{
				{Name: "WebDAV: Methoden- und Content-Type-Prüfung aus", Enabled: true, Mode: "builder", Action: "exclude",
					Exclude:    []string{"911100", "920420", "920440"},
					Conditions: []Cond{{Field: "path", Op: "regex", Value: `^/(remote|public)\.php/(web)?dav`}}},
				{Name: "Sync-Client: Protokollprüfung lockern", Enabled: true, Mode: "builder", Action: "exclude",
					Exclude:    []string{"920000-920999"},
					Conditions: []Cond{{Field: "user_agent", Op: "contains", Value: "mirall"}}},
			},
		},
		{
			Key:         "login-protection",
			Name:        "Login-Schutz",
			Description: "Markiert Login-Versuche mit verdächtigen Mustern. Kombiniere mit einem Ratelimit auf den Login-Pfad.",
			Rules: []Rule{
				{Name: "Login: SQLi im Benutzernamen", Enabled: true, Mode: "builder", Action: "block",
					Conditions: []Cond{
						cond("path", "regex", `(?i)/(login|signin|wp-login\.php|user/login|auth)`),
						{Field: "args", Op: "detect_sqli"},
					}},
			},
		},
	}
}
