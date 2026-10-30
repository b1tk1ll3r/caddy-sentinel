package sentinel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The bot challenge is a small JavaScript proof-of-work: the browser has to
// find a counter so that SHA-256(token ":" counter) starts with N zero bits.
// Real browsers solve it in about a second, simple bots and scripts that do
// not execute JavaScript cannot. A solved challenge sets a signed cookie
// bound to the client IP.

const (
	challengePath   = "/.sentinel/challenge"
	challengeCookie = "__sentinel_pass"
	tokenMaxAge     = 10 * time.Minute
)

var b64 = base64.RawURLEncoding

func sign(secret []byte, parts ...string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strings.Join(parts, "|")))
	return b64.EncodeToString(m.Sum(nil)[:20])
}

func challengeSecret(hexSecret string) []byte {
	b, err := hex.DecodeString(hexSecret)
	if err != nil || len(b) < 16 {
		return nil
	}
	return b
}

// validPass checks the pass cookie for ip.
func validPass(r *http.Request, secret []byte, ip string, now time.Time) bool {
	c, err := r.Cookie(challengeCookie)
	if err != nil {
		return false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return false
	}
	fields := strings.Split(string(raw), "|")
	if len(fields) != 3 || fields[0] != "v1" || fields[1] != ip {
		return false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || exp < now.Unix() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(mac), []byte(sign(secret, "pass", string(raw)))) == 1
}

func passCookie(secret []byte, ip string, ttl time.Duration, now time.Time, secure bool) *http.Cookie {
	raw := fmt.Sprintf("v1|%s|%d", ip, now.Add(ttl).Unix())
	return &http.Cookie{
		Name: challengeCookie, Value: b64.EncodeToString([]byte(raw)) + "." + sign(secret, "pass", raw),
		Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	}
}

func newToken(secret []byte, ip string, difficulty int, now time.Time) string {
	n := make([]byte, 9)
	_, _ = rand.Read(n)
	raw := fmt.Sprintf("%s|%d|%d|%s", ip, now.Unix(), difficulty, b64.EncodeToString(n))
	return b64.EncodeToString([]byte(raw)) + "." + sign(secret, "tok", raw)
}

func leadingZeroBits(h []byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// verifySolution validates token and proof of work.
func verifySolution(secret []byte, ip, token, counter string, now time.Time) error {
	payload, mac, ok := strings.Cut(token, ".")
	if !ok {
		return fmt.Errorf("token malformed")
	}
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("token malformed")
	}
	if subtle.ConstantTimeCompare([]byte(mac), []byte(sign(secret, "tok", string(raw)))) != 1 {
		return fmt.Errorf("token signature invalid")
	}
	f := strings.Split(string(raw), "|")
	if len(f) != 4 || f[0] != ip {
		return fmt.Errorf("token not issued for this client")
	}
	ts, _ := strconv.ParseInt(f[1], 10, 64)
	if now.Sub(time.Unix(ts, 0)) > tokenMaxAge {
		return fmt.Errorf("token expired")
	}
	diff, _ := strconv.Atoi(f[2])
	if len(counter) > 20 {
		return fmt.Errorf("counter invalid")
	}
	sum := sha256.Sum256([]byte(token + ":" + counter))
	if leadingZeroBits(sum[:]) < diff {
		return fmt.Errorf("proof of work insufficient")
	}
	return nil
}

// safeReturn accepts only a local path. Browsers drop tabs/newlines and treat
// "\\" like "/", so "/\t/evil" or "/\\evil" would become "//evil".
func safeReturn(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsRune(s, '\\') {
		return "/"
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	return s
}

// challengeAccepts reports whether the client is likely a browser that can
// render the interstitial (navigation requests).
func challengeAccepts(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	acc := r.Header.Get("Accept")
	return acc == "" || strings.Contains(acc, "text/html") || strings.Contains(acc, "*/*")
}

func renderChallenge(w http.ResponseWriter, token string, difficulty int, returnTo string) int {
	page := strings.NewReplacer(
		"{{TOKEN}}", html.EscapeString(token),
		"{{DIFF}}", strconv.Itoa(difficulty),
		"{{RETURN}}", html.EscapeString(returnTo),
		"{{PATH}}", challengePath,
	).Replace(challengeHTML)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'")
	w.WriteHeader(http.StatusForbidden)
	n, _ := w.Write([]byte(page))
	return n
}

const challengeHTML = `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Einen Moment …</title>
<style>
:root{color-scheme:light dark;--bg:#eef1f4;--card:#fff;--ink:#18202b;--muted:#5a6573;--accent:#2d47c9}
@media(prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1a2028;--ink:#e4e9f0;--muted:#94a0af;--accent:#7d93ff}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{background:var(--card);padding:32px 36px;border-radius:10px;max-width:420px;margin:16px;box-shadow:0 2px 16px rgba(0,0,0,.08)}
h1{font-size:19px;margin:0 0 8px}p{margin:0 0 14px;color:var(--muted)}
.bar{height:6px;border-radius:3px;background:rgba(127,127,127,.2);overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
small{display:block;margin-top:14px;color:var(--muted)}
</style></head><body><main>
<h1>Kurze Sicherheitsprüfung</h1>
<p>Dein Browser bestätigt gerade automatisch, dass er kein Bot ist. Das dauert meist nur eine Sekunde.</p>
<div class="bar"><i id="b"></i></div>
<small id="s">Checking your browser …</small>
<noscript><p><b>Bitte JavaScript aktivieren, um fortzufahren.</b> Please enable JavaScript to continue.</p></noscript>
<form id="f" method="post" action="{{PATH}}" hidden>
<input type="hidden" name="token" value="{{TOKEN}}"><input type="hidden" name="counter" id="c">
<input type="hidden" name="return" value="{{RETURN}}"></form>
</main>
<script>
(async function(){
  var token=document.querySelector('input[name=token]').value, diff={{DIFF}}, enc=new TextEncoder();
  var bar=document.getElementById('b'), st=document.getElementById('s');
  function zeros(buf){var a=new Uint8Array(buf),n=0;for(var i=0;i<a.length;i++){if(a[i]===0){n+=8;continue}return n+Math.clz32(a[i])-24}return n}
  // compact SHA-256 for plain-HTTP pages where crypto.subtle is unavailable
  var K=[],H0=[];(function(){function f(x){return (x-Math.floor(x))*4294967296|0}var n=2,c=0;while(c<64){var p=true;for(var d=2;d*d<=n;d++)if(n%d===0){p=false;break}if(p){if(c<8)H0[c]=f(Math.pow(n,1/2));K[c]=f(Math.pow(n,1/3));c++}n++}})();
  function sha(b){var l=b.length,w=new Int32Array(64),m=new Uint8Array(((l+9+63)>>6)<<6);m.set(b);m[l]=128;var bl=l*8;m[m.length-4]=bl>>>24;m[m.length-3]=bl>>>16;m[m.length-2]=bl>>>8;m[m.length-1]=bl;var h=H0.slice();
    for(var o=0;o<m.length;o+=64){for(var t=0;t<16;t++)w[t]=m[o+4*t]<<24|m[o+4*t+1]<<16|m[o+4*t+2]<<8|m[o+4*t+3];
      for(t=16;t<64;t++){var a=w[t-15],b2=w[t-2];w[t]=((a>>>7|a<<25)^(a>>>18|a<<14)^(a>>>3))+w[t-16]+((b2>>>17|b2<<15)^(b2>>>19|b2<<13)^(b2>>>10))+w[t-7]|0}
      var A=h[0],B=h[1],C=h[2],D=h[3],E=h[4],F=h[5],G=h[6],Hh=h[7];
      for(t=0;t<64;t++){var t1=Hh+((E>>>6|E<<26)^(E>>>11|E<<21)^(E>>>25|E<<7))+(E&F^~E&G)+K[t]+w[t]|0,t2=((A>>>2|A<<30)^(A>>>13|A<<19)^(A>>>22|A<<10))+(A&B^A&C^B&C)|0;Hh=G;G=F;F=E;E=D+t1|0;D=C;C=B;B=A;A=t1+t2|0}
      h[0]=h[0]+A|0;h[1]=h[1]+B|0;h[2]=h[2]+C|0;h[3]=h[3]+D|0;h[4]=h[4]+E|0;h[5]=h[5]+F|0;h[6]=h[6]+G|0;h[7]=h[7]+Hh|0}
    var out=new Uint8Array(32);for(var i=0;i<8;i++){out[4*i]=h[i]>>>24;out[4*i+1]=h[i]>>>16;out[4*i+2]=h[i]>>>8;out[4*i+3]=h[i]}return out.buffer}
  var subtle=window.crypto&&crypto.subtle;
  var expected=Math.pow(2,diff), i=0, t0=Date.now();
  for(;;i++){
    var data=enc.encode(token+':'+i);
    var h=subtle?await crypto.subtle.digest('SHA-256',data):sha(data);
    if(zeros(h)>=diff)break;
    if(i%2000===0){bar.style.width=Math.min(95,(i/expected)*100)+'%';if(!subtle)await new Promise(function(r){setTimeout(r,0)})}
  }
  bar.style.width='100%';st.textContent='Fertig – weiter geht’s ('+((Date.now()-t0)/1000).toFixed(1)+' s)';
  document.getElementById('c').value=i;document.getElementById('f').submit();
})();
</script></body></html>`
