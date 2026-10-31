package protocol

import "testing"

func TestRedactQuery(t *testing.T) {
	cases := []struct{ path, in, want string }{
		{"/.sentinel/auth/reset", "t=abc123", "t=***"},
		{"/videos", "page=2&sort=-date", "page=2&sort=-date"},
		{"/cb", "code=xyz&state=s1&lang=de", "code=***&state=***&lang=de"},
		{"/f", "access_token=a&refresh_token=b&x=1", "access_token=***&refresh_token=***&x=1"},
		{"/s3", "X-Amz-Signature=abc&X-Amz-Credential=c&X-Amz-Date=1", "X-Amz-Signature=***&X-Amz-Credential=***&X-Amz-Date=1"},
		{"/p", "videoFileToken=a&apiKey=b&password=c", "videoFileToken=***&apiKey=***&password=***"},
		{"/e", "access%5Ftoken=a", "access%5Ftoken=***"},
		{"/flag", "debug&q=test", "debug&q=test"},
		{"/blog", "author=bob&auth=x", "author=bob&auth=***"},
		{"/", "", ""},
	}
	for _, c := range cases {
		if got := RedactQuery(c.path, c.in); got != c.want {
			t.Errorf("RedactQuery(%q, %q) = %q, want %q", c.path, c.in, got, c.want)
		}
	}
}
