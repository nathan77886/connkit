package files

import (
	"encoding/base64"
	"github.com/nathan77886/connkit/internal/store"
	"strings"
	"testing"
)

func TestWindowsDestinations(t *testing.T) {
	for _, v := range []struct {
		p  string
		ok bool
	}{{"C:/Wanghu/package.zip", true}, {"C:/temp/../secret", false}, {"C:/", false}, {"C:/temp/file:stream", false}, {"C:relative", false}, {"C:/dir\\file", false}, {"/tmp/file", true}, {"/tmp/../file", false}} {
		if validDestination(v.p) != v.ok {
			t.Errorf("%q destination check", v.p)
		}
	}
}
func TestWindowsDownloadCommand(t *testing.T) {
	c, e := windowsDownloadCommand(store.File{Destination: "C:/Wanghu/O'Brien.zip", Size: 123, SHA256: strings.Repeat("a", 64)}, "https://example.com/file?x=1&y=2")
	if e != nil {
		t.Fatal(e)
	}
	prefix := "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(c, prefix) {
		t.Fatal("wrong remote shell")
	}
	if _, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(c, prefix)); e != nil {
		t.Fatal(e)
	}
	if _, e := windowsDownloadCommand(store.File{Destination: "C:/file"}, "file:///etc/passwd"); e == nil {
		t.Fatal("unsafe URL accepted")
	}
}
