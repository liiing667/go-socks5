package socks5

import (
	"bytes"
	"io"
	"testing"
)

// chunkedReader returns at most chunkSize bytes per Read to
// simulate slow connections that deliver short reads
type chunkedReader struct {
	r         io.Reader
	chunkSize int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if len(p) > c.chunkSize {
		p = p[:c.chunkSize]
	}
	return c.r.Read(p)
}

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != NoAuth {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != UserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["Username"]
	if !ok {
		t.Fatal("Missing key Username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != UserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&resp, req)
	if err != NoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestReadMethods_Duplicate(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, NoAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for duplicate methods")
	}
}

func TestReadMethods_Unknown(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, 0x7f})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestReadMethods_None(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{0})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for zero methods")
	}
}

func TestReadMethods_Truncated(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for truncated methods")
	}
}

func TestPasswordAuth_ShortReads(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	// Deliver one byte at a time to simulate a slow connection
	ctx, err := s.authenticate(&resp, &chunkedReader{r: req, chunkSize: 1})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != UserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	if ctx.Payload["Username"] != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}
}

func TestPasswordAuth_EmptyUsername(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 0, 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestPasswordAuth_EmptyPassword(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 0})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestPasswordAuth_TruncatedPassword(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for truncated password")
	}
}

func TestPasswordAuth_BadVersion(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{2, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	if _, err := s.authenticate(&resp, req); err == nil {
		t.Fatal("expected error for bad auth version")
	}
}
