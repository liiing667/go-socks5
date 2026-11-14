package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestNewRequest_BadVersion(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{4, 1, 0, 1, 127, 0, 0, 1, 0, 80})

	if _, err := NewRequest(buf); err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestNewRequest_Truncated(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1})

	if _, err := NewRequest(buf); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadAddrSpec_IPv6(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{4})
	buf.Write(net.ParseIP("::1").To16())
	buf.Write([]byte{0, 80})

	spec, err := readAddrSpec(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !spec.IP.Equal(net.ParseIP("::1")) || spec.Port != 80 {
		t.Fatalf("bad: %v", spec)
	}
}

func TestReadAddrSpec_FQDN_ShortReads(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{3, 11})
	buf.WriteString("example.com")
	buf.Write([]byte{0, 80})

	// Deliver one byte at a time to simulate a slow connection
	spec, err := readAddrSpec(&chunkedReader{r: buf, chunkSize: 1})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if spec.FQDN != "example.com" || spec.Port != 80 {
		t.Fatalf("bad: %v", spec)
	}
}

func TestReadAddrSpec_UnknownType(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{9, 0, 0, 0, 0, 0, 0})

	if _, err := readAddrSpec(buf); err != unrecognizedAddrType {
		t.Fatalf("err: %v", err)
	}
}

func TestReadAddrSpec_EmptyFQDN(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{3, 0, 0, 80})

	if _, err := readAddrSpec(buf); err == nil {
		t.Fatal("expected error for empty FQDN")
	}
}

func TestReadAddrSpec_TruncatedFQDN(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{3, 11})
	buf.WriteString("example")

	if _, err := readAddrSpec(buf); err == nil {
		t.Fatal("expected error for truncated FQDN")
	}
}

func TestReadAddrSpec_TruncatedIPv4(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{1, 127, 0})

	if _, err := readAddrSpec(buf); err == nil {
		t.Fatal("expected error for truncated IPv4 address")
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}
