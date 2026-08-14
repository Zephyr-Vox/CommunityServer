package server

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

const (
	// sniffTimeout bounds how long an accepted connection may wait for its
	// first byte. Without it, an idle client would occupy a classification
	// goroutine forever; with it, dead connections are dropped quickly.
	sniffTimeout = 3 * time.Second
	// sniffQueueSize bounds how many classified connections can wait for
	// http.Server to accept them before classification backpressure applies.
	sniffQueueSize = 64
)

// sniffListener serves plaintext HTTP and TLS on the same TCP port for
// tls_mode = optional. A background accept loop accepts raw connections and
// classifies each one concurrently, so an empty or idle connection can never
// block the accept loop or surface as a fatal Serve error.
type sniffListener struct {
	net.Listener
	tlsConfig *tls.Config
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	acceptErr error
}

func newSniffListener(ln net.Listener, tlsConfig *tls.Config) net.Listener {
	l := &sniffListener{
		Listener:  ln,
		tlsConfig: tlsConfig,
		conns:     make(chan net.Conn, sniffQueueSize),
		closed:    make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *sniffListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			// The underlying listener failed (usually Close). Store it so
			// every future Accept returns the same error instead of blocking
			// forever after the channel is drained.
			l.mu.Lock()
			l.acceptErr = err
			l.mu.Unlock()
			return
		}
		go l.classify(conn)
	}
}

func (l *sniffListener) classify(conn net.Conn) {
	if err := conn.SetReadDeadline(time.Now().Add(sniffTimeout)); err != nil {
		conn.Close()
		return
	}
	// Peek instead of Read so the buffered bytes stay available for the HTTP
	// or TLS layer; dropping them would corrupt every request.
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		// Empty connection, idle timeout or a network error: drop it. These
		// failures are per-connection and must never bubble out of Accept,
		// otherwise http.Server would treat them as fatal and exit.
		conn.Close()
		return
	}
	var out net.Conn
	if first[0] == 0x16 {
		out = tls.Server(&bufferedConn{Conn: conn, r: br}, l.tlsConfig)
	} else {
		out = &bufferedConn{Conn: conn, r: br}
	}
	select {
	case l.conns <- out:
		// Ownership moves to http.Server; classify must not close conn now.
	case <-l.closed:
		out.Close()
	}
}

func (l *sniffListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	err := l.acceptErr
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *sniffListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// bufferedConn preserves the bytes already read by the sniffing bufio.Reader;
// net/http will then see the complete request/TLS stream.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
