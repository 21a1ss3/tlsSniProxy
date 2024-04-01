package mitm

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/21a1ss3/tlsSniProxy/log"
)

type connWrapper struct {
	realConn   net.Conn
	ReadBuffer bytes.Buffer
}

func NewConnectionWrapper(realConn net.Conn) *connWrapper {
	cw := &connWrapper{
		realConn:   realConn,
		ReadBuffer: *bytes.NewBuffer([]byte{}),
	}

	return cw
}

func (cw *connWrapper) Read(b []byte) (n int, err error) {
	count, err := cw.realConn.Read(b)

	log.A.Tracef("Intercepted %d bytes for connection between %v <-> %v, err=%v", count, cw.realConn.LocalAddr(), cw.realConn.RemoteAddr(), err)

	if (err == nil) || (err == io.EOF) {
		cw.ReadBuffer.Grow(count)
		//cw.Write(b[0:count])
		cw.ReadBuffer.Write(b[0:count])
	}

	log.A.Tracef("Intercepted buffer size %d for connection between %v <-> %v", cw.ReadBuffer.Len(), cw.realConn.LocalAddr(), cw.realConn.RemoteAddr())

	return count, err
}

func (cw *connWrapper) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (cw *connWrapper) Close() error {
	return nil
}

func (cw *connWrapper) LocalAddr() net.Addr {
	return cw.realConn.LocalAddr()
}
func (cw *connWrapper) RemoteAddr() net.Addr {
	return cw.realConn.RemoteAddr()
}

func (cw *connWrapper) SetDeadline(t time.Time) error {
	return nil
}
func (cw *connWrapper) SetReadDeadline(t time.Time) error {
	return nil
}
func (cw *connWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}
