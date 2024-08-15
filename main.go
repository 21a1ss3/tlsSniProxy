package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"syscall"

	"github.com/21a1ss3/goPatchedTls"
	"github.com/21a1ss3/tlsSniProxy/conf"
	"github.com/21a1ss3/tlsSniProxy/log"
	"github.com/21a1ss3/tlsSniProxy/mitm"
)

func main() {
	err := coreRun()

	if err != nil {
		log.A.Errorf("An unexpected error occured: %v", err)
		panic(err)
	}
}

func coreRun() error {
	log.InitLog()

	confPath := "config.json"

	if len(os.Args) > 1 {
		confPath = os.Args[1]
	}

	conf, err := conf.LoadConf(confPath)

	if err != nil {
		log.A.Infof("Config file path: %v", confPath)
		log.A.Error("Unable to open or parse config file")
		return err
	}

	log.A.SetLevel(conf.LogLevel)

	tcpListener, err := net.Listen("tcp", conf.BindSocket)

	if err != nil {
		log.A.Info("Unable to listen port")

		return err
	}

	log.A.Infof("Listening socket %v", conf.BindSocket)

	for {
		conn, err := tcpListener.Accept()

		if err != nil {
			log.A.Errorf("An error happend while new socket was awaited: %v", err)
			//ignoring error
			continue
		}

		log.A.Infof("Recevied connection, client = %v", conn.RemoteAddr())

		go handleClientConnection(conn, conf)
	}
}

func handleClientConnection(cliConn net.Conn, conf *conf.Conf) {
	log.A.Infof("Start handling connection, client = %v", cliConn.RemoteAddr())

	defer func() {
		addr := cliConn.RemoteAddr()
		cliConn.Close()
		log.A.Infof("Client connection has been closed. client = %v", addr)
	}()

	intermediate := mitm.NewConnectionWrapper(cliConn)

	tlsHelper := goPatchedTls.Server(intermediate, &goPatchedTls.Config{})

	log.A.Debug("Reading handshake")

	msg, err := tlsHelper.ReadHandshake(nil)

	if err != nil {
		log.A.Infof("Error in reading client hello package. client = %v, err = %v", cliConn.RemoteAddr(), err)
		return
	}

	clientHello, ok := msg.(*goPatchedTls.ClientHelloMsg)
	if !ok {
		//We've got not a client hello, what else it could be on a new connection?
		log.A.Infof("Wrong type of handshake. client = %v", cliConn.RemoteAddr())
		return
	}

	serverName := clientHello.GetServerName()

	if len(serverName) == 0 {
		log.A.Warningf("No servername is present. client = %v", cliConn.RemoteAddr())
		return
	}
	log.A.Infof("extracted SNI: '%v'", serverName)

	dscp := conf.DefaultDscp
	nextDscp := dscp
	leadBytes := 0

	fullSrvName := fmt.Sprintf("%v:443", serverName)

	func() {
		for _, srvLvl := range conf.Levels {
			for _, pattern := range srvLvl.Patterns {
				matched, err := regexp.MatchString(pattern, serverName)

				if err != nil {
					log.A.Errorf("Pattern '%v' is inocrrect ast service level: %d. err: %v", pattern, srvLvl.Dscp, err)
					//and skip intereation
					continue
				}

				if matched {
					dscp = srvLvl.LeadDscp
					nextDscp = srvLvl.Dscp
					leadBytes = srvLvl.LeadBytes

					//TODO: emit log about match
					log.A.Debugf("Found match for server '%v' with pattern '%v'. client = %v", serverName, pattern, cliConn.RemoteAddr())

					return //stop search
				}
			}
		}
	}()

	log.A.Infof("Using %v DSCP for connection. client = %v", dscp, cliConn.RemoteAddr())

	srvDialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				err := syscall.SetsockoptInt(int /* */ /*syscall.Handle/* */ (fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp*4)

				if err != nil {
					//TODO: log error out
					return
				}
			})
		},
	}

	log.A.Debugf("Calling server '%v' with DSCP '%v'. client = %v", fullSrvName, dscp, cliConn.RemoteAddr())
	srvConn, err := srvDialer.Dial("tcp", fullSrvName)
	continueProxy := true

	if err != nil {
		log.A.Errorf("Call to server '%v' (client = %v) has failed with error: %v", fullSrvName, cliConn.RemoteAddr(), err)
		return
	}

	log.A.Debugf("Established connection between %v <-> %v. client = %v", srvConn.LocalAddr(), srvConn.RemoteAddr(), cliConn.RemoteAddr())

	defer func() {
		continueProxy = false
		srvConn.Close()
	}()

	{
		firstBytes := intermediate.ReadBuffer.Bytes()
		originalLen := len(firstBytes)
		initialLen := leadBytes

		if originalLen < leadBytes {
			initialLen = originalLen
		}

		if initialLen > 0 {
			_, err = ensureWritten(srvConn, firstBytes[:initialLen])
		}
		if err != nil {
			log.A.Debugf("Unable to write initial handshake to server[P1]. client = %v, err: %v", cliConn.RemoteAddr(), err)
			return
		}

		tcpSrvConn := srvConn.(*net.TCPConn)
		srvConnFd, err := tcpSrvConn.File()

		if err != nil {
			log.A.Errorf("Unable to switch NEXT DCSP (ERR_NO_FD_DESC). client = %v, err: %v", cliConn.RemoteAddr(), err)
			return
		}

		err = syscall.SetsockoptInt(int /* */ /*syscall.Handle/* */ (srvConnFd.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, nextDscp*4)

		if err != nil {
			log.A.Errorf("Unable to switch NEXT DCSP (ERR_OPT_FAIL). client = %v, err: %v", cliConn.RemoteAddr(), err)
			return
		}

		if (originalLen - initialLen) > 0 {
			_, err = ensureWritten(srvConn, firstBytes[initialLen:originalLen])
		}
		if err != nil {
			log.A.Debugf("Unable to write initial handshake to server[P2]. client = %v, err: %v", cliConn.RemoteAddr(), err)
			return
		}
	}

	log.A.Debugf("Launching forwarding. client = %v", cliConn.RemoteAddr())
	go forwardTrafficBetweenConnections(cliConn, srvConn, &continueProxy)
	forwardTrafficBetweenConnections(srvConn, cliConn, &continueProxy)
}

func ensureWritten(dst net.Conn, b []byte) (int, error) {
	log.A.Tracef("Writing %d bytes to conn: %v <-> %v", len(b), dst.LocalAddr(), dst.RemoteAddr())

	writtenCountTotal := 0
	for writtenCountTotal < len(b) {
		writtenCount, err := dst.Write(b[writtenCountTotal : len(b)-writtenCountTotal])
		writtenCountTotal += writtenCount

		if err != nil {
			return writtenCountTotal, err
		}
	}

	return writtenCountTotal, nil
}

func forwardTrafficBetweenConnections(src, dst net.Conn, continueProxyFlag *bool) {
	defer func() {
		*continueProxyFlag = false
	}()

	buffer := make([]byte, 1500)

	for err := error(nil); *continueProxyFlag && err != io.EOF; {
		count, err := src.Read(buffer)

		_, err2 := ensureWritten(dst, buffer[0:count])

		log.A.Tracef("Read and wrote %d bytes between src = [%v <-> %v], dst = [%v <-> %v], continueProxyFlag: %v, err: %v, err2: %v",
			count, src.LocalAddr(), src.RemoteAddr(), dst.LocalAddr(), dst.RemoteAddr(), *continueProxyFlag, err, err2)

		if err != nil {
			if err != io.EOF {
				//TODO: we need to handle this

				log.A.Errorf("forwardTrafficBetweenConnections has unexpected io error(1). src = [%v <-> %v], dst = [%v <-> %v], err: %v",
					src.LocalAddr(), src.RemoteAddr(), dst.LocalAddr(), dst.RemoteAddr(), err)
			}

			return
		}

		if err2 != nil {
			if err2 != io.EOF {
				log.A.Errorf("forwardTrafficBetweenConnections has unexpected io error(2). src = [%v <-> %v], dst = [%v <-> %v], err: %v",
					src.LocalAddr(), src.RemoteAddr(), dst.LocalAddr(), dst.RemoteAddr(), err2)
			}

			//server closed the connection (?)

			return
		}
	}
}
