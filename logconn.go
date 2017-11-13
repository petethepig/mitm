package main

import (
	"log"
	"net"
)

type dir int

const (
	dirUpstream dir = iota
	dirDownstream
)

func (d dir) String() string {
	if d == dirUpstream {
		return redColor + "->"
	} else if d == dirDownstream {
		return blueColor + "<-"
	} else {
		panic("invalid direction")
	}
}

const (
	redColor  = "\033[31m"
	blueColor = "\033[34m"
	defColor  = "\033[0m"
)

type logConn struct {
	net.Conn
	logger    *log.Logger
	direction dir
}

func (lc logConn) Read(p []byte) (int, error) {
	n, err := lc.Conn.Read(p)
	if n > 0 {
		lc.logger.Printf("%s %q %s", lc.direction.String(), p[:n], defColor)
	}
	return n, err
}
