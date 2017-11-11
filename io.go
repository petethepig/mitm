package main

import (
	"io"
	"log"
	"net"
	"sync"
)

type logger struct {
	io.Reader
	dir string
}

func (l logger) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	if n > 0 {
		log.Printf("%s %q", l.dir, p[:n])
	}
	return n, err
}

func oneWay(dir string, wg *sync.WaitGroup, a net.Conn, b net.Conn) {
	defer wg.Done()
	defer a.Close()

	io.Copy(a, logger{b, dir})
}

func duplex(a net.Conn, b net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go oneWay("<-", &wg, a, b)
	go oneWay("->", &wg, b, a)
	wg.Wait()
}
