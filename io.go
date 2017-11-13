package main

import (
	"io"
	"net"
	"sync"
)

func oneWay(wg *sync.WaitGroup, a net.Conn, b net.Conn) {
	defer wg.Done()
	defer a.Close()
	defer b.Close()

	io.Copy(a, b)
}

func duplex(a net.Conn, b net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go oneWay(&wg, a, b)
	go oneWay(&wg, b, a)
	wg.Wait()
}
