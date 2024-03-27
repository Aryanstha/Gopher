package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Define a map of common port numbers to service names
var commonServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3306: "MySQL",
	// Add more ports and services as needed
}

type PortScanner struct {
	ip      string
	ports   []int
	timeout time.Duration
}

func Ulimit() int64 {
	out, err := exec.Command("ulimit", "-n").Output()
	if err != nil {
		panic(err)
	}

	s := strings.TrimSpace(string(out))
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}

	return i
}

func GetMaxFileDescriptors() int64 {
	return 2048 // Default value for Windows
}

func PingHost(ip string) bool {
	cmd := exec.Command("ping", "-n", "1", ip)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Host %s is not reachable\n", ip)
		return false
	}
	fmt.Printf("Host %s is reachable, proceeding with port scan...\n", ip)
	return true
}

func ScanPort(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, lock *semaphore.Weighted) {
	defer wg.Done()
	defer lock.Release(1)

	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return
	}
	conn.Close()

	serviceName, ok := commonServices[port]
	if !ok {
		serviceName = "Unknown"
	}

	fmt.Printf("\x1b[32m%d open\x1b[0m (Service: %s)\n", port, serviceName) // Green color for success
}

func (ps *PortScanner) Start() {
	if !PingHost(ps.ip) {
		return // Exit if host is not reachable
	}

	lock := semaphore.NewWeighted(GetMaxFileDescriptors())
	wg := sync.WaitGroup{}

	for _, port := range ps.ports {
		lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go ScanPort(ps.ip, port, ps.timeout, &wg, lock)
	}

	wg.Wait()
}

func PerformNSLookup(domain string) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		fmt.Printf("Failed to perform NS lookup for %s: %v\n", domain, err)
		return
	}
	fmt.Println("Name Servers:")
	for _, ns := range nsRecords {
		fmt.Println(ns.Host)
	}
}

func main() {
	var hostname string
	fmt.Print("Enter the hostname or IP address to scan: ")
	fmt.Scanln(&hostname)
	PerformNSLookup(hostname)

	ip := hostname
	if ips, err := net.LookupIP(hostname); err == nil && len(ips) > 0 {
		ip = ips[0].String()
		fmt.Printf("Resolved hostname %s to IP %s\n", hostname, ip)
	}

	ps := PortScanner{
		ip:      ip,
		ports:   make([]int, 65535),
		timeout: 500 * time.Millisecond,
	}

	for i := 1; i <= 65535; i++ {
		ps.ports[i-1] = i
	}

	ps.Start()
}
