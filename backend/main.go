package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

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
}

type PortScanner struct {
	ip      string
	ports   []int
	timeout time.Duration
	results []string
	lock    *sync.Mutex
}

func GetMaxFileDescriptors() int64 {
	return 2048
}

func NewPortScanner(ip string, timeout time.Duration) *PortScanner {
	return &PortScanner{
		ip:      ip,
		ports:   make([]int, 65535),
		timeout: timeout,
		results: make([]string, 0),
		lock:    &sync.Mutex{},
	}
}

func (ps *PortScanner) ScanPort(port int, wg *sync.WaitGroup, semaphore *semaphore.Weighted) {
	defer wg.Done()
	defer semaphore.Release(1)

	target := fmt.Sprintf("%s:%d", ps.ip, port)
	conn, err := net.DialTimeout("tcp", target, ps.timeout)
	if err != nil {
		return
	}
	conn.Close()

	serviceName, ok := commonServices[port]
	if !ok {
		serviceName = "Unknown"
	}

	result := fmt.Sprintf("Port %d open (Service: %s)", port, serviceName)
	ps.lock.Lock()
	ps.results = append(ps.results, result)
	ps.lock.Unlock()
}

func (ps *PortScanner) Start() {
	semaphore := semaphore.NewWeighted(int64(GetMaxFileDescriptors()))
	wg := sync.WaitGroup{}

	for i := 1; i <= len(ps.ports); i++ {
		ps.ports[i-1] = i
		semaphore.Acquire(context.Background(), 1)
		wg.Add(1)
		go ps.ScanPort(i, &wg, semaphore)
	}

	wg.Wait()
}

func SimplePing(ip string) string {
	conn, err := net.DialTimeout("tcp", ip+":80", 2*time.Second)
	if err != nil {
		return "Ping: Host is not reachable\n"
	}
	conn.Close()
	return "Ping: Host is reachable\n"
}

func PerformNSLookup(domain string) string {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return fmt.Sprintf("Failed to perform NS lookup for %s: %v\n", domain, err)
	}
	var nsResults strings.Builder
	nsResults.WriteString("Name Servers:\n")
	for _, ns := range nsRecords {
		nsResults.WriteString(fmt.Sprintf("%s\n", ns.Host))
	}
	return nsResults.String()
}

func PerformDNSLookup(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Sprintf("Failed to perform DNS lookup for %s: %v\n", domain, err)
	}
	var ipResults strings.Builder
	ipResults.WriteString("DNS Lookup IPs:\n")
	for _, ip := range ips {
		ipResults.WriteString(fmt.Sprintf("%s\n", ip.String()))
	}
	return ipResults.String()
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	hostname := query.Get("hostname")

	if hostname == "" {
		http.Error(w, "Hostname is required", http.StatusBadRequest)
		return
	}

	// Perform and print ping, nslookup, and dnslookup before starting the port scan
	fmt.Fprintln(w, SimplePing(hostname))
	fmt.Fprintln(w, PerformNSLookup(hostname))
	fmt.Fprintln(w, PerformDNSLookup(hostname))

	ip, _ := net.LookupHost(hostname)
	if len(ip) == 0 {
		fmt.Fprintf(w, "Failed to resolve hostname: %s\n", hostname)
		return
	}
	ps := NewPortScanner(ip[0], 500*time.Millisecond)
	ps.Start()

	// Return the port scan results
	for _, result := range ps.results {
		fmt.Fprintln(w, result)
	}
}

func main() {
	http.HandleFunc("/scan", scanHandler)
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
