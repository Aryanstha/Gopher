package main

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
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

func CheckRobotsTxt(domain string) string {
	robotsURL := "http://" + domain + "/robots.txt"
	resp, err := http.Get(robotsURL)
	if err != nil {
		return "Failed to fetch robots.txt file: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "robots.txt file exists"
	}
	return "robots.txt file does not exist"
}

func CheckSecurityTxt(domain string) string {
	securityURL := "http://" + domain + "/.well-known/security.txt"
	resp, err := http.Get(securityURL)
	if err != nil {
		return "Failed to fetch security.txt file: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// If security.txt exists, read its content and return it
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "Failed to read security.txt file: " + err.Error()
		}
		return string(content)
	}
	return "security.txt file does not exist"
}

func CheckSecurityHeaders(domain string) string {
	resp, err := http.Get("http://" + domain)
	if err != nil {
		return "Failed to fetch website: " + err.Error()
	}
	defer resp.Body.Close()

	headers := resp.Header
	var results strings.Builder
	results.WriteString("Security Headers:\n")
	for header, values := range headers {
		if strings.HasPrefix(header, "X-") || strings.HasPrefix(header, "Content-Security-Policy") || header == "Strict-Transport-Security" {
			results.WriteString(fmt.Sprintf("%s: %s\n", header, strings.Join(values, ", ")))
		}
	}
	return results.String()
}

func WebServer(hostname string) (string, error) {
	resp, err := http.Get("http://" + hostname)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	return serverHeader, nil
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	hostname := query.Get("hostname")

	if hostname == "" {
		http.Error(w, "Hostname is required", http.StatusBadRequest)
		return
	}

	// Perform ping, nslookup, and dnslookup before starting the port scan
	results := "<h2>Network Information:</h2>"
	results += "<p>"
	results += "<strong>" + SimplePing(hostname) + "</strong><br>"
	results += PerformNSLookup(hostname) + "<br>"
	results += PerformDNSLookup(hostname) + "<br>"
	results += "</p>"

	serverHeader, err := WebServer(hostname)
	if err != nil {
		results += fmt.Sprintf("<p><strong>Failed to get server header: %v</strong></p>", err)
		fmt.Fprintln(w, results)
		return
	}
	results += "<p><strong>Server Header:</strong> " + serverHeader + "</p>"

	ip, _ := net.LookupHost(hostname)
	if len(ip) == 0 {
		results += "<p><strong>Failed to resolve hostname: " + hostname + "</strong></p>"
		fmt.Fprintln(w, results)
		return
	}
	ps := NewPortScanner(ip[0], 500*time.Millisecond)
	ps.Start()

	// Append the port scan results to the results string
	results += "<h2>Port Scan Results:</h2>"
	results += "<ul>"
	for _, result := range ps.results {
		results += "<li>" + result + "</li>"
	}
	results += "</ul>"

	// Render the HTML template with the results
	tmpl, err := template.New("").Parse(results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	tmpl, err := template.ParseFiles("./index.tmpl")
	if err != nil {
		log.Fatalf("template.ParseFiles: %v", err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("tmpl.Execute: %v", err)
		}
	})

	http.HandleFunc("/scan", scanHandler)
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
