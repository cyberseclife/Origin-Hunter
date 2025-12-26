package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Colors ---
const (
	ColorReset     = "\033[0m"
	ColorWhite     = "\033[97m"
	ColorBoldRed   = "\033[1;31m"
	ColorBoldGreen = "\033[1;32m"
	ColorGrey      = "\033[90m"
	
	// Rainbow Colors
	ColorRed     = "\033[31m"
	ColorYellow  = "\033[33m"
	ColorGreen   = "\033[32m"
	ColorCyan    = "\033[36m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
)

// ... (Structs and Globals remain unchanged) ...

func printBanner() {
	// Simple vertical rainbow gradient
	lines := []string{
		`   ___       _      _          _  _            _            `,
		`  / _ \ _ _ (_)__ _(_)_ _     | || |_  _ _ __ | |_ ___ _ _  `,
		` | (_) | '_|| / _` + "`" + ` | | ' \    | __ | || | '_ \|  _/ -_) '_| `,
		`  \___/|_|  |_\__, |_|_||_|   |_||_|\_,_|_| |_|\__\___|_|   `,
		`              |___/                                         `,
	}

	colors := []string{ColorRed, ColorYellow, ColorGreen, ColorCyan, ColorBlue}

	for i, line := range lines {
		c := colors[i%len(colors)]
		fmt.Println(c + line + ColorReset)
	}
}
	
	func main() {
		printBanner()
	
		// Flags
		flag.StringVar(&targetURL, "u", "", "Target URL/Domain (e.g. example.com)")
		flag.StringVar(&targetList, "l", "", "Comma-separated list of targets")
		flag.StringVar(&targetFile, "f", "", "File containing list of targets")
		flag.StringVar(&outputFile, "o", "", "Output file to save results")
		flag.StringVar(&resolvers, "r", "", "Custom DNS resolver (e.g. 8.8.8.8:53)")
		flag.BoolVar(&wildcardMode, "w", false, "Enable Wildcard/Enumeration mode (find subdomains)")
		flag.BoolVar(&activeScan, "A", false, "Enable active scan (brute-force) (requires -w)")
		flag.BoolVar(&passiveScan, "P", true, "Enable passive scan (default) (requires -w)")
		flag.BoolVar(&jsonOutput, "json", false, "Save results in JSON format")
		flag.BoolVar(&verbose, "v", false, "Enable verbose output")
		flag.IntVar(&threads, "t", 20, "Number of concurrent threads")
		flag.Parse()
	
		// Help Menu
		flag.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: origin-hunter [options]\n")
			flag.PrintDefaults()
		}
	
		// Validate Targets
		var targets []string
		if targetURL != "" {
			targets = append(targets, targetURL)
		}
		if targetList != "" {
			parts := strings.Split(targetList, ",")
			targets = append(targets, parts...)
		}
		if targetFile != "" {
			lines, err := readLines(targetFile)
			if err != nil {
				fmt.Printf("[-] Error reading target file: %v\n", err)
			} else {
				targets = append(targets, lines...)
			}
		}
	
		if len(targets) == 0 {
			flag.Usage()
			os.Exit(1)
		}
	
		// Setup Resolver
		setupResolver()
	
		// Processing
		uniqueSubdomains := make(map[string]bool)
		var finalTargets []string
	
		if wildcardMode {
			fmt.Println("[*] Wildcard mode enabled. Enumerating subdomains...")
		} else {
			fmt.Println("[*] Single target mode. Scanning specific targets...")
		}
	
		for _, t := range targets {
			// Clean URL
			domain := cleanDomain(t)
			
			if wildcardMode {
				// Passive Enum (crt.sh + HackerTarget)
				if passiveScan {
					// Source 1: crt.sh
					subs1 := fetchCrtSh(domain)
					for _, s := range subs1 {
						if !uniqueSubdomains[s] {
							uniqueSubdomains[s] = true
							finalTargets = append(finalTargets, s)
						}
					}
					
					// Source 2: HackerTarget
					subs2 := fetchHackerTarget(domain)
					for _, s := range subs2 {
						if !uniqueSubdomains[s] {
							uniqueSubdomains[s] = true
							finalTargets = append(finalTargets, s)
						}
					}
				}
	
				// Active Enum (Expanded list)
				if activeScan {
					common := []string{
						"www", "mail", "dev", "stage", "test", "admin", "api", "origin", "corp", "webmail", "remote",
						"vpn", "m", "mobile", "shop", "beta", "secure", "demo", "portal", "support", "billing",
						"git", "jenkins", "jira", "monitor", "dashboard", "panel", "auth", "login", "sts", "sso",
					}
					for _, prefix := range common {
						s := fmt.Sprintf("%s.%s", prefix, domain)
						if !uniqueSubdomains[s] {
							uniqueSubdomains[s] = true
							finalTargets = append(finalTargets, s)
						}
					}
				}
				
				// Add the domain itself
				if !uniqueSubdomains[domain] {
					uniqueSubdomains[domain] = true
					finalTargets = append(finalTargets, domain)
				}
			} else {
				// No Wildcard -> Just scan the target as provided (cleaned)
				if !uniqueSubdomains[domain] {
					uniqueSubdomains[domain] = true
					finalTargets = append(finalTargets, domain)
				}
			}
		}

	fmt.Printf("[*] Found %d potential subdomains. Probing...\n\n", len(finalTargets))

	// Worker Pool
	jobs := make(chan string, len(finalTargets))
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				probeTarget(target)
			}
		}()
	}

	for _, t := range finalTargets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	// Output Results
	printResults()
}

// --- Core Logic ---

func setupResolver() {
	if resolvers == "" {
		resolvers = "8.8.8.8:53" // Default to Google
	}
	if !strings.Contains(resolvers, ":") {
		resolvers += ":53"
	}
	
	customResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", resolvers)
		},
	}
}

func fetchCrtSh(domain string) []string {
	// Simple CRT.SH scraper
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		if verbose { fmt.Printf("[-] crt.sh failed for %s: %v\n", domain, err) }
		return []string{}
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return []string{}
	}

	var subs []string
	for _, e := range entries {
		// Clean lines
		lines := strings.Split(e.NameValue, "\n")
		for _, l := range lines {
			if !strings.Contains(l, "*") {
				subs = append(subs, l)
			}
		}
	}
	return subs
}

func fetchHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		if verbose { fmt.Printf("[-] HackerTarget failed for %s: %v\n", domain, err) }
		return []string{}
	}
	defer resp.Body.Close()

	var subs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// Format is: hostname,IP
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			host := strings.TrimSpace(parts[0])
			if host != "" && strings.Contains(host, domain) {
				subs = append(subs, host)
			}
		}
	}
	return subs
}

func probeTarget(domain string) {
	// 1. Resolve IP
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Try multiple lookups to find round-robin IPs
	ips, err := customResolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		return
	}

	// 2. HTTP Probe
	// We'll just check the first IP for simplicity in this CLI output, 
	// or iterate if we were doing deep analysis. Let's check the domain normally.
	
	targetProto := "https://" + domain
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Force use of our resolver logic via direct dial if needed, 
				// but here we just want to connect.
				return net.DialTimeout(network, addr, 5*time.Second)
			},
		},
		Timeout: 8 * time.Second,
	}

	resp, err := client.Get(targetProto)
	if err != nil {
		// Try HTTP
		targetProto = "http://" + domain
		resp, err = client.Get(targetProto)
		if err != nil {
			return
		}
	}
	defer resp.Body.Close()

	// Read Body for WAF
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	wafName := detectWAF(resp, bodyStr)
	
	res := Result{
		URL:        targetProto,
		IP:         ips[0],
		WAF:        wafName,
		Status:     "Protected",
		StatusCode: resp.StatusCode,
		Method:     "GET",
		Port:       "443/80", // Simplified
	}

	if wafName == "" {
		res.Status = "Misconfigured"
	}

	resultsMutex.Lock()
	results = append(results, res)
	
	// Live Output (Left/Right format)
	printLiveEntry(res)
	
	resultsMutex.Unlock()
}

func detectWAF(resp *http.Response, body string) string {
	for _, sig := range wafSignatures {
		// Headers
		for k, v := range sig.Headers {
			if h := resp.Header.Get(k); h != "" {
				// Simple contains/match
				// In real regex world we'd use regexp, simplified here for speed/demo
				if strings.Contains(strings.ToLower(h), strings.ToLower(v)) || v == ".*" {
					return sig.Name
				}
			}
		}
		// Cookies
		for _, c := range resp.Cookies() {
			for _, sc := range sig.Cookies {
				if strings.Contains(c.Name, sc) {
					return sig.Name
				}
			}
		}
		// Body
		for _, b := range sig.Body {
			if strings.Contains(body, b) {
				return sig.Name
			}
		}
	}
	return ""
}

// --- Output ---

func printLiveEntry(res Result) {
	// "on the left side of the screen show the subdomain's full url in white and on the right show the WAF brand and details about the waf and it's IP address marked in bold red"
	
	// Calculate padding for alignment
	padding := 50 - len(res.URL)
	if padding < 1 { padding = 1 }
	padStr := strings.Repeat(" ", padding)

	if res.WAF != "" {
		// WAF Detected
		fmt.Printf("%s%s%s %s[WAF: %s | IP: %s]%s\n", 
			ColorWhite, res.URL, padStr, 
			ColorBoldRed, res.WAF, res.IP, ColorReset)
	} else {
		// Potential Misconfiguration (No WAF detected)
		// We print this in the live feed too, but maybe user wants separate section?
		// The prompt says "at the bottom have a section called misconfigured subdomains".
		// So we won't print "Misconfigured" details fully here, or we will?
		// Let's just print basic info here and summary later.
		fmt.Printf("%s%s%s %s[No WAF Detected | IP: %s]%s\n", 
			ColorWhite, res.URL, padStr, 
			ColorGrey, res.IP, ColorReset)
	}
	
	if verbose {
		fmt.Printf("    ↳ Code: %d, Method: %s\n", res.StatusCode, res.Method)
	}
}

func printResults() {
	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println(ColorBoldGreen + "MISCONFIGURED SUBDOMAINS (Origin IPs Exposed)" + ColorReset)
	fmt.Println(strings.Repeat("-", 60))

	var misc []Result
	for _, r := range results {
		if r.Status == "Misconfigured" {
			misc = append(misc, r)
			// "left under that have the full url in white and the web site's real IP address in bold green"
			padding := 50 - len(r.URL)
			if padding < 1 { padding = 1 }
			padStr := strings.Repeat(" ", padding)
			
			fmt.Printf("%s%s%s %s%s%s\n", ColorWhite, r.URL, padStr, ColorBoldGreen, r.IP, ColorReset)
		}
	}

	if outputFile != "" {
		saveToFile()
	}
}

func saveToFile() {
	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("[-] Error saving file: %v\n", err)
		return
	}
	defer f.Close()

	if jsonOutput {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		for _, r := range results {
			f.WriteString(fmt.Sprintf("URL: %s | IP: %s | WAF: %s | Status: %s\n", r.URL, r.IP, r.WAF, r.Status))
		}
	}
	fmt.Printf("\n[*] Results saved to %s\n", outputFile)
}

// --- Utils ---

func cleanDomain(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	u = strings.Split(u, "/")[0]
	return u
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}
