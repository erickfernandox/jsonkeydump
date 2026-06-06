package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
   Vulnerability Testing Tool — Com seletor de vulnerabilidades
*/

// =====================================
// Flags e globais
// =====================================

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error { *h = append(*h, val); return nil }

var (
	// execução
	concurrency int
	headers     customheaders
	proxy       string
	htmlOnly    bool
	onlyPOC     bool

	// requisições
	userAgent  string
	timeoutSec int

	// injeção
	paramCount int    // 0 = todos (padrão 70)
	mode       int    // 0=todos,1=JSON,2=name,3=id,4=query,5=JS vars
	vulnTypes  string // tipos de vulnerabilidade a testar (ex: "1,2,5")
	payload    string
)

const (
	clusterSize = 50 // Tamanho do cluster para envio em lote
)

// Tipos de vulnerabilidade
const (
	VULN_XSS_REFLECTED = 1
	VULN_XSS_SCRIPT    = 2
	VULN_CRLF          = 3
	VULN_REDIRECT      = 4
	VULN_LINK_MANIP    = 5
	VULN_SSTI          = 6
)

var vulnNames = map[int]string{
	VULN_XSS_REFLECTED: "XSS-Reflected",
	VULN_XSS_SCRIPT:    "XSS-Script",
	VULN_CRLF:          "CRLF-Injection",
	VULN_REDIRECT:      "Redirect/SSRF",
	VULN_LINK_MANIP:    "Link-Manipulation",
	VULN_SSTI:          "SSTI",
}

func init() {
	flag.IntVar(&concurrency, "t", 50, "Threads (mínimo 15)")
	flag.Var(&headers, "H", "Header extra (repetível)")
	flag.StringVar(&proxy, "proxy", "", "Proxy HTTP (também aceita -x)")
	flag.StringVar(&proxy, "x", "", "Proxy HTTP (atalho de -proxy)")
	flag.BoolVar(&htmlOnly, "html", false, "Só reportar se Content-Type for text/html")
	flag.BoolVar(&onlyPOC, "s", false, "Somente PoC (esconde Not Vulnerable)")

	flag.StringVar(&userAgent, "ua", "efx-scanner/3.0", "User-Agent")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout (segundos)")

	flag.IntVar(&paramCount, "params", 70, "Quantidade de parâmetros por endpoint (amostra; 0=todos, padrão=70)")
	flag.IntVar(&mode, "mode", 0, "Modo de extração: 0=todos,1=JSON,2=name,3=id,4=query,5=JS vars")
	flag.StringVar(&vulnTypes, "vulns", "1,2,3,4,5,6", "Tipos de vulnerabilidade (1=XSS-Reflected,2=XSS-Script,3=CRLF,4=Redirect/SSRF,5=Link-Manip,6=SSTI)")
	flag.StringVar(&payload, "p", "FUZZ", "Payload para modo normal (só para XSS-Reflected/XSS-Script)")
}

func usage() {
	fmt.Fprintln(os.Stderr, `Uso:
  echo "https://alvo" | go run scanner.go -params 70 -mode 2 -vulns "1,2,4"

Tipos de vulnerabilidade:
  1 - XSS Reflected (teste com '"teste)
  2 - XSS Script (teste com </script><teste>)
  3 - CRLF Injection (teste com set-cookie via raw request)
  4 - Redirect/SSRF (teste com https://example.com)
  5 - Link Manipulation (teste com https://efxtech.com em href/src/action)
  6 - SSTI (teste com {{7*7}}efxtech)

Flags:
  -params      Quantidade de parâmetros por endpoint (padrão 70, 0=todos)
  -vulns       Lista de vulns separadas por vírgula (ex: "1,2,5")
  -t           Threads (mín 15, default 50)
  -proxy/-x    Proxy HTTP
  -H           Header extra (repetível)
  -html        Só reportar se Content-Type for text/html (para vulns que precisam HTML)
  -s           Só linhas PoC (oculta "Not Vulnerable")
  -ua          User-Agent
  -timeout     Timeout em segundos
  -mode        Extração: 0=todos,1=JSON,2=name=,3=id=,4=query,5=JS vars
  -p           Payload para modo normal (default "FUZZ")
`)
}

// =====================================
// HTTP utils
// =====================================

func buildClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}).DialContext,
	}
	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{Transport: tr, Timeout: time.Duration(timeoutSec) * time.Second}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func isHTML(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func fetchBody(rawURL string) (string, *http.Response, error) {
	client := buildClient()
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", nil, err
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), resp, err
}

func fetchRawResponseHead(method, fullURL, body string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialTimeout := time.Duration(timeoutSec) * time.Second

	readHead := func(c net.Conn, reqTarget string, tlsWrap bool) (string, error) {
		if tlsWrap {
			sn := u.Hostname()
			tconn := tls.Client(c, &tls.Config{ServerName: sn, InsecureSkipVerify: true})
			if err := tconn.Handshake(); err != nil {
				return "", err
			}
			c = tconn
		}
		if reqTarget == "" {
			reqTarget = u.RequestURI()
		}
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"
		var b strings.Builder
		b.WriteString(reqLine)
		b.WriteString("Host: " + u.Host + "\r\n")
		b.WriteString("Connection: close\r\n")
		if userAgent != "" {
			b.WriteString("User-Agent: " + userAgent + "\r\n")
		}
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				b.WriteString(strings.TrimSpace(parts[0]) + ": " + strings.TrimSpace(parts[1]) + "\r\n")
			}
		}
		if method == "POST" && body != "" {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		b.WriteString("\r\n")
		if method == "POST" && body != "" {
			b.WriteString(body)
		}

		c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
		if _, err := c.Write([]byte(b.String())); err != nil {
			return "", err
		}

		rd := bufio.NewReader(c)
		var head strings.Builder
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return "", err
			}
			head.WriteString(line)
			if strings.HasSuffix(head.String(), "\r\n\r\n") {
				break
			}
			if head.Len() > 64*1024 {
				break
			}
		}
		return strings.TrimSuffix(head.String(), "\r\n\r\n"), nil
	}

	if proxy == "" {
		c, err := net.DialTimeout("tcp", host, dialTimeout)
		if err != nil {
			return "", err
		}
		defer c.Close()
		needTLS := (u.Scheme == "https")
		return readHead(c, "", needTLS)
	}

	pURL, err := url.Parse(proxy)
	if err != nil {
		return "", err
	}
	if pURL.Scheme != "http" {
		return "", fmt.Errorf("proxy scheme not supported for raw: %s", pURL.Scheme)
	}
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":80"
	}
	c, err := net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil {
		return "", err
	}
	defer c.Close()

	if u.Scheme == "http" {
		return readHead(c, u.String(), false)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	if _, err := c.Write([]byte(connectReq)); err != nil {
		return "", err
	}
	br := bufio.NewReader(c)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		respHead.WriteString(line)
		if strings.HasSuffix(respHead.String(), "\r\n\r\n") {
			break
		}
		if respHead.Len() > 32*1024 {
			break
		}
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") {
		return "", fmt.Errorf("proxy CONNECT failed")
	}
	return readHead(c, "", true)
}

// =====================================
// Extração de parâmetros
// =====================================

func extractParamNamesFromBody(body string, modo int) []string {
	var regexes []*regexp.Regexp
	switch modo {
	case 0:
		regexes = []*regexp.Regexp{
			regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`),
			regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`),
			regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`),
			regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`),
			regexp.MustCompile(`\b([a-zA-Z0-9_-]+)\s*=\s*`),
		}
	case 1:
		regexes = []*regexp.Regexp{regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)}
	case 2:
		regexes = []*regexp.Regexp{regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`)}
	case 3:
		regexes = []*regexp.Regexp{regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`)}
	case 4:
		regexes = []*regexp.Regexp{regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)}
	case 5:
		regexes = []*regexp.Regexp{regexp.MustCompile(`\b([a-zA-Z0-9_-]+)\s*=\s*`)}
	default:
		return nil
	}

	unique := make(map[string]bool)
	for _, rx := range regexes {
		for _, m := range rx.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && len(m[1]) > 1 {
				unique[m[1]] = true
			}
		}
	}
	var keys []string
	for k := range unique {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func queryKeysFromURL(u *url.URL) []string {
	keys := map[string]struct{}{}
	for k := range u.Query() {
		if k != "" {
			keys[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// =====================================
// URL helpers
// =====================================

// montarURL monta URL com os parâmetros já codificados corretamente
func montarURL(base string, params []string, rawPayload string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	
	q := u.Query()
	for _, k := range params {
		// AQUI ESTÁ A CORREÇÃO: Não codificamos novamente o payload
		// Pois o rawPayload já vem com a codificação correta (ex: %27%22teste)
		// O Query.Set() vai fazer encoding automático, então precisamos usar valores raw
		q.Set(k, rawPayload)
	}
	u.RawQuery = q.Encode()
	
	// CORREÇÃO: O Encode() acima vai codificar novamente nosso payload já codificado
	// Solução: construir a query string manualmente sem dupla codificação
	var queryParts []string
	for k, values := range q {
		for _, v := range values {
			// Manter o payload como está, sem codificar novamente
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), v))
		}
	}
	if len(queryParts) > 0 {
		u.RawQuery = strings.Join(queryParts, "&")
	}
	
	return u.String()
}

// montarURLRaw alternativa que não faz dupla codificação
func montarURLRaw(base string, params []string, rawPayload string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	
	var queryParts []string
	// Preservar query string original
	if u.RawQuery != "" {
		queryParts = append(queryParts, u.RawQuery)
	}
	
	// Adicionar novos parâmetros com payload cru
	for _, k := range params {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), rawPayload))
	}
	
	if len(queryParts) > 0 {
		u.RawQuery = strings.Join(queryParts, "&")
	}
	
	return u.String()
}

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for size < len(slice) {
		slice, chunks = slice[size:], append(chunks, slice[0:size:size])
	}
	return append(chunks, slice)
}

// =====================================
// Testes de vulnerabilidade
// =====================================

func formatVuln(kind, method, urlStr, detail string) string {
	msg := fmt.Sprintf("Vulnerable [%s] - %s %s", kind, method, urlStr)
	if detail != "" {
		msg += " | " + detail
	}
	if onlyPOC {
		return fmt.Sprintf("%s | %s", urlStr, kind)
	}
	return msg
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func getRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 {
		return params
	}
	if count >= len(params) {
		return params
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

// Teste XSS Reflected - Payload: '"teste (codificado como %27%22teste)
func testXSSReflected(baseURL string, params []string, client *http.Client) []string {
	var results []string
	// Payload CRU: '"teste (sem codificação extra)
	// Codificação URL correta: %27%22teste
	rawPayload := `'"teste`
	encodedPayload := url.QueryEscape(rawPayload) // Isso vai gerar %27%22teste
	
	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		applyHeaders(req)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		// Verificar se o payload foi refletido (agora sem codificação)
		if strings.Contains(string(body), rawPayload) {
			results = append(results, formatVuln("XSS-Reflected", "GET", testURL, fmt.Sprintf("match: %s", rawPayload)))
		} else if !onlyPOC {
			results = append(results, formatNotVuln("XSS-Reflected", "GET", testURL))
		}
	}
	return results
}

// Teste XSS Script - Payload: </script><teste>
func testXSSScript(baseURL string, params []string, client *http.Client) []string {
	var results []string
	rawPayload := `</script><teste>`
	encodedPayload := url.QueryEscape(rawPayload)
	
	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		applyHeaders(req)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if strings.Contains(string(body), rawPayload) {
			results = append(results, formatVuln("XSS-Script", "GET", testURL, fmt.Sprintf("match: %s", rawPayload)))
		} else if !onlyPOC {
			results = append(results, formatNotVuln("XSS-Script", "GET", testURL))
		}
	}
	return results
}

// Teste CRLF Injection
func testCRLF(baseURL string, params []string) []string {
	var results []string
	// CRLF payload: \r\nset-cookie:efx\r\n
	rawPayload := "\r\nset-cookie:efx\r\n"
	encodedPayload := url.QueryEscape(rawPayload)
	
	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		rawHead, err := fetchRawResponseHead("GET", testURL, "")
		if err == nil {
			if strings.Contains(strings.ToLower(rawHead), "set-cookie: efx") {
				results = append(results, formatVuln("CRLF-Injection", "GET", testURL, "raw-header injection"))
			} else if !onlyPOC {
				results = append(results, formatNotVuln("CRLF-Injection", "GET", testURL))
			}
		}
	}
	return results
}

// Teste Redirect/SSRF
func testRedirect(baseURL string, params []string, client *http.Client) []string {
	var results []string
	rawPayload := `https://example.com`
	encodedPayload := url.QueryEscape(rawPayload)
	
	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		applyHeaders(req)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if strings.Contains(string(body), "Example Domain") {
			results = append(results, formatVuln("Redirect/SSRF", "GET", testURL, "match: Example Domain"))
		} else if !onlyPOC {
			results = append(results, formatNotVuln("Redirect/SSRF", "GET", testURL))
		}
	}
	return results
}

// Teste Link Manipulation
func testLinkManip(baseURL string, params []string, client *http.Client) []string {
	var results []string
	rawPayload := `https://efxtech.com`
	encodedPayload := url.QueryEscape(rawPayload)
	
	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		applyHeaders(req)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		bodyLower := strings.ToLower(string(body))
		resp.Body.Close()
		
		if (!htmlOnly || isHTML(resp)) && 
		   (strings.Contains(bodyLower, `href="https://efxtech.com`) ||
		    strings.Contains(bodyLower, `src="https://efxtech.com`) ||
		    strings.Contains(bodyLower, `action="https://efxtech.com`)) {
			results = append(results, formatVuln("Link-Manipulation", "GET", testURL, "injected link in href/src/action"))
		} else if !onlyPOC {
			results = append(results, formatNotVuln("Link-Manipulation", "GET", testURL))
		}
	}
	return results
}

// Teste SSTI
func testSSTI(baseURL string, params []string, client *http.Client) []string {
	var results []string
	payloads := []string{`{{7*7}}efxtech`, `${{7*7}}efxtech`, `*{7*7}efxtech`}
	
	for _, rawPayload := range payloads {
		encodedPayload := url.QueryEscape(rawPayload)
		for _, cluster := range chunkSlice(params, clusterSize) {
			testURL := montarURLRaw(baseURL, cluster, encodedPayload)
			if testURL == "" {
				continue
			}

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			applyHeaders(req)
			
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			if strings.Contains(string(body), "49efxtech") {
				results = append(results, formatVuln("SSTI", "GET", testURL, "match: 49efxtech"))
				break
			} else if !onlyPOC {
				results = append(results, formatNotVuln("SSTI", "GET", testURL))
			}
		}
	}
	return results
}

// =====================================
// Processamento de URL única
// =====================================

func parseVulnTypes() map[int]bool {
	selected := make(map[int]bool)
	if vulnTypes == "" {
		// default todas
		for i := 1; i <= 6; i++ {
			selected[i] = true
		}
		return selected
	}
	
	parts := strings.Split(vulnTypes, ",")
	for _, part := range parts {
		var num int
		fmt.Sscanf(strings.TrimSpace(part), "%d", &num)
		if num >= 1 && num <= 6 {
			selected[num] = true
		}
	}
	return selected
}

func processURL(rawURL string, selectedVulns map[int]bool) []string {
	// Normalizar URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	
	u, err := url.Parse(rawURL)
	if err != nil {
		return []string{fmt.Sprintf("Error parsing URL: %s", rawURL)}
	}
	if u.Host == "" {
		return []string{fmt.Sprintf("Invalid URL (no host): %s", rawURL)}
	}

	// Fetch da página
	body, resp, err := fetchBody(rawURL)
	if err != nil {
		return []string{fmt.Sprintf("Error fetching %s: %s", rawURL, err.Error())}
	}
	
	// Extrair parâmetros
	pSet := map[string]struct{}{}
	for _, k := range extractParamNamesFromBody(body, mode) {
		if k != "" {
			pSet[k] = struct{}{}
		}
	}
	for _, k := range queryKeysFromURL(u) {
		if k != "" {
			pSet[k] = struct{}{}
		}
	}

	if len(pSet) == 0 {
		return []string{fmt.Sprintf("No parameters found for: %s", rawURL)}
	}

	params := make([]string, 0, len(pSet))
	for k := range pSet {
		params = append(params, k)
	}
	sort.Strings(params)
	
	selectedParams := getRandomParams(params, paramCount)

	fmt.Fprintf(os.Stderr, "[*] Found %d parameters for %s (using %d)\n", len(params), rawURL, len(selectedParams))

	client := buildClient()
	var allResults []string

	// Executar testes selecionados
	if selectedVulns[VULN_XSS_REFLECTED] {
		results := testXSSReflected(rawURL, selectedParams, client)
		allResults = append(allResults, results...)
	}
	
	if selectedVulns[VULN_XSS_SCRIPT] {
		results := testXSSScript(rawURL, selectedParams, client)
		allResults = append(allResults, results...)
	}
	
	if selectedVulns[VULN_CRLF] {
		results := testCRLF(rawURL, selectedParams)
		allResults = append(allResults, results...)
	}
	
	if selectedVulns[VULN_REDIRECT] {
		results := testRedirect(rawURL, selectedParams, client)
		allResults = append(allResults, results...)
	}
	
	if selectedVulns[VULN_LINK_MANIP] {
		results := testLinkManip(rawURL, selectedParams, client)
		allResults = append(allResults, results...)
	}
	
	if selectedVulns[VULN_SSTI] {
		results := testSSTI(rawURL, selectedParams, client)
		allResults = append(allResults, results...)
	}

	// Payload customizado
	if payload != "FUZZ" && payload != "" {
		encodedPayload := url.QueryEscape(payload)
		for _, cluster := range chunkSlice(selectedParams, clusterSize) {
			testURL := montarURLRaw(rawURL, cluster, encodedPayload)
			if testURL != "" {
				allResults = append(allResults, fmt.Sprintf("[Custom Payload] %s", testURL))
			}
		}
	}

	_ = resp // usado para isHTML em alguns testes
	return allResults
}

// =====================================
// Main
// =====================================

func main() {
	flag.Parse()
	if concurrency < 15 {
		concurrency = 15
	}
	rand.Seed(time.Now().UnixNano())

	selectedVulns := parseVulnTypes()
	
	fmt.Fprintf(os.Stderr, "[*] Selected vulnerabilities:\n")
	for v := range selectedVulns {
		fmt.Fprintf(os.Stderr, "    - %s\n", vulnNames[v])
	}
	fmt.Fprintf(os.Stderr, "[*] Params per endpoint: %d (0=todos)\n", paramCount)
	fmt.Fprintf(os.Stderr, "[*] Extraction mode: %d\n", mode)
	fmt.Fprintf(os.Stderr, "[*] Threads: %d\n\n", concurrency)

	// Ler URLs do stdin
	var urls []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw != "" {
			urls = append(urls, raw)
		}
	}

	if len(urls) == 0 {
		usage()
		return
	}

	// Processar URLs com workers
	jobs := make(chan string, len(urls))
	results := make(chan []string, len(urls))

	var wg sync.WaitGroup

	// Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				res := processURL(url, selectedVulns)
				results <- res
			}
		}()
	}

	// Enviar jobs
	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	// Aguardar workers e fechar results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Coletar e imprimir resultados
	for res := range results {
		for _, line := range res {
			if line != "" {
				fmt.Println(line)
			}
		}
	}
}
