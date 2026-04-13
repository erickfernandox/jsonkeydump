package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	clusterSize = 50
	scanMarker  = "https://PSCAN7x9zMARKER"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

func fetchBody(rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// ── Extração de parâmetros ────────────────────────────────────────────────────

func extrairChaves(body string, modo int) []string {
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
	return keys
}

// ── URL helpers ───────────────────────────────────────────────────────────────

func montarURL(base string, params []string, valor string) string {
	p, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := p.Query()
	for _, k := range params {
		q.Set(k, valor)
	}
	p.RawQuery = q.Encode()
	return p.String()
}

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for size < len(slice) {
		slice, chunks = slice[size:], append(chunks, slice[0:size:size])
	}
	return append(chunks, slice)
}

// ── FASE 1: encontrar variável que recebeu o marker ───────────────────────────
//
// Cobre todos esses padrões:
//   var x = 'MARKER'          let x = 'MARKER'        const x = 'MARKER'
//   x = 'MARKER'               x = "MARKER"            x = `MARKER`
//   "x": "MARKER"              x: 'MARKER'             'x': "MARKER"

func encontrarVarsComMarker(body, marker string) []string {
	escaped := regexp.QuoteMeta(marker)
	patterns := []*regexp.Regexp{
		// var/let/const x = 'MARKER'
		regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*['"\x60]` + escaped),
		// x = 'MARKER'  (bare assignment)
		regexp.MustCompile(`\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*['"\x60]` + escaped),
		// "x": "MARKER"  (JSON quoted key)
		regexp.MustCompile(`['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"][ \t]*:[ \t]*['"\x60]` + escaped),
		// x: 'MARKER'  (object literal unquoted key)
		regexp.MustCompile(`\b([a-zA-Z_$][a-zA-Z0-9_$]*)[ \t]*:[ \t]*['"\x60]` + escaped),
	}

	unique := make(map[string]bool)
	for _, rx := range patterns {
		for _, m := range rx.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && m[1] != "" {
				unique[m[1]] = true
			}
		}
	}
	var vars []string
	for v := range unique {
		vars = append(vars, v)
	}
	return vars
}

// ── FASE 2: verificar se a variável está dentro de um sink de redirect ────────

func encontrarSinkParaVar(body, varName string) string {
	v := regexp.QuoteMeta(varName)
	// padrão: sink( varName  ou  sink = varName
	// [\s,);] garante que é o nome da var e não substring de outra
	end := `[\s,);\n+]`
	sinks := []struct {
		nome    string
		pattern string
	}{
		{"location.replace()", `location\.replace\s*\(\s*` + v + end},
		{"location.assign()", `location\.assign\s*\(\s*` + v + end},
		{"location.href =", `location\.href\s*=\s*` + v + end},
		{"location =", `(?:^|[^.\w])location\s*=\s*` + v + end},
		{"window.location =", `window\.location\s*=\s*` + v + end},
		{"window.location.href =", `window\.location\.href\s*=\s*` + v + end},
		{"window.location.replace()", `window\.location\.replace\s*\(\s*` + v + end},
		{"document.location =", `document\.location\s*=\s*` + v + end},
		{"window.navigate()", `window\.navigate\s*\(\s*` + v + end},
		{"window.open()", `window\.open\s*\(\s*` + v + end},
		{"navigate()", `(?:^|[^.\w])navigate\s*\(\s*` + v + end},
		{"router.push()", `router\.push\s*\(\s*` + v + end},
		{"router.replace()", `router\.replace\s*\(\s*` + v + end},
		{"history.pushState()", `history\.pushState\s*\([^,]*,[^,]*,\s*` + v + end},
		{"history.replaceState()", `history\.replaceState\s*\([^,]*,[^,]*,\s*` + v + end},
	}

	for _, s := range sinks {
		rx, err := regexp.Compile(s.pattern)
		if err != nil {
			continue
		}
		if rx.MatchString(body) {
			return s.nome
		}
	}
	return ""
}

// ── Scan cluster bomb ─────────────────────────────────────────────────────────

func clusterScan(baseURL string, modo int) {
	body, err := fetchBody(baseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s → %v\n", baseURL, err)
		return
	}

	params := extrairChaves(body, modo)
	if len(params) == 0 {
		return
	}

	for _, cluster := range chunkSlice(params, clusterSize) {
		testURL := montarURL(baseURL, cluster, scanMarker)
		if testURL == "" {
			continue
		}

		respBody, err := fetchBody(testURL)
		if err != nil {
			continue
		}

		// marker não refletiu nesse cluster — pula
		if !strings.Contains(respBody, scanMarker) {
			continue
		}

		// FASE 1: qual variável recebeu o marker?
		vars := encontrarVarsComMarker(respBody, scanMarker)

		if len(vars) == 0 {
			fmt.Printf("[Not Vulnerable] - %s\n", testURL)
			continue
		}

		for _, varName := range vars {
			// FASE 2: essa variável é usada em algum sink?
			sink := encontrarSinkParaVar(respBody, varName)
			if sink != "" {
				fmt.Printf("\033[31m[Vulnerable] - %s - [var \"%s\" → %s]\033[0m\n",
					testURL, varName, sink)
			} else {
				fmt.Printf("[Not Vulnerable] - %s\n", testURL)
			}
		}
	}
}

// ── Modo normal (gerar URLs com payload) ─────────────────────────────────────

func processarURLNormal(baseURL, payload string, modo int) {
	body, err := fetchBody(baseURL)
	if err != nil {
		return
	}
	params := extrairChaves(body, modo)
	for _, bloco := range chunkSlice(params, clusterSize) {
		if u := montarURL(baseURL, bloco, payload); u != "" {
			fmt.Println(u)
		}
	}
}

// ── Workers ───────────────────────────────────────────────────────────────────

func worker(jobs <-chan string, wg *sync.WaitGroup, payload string, modo int, scan bool) {
	defer wg.Done()
	for u := range jobs {
		if scan {
			clusterScan(u, modo)
		} else {
			processarURLNormal(u, payload, modo)
		}
	}
}

func main() {
	payload := flag.String("p", "FUZZ", "Payload para modo normal")
	modo := flag.Int("o", 0, "0=todos, 1=JSON keys, 2=name=, 3=id=, 4=query params, 5=JS vars")
	threads := flag.Int("t", 15, "Threads")
	scan := flag.Bool("scan", false, "Scan: cluster bomb → var refletida → sink de redirect")
	flag.Parse()

	if *scan {
		fmt.Fprintf(os.Stderr, "[*] SCAN | cluster=%d | marker=%s\n", clusterSize, scanMarker)
		fmt.Fprintf(os.Stderr, "[*] \033[31mVULN\033[0m=var→sink  \033[33mSUSP\033[0m=var reflete/sink indireto  \033[34mINFO\033[0m=reflexão bruta\n\n")
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, &wg, *payload, *modo, *scan)
	}

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u != "" {
			jobs <- u
		}
	}
	close(jobs)
	wg.Wait()
}
