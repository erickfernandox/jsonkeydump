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
)

const maxParamsPerURL = 70

// Sinks JS que causam redirecionamento (DOM Redirect / Open Redirect)
var redirectSinks = []*regexp.Regexp{
	regexp.MustCompile(`location\.replace\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`location\.assign\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`location\.href\s*=\s*['"\x60]?([^'"\x60;\n]+)`),
	regexp.MustCompile(`location\s*=\s*['"\x60]?([^'"\x60;\n]+)`),
	regexp.MustCompile(`window\.location\s*=\s*['"\x60]?([^'"\x60;\n]+)`),
	regexp.MustCompile(`document\.location\s*=\s*['"\x60]?([^'"\x60;\n]+)`),
	regexp.MustCompile(`window\.location\.href\s*=\s*['"\x60]?([^'"\x60;\n]+)`),
	regexp.MustCompile(`window\.location\.replace\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`window\.navigate\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`window\.open\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`navigate\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`router\.push\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`router\.replace\s*\(\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`history\.pushState\s*\([^,]+,[^,]+,\s*['"\x60]?([^'"\x60\)]+)`),
	regexp.MustCompile(`history\.replaceState\s*\([^,]+,[^,]+,\s*['"\x60]?([^'"\x60\)]+)`),
}

// Nomes de variáveis JS comuns que indicam redirecionamento
var redirectVarNames = regexp.MustCompile(
	`(?i)(redirect|redirectUrl|redirectUri|next|returnUrl|return_url|goto|dest|destination|target|url|link|ref|referer|callback|forward|continue|redir|path|location)\s*=\s*['"\x60]?([^'"\x60;\n&]+)`,
)

func extrairChaves(body string, modo int) []string {
	var regexes []*regexp.Regexp

	switch modo {
	case 0: // Todos os modos
		regexes = []*regexp.Regexp{
			regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`),
			regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`),
			regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`),
			regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`),
			regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*`),
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
		regexes = []*regexp.Regexp{regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*`)}
	default:
		return []string{}
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

func montarURL(base string, chaves []string, payload string) string {
	parsedURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := parsedURL.Query()
	for _, chave := range chaves {
		q.Set(chave, payload)
	}
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String()
}

func montarURLParam(base, chave, valor string) string {
	parsedURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := parsedURL.Query()
	q.Set(chave, valor)
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String()
}

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for size < len(slice) {
		slice, chunks = slice[size:], append(chunks, slice[0:size:size])
	}
	return append(chunks, slice)
}

func fetchBody(u string) (string, error) {
	resp, err := http.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

// scanRedirect analisa se um parâmetro reflete dentro de um sink de redirecionamento
func scanRedirect(baseURL, param string) {
	marker := "PSCAN_REDIR_" + strings.ToUpper(param) + "_7x9z"
	testURL := montarURLParam(baseURL, param, marker)

	body, err := fetchBody(testURL)
	if err != nil {
		return
	}

	// Verifica se o marker aparece em algum sink de redirect
	for _, sink := range redirectSinks {
		matches := sink.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			for _, val := range m[1:] {
				if strings.Contains(val, marker) {
					sinkName := extractSinkName(sink.String())
					fmt.Printf("[REDIRECT SINK] %s | param=%s | sink=%s | url=%s\n",
						"\033[31mVULN\033[0m", param, sinkName, testURL)
					return
				}
			}
		}
	}

	// Verifica se o marker aparece em variáveis JS com nomes suspeitos
	varMatches := redirectVarNames.FindAllStringSubmatch(body, -1)
	for _, m := range varMatches {
		if len(m) > 2 && strings.Contains(m[2], marker) {
			fmt.Printf("[REDIRECT VAR]  %s | param=%s | var=%s | url=%s\n",
				"\033[33mSUSP\033[0m", param, m[1], testURL)
			return
		}
	}

	// Verifica reflexão simples em qualquer lugar (para pesquisa manual)
	if strings.Contains(body, marker) {
		fmt.Printf("[REFLECTED]     %s | param=%s | url=%s\n",
			"\033[34mINFO\033[0m", param, testURL)
	}
}

func extractSinkName(pattern string) string {
	knownSinks := []string{
		"location.replace", "location.assign", "location.href", "window.location",
		"document.location", "window.navigate", "window.open", "navigate",
		"router.push", "router.replace", "history.pushState", "history.replaceState",
	}
	for _, s := range knownSinks {
		if strings.Contains(pattern, strings.ReplaceAll(s, ".", `\.`)) ||
			strings.Contains(pattern, s) {
			return s
		}
	}
	return "unknown"
}

func processarURL(u, payload string, modo int, scan bool) {
	body, err := fetchBody(u)
	if err != nil {
		return
	}

	chaves := extrairChaves(body, modo)
	if len(chaves) == 0 {
		return
	}

	if scan {
		// Modo scan: testa cada parâmetro individualmente
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)
		for _, chave := range chaves {
			wg.Add(1)
			sem <- struct{}{}
			go func(c string) {
				defer wg.Done()
				defer func() { <-sem }()
				scanRedirect(u, c)
			}(chave)
		}
		wg.Wait()
		return
	}

	// Modo normal: monta URLs com blocos de parâmetros
	chunks := chunkSlice(chaves, maxParamsPerURL)
	for _, bloco := range chunks {
		result := montarURL(u, bloco, payload)
		if result != "" {
			fmt.Println(result)
		}
	}
}

func worker(jobs <-chan string, wg *sync.WaitGroup, payload string, modo int, scan bool) {
	defer wg.Done()
	for u := range jobs {
		processarURL(u, payload, modo, scan)
	}
}

func main() {
	payload := flag.String("p", "FUZZ", "Payload para os parâmetros")
	modo := flag.Int("o", 0, "Modo: 0=todos, 1=JSON keys, 2=Input name, 3=ID, 4=Query params, 5=JS vars")
	threads := flag.Int("t", 15, "Threads simultâneas")
	scan := flag.Bool("scan", false, "Scan de Open Redirect / DOM Redirect por parâmetro")
	flag.Parse()

	if *scan {
		fmt.Fprintf(os.Stderr, "[*] Modo SCAN ativo — detectando Open Redirect / DOM Redirect\n")
		fmt.Fprintf(os.Stderr, "[*] Legendas: \033[31mVULN\033[0m=sink confirmado  \033[33mSUSP\033[0m=variável suspeita  \033[34mINFO\033[0m=reflexão simples\n\n")
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, &wg, *payload, *modo, *scan)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			jobs <- u
		}
	}

	close(jobs)
	wg.Wait()
}
