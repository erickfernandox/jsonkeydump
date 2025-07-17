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

func extrairChaves(body string, modo int) []string {
	var regex *regexp.Regexp
	switch modo {
	case 1:
		regex = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	case 2:
		regex = regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`)
	case 3:
		regex = regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`)
	case 4:
		regex = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	case 5:
		regex = regexp.MustCompile(`([a-zA-Z0-9_-]+) =`)
	default:
		return []string{}
	}

	match := regex.FindAllStringSubmatch(body, -1)
	unique := make(map[string]bool)
	for _, m := range match {
		if len(m) > 1 {
			unique[m[1]] = true
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

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for size < len(slice) {
		slice, chunks = slice[size:], append(chunks, slice[0:size:size])
	}
	chunks = append(chunks, slice)
	return chunks
}

func processarURL(u string, payload string, modo int) {
	resp, err := http.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body := string(bodyBytes)

	chaves := extrairChaves(body, modo)
	if len(chaves) == 0 {
		return
	}

	chunks := chunkSlice(chaves, maxParamsPerURL)
	for _, bloco := range chunks {
		result := montarURL(u, bloco, payload)
		if result != "" {
			fmt.Println(result)
		}
	}
}

func worker(jobs <-chan string, wg *sync.WaitGroup, payload string, modo int) {
	defer wg.Done()
	for u := range jobs {
		processarURL(u, payload, modo)
	}
}

func main() {
	payload := flag.String("p", "FUZZ", "Payload para os parâmetros (ex: -p '<script>')")
	modo := flag.Int("o", 1, "Modo de extração: 1=JSON keys, 2=Input name, 3=ID, 4=Query params, 5=var x =")
	threads := flag.Int("t", 15, "Número de threads para execução simultânea")
	flag.Parse()

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(jobs, &wg, *payload, *modo)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			jobs <- url
		}
	}

	close(jobs)
	wg.Wait()
}
