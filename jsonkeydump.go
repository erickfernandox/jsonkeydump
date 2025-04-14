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

const numWorkers = 15
const maxParamsPerURL = 100

func extrairChaves(body string) []string {
	regex := regexp.MustCompile(`([a-zA-Z0-9_-]+):\s*"`)
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

func processarURL(u string, payload string) {
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

	chaves := extrairChaves(body)
	if len(chaves) == 0 {
		return
	}

	// Divide as chaves em blocos de até 100
	chunks := chunkSlice(chaves, maxParamsPerURL)
	for _, bloco := range chunks {
		fmt.Println(montarURL(u, bloco, payload))
	}
}

func worker(jobs <-chan string, wg *sync.WaitGroup, payload string) {
	defer wg.Done()
	for url := range jobs {
		processarURL(url, payload)
	}
}

func main() {
	payload := flag.String("p", "FUZZ", "Payload para os parâmetros (ex: -p \"<script>\")")
	flag.Parse()

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(jobs, &wg, *payload)
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
