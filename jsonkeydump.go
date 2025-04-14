package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const numWorkers = 10

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

func montarURL(base string, chaves []string) string {
	parsedURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := parsedURL.Query()
	for _, chave := range chaves {
		q.Set(chave, "'\"teste")
	}
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String()
}

func worker(jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for u := range jobs {
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		chaves := extrairChaves(string(bodyBytes))
		if len(chaves) == 0 {
			continue
		}
		fmt.Println(montarURL(u, chaves))
	}
}

func main() {
	jobs := make(chan string)
	var wg sync.WaitGroup

	// Inicia os workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(jobs, &wg)
	}

	// Lê URLs da stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			jobs <- url
		}
	}
	close(jobs) // avisa que não tem mais URLs
	wg.Wait()   // espera todos os workers terminarem
}
