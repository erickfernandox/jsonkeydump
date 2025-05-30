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

// Extrai chaves com base na opção selecionada
func extrairChaves(body string, modo int) []string {
	var regex *regexp.Regexp

	switch modo {
	case 1:
		// Aceita aspas simples ou duplas na chave, espaços infinitos antes/depois do ':' e aspas após
		regex = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	case 2:
		regex = regexp.MustCompile(`name="([a-zA-Z0-9_-]+)"`) //Input Name
	case 3:
		regex = regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`) // Tudo que tem ID=
	case 4:
		regex = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`) //Parametros ?X= or &X=
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

// Monta uma URL com os parâmetros extraídos
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

// Divide slice em blocos de tamanho fixo
func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for size < len(slice) {
		slice, chunks = slice[size:], append(chunks, slice[0:size:size])
	}
	chunks = append(chunks, slice)
	return chunks
}

// Faz o request, extrai as chaves e gera URLs
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
		fmt.Println(montarURL(u, bloco, payload))
	}
}

// Worker que consome URLs do canal
func worker(jobs <-chan string, wg *sync.WaitGroup, payload string, modo int) {
	defer wg.Done()
	for url := range jobs {
		processarURL(url, payload, modo)
	}
}

// Função principal
func main() {
	payload := flag.String("p", "FUZZ", "Payload para os parâmetros (ex: -p '<script>')")
	modo := flag.Int("o", 1, "Modo de extração: 1=chave em JSON:, 2=Input name, 3=div ids:, 4=parametros no HTML")
	flag.Parse()

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
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
