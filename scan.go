package main

import (
	"fmt"
	"net/http"
	"sync"
)

var directories = []string{"admin", "cgi-bin", "css", "images", "js", "php", "uploads", "secret"}

func checkDirectory(baseURL, directory string, wg *sync.WaitGroup) {
	defer wg.Done()
	url := fmt.Sprintf("%s/%s", baseURL, directory)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error checking %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Directory found: %s\n", url)
	}
}

func main() {
	var baseURL string
	fmt.Print("Enter the base URL (e.g., http://example.com): ")
	fmt.Scanln(&baseURL)

	var wg sync.WaitGroup
	for _, directory := range directories {
		wg.Add(1)
		go checkDirectory(baseURL, directory, &wg)
	}
	wg.Wait()
}
