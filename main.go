package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"net/url"

	"github.com/gocolly/colly"
	"golang.org/x/net/publicsuffix"
)

type Progress struct {
	visitedLinks      int
	matchingFiles     int
	downloaded        int
	alreadyDownloaded int
	failedDownload    int
}

type progressWriter struct {
	total      int64
	written    int64
	writer     io.Writer
	filename   string
	downloaded int64
}

var progress = &Progress{}
var progressMutex = &sync.Mutex{}
var ErrFileAlreadyDownloaded = errors.New("File already downloaded")
var fileWriteMutex = &sync.Mutex{}
var visitedLinks = make(map[string]bool)
var visitedLinksMutex = &sync.Mutex{}

func main() {
	showBanner()

	var fileGroups = map[string][]string{
		"images":    []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".tiff", ".ico", ".heif", ".indd"},
		"movies":    []string{".mov", ".avi", ".mp4", ".webp", ".mkv", ".flv", ".wmv", ".m4v", ".3gp", ".mpg", ".mpeg"},
		"audio":     []string{".wav", ".mp3", ".aac", ".flac", ".m4a", ".ogg", ".wma"},
		"archives":  []string{".zip", ".tar", ".tar.gz", ".tar.gz2", ".rar", ".7z", ".bz2", ".jar", ".iso"},
		"documents": []string{".doc", ".docx", ".pdf", ".xls", ".xlsx", ".txt", ".csv", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".tex"},
		"configs":   []string{".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".cfg", ".toml"},
		"logs":      []string{".log", ".out", ".err", ".syslog", ".event"},
		"databases": []string{".db", ".sql", ".dbf", ".mdb", ".accdb", ".sqlite", ".sqlite3", ".csv", ".tsv", ".json"},
	}

	urlFlag := flag.String("url", "", "The target URL to search including http:// or https://")
	depthFlag := flag.Int("depth", 10, "The maximum depth to follow links")
	fileTypesFlag := flag.String("filetypes", "documents", "Comma-separated list of file extensions to download")
	userAgentFlag := flag.String("useragent", "random", "The User-Agent string to use")
	fileTextFlag := flag.String("filetext", "", "The text to be present in the filename (optional)")
	downloadExternalFlag := flag.Bool("external", true, "Enable or disable downloading files from external domains")
	timeOutFlag := flag.Int("timeout", 10, "The maximum time in minutes the crawler will run.")

	flag.Parse()

	if *urlFlag == "" {
		fmt.Println("No target address URL specified.")
		usage()
	}

	fileTypes := make(map[string]bool)
	for _, fileType := range strings.Split(*fileTypesFlag, ",") {
		if group, ok := fileGroups[fileType]; ok {
			// if it's a group, add each file type in the group
			for _, fileType := range group {
				fileTypes[fileType] = true
			}
		} else {
			// if it's a single file type, just add it
			fileTypes[fileType] = true
		}
	}

	maxConcurrentDownloads := 5
	semaphore := make(chan struct{}, maxConcurrentDownloads)

	if *userAgentFlag == "random" {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.35",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/113.0.5672.69 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/113.0  Mobile/15E148 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
		}

		rand.Seed(time.Now().UnixNano())
		*userAgentFlag = userAgents[rand.Intn(len(userAgents))]
	}

	checkedURL, ok := checkURL(*urlFlag, *userAgentFlag)
	if !ok {
		fmt.Printf("The target URL is not valid or not reachable.\n")
		return
	}

	*urlFlag = checkedURL
	fileText := *fileTextFlag
	downloadExternal := *downloadExternalFlag
	targetUrl := *urlFlag
	maxDepth := *depthFlag
	userAgent := *userAgentFlag
	setTimeOut := *timeOutFlag

	parsedURL, err := url.Parse(targetUrl)
	if err != nil {
		fmt.Printf("Failed to parse URL: %v\n", err)
		return
	}

	baseUrl, err := url.Parse(*urlFlag)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Clean the targetURL for use as a directory name
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		fmt.Printf("An error occurred: %v", err)
	}
	cleanTargetString := reg.ReplaceAllString(baseUrl.Hostname(), "")
	cleanTargetString = strings.ToLower(cleanTargetString)

	// Create the log directory if it doesn't exist
	logDirectoryPath := filepath.Join(cleanTargetString, "logs")
	err = os.MkdirAll(logDirectoryPath, os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}

	// Create a new file to store crawled URLs
	f, err := os.OpenFile(filepath.Join(logDirectoryPath, "crawled.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	fmt.Printf("TargetURL:  %s\n", *urlFlag)
	fmt.Printf("FileType:   %s\n", *fileTypesFlag)
	fmt.Printf("UserAgent:  %s\n", *userAgentFlag)
	fmt.Printf("Directory:  %s\n\n", cleanTargetString)

	c := colly.NewCollector(
		colly.MaxDepth(maxDepth),
		colly.UserAgent(userAgent),
		colly.AllowedDomains(parsedURL.Hostname()),
		colly.Async(true),
		colly.CacheDir("./_cache"),
	)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 5,
		Delay:       1 * time.Second,
		RandomDelay: 3 * time.Second,
	})

	var isFirstRequest = true

	c.OnRequest(func(r *colly.Request) {

		if !isFirstRequest {
			displayProgress()
		}
		isFirstRequest = false
	})

	c.OnHTML("a", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		processLink(e, link, fileTypes, fileText, cleanTargetString, downloadExternal, semaphore, f)
	})

	c.OnHTML("[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		processLink(e, src, fileTypes, fileText, cleanTargetString, downloadExternal, semaphore, f)
	})

	c.OnHTML("link", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		processLink(e, link, fileTypes, fileText, cleanTargetString, downloadExternal, semaphore, f)
	})

	c.OnHTML("object", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("data"))
		processLink(e, src, fileTypes, fileText, cleanTargetString, downloadExternal, semaphore, f)
	})

	// Create a new signal receiver
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Create a new context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*time.Duration(setTimeOut))
	defer cancel()

	// Start the scraping process in a new goroutine
	done := make(chan bool)
	go func() {
		c.Visit(targetUrl)
		c.Wait()
		done <- true
	}()

	// Select the first channel to send a signal
	select {
	case <-ctx.Done():
		fmt.Println("\n\nTimeout reached, stopping the process...")
	case <-done:
		fmt.Println("\n\nFinished crawling.")
	case <-sig:
		fmt.Println("\n\nSignal received, stopping the process...")
	}

}

func processLink(e *colly.HTMLElement, link string, fileTypes map[string]bool, fileText string, cleanTargetString string, downloadExternal bool, semaphore chan struct{}, f *os.File) {

	u, err := url.Parse(link)
	if err != nil {
		fmt.Printf("Failed to parse URL: %s", link)
		return
	}

	if u.IsAbs() {
		// Absolute URL
		link = u.String()
	} else {
		// Relative URL
		baseURL := getBaseURL(e.Request)
		base, err := url.Parse(baseURL)
		if err != nil {
			fmt.Printf("Failed to parse base URL: %s", baseURL)
			return
		}
		link = base.ResolveReference(u).String()
	}

	visitedLinksMutex.Lock()
	if visitedLinks[link] {
		visitedLinksMutex.Unlock()
		return
	} else {
		visitedLinks[link] = true
		visitedLinksMutex.Unlock()

		// Write to visited_links.txt after confirming it is a new link
		writeToFile(f, link)

		// Always visit the link, regardless of the file type
		e.Request.Visit(link)

		progressMutex.Lock()
		progress.visitedLinks++
		progressMutex.Unlock()
		displayProgress()

		baseURL := getBaseURL(e.Request)
		baseDomain, err := getBaseDomain(baseURL)
		if err != nil {
			fmt.Println(err)
		}

		// Check if the link leads to a file of the specified type
		if downloadExternal || strings.Contains(link, baseDomain) {
			if fileText == "" || (fileText != "" && strings.Contains(filepath.Base(link), fileText)) {
				ext := filepath.Ext(link)
				if fileTypes[ext] {
					// found a matching file
					progressMutex.Lock()
					progress.matchingFiles++
					progressMutex.Unlock()
					displayProgress()
					err := downloadFile(baseURL, link, cleanTargetString, semaphore)
					if err != nil {
						if err == ErrFileAlreadyDownloaded {
							// If already downloaded
							progressMutex.Lock()
							progress.alreadyDownloaded++
							progressMutex.Unlock()
							displayProgress()
						} else {
							// If download failed
							progressMutex.Lock()
							progress.failedDownload++
							progressMutex.Unlock()
							displayProgress()
						}
					} else {
						// if download successful
						progressMutex.Lock()
						progress.downloaded++
						progressMutex.Unlock()
						displayProgress()
					}
				}
			}
		}
	}
}

func getBaseURL(req *colly.Request) string {
	return fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)
}

func getBaseDomain(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Hostname())
	if err != nil {
		return "", err
	}

	return baseDomain, nil
}

func getDomain(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "" // or handle error as you see fit
	}
	return parsedURL.Hostname()
}

func checkURL(urlStr string, userAgent string) (string, bool) {
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		// if url parsing fails, it's likely due to missing scheme. Try both.
		for _, scheme := range []string{"http://", "https://"} {
			if validURL, isValid := tryURL(scheme+urlStr, userAgent); isValid {
				return validURL, isValid
			}
		}
	} else {
		if validURL, isValid := tryURL(u.String(), userAgent); isValid {
			return validURL, isValid
		}

		// Switch protocol and try again
		u = flipProtocol(u)
		if validURL, isValid := tryURL(u.String(), userAgent); isValid {
			return validURL, isValid
		}
	}

	return "", false
}

func tryURL(urlStr string, userAgent string) (string, bool) {
	for _, variantURL := range []string{urlStr, convertToWWW(urlStr), convertToNonWWW(urlStr)} {
		req, err := http.NewRequest("HEAD", variantURL, nil)
		if err != nil {
			continue
		}

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			redirectURL, err := resp.Location()
			if err != nil {
				continue
			}
			return redirectURL.String(), true
		}

		if resp.StatusCode == http.StatusOK {
			return variantURL, true
		}
	}
	return "", false
}

func convertToWWW(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	if !strings.HasPrefix(u.Host, "www.") {
		u.Host = "www." + u.Host
	}
	return u.String()
}

func convertToNonWWW(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	u.Host = strings.TrimPrefix(u.Host, "www.")
	return u.String()
}

func flipProtocol(u *url.URL) *url.URL {
	if u.Scheme == "http" {
		u.Scheme = "https"
	} else if u.Scheme == "https" {
		u.Scheme = "http"
	}
	return u
}

func downloadFile(baseURL, fileURL, cleanTargetString string, semaphore chan struct{}) error {
	semaphore <- struct{}{}        // Acquire a token.
	defer func() { <-semaphore }() // Release the token when downloadFile returns.
	absoluteURL, err := url.Parse(fileURL)
	if err != nil {
		return err
	}
	if !absoluteURL.IsAbs() {
		base, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		absoluteURL = base.ResolveReference(absoluteURL)
	}

	resp, err := http.Get(absoluteURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Parse the URL to get the domain
	parsedURL, err := url.Parse(absoluteURL.String())
	if err != nil {
		return err
	}

	// Clean the link URL to get host domain
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return err
	}
	cleanLinkDomain := reg.ReplaceAllString(parsedURL.Hostname(), "")
	cleanLinkDomain = strings.ToLower(cleanLinkDomain)

	var dir string
	if cleanTargetString != cleanLinkDomain {
		dir = filepath.Join(cleanTargetString, cleanLinkDomain)
	} else {
		dir = cleanTargetString
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		fmt.Println(err)
		return err
	}

	originalFilename := filepath.Base(absoluteURL.Path)
	ext := filepath.Ext(originalFilename)
	name := originalFilename[0 : len(originalFilename)-len(ext)]

	// Calculate the SHA256 hash of the file URL
	hasher := sha256.New()
	hasher.Write([]byte(absoluteURL.String()))
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Create a new filename with the hash prefix
	newFilename := hash + "_" + name + ext
	newFilePath := filepath.Join(dir, newFilename)

	// Check if the file already exists
	if _, err := os.Stat(newFilePath); err == nil {
		return ErrFileAlreadyDownloaded
	} else if !os.IsNotExist(err) {
		return err
	}

	// Create the file
	out, err := os.Create(newFilePath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Create a progress writer
	pw := &progressWriter{
		total:    resp.ContentLength,
		writer:   out,
		filename: newFilename,
	}

	// Copy the response body into file via progress writer
	_, err = io.Copy(pw, resp.Body)
	if err != nil {
		// If an error occurred, drain the response body to avoid leaking resources
		io.Copy(io.Discard, resp.Body)
		return err
	}

	return err
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if err != nil {
		return n, err
	}
	pw.written += int64(n)
	pw.downloaded += int64(n)
	percentage := float64(pw.written) / float64(pw.total) * 100

	fileType := "File"
	if strings.Contains(pw.filename, "audio") {
		fileType = "Audio"
	} else if strings.Contains(pw.filename, "video") {
		fileType = "Video"
	}

	fmt.Printf("\rDownloading %s: %.0f%% (%s/%s)\033[K", fileType, percentage, formatBytes(pw.downloaded), formatBytes(pw.total))

	return n, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func displayProgress() {
	progressMutex.Lock()
	defer progressMutex.Unlock()
	fmt.Printf("\rCount: %d | Matches: %d | New Downloads: %d | Existing: %d | Failed: %d", progress.visitedLinks, progress.matchingFiles, progress.downloaded, progress.alreadyDownloaded, progress.failedDownload)
}

func writeToFile(f *os.File, content string) {
	fileWriteMutex.Lock()
	defer fileWriteMutex.Unlock()

	// Calculate the SHA256 hash of the file URL
	hasher := sha256.New()
	hasher.Write([]byte(content))
	hash := hex.EncodeToString(hasher.Sum(nil))

	_, err := f.WriteString(fmt.Sprintf("%s %s\n", hash, content))
	if err != nil {
		fmt.Println(err)
	}
}

func showBanner() {
	bannerArt := `
   __________  ___________   ______  ____________    ___________
  / ____/ __ \/ ____/  _/ | / / __ \/ ____/  _/ /   / ____/ ___/
 / / __/ / / / /_   / //  |/ / / / / /_   / // /   / __/  \__ \ 
/ /_/ / /_/ / __/ _/ // /|  / /_/ / __/ _/ // /___/ /___ ___/ / 
\____/\____/_/   /___/_/ |_/_____/_/   /___/_____/_____//____/  
																  
`
	fmt.Println(bannerArt)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(0)
}
