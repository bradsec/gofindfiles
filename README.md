# GoFindFiles

Uses Go Colly to crawl websites attempting to find files with matching file types. For use as OSINT or RECON intelligence collection tool.

## Installation

### Build from source (Go required)
To install / build redgrab binary from source, you need to have Go installed on your system (https://go.dev/doc/install). Once you have Go installed, you can either clone and run from source or download and install with the following command:

```terminal
go install github.com/bradsec/gofindfiles@latest
```

## Basic Usage 

```terminal
# With URL only will default to looking for document files types
gofindfiles --url https://thisurlexamplesite.com

# Specify individual file types
gofindfiles --url https://thisurlexamplesite.com --filetypes ".pdf,.jpg"
```

### Predefined File Type Groups

Use with flag --filetypes  
Example using more than one group `--filetypes "images,documents"`

```
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
```

## Full Usage options

```terminal
  -depth int
    	The maximum depth to follow links (default 10)
  -external
    	Enable or disable downloading files from external domains (default true)
  -filetext string
    	The text to be present in the filename (optional)
  -filetypes string
    	Comma-separated list of file extensions to download (default "documents")
  -timeout int
    	The maximum time the crawling will run. (default 10)
  -url string
    	The target URL to search including http:// or https://
  -useragent string
    	The User-Agent string to use (default "random")
```

## Other Notes

### Visited Log - sitemap
A list of the crawled/visited URLs will be stored a text file `crawled.txt` in the `logs` sub-directory of the target URL.

### File Naming
As images are dumped in the main root directory made for the targetURL a SHA256 hash has been added to filename based of the files full source URL location to allow for when files may be different but have the same name in another location. You can match the HASH in the `logs/crawled.txt` to find where the file came from.  

### External File Links

If files are from an external domain/url there will be sub-director of the external domain/url within the main target URL directory containing the files from that site. You can disable downloading from external links using the `--external false` flag.

## Limitations

- Will not work for some dynamic content sites.
- Will not work for sites with reCAPTCHA/CAPTCHA type protection.