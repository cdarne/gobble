package main

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sync"

	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
)

var (
	reNum         = regexp.MustCompile(`%\d+`)
	reDate        = regexp.MustCompile(`\w+\s+[0-9-]+\s+\d+\:\d+\:\d+`)
	reIP          = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reURL         = regexp.MustCompile(`"(?:GET|POST) (.+?) HTTP\/1\.1"`)
	reSQLInj      = regexp.MustCompile(`('|--)[^&]*&?`)
	reExecInj     = regexp.MustCompile(`\|.*\|\|\w`)
	reExecBQInj   = regexp.MustCompile("`.*`")
	reExecPathInj = regexp.MustCompile(`(\.\.|c:)[^&]*&?`)
	reHTMLInj     = regexp.MustCompile(`(\\?"|--)>[^&]*&?`)
	reURLInj      = regexp.MustCompile(`http:\/\/[^&]+&?`)
	reCodeInj     = regexp.MustCompile(`(\*|\)).+\*`)
	//dbMtx         sync.Mutex

	yellow  = colorizeWith(color.New(color.FgYellow).SprintFunc())
	green   = colorizeWith(color.New(color.FgGreen).SprintFunc())
	magenta = colorizeWith(color.New(color.FgMagenta).SprintFunc())
	blue    = colorizeWith(color.New(color.FgBlue).SprintFunc())
	red     = colorizeWith(color.New(color.FgRed).SprintFunc())
)

func colorizeWith(fn func(...interface{}) string) func(string) string {
	return func(str string) string { return fn(str) }
}

func WorkerPool(n int, prettify bool) (input, output chan string, wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	input = make(chan string, n*1024)
	output = make(chan string, n*1024)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go Worker(input, output, wg, prettify)
	}

	return
}

func Worker(input, output chan string, wg *sync.WaitGroup, prettify bool) {
	defer wg.Done()
	for line := range input {
		if reNum.MatchString(line) {
			if prettify {
				urlPath := ""
				m := reURL.FindStringSubmatch(line)
				if len(m) > 1 {
					urlPath = m[1]
				}
				date := reDate.FindString(line)
				ip := reIP.FindString(line)
				urlPath, _ = url.QueryUnescape(urlPath)
				urlPath, _ = url.QueryUnescape(urlPath)

				urlPath = reSQLInj.ReplaceAllStringFunc(urlPath, blue)

				urlPath = reExecInj.ReplaceAllStringFunc(urlPath, magenta)
				urlPath = reExecBQInj.ReplaceAllStringFunc(urlPath, magenta)
				urlPath = reExecPathInj.ReplaceAllStringFunc(urlPath, magenta)

				urlPath = reHTMLInj.ReplaceAllStringFunc(urlPath, red)
				urlPath = reURLInj.ReplaceAllStringFunc(urlPath, red)
				urlPath = reCodeInj.ReplaceAllStringFunc(urlPath, red)

				line = fmt.Sprintf("%s (%s) - %s", yellow(date), green(ip), urlPath)
			}

			output <- line
		}
	}
}

func Printer(output chan string) (wg *sync.WaitGroup) {
	wg = &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		for line := range output {
			fmt.Println(line)
		}
	}()

	return
}

/*
func DBSaverPool(n int, output chan string) (wg sync.WaitGroup) {
	db, err := sql.Open("sqlite3", "./exploit.db")
	if err != nil {
		log.Fatalln(err)
	}

	sqlStmt := `
			CREATE TABLE IF NOT EXISTS log (
				line text, date text, ip text,
				url text, path text,
				query text);
				DELETE FROM log;`

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}

	sqlStmt = "INSERT INTO log(line, date, ip, url, path, query) VALUES (?,?,?,?,?,?)"
	stmt, err := db.Prepare(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}

	wg.Add(n)
	for i := 0; i < n; i++ {
		go DBValueFormatter(output, stmt, wg)
	}

	// Wait before closing DB
	go func() {
		wg.Wait()
		stmt.Close()
		db.Close()
	}()

	return
}

func DBValueFormatter(input chan string, db *sql.Stmt, wg sync.WaitGroup) {
	defer wg.Done()

	for line := range input {
		fullURL := ""
		date := reDate.FindString(line)
		ip := reIP.FindString(line)
		m := reURL.FindStringSubmatch(line)
		if len(m) > 1 {
			fullURL = m[1]
		}
		urlObj, _ := url.Parse(fmt.Sprintf("http://www.mediatraffic.com%s", fullURL))

		urlPath, _ := url.QueryUnescape(fullURL)
		urlPath, _ = url.QueryUnescape(urlPath)

		query := urlObj.RawQuery
		query, _ = url.QueryUnescape(query)
		query, _ = url.QueryUnescape(query)

		dbMtx.Lock()
		_, err := db.Exec(line, date, ip, urlPath, urlObj.Path, query)
		dbMtx.Unlock()

		if err != nil {
			log.Fatalln(err)
		}
	}
}
*/

func main() {
	var (
		file *os.File
		err  error
	)
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	input, output, workerWG := WorkerPool(numCPU-1, true)
	printerWG := Printer(output)
	//printerWG := DBSaverPool(numCPU-1, output)

	if len(os.Args) > 1 {
		file, err = os.Open(os.Args[1])
		if err != nil {
			log.Fatalln(err)
		}
		defer file.Close()
	} else {
		file = os.Stdin
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		input <- scanner.Text()
	}
	close(input)
	err = scanner.Err()
	if err != nil {
		log.Fatalln(err)
	}
	workerWG.Wait()
	close(output)
	printerWG.Wait()
}
