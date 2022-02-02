package main

import (
	"compress/bzip2"
	"database/sql"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/fleetdm/fleet/v4/server/vulnerabilities"
	"github.com/gocolly/colly"
	_ "github.com/mattn/go-sqlite3"
	"github.com/ulikunitz/xz"
)

const (
	repositoryDomain = "mirror.centos.org"
	repositoryURL    = "http://" + repositoryDomain
	root             = "/centos/"
)

var (
	dir      string
	runCrawl bool
	runParse bool
	verbose  bool
)

func main() {
	flag.StringVar(&dir, "dir", "output", "Local directory to use for crawling and parsing")
	flag.BoolVar(&runCrawl, "crawl", true, "Sets whether to crawl the repository")
	flag.BoolVar(&runParse, "parse", true, "Sets whether to parse the crawled files")
	flag.BoolVar(&verbose, "verbose", true, "Verbose mode")

	flag.Parse()

	if runCrawl {
		if err := crawl(); err != nil {
			log.Fatal(err)
		}
	}
	if runParse {
		pkgs, err := parse()
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			for pkg, cves := range pkgs {
				var cveList []string
				for cve := range cves {
					cveList = append(cveList, cve)
				}
				fmt.Printf("%s: %v\n", pkg, cveList)
			}
		}
		if err := genRPMSqlite(pkgs); err != nil {
			log.Fatal(err)
		}
	}
}

func crawl() error {
	c := colly.NewCollector()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var repoMDs []url.URL
	c.OnHTML("#indexlist .indexcolname a[href]", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		// Skip going to parent directory.
		if strings.HasPrefix(root, href) {
			return
		}
		if href == "repomd.xml" {
			u := *e.Request.URL
			u.Path = path.Join(u.Path, href)
			repoMDs = append(repoMDs, u)
			if verbose {
				fmt.Printf("%s\n", u.Path)
			}
			return
		}
		if !strings.Contains(href, "/") {
			return
		}
		e.Request.Visit(href)
	})

	c.AllowedDomains = append(c.AllowedDomains, repositoryDomain)

	if err := c.Visit(repositoryURL + root); err != nil {
		return err
	}

	for _, u := range repoMDs {
		if err := processRepoMD(u); err != nil {
			return err
		}
	}

	return nil
}

type dbs struct {
	primary, other string
}

func parse() (vulnerabilities.CentOSPkgSet, error) {
	dbPaths := make(map[string]dbs)
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sqlite") {
			return nil
		}
		dbp := dbPaths[filepath.Dir(path)]
		if strings.HasSuffix(path, "-primary.sqlite") {
			dbp.primary = path
		} else if strings.HasSuffix(path, "-other.sqlite") {
			dbp.other = path
		}
		dbPaths[filepath.Dir(path)] = dbp
		return nil
	}); err != nil {
		return nil, err
	}

	allPkgs := make(vulnerabilities.CentOSPkgSet)
	for _, db := range dbPaths {
		pkgs, err := processSqlites(db)
		if err != nil {
			return nil, err
		}
		for pkg, cves := range pkgs {
			for cve := range cves {
				allPkgs.Add(pkg, cve)
			}
		}
	}

	return allPkgs, nil
}

func processRepoMD(mdURL url.URL) error {
	resp, err := http.Get(mdURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	type location struct {
		Href string `xml:"href,attr"`
	}
	type repoDataItem struct {
		Type     string   `xml:"type,attr"`
		Location location `xml:"location"`
	}
	type repoMetadata struct {
		XMLName xml.Name       `xml:"repomd"`
		Datas   []repoDataItem `xml:"data"`
	}
	var md repoMetadata
	if err := xml.Unmarshal(b, &md); err != nil {
		return err
	}
	for _, data := range md.Datas {
		if data.Type != "primary_db" && data.Type != "other_db" {
			continue
		}
		sqliteURL := mdURL
		sqliteURL.Path = strings.TrimSuffix(sqliteURL.Path, "repomd.xml") + strings.TrimPrefix(data.Location.Href, "repodata/")
		if err := downloadSqlite(sqliteURL); err != nil {
			return err
		}
	}
	return nil
}

func downloadSqlite(sqliteURL url.URL) error {
	if verbose {
		fmt.Printf("%s\n", sqliteURL.Path)
	}
	filePath := filepath.Join(dir, sqliteURL.Path)
	filePath = strings.TrimSuffix(filePath, ".bz2")
	filePath = strings.TrimSuffix(filePath, ".xz")
	_, err := os.Stat(filePath)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		// OK
	default:
		return err
	}

	resp, err := http.Get(sqliteURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	tmpFile, err := ioutil.TempFile("", fmt.Sprintf("%s*", filepath.Base(filePath)))
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	var decompressor io.Reader
	switch {
	case strings.HasSuffix(sqliteURL.Path, "bz2"):
		decompressor = bzip2.NewReader(resp.Body)
	case strings.HasSuffix(sqliteURL.Path, "xz"):
		decompressor, err = xz.NewReader(resp.Body)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown extension: %s", sqliteURL.Path)
	}
	if _, err := io.Copy(tmpFile, decompressor); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpFile.Name(), filePath); err != nil {
		return err
	}
	return nil
}

func processSqlites(dbPaths dbs) (vulnerabilities.CentOSPkgSet, error) {
	db, err := sql.Open("sqlite3", dbPaths.primary)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	if _, err := db.Exec(fmt.Sprintf("ATTACH DATABASE '%s' as other;", dbPaths.other)); err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	rows, err := db.Query(`SELECT
		p.name, p.version, p.release, p.arch, c.changelog 
		FROM packages p 
		JOIN other.changelog c ON (p.pkgKey=c.pkgKey) 
		WHERE c.changelog LIKE '%CVE-%-%';`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pkgs := make(vulnerabilities.CentOSPkgSet)
	for rows.Next() {
		var p vulnerabilities.CentOSPkg
		var changelog string
		if err := rows.Scan(&p.Name, &p.Version, &p.Release, &p.Arch, &changelog); err != nil {
			return nil, err
		}
		cves := parseCVEs(changelog)
		for _, cve := range cves {
			pkgs.Add(p, cve)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

var cveRegex = regexp.MustCompile(`CVE\-[0-9]+\-[0-9]+`)

func parseCVEs(changelog string) []string {
	return cveRegex.FindAllString(changelog, -1)
}

func genRPMSqlite(pkgs vulnerabilities.CentOSPkgSet) error {
	db, err := sql.Open("sqlite3", "centos_cve.sqlite")
	if err != nil {
		return err
	}
	defer db.Close()

	if err := createSchema(db); err != nil {
		return err
	}
	type pkgWithCVEs struct {
		pkg  vulnerabilities.CentOSPkg
		cves string
	}
	var pkgsWithCVEs []pkgWithCVEs
	for pkg, cves := range pkgs {
		var cveList []string
		for cve := range cves {
			cveList = append(cveList, strings.TrimPrefix(cve, "CVE-"))
		}
		sort.Slice(cveList, func(i, j int) bool {
			return cveList[i] < cveList[j]
		})
		pkgsWithCVEs = append(pkgsWithCVEs, pkgWithCVEs{
			pkg:  pkg,
			cves: strings.Join(cveList, ","),
		})
	}
	for _, pkgWithCVEs := range pkgsWithCVEs {
		if _, err := db.Exec(
			"REPLACE INTO pkgs_cves (name, version, release, arch, cves) VALUES (?, ?, ?, ?, ?)",
			pkgWithCVEs.pkg.Name,
			pkgWithCVEs.pkg.Version,
			pkgWithCVEs.pkg.Release,
			pkgWithCVEs.pkg.Arch,
			pkgWithCVEs.cves,
		); err != nil {
			return err
		}
	}
	return nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS pkgs_cves (
		name TEXT,
		version TEXT,
		release TEXT,
		arch TEXT,
		cves TEXT,

		UNIQUE (name, version, release, arch)
	);`)
	return err
}
