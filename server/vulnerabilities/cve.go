package vulnerabilities

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/providers/nvd"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/fleet"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

func SyncCVEData(vulnPath string, config config.FleetConfig) error {
	if config.Vulnerabilities.DisableDataSync {
		return nil
	}

	cve := nvd.SupportedCVE["cve-1.1.json.gz"]

	source := nvd.NewSourceConfig()
	if config.Vulnerabilities.CVEFeedPrefixURL != "" {
		parsed, err := url.Parse(config.Vulnerabilities.CVEFeedPrefixURL)
		if err != nil {
			return fmt.Errorf("parsing cve feed url prefix override: %w", err)
		}
		source.Host = parsed.Host
		source.Scheme = parsed.Scheme
	}

	dfs := nvd.Sync{
		Feeds:    []nvd.Syncer{cve},
		Source:   source,
		LocalDir: vulnPath,
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelFunc()

	return dfs.Do(ctx)
}

func TranslateCPEToCVE(
	ctx context.Context,
	ds fleet.Datastore,
	vulnPath string,
	logger kitlog.Logger,
	config config.FleetConfig,
) error {
	err := SyncCVEData(vulnPath, config)
	if err != nil {
		return err
	}

	var files []string
	err = filepath.Walk(vulnPath, func(path string, info os.FileInfo, err error) error {
		if match, err := regexp.MatchString("nvdcve.*\\.gz$", path); !match || err != nil {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return err
	}

	cpeList, err := ds.AllCPEs(ctx)
	if err != nil {
		return err
	}

	cpes := make([]*wfn.Attributes, 0, len(cpeList))
	for _, uri := range cpeList {
		attr, err := wfn.Parse(uri)
		if err != nil {
			return err
		}
		cpes = append(cpes, attr)
	}

	if len(cpes) == 0 {
		return nil
	}

	for _, file := range files {
		err := checkCVEs(ctx, ds, logger, cpes, file)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkCVEs(ctx context.Context, ds fleet.Datastore, logger kitlog.Logger, cpes []*wfn.Attributes, files ...string) error {
	dict, err := cvefeed.LoadJSONDictionary(files...)
	if err != nil {
		return err
	}
	cache := cvefeed.NewCache(dict).SetRequireVersion(true).SetMaxSize(-1)
	// This index consumes too much RAM
	// cache.Idx = cvefeed.NewIndex(dict)

	cpeCh := make(chan *wfn.Attributes)

	var wg sync.WaitGroup

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		goRoutineKey := i
		go func() {
			defer wg.Done()

			logKey := fmt.Sprintf("cpe-processing-%d", goRoutineKey)
			level.Debug(logger).Log(logKey, "start")

			for {
				select {
				case cpe, more := <-cpeCh:
					if !more {
						level.Debug(logger).Log(logKey, "done")
						return
					}
					cacheHits := cache.Get([]*wfn.Attributes{cpe})
					for _, matches := range cacheHits {
						ml := len(matches.CPEs)
						if ml == 0 {
							continue
						}
						matchingCPEs := make([]string, 0, ml)
						for _, attr := range matches.CPEs {
							if attr == nil {
								level.Error(logger).Log("matches nil CPE", matches.CVE.ID())
								continue
							}
							cpe := attr.BindToFmtString()
							if len(cpe) == 0 {
								continue
							}
							matchingCPEs = append(matchingCPEs, cpe)
						}
						err = ds.InsertCVEForCPE(ctx, matches.CVE.ID(), matchingCPEs)
						if err != nil {
							level.Error(logger).Log("cpe processing", "error", "err", err)
						}
					}
				case <-ctx.Done():
					level.Debug(logger).Log(logKey, "quitting")
					return
				}
			}
		}()
	}

	level.Debug(logger).Log("pushing cpes", "start")
	for _, cpe := range cpes {
		cpeCh <- cpe
	}
	close(cpeCh)

	level.Debug(logger).Log("pushing cpes", "done")

	wg.Wait()

	return nil
}

func PostProcess(
	ctx context.Context,
	ds fleet.Datastore,
	vulnPath string,
	logger kitlog.Logger,
	config config.FleetConfig,
) error {
	if err := centosPostProcessing(ctx, ds, vulnPath, logger, config); err != nil {
		return err
	}
	return nil
}

type CentOSPkg struct {
	Name    string
	Version string
	Release string
	Arch    string
}

func (p CentOSPkg) String() string {
	return p.Name + "-" + p.Version + "-" + p.Release + "." + p.Arch
}

type CVESet map[string]struct{}

type CentOSPkgSet map[CentOSPkg]CVESet

func (p CentOSPkgSet) Add(pkg CentOSPkg, cve string) {
	s := p[pkg]
	if s == nil {
		s = make(CVESet)
	}
	s[cve] = struct{}{}
	p[pkg] = s
}

func centosPostProcessing(
	ctx context.Context,
	ds fleet.Datastore,
	vulnPath string,
	logger kitlog.Logger,
	config config.FleetConfig,
) error {
	dbFilePath := filepath.Join(vulnPath, "centos_cve.sqlite")
	switch _, err := os.Stat(dbFilePath); {
	case err == nil:
		// OK
	case errors.Is(err, os.ErrNotExist):
		level.Info(logger).Log("msg", "centos_cve.sqlite not found, skipping CentOS post-processing")
		return nil
	default:
		return err
	}
	db, err := sql.Open("sqlite3", dbFilePath)
	if err != nil {
		return fmt.Errorf("failed to open centos db: %w", err)
	}
	centOSPkgs, err := loadCentOSCVEs(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to fetch CentOS packages: %w", err)
	}
	rpmVulnerable, err := ds.ListVulnerableSoftwareBySource(ctx, "rpm_packages")
	if err != nil {
		return fmt.Errorf("failed to list vulnerable software: %w", err)
	}
	level.Info(logger).Log("centosPackages", len(centOSPkgs), "vulnerable", len(rpmVulnerable))
	var fixedCVEs []fleet.SoftwareVulnerability
	for _, software := range rpmVulnerable {
		if software.Vendor == nil || *software.Vendor != "CentOS" {
			continue
		}
		release := ""
		if software.Release != nil {
			release = *software.Release
		}
		arch := ""
		if software.Arch != nil {
			arch = *software.Arch
		}
		pkgCVEs, ok := centOSPkgs[CentOSPkg{
			Name:    software.Name,
			Version: software.Version,
			Release: release,
			Arch:    arch,
		}]
		if !ok {
			continue
		}
		for _, vulnerability := range software.Vulnerabilities {
			if _, ok := pkgCVEs[vulnerability.CVE]; ok {
				level.Info(logger).Log("fixedVuln", software.Name, "cve", vulnerability.CVE)
				fixedCVEs = append(fixedCVEs, fleet.SoftwareVulnerability{
					CPE: software.CPE,
					CVE: vulnerability.CVE,
				})
			}
		}
	}

	level.Info(logger).Log("fixedCVEsCount", len(fixedCVEs))
	level.Debug(logger).Log("fixedCVEs", fmt.Sprintf("%+v", fixedCVEs))

	if err := ds.DeleteVulnerabilities(ctx, fixedCVEs); err != nil {
		return fmt.Errorf("failed to delete fixed vulnerabilities: %w", err)
	}
	return nil
}

func loadCentOSCVEs(ctx context.Context, db *sql.DB) (CentOSPkgSet, error) {
	rows, err := db.QueryContext(ctx, `SELECT name, version, release, arch, cves from pkgs_cves`)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch packages: %w", err)
	}
	defer rows.Close()

	pkgs := make(CentOSPkgSet)
	for rows.Next() {
		var pkg CentOSPkg
		var cves string
		if err := rows.Scan(&pkg.Name, &pkg.Version, &pkg.Release, &pkg.Arch, &cves); err != nil {
			return nil, err
		}
		for _, cve := range strings.Split(cves, ",") {
			pkgs.Add(pkg, "CVE-"+cve)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to traverse packages: %w", err)
	}
	return pkgs, nil
}
