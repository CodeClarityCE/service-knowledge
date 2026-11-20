// Package kev mirrors the CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/override"
	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// catalogURL is the CISA KEV catalog in JSON.
var catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// configColumn holds the KEV watermark in the config row.
const configColumn = "kev_last"

// Update mirrors the whole catalog, removes entries it no longer lists and advances the watermark.
func Update(db *bun.DB, configDB *bun.DB) error {
	return sourcesync.RunCounted(db, knowledge.SourceKEV, func() (sourcesync.Result, error) {
		syncedAt := time.Now()
		entries, err := download(catalogURL)
		if err != nil {
			return sourcesync.Result{}, err
		}
		if err := pgsql.UpdateKEV(db, entries); err != nil {
			return sourcesync.Result{}, err
		}
		cves := make([]string, len(entries))
		for i, entry := range entries {
			cves[i] = entry.CVE
		}
		if err := pgsql.ReconcileKEV(db, cves); err != nil {
			return sourcesync.Result{}, err
		}
		if err := sourcesync.SetConfigLast(configDB, configColumn, syncedAt); err != nil {
			return sourcesync.Result{}, err
		}
		return sourcesync.Result{Watermark: syncedAt, UpstreamTotal: sourcesync.Total(len(cves))}, nil
	})
}

// catalog is the KEV JSON feed.
type catalog struct {
	Count           *int           `json:"count"`
	Vulnerabilities []catalogEntry `json:"vulnerabilities"`
}

type catalogEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// download returns every catalog entry. Any defect fails the whole download.
func download(url string) ([]knowledge.KEV, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch the KEV catalog: " + resp.Status)
	}
	var feed catalog
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("read KEV catalog: %w", err)
	}
	return parse(feed)
}

// parse checks the catalog against its own count and converts its entries.
func parse(feed catalog) ([]knowledge.KEV, error) {
	if feed.Count == nil {
		return nil, errors.New("KEV catalog has no count")
	}
	if *feed.Count != len(feed.Vulnerabilities) {
		return nil, fmt.Errorf("KEV catalog lists %d entries but counts %d", len(feed.Vulnerabilities), *feed.Count)
	}
	if len(feed.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("KEV catalog has no entries: %w", sourcesync.ErrNoUpstreamRecords)
	}
	seen := make(map[string]bool, len(feed.Vulnerabilities))
	entries := make([]knowledge.KEV, 0, len(feed.Vulnerabilities))
	for i, raw := range feed.Vulnerabilities {
		entry, err := convert(raw)
		if err != nil {
			return nil, fmt.Errorf("KEV entry %d: %w", i, err)
		}
		if seen[entry.CVE] {
			return nil, fmt.Errorf("KEV entry %d: %s is listed twice", i, entry.CVE)
		}
		seen[entry.CVE] = true
		entries = append(entries, entry)
	}
	return entries, nil
}

func convert(raw catalogEntry) (knowledge.KEV, error) {
	cve := strings.ToUpper(strings.TrimSpace(raw.CVEID))
	if !strings.HasPrefix(cve, "CVE-") {
		return knowledge.KEV{}, fmt.Errorf("bad cveID %q", raw.CVEID)
	}
	added, err := time.Parse(time.DateOnly, raw.DateAdded)
	if err != nil {
		return knowledge.KEV{}, fmt.Errorf("%s: bad dateAdded: %w", cve, err)
	}
	var due *time.Time
	if raw.DueDate != "" {
		parsed, err := time.Parse(time.DateOnly, raw.DueDate)
		if err != nil {
			return knowledge.KEV{}, fmt.Errorf("%s: bad dueDate: %w", cve, err)
		}
		due = &parsed
	}
	cwes := raw.CWEs
	if cwes == nil {
		cwes = []string{}
	}
	return knowledge.KEV{
		CVE:                cve,
		VendorProject:      raw.VendorProject,
		Product:            raw.Product,
		Name:               raw.VulnerabilityName,
		DateAdded:          added,
		DueDate:            due,
		ShortDescription:   raw.ShortDescription,
		RequiredAction:     raw.RequiredAction,
		Notes:              raw.Notes,
		KnownRansomwareUse: raw.KnownRansomwareCampaignUse == "Known",
		CWEs:               cwes,
	}, nil
}

// UseUpstream points the mirror at another catalog URL and returns a function that undoes it.
func UseUpstream(url string) (restore func()) {
	return override.Set(&catalogURL, url)
}
