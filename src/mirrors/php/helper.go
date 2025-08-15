package php

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PackagistPackage represents a package from Packagist API
type PackagistPackage struct {
	Package PackagistPackageDetails `json:"package"`
}

type PackagistPackageDetails struct {
	Name        string                          `json:"name"`
	Description string                          `json:"description"`
	Time        string                          `json:"time"`
	Type        string                          `json:"type"`
	Keywords    []string                        `json:"keywords"`
	Homepage    string                          `json:"homepage"`
	Repository  string                          `json:"repository"`
	Versions    map[string]PackagistVersionInfo `json:"versions"`
}

type PackagistVersionInfo struct {
	Name               string                 `json:"name"`
	Version            string                 `json:"version"`
	VersionNormalized  string                 `json:"version_normalized"`
	Source             PackagistSource        `json:"source"`
	Dist               PackagistDist          `json:"dist"`
	Require            interface{}            `json:"require"`      // Can be map[string]string or string
	RequireDev         interface{}            `json:"require-dev"`  // Can be map[string]string or string
	Suggest            interface{}            `json:"suggest"`      // Can be map[string]string or string
	Provide            interface{}            `json:"provide"`      // Can be map[string]string or string
	Replace            interface{}            `json:"replace"`      // Can be map[string]string or string
	Conflict           interface{}            `json:"conflict"`     // Can be map[string]string or string
	Time               string                 `json:"time"`
	Type               string                 `json:"type"`
	Extra              interface{}            `json:"extra"` // Can be string or map
	InstallationSource string                 `json:"installation-source"`
	Autoload           interface{}            `json:"autoload"` // Can be map or string
	NotificationUrl    string                 `json:"notification-url"`
	License            interface{}            `json:"license"` // Can be string or []string
	Authors            []PackagistAuthor      `json:"authors"`
	Description        string                 `json:"description"`
	Keywords           []string               `json:"keywords"`
	Homepage           string                 `json:"homepage"`
	Support            interface{}            `json:"support"` // Can be map or string
	Funding            interface{}            `json:"funding"` // Can be string or []PackagistFunding
}

type PackagistSource struct {
	Type      string `json:"type"`
	Url       string `json:"url"`
	Reference string `json:"reference"`
}

type PackagistDist struct {
	Type      string `json:"type"`
	Url       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum"`
}

type PackagistAuthor struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Homepage string `json:"homepage"`
	Role     string `json:"role"`
}

type PackagistFunding struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

// PackagistSearchResult represents search results from Packagist
type PackagistSearchResult struct {
	Results []PackagistSearchItem `json:"results"`
	Total   int                   `json:"total"`
	Next    string                `json:"next"`
}

type PackagistSearchItem struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Url         string `json:"url"`
	Repository  string `json:"repository"`
	Downloads   int    `json:"downloads"`
	Favers      int    `json:"favers"`
}

// downloadPackagist downloads a package from Packagist.org
func downloadPackagist(packageName string) (*PackagistPackage, error) {
	// Clean package name
	packageName = strings.TrimSpace(packageName)
	
	// Build URL for Packagist API v2
	apiUrl := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", url.QueryEscape(packageName))
	
	// Create HTTP request
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		log.Printf("Error creating request for package %s: %v", packageName, err)
		return nil, err
	}
	
	// Set User-Agent header (required by Packagist)
	req.Header.Set("User-Agent", "CodeClarity/1.0")
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching package %s: %v", packageName, err)
		return nil, err
	}
	defer resp.Body.Close()
	
	// Handle response status
	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return nil, fmt.Errorf("package not found: %s", packageName)
		} else if resp.StatusCode == 429 {
			// Rate limited, wait and retry
			time.Sleep(60 * time.Second)
			log.Printf("Rate limited for package %s, retrying after 60 seconds", packageName)
			return downloadPackagist(packageName)
		} else {
			return nil, fmt.Errorf("failed to fetch package %s: HTTP %d", packageName, resp.StatusCode)
		}
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response for package %s: %v", packageName, err)
		return nil, err
	}
	
	// Parse JSON response
	// Packagist v2 API returns packages in a wrapper object
	var wrapper struct {
		Packages map[string][]PackagistVersionInfo `json:"packages"`
	}
	
	err = json.Unmarshal(body, &wrapper)
	if err != nil {
		log.Printf("Error unmarshaling response for package %s: %v", packageName, err)
		return nil, err
	}
	
	// Extract package versions
	versions, ok := wrapper.Packages[packageName]
	if !ok {
		return nil, fmt.Errorf("package %s not found in response", packageName)
	}
	
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for package %s", packageName)
	}
	
	// Convert to our internal format
	result := &PackagistPackage{
		Package: PackagistPackageDetails{
			Name:     packageName,
			Versions: make(map[string]PackagistVersionInfo),
		},
	}
	
	// Process versions and extract package metadata from latest stable version
	var latestStable *PackagistVersionInfo
	for _, version := range versions {
		result.Package.Versions[version.Version] = version
		
		// Track latest stable version for metadata
		if !strings.Contains(version.Version, "-") && !strings.Contains(version.Version, "dev") {
			if latestStable == nil || version.Time > latestStable.Time {
				latestStable = &version
			}
		}
	}
	
	// Use latest stable version for package metadata, or first version if no stable found
	if latestStable == nil && len(versions) > 0 {
		latestStable = &versions[0]
	}
	
	if latestStable != nil {
		result.Package.Description = latestStable.Description
		result.Package.Homepage = latestStable.Homepage
		result.Package.Keywords = latestStable.Keywords
		result.Package.Type = latestStable.Type
		result.Package.Time = latestStable.Time
	}
	
	return result, nil
}

// NormalizeDependencies converts various dependency formats to a consistent map[string]string
func NormalizeDependencies(deps interface{}) map[string]string {
	if deps == nil {
		return nil
	}
	
	switch d := deps.(type) {
	case map[string]interface{}:
		result := make(map[string]string)
		for k, v := range d {
			if str, ok := v.(string); ok {
				result[k] = str
			}
		}
		return result
	case map[string]string:
		return d
	case string:
		// If it's a single string, return empty map
		return make(map[string]string)
	default:
		return nil
	}
}

// NormalizeFunding converts various funding formats to a consistent structure
func NormalizeFunding(funding interface{}) interface{} {
	if funding == nil {
		return nil
	}
	
	switch f := funding.(type) {
	case string:
		// If it's a string URL, convert to single funding object
		return []map[string]string{
			{"type": "custom", "url": f},
		}
	case []interface{}:
		// Already an array, return as is
		return f
	case map[string]interface{}:
		// Single funding object, wrap in array
		return []interface{}{f}
	default:
		return funding
	}
}

// searchPackagist searches for packages on Packagist.org
func searchPackagist(query string, page int) (*PackagistSearchResult, error) {
	// Build search URL
	searchUrl := fmt.Sprintf("https://packagist.org/search.json?q=%s&page=%d", url.QueryEscape(query), page)
	
	// Create HTTP request
	req, err := http.NewRequest("GET", searchUrl, nil)
	if err != nil {
		return nil, err
	}
	
	// Set User-Agent header
	req.Header.Set("User-Agent", "CodeClarity/1.0")
	
	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("search failed: HTTP %d", resp.StatusCode)
	}
	
	// Parse response
	var result PackagistSearchResult
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	
	return &result, nil
}