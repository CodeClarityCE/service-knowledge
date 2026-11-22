package js

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
)

// Shared HTTP client with connection pooling and timeout
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

type NpmChanges struct {
	Last_seq string      `json:"last_seq"`
	Results  []NpmResult `json:"results"`
}

type NpmResult struct {
	Changes []struct {
		Rev string `json:"rev"`
	} `json:"changes"`
	ID      string `json:"id"`
	Seq     string `json:"seq"`
	Deleted bool   `json:"deleted"`
}

func download(pack string) (types.Npm, error) {
	return downloadWithRetry(pack, 0)
}

func downloadWithRetry(pack string, retryCount int) (types.Npm, error) {
	npmURL := os.Getenv("NPM_URL")
	if npmURL == "" {
		npmURL = "http://localhost:5984/npm/"
	}
	couchLogin := os.Getenv("COUCH_LOGIN")
	couchPassword := os.Getenv("COUCH_PASSWORD")

	if !strings.Contains(npmURL, "registry.npmjs.org") {
		pack = url.QueryEscape(pack)
	}
	url := fmt.Sprintf("%s%s", npmURL, pack)

	// NPM_URL fixes the host; the package name only extends the path.
	req, err := http.NewRequest("GET", url, nil) //nolint:gosec // G704: host comes from operator config
	if err != nil {
		return types.Npm{}, err
	}

	if couchLogin != "" && couchPassword != "" {
		auth := couchLogin + ":" + couchPassword
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", "Basic "+encodedAuth)
	}

	resp, err := httpClient.Do(req) //nolint:gosec // G704: host comes from operator config
	if err != nil {
		return types.Npm{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		switch resp.StatusCode {
		case 404:
			return types.Npm{}, fmt.Errorf("package not found: %s (%s)", pack, resp.Status)
		case 429:
			if retryCount >= 3 {
				return types.Npm{}, fmt.Errorf("rate limited after %d retries: %s", retryCount, pack)
			}
			backoff := time.Duration(30*(retryCount+1)) * time.Second
			log.Printf("Rate limited for %s, retrying in %v (attempt %d/3)", pack, backoff, retryCount+1)
			time.Sleep(backoff)
			return downloadWithRetry(pack, retryCount+1)
		default:
			return types.Npm{}, fmt.Errorf("can't fetch package: %s (%s)", pack, resp.Status)
		}
	}

	var result types.Npm
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.Npm{}, fmt.Errorf("can't read response body for %s: %w", pack, err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return types.Npm{}, fmt.Errorf("can't unmarshal response body for %s: %w", pack, err)
	}

	return result, nil
}
