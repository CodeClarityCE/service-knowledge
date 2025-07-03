package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	config "github.com/CodeClarityCE/utility-types/config_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/schollz/progressbar/v3"
	"github.com/uptrace/bun"
)

type NVDStats struct {
	TotalResults int `json:"totalResults"`
}

type Config struct {
	Key  string `json:"_key"`
	Last string `json:"last"`
}

// getLastNVDChangeNumber retrieves the last change number from the NVD configuration document in the specified collection.
// It reads the "nvd_config" document and returns the value of the "Last" field.
// If an error occurs during the retrieval process, it logs the error and returns an empty string along with the error.
func getLastNVDChangeNumber(db_config *bun.DB) (config.Config, error) {
	ctx := context.Background()
	var configs []config.Config
	err := db_config.NewSelect().Model(&configs).Limit(1).Scan(ctx)
	if err != nil {
		panic(err)
	}

	return configs[0], nil
}

// setLastNVDChangeNumber updates the last change number for the NVD configuration in the specified collection.
// It takes a driver.Collection and a string representing the last change number as parameters.
// It returns an error if the update operation fails.
func setLastNVDChangeNumber(db_config *bun.DB, conf config.Config) error {
	_, err := db_config.NewUpdate().Model(&conf).Where("id = ?", conf.Id).Exec(context.Background())

	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// Update is a function that updates the NVD (National Vulnerability Database) by fetching the latest CVE (Common Vulnerabilities and Exposures) data.
// It takes a driver.Collection and a driver.Graph as parameters.
// The function retrieves the last modified date from the configuration, and if available, checks if it is older than 120 days compared to the current date.
// If the last modified date is older than 120 days, the function updates the start date to 120 days before the last modified date and sets the restart flag to true.
// The function then constructs the URL for fetching the CVE data from the NVD API based on the results per page, last modified start date, and current date.
// It makes an HTTP GET request to the constructed URL, including the NVD API key if available.
// The function reads the response body and unmarshals it into a struct representing the NVD statistics.
// It calculates the number of pages required to fetch all the CVE data based on the total number of results and the number of results per page.
// The function uses a progress bar to track the progress of downloading and processing the CVE data.
// It spawns multiple goroutines to download and process the CVE data concurrently, with a maximum number of goroutines based on the availability of the NVD API key.
// After downloading and processing each page of CVE data, the function waits for 35 seconds before proceeding to the next page.
// Finally, the function updates the last modified date in the configuration and, if the restart flag is set, recursively calls itself to continue updating the NVD data.
// If any error occurs during the update process, the function logs the error and returns it.
func Update(db *bun.DB, db_config *bun.DB) error {
	log.Println("Start updating NVD")

	// Get last date from config
	conf, err := getLastNVDChangeNumber(db_config)
	lastModStartDate := conf.NvdLast
	if err != nil {
		log.Println("Can't get last date from config", err)
		return err
	}

	log.Println("Last date: ", lastModStartDate)

	// Get current date
	now := time.Now()
	now_string := now.Format("2006-01-02T15:04:05.000Z")

	restart := false

	since := lastModStartDate.Format("2006-01-02T15:04:05.000Z")
	// Check if current date isn't older than 120 days compared to lastModStartDate
	diff := time.Since(lastModStartDate)
	if diff.Hours() > 24*120 {
		log.Println("lastModStartDate is older than 120 days compared to current date")
		now = lastModStartDate.AddDate(0, 0, 120)
		now_string = now.Format("2006-01-02T15:04:05.000Z")
		restart = true
	}

	apiKey, ok := os.LookupEnv("NVD_API_KEY")
	if !ok || apiKey == "" {
		log.Println("NVD_API_KEY environment variable not set")
		apiKey = ""
	}

	element_page := 2000
	maxRequests := 50
	if apiKey == "" {
		maxRequests = 5
	}

	urlTemplate := "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s"

	var result NVDStats
	err = fetchNVDStats(urlTemplate, element_page, since, now_string, apiKey, &result)
	if err != nil {
		log.Println("Failed to fetch NVD stats", err)
		return err
	}

	log.Printf("Total CVEs: %d", result.TotalResults)

	n_page := int(result.TotalResults / element_page)
	if result.TotalResults%element_page != 0 {
		n_page++
	}

	bar := progressbar.Default(int64(n_page))

	var wg sync.WaitGroup
	rateLimiter := make(chan struct{}, maxRequests)

	// Enhance rate limiter logic to dynamically adjust sleep duration based on server response
	var rateLimiterSleep time.Duration = 60 * time.Second / time.Duration(maxRequests)

	// Fill rate limiter tokens
	if apiKey == "" {
		go func() {
			for {
				rateLimiter <- struct{}{}
				time.Sleep(rateLimiterSleep) // Use dynamic sleep duration
			}
		}()
	} else {
		go func() {
			for {
				rateLimiter <- struct{}{}
				time.Sleep(30 * time.Second / time.Duration(maxRequests))
			}
		}()
	}

	for i := 0; i < n_page; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, i int) {
			defer wg.Done()
			defer bar.Add(1)

			vulns, err := downloadBatch(i, element_page, urlTemplate, since, now_string, apiKey, rateLimiter)
			if err != nil {
				log.Println(err)
			}

			pgsql.UpdateNvd(db, vulns)
		}(&wg, i)
	}

	wg.Wait()

	conf.NvdLast = now
	err = setLastNVDChangeNumber(db_config, conf)
	if err != nil {
		log.Println("Can't set last date in config", err)
		return err
	}

	if restart {
		err = Update(db, db_config)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func fetchNVDStats(urlTemplate string, element_page int, since, now_string, apiKey string, result *NVDStats) error {
	url := fmt.Sprintf(urlTemplate, element_page, 0, since, now_string)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	if apiKey != "" {
		req.Header.Add("apiKey", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(body, result)
	if err != nil {
		return fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return nil
}

func downloadBatch(i, element_page int, urlTemplate, since, now_string, apiKey string, rateLimiter chan struct{}) ([]knowledge.NVDItem, error) {
	index := i * element_page
	url := fmt.Sprintf(urlTemplate, element_page, index, since, now_string)

	var resp *http.Response
	var err error
	var retries int
	maxRetries := 5

	for retries = 0; retries < maxRetries; retries++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
		}

		if apiKey != "" {
			req.Header.Add("apiKey", apiKey)
		}

		<-rateLimiter // Wait for rate limiter token
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("error executing request: %v, retrying... (%d/%d)", err, retries+1, maxRetries)
			time.Sleep(time.Duration(2<<retries) * time.Second) // Exponential backoff
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			log.Printf("rate limit exceeded, retrying... (%d/%d)", retries+1, maxRetries)
			time.Sleep(time.Duration(2<<retries) * time.Second) // Exponential backoff
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
		}

		break
	}

	if retries == maxRetries {
		return nil, fmt.Errorf("max retries reached, unable to fetch data")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var result knowledge.NVD
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	return knowledge.GetVulns(result), nil
}
