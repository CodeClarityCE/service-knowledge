package epss

import (
	"compress/gzip"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// downloadEPSS downloads the list of EPSS scores from the given URL and parses it as an array of knowledge.EPSS.
func downloadEPSS(url string) ([]knowledge.EPSS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch EPSS scores")
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	decompressedContent := new(strings.Builder)
	_, err = io.Copy(decompressedContent, gzipReader)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(decompressedContent.String(), "\n")
	if len(lines) < 2 {
		return nil, errors.New("CSV file does not contain enough rows")
	}

	csvReader := csv.NewReader(strings.NewReader(strings.Join(lines[1:], "\n"))) // Skip the first line
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	var epssScores []knowledge.EPSS
	for _, record := range records { // Skip header row
		if len(record) < 3 {
			continue
		}
		score, err := strconv.ParseFloat(record[1], 32)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(record[2], 32)
		if err != nil {
			continue
		}
		epssScores = append(epssScores, knowledge.EPSS{
			CVE:        record[0],
			Score:      float32(score),
			Percentile: float32(percentile),
		})
	}

	return epssScores, nil
}
