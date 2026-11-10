package epss

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/utilities/pgsql"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// baseURL hosts the current and dated EPSS score files.
var baseURL = "https://epss.empiricalsecurity.com/"

// downloadEPSS returns every score in the file. Any defect fails the whole download.
func downloadEPSS(url string) ([]knowledge.EPSS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch EPSS scores: " + resp.Status)
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	return parseEPSS(bufio.NewScanner(gzipReader))
}

// parseEPSS reads the comment line holding the score date, the header row, then the scores.
func parseEPSS(scanner *bufio.Scanner) ([]knowledge.EPSS, error) {
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var scoreDate time.Time
	var scores []knowledge.EPSS
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			date, err := parseScoreDate(line)
			if err != nil {
				return nil, err
			}
			scoreDate = date
		case strings.HasPrefix(line, "cve,"):
			continue
		default:
			fields := strings.Split(line, ",")
			if len(fields) < 3 {
				return nil, fmt.Errorf("EPSS line %d: expected 3 fields, got %q", lineNumber, line)
			}
			score, err := strconv.ParseFloat(fields[1], 32)
			if err != nil {
				return nil, fmt.Errorf("EPSS line %d: bad score: %w", lineNumber, err)
			}
			percentile, err := strconv.ParseFloat(fields[2], 32)
			if err != nil {
				return nil, fmt.Errorf("EPSS line %d: bad percentile: %w", lineNumber, err)
			}
			scores = append(scores, knowledge.EPSS{CVE: fields[0], Score: float32(score), Percentile: float32(percentile)})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read EPSS file: %w", err)
	}

	if scoreDate.IsZero() {
		return nil, errors.New("EPSS file has no score date")
	}
	if len(scores) == 0 {
		return nil, fmt.Errorf("EPSS file has no scores: %w", sourcesync.ErrNoUpstreamRecords)
	}
	for i := range scores {
		scores[i].ScoreDate = scoreDate
	}
	return scores, nil
}

// parseScoreDate extracts the date from a line such as #model_version:v1,score_date:2026-11-08T12:55:00.000+0000.
func parseScoreDate(line string) (time.Time, error) {
	_, after, found := strings.Cut(line, "score_date:")
	if !found {
		return time.Time{}, nil
	}
	raw, _, _ := strings.Cut(after, ",")
	normalized, ok := pgsql.NormalizeTimestamp(strings.TrimSpace(raw))
	if !ok || normalized == "" {
		return time.Time{}, fmt.Errorf("EPSS file has a bad score date: %q", raw)
	}
	parsed, err := time.Parse(time.RFC3339Nano, normalized)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Truncate(24 * time.Hour), nil
}
