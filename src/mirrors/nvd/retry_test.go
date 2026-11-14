package nvd

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// fastRetries shortens the retry backoff for the test.
func fastRetries(t *testing.T) {
	t.Helper()
	original := retryBackoff
	retryBackoff = time.Millisecond
	t.Cleanup(func() { retryBackoff = original })
}

// serveTwoFullPages answers a full fetch of 2001 CVEs over two pages.
// fail picks the response for the second page, by its attempt number from 1; 0 means answer it.
func serveTwoFullPages(t *testing.T, fail func(attempt int) int) (secondPageAttempts func() int) {
	t.Helper()
	first := make([]string, 2000)
	for i := range first {
		first[i] = record(fmt.Sprintf("CVE-%d", i), "Analyzed")
	}
	firstPage := fmt.Sprintf(`{"totalResults":2001,"vulnerabilities":[%s]}`, strings.Join(first, ","))
	secondPage := fmt.Sprintf(`{"totalResults":2001,"vulnerabilities":[%s]}`, record("CVE-2000", "Analyzed"))

	var mu sync.Mutex
	attempts := 0
	serveRequests(t, func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		if start == 0 {
			fmt.Fprint(w, firstPage)
			return
		}
		mu.Lock()
		attempts++
		status := fail(attempts)
		mu.Unlock()
		if status != 0 {
			http.Error(w, "error code: "+strconv.Itoa(status), status)
			return
		}
		fmt.Fprint(w, secondPage)
	})
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return attempts
	}
}

// A Cloudflare timeout on one page is retried instead of failing the whole full fetch.
func TestFullFetchRetriesAPageThatFailsTwice(t *testing.T) {
	db := setupNoWatermark(t)
	attempts := serveTwoFullPages(t, func(attempt int) int {
		if attempt <= 2 {
			return 524
		}
		return 0
	})

	before := time.Now().Add(-time.Second)
	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if got := attempts(); got != 3 {
		t.Errorf("second page requested %d times, want 3", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceNVD, before)
}

// A page that keeps failing is retried a bounded number of times, then fails the source.
func TestFullFetchFailsWhenAPageKeepsFailing(t *testing.T) {
	db := setupNoWatermark(t)
	attempts := serveTwoFullPages(t, func(int) int { return 524 })

	if err := Update(db, db); err == nil {
		t.Fatal("a page that always fails should fail the source")
	}

	if got := attempts(); got != maxAttempts {
		t.Errorf("second page requested %d times, want %d", got, maxAttempts)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceNVD)
}

// A status that retrying cannot fix fails the source on the first answer.
func TestFullFetchDoesNotRetryAClientError(t *testing.T) {
	db := setupNoWatermark(t)
	attempts := serveTwoFullPages(t, func(int) int { return http.StatusNotFound })

	if err := Update(db, db); err == nil {
		t.Fatal("a 404 page should fail the source")
	}

	if got := attempts(); got != 1 {
		t.Errorf("second page requested %d times, want 1", got)
	}
	testhelper.AssertFailed(t, db, knowledge.SourceNVD)
}
