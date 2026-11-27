package js

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// refusingConnector stands in for a database the caller may not write to.
type refusingConnector struct{}

func (refusingConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("permission denied for table package")
}
func (refusingConnector) Driver() driver.Driver { return nil }

func TestAnImportThatCannotWriteReturnsAnError(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"left-pad","dist-tags":{"latest":"1.3.0"},"versions":{"1.3.0":{"name":"left-pad","version":"1.3.0","license":"MIT"}},"time":{"1.3.0":"2018-04-09T01:26:43.000Z"}}`))
	}))
	defer registry.Close()
	t.Setenv("NPM_URL", registry.URL+"/")
	db := bun.NewDB(sql.OpenDB(refusingConnector{}), pgdialect.New())
	defer func() { _ = db.Close() }()

	err := ImportListWithBatching(db, []string{"left-pad"})

	if err == nil {
		t.Fatal("expected an error when no package could be stored")
	}
	for _, want := range []string{"1 of 1", "left-pad", "permission denied for table package"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestAnEmptyImportSucceeds(t *testing.T) {
	if err := ImportListWithBatching(nil, nil); err != nil {
		t.Fatal(err)
	}
}
