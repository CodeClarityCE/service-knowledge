package gcve

import (
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// staleDumpWarnings returns the warnings that report a stale bulk dump.
func staleDumpWarnings(hook *logtest.Hook) []logrus.Entry {
	var out []logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Data["dump_age_days"] != nil {
			out = append(out, *entry)
		}
	}
	return out
}

func TestFullImportFromATenDayOldDumpWarnsAndSucceeds(t *testing.T) {
	db := setup(t, false)
	dumpTime := time.Now().Add(-10 * 24 * time.Hour)
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", dumpTime.Add(-time.Hour)),
		dumpTime: dumpTime,
		records:  map[string]time.Time{"CVE-2026-2": dumpTime.Add(time.Hour)},
	}
	upstream.serve(t)
	hook := logtest.NewGlobal()
	defer hook.Reset()

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	warnings := staleDumpWarnings(hook)
	if len(warnings) != 1 {
		t.Fatalf("stale dump warnings = %d, want exactly 1", len(warnings))
	}
	if got := warnings[0].Data["source"]; got != knowledge.SourceGCVE {
		t.Errorf("source = %v, want %v", got, knowledge.SourceGCVE)
	}
	if got := warnings[0].Data["dump_age_days"]; got != 10 {
		t.Errorf("dump_age_days = %v (%T), want 10", got, got)
	}
	if got := gcveRows(t, db); got != 2 {
		t.Errorf("rows = %d, want the dump record and the caught-up one", got)
	}
	testhelper.AssertSucceededAfter(t, db, knowledge.SourceGCVE, dumpTime)
}

func TestFullImportFromAFreshDumpDoesNotWarn(t *testing.T) {
	db := setup(t, false)
	dumpTime := time.Now().Add(-6 * 24 * time.Hour)
	upstream := &fakeUpstream{
		dump:     dated("CVE-2026-1", dumpTime.Add(-time.Hour)),
		dumpTime: dumpTime,
		records:  map[string]time.Time{},
	}
	upstream.serve(t)
	hook := logtest.NewGlobal()
	defer hook.Reset()

	if err := Update(db, db); err != nil {
		t.Fatal(err)
	}

	if warnings := staleDumpWarnings(hook); len(warnings) != 0 {
		t.Errorf("stale dump warnings = %d, want none for a 6 day old dump", len(warnings))
	}
}
