package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/sourcesync"
	"github.com/CodeClarityCE/service-knowledge/src/testhelper"
	"github.com/CodeClarityCE/service-knowledge/src/validation"
	knowledgedb "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// The build-from-empty test updates every source from a fake upstream into empty databases, then runs the gate.
// Each source registers itself from its own build_<source>_test.go file.

// fakeSource is one knowledge source in the build-from-empty test.
type fakeSource struct {
	// name is the knowledge source, as in knowledge_source_sync.
	name string
	// createTables creates the tables the source writes in the scratch knowledge schema.
	createTables func(t *testing.T, db *bun.DB)
	// serve starts the fake upstream and points the mirror at it. With empty it holds no records.
	serve func(t *testing.T, empty bool)
	// upstreamTotal is the total the full fake upstream offers.
	upstreamTotal int64
	// breaks are the source's own gate checks, each with a change that makes only it fail.
	breaks []gateBreak
	// withoutRows names the source's own checks that also fail when its table is empty.
	withoutRows []string
}

// gateBreak is a change to a built database that makes the named gate checks fail.
type gateBreak struct {
	name  string
	fails []string
	apply func(t *testing.T, b build)
}

var fakeSources = map[string]fakeSource{}

func registerFakeSource(source fakeSource) {
	if _, taken := fakeSources[source.name]; taken {
		panic("fake source registered twice: " + source.name)
	}
	fakeSources[source.name] = source
}

// builtSources lists the registered sources in a stable order.
func builtSources() []fakeSource {
	var sources []fakeSource
	for _, source := range fakeSources {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	return sources
}

func builtSourceNames() []string {
	var names []string
	for _, source := range builtSources() {
		names = append(names, source.name)
	}
	return names
}

// build is a scratch knowledge and config database, as an empty API-migrated install.
type build struct {
	knowledge *bun.DB
	config    *bun.DB
}

func newBuild(t *testing.T) build {
	t.Helper()
	knowledgeDB, configDB := testhelper.SetupBuildTestDBs(t)
	b := build{knowledge: knowledgeDB, config: configDB}
	b.recordMigrations(t, b.knowledge, validation.ExpectedKnowledgeMigrations)
	b.recordMigrations(t, b.config, validation.ExpectedConfigMigrations)
	for _, source := range builtSources() {
		source.createTables(t, b.knowledge)
	}
	return b
}

// recordMigrations marks migrations as applied, as the API does after running them.
func (b build) recordMigrations(t *testing.T, db *bun.DB, names []string) {
	t.Helper()
	for i, name := range names {
		b.exec(t, db, "INSERT INTO migrations (timestamp, name) VALUES (?, ?)", int64(i), name)
	}
}

func (b build) exec(t *testing.T, db *bun.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// update serves every source's full upstream and runs the knowledge update for them.
func (b build) update(t *testing.T) error {
	t.Helper()
	for _, source := range builtSources() {
		source.serve(t, false)
	}
	return updateSources(b.knowledge, b.config, builtSourceNames()...)
}

func (b build) mustUpdate(t *testing.T) {
	t.Helper()
	if err := b.update(t); err != nil {
		t.Fatalf("update: %v", err)
	}
}

func (b build) gate(t *testing.T) validation.GateReport {
	t.Helper()
	report, err := validation.RunGate(context.Background(), b.knowledge, b.config, time.Now(), builtSourceNames()...)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	return report
}

// contents fingerprints every table in both scratch schemas.
func (b build) contents(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for label, db := range map[string]*bun.DB{"knowledge": b.knowledge, "config": b.config} {
		var tables []string
		if err := db.NewRaw("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()").Scan(context.Background(), &tables); err != nil {
			t.Fatal(err)
		}
		for _, table := range tables {
			var digest string
			err := db.QueryRowContext(context.Background(),
				"SELECT coalesce(md5(string_agg(r::text, ',' ORDER BY r::text)), '') FROM ? r", bun.Ident(table)).Scan(&digest)
			if err != nil {
				t.Fatal(err)
			}
			out[label+"."+table] = digest
		}
	}
	return out
}

func failedChecks(report validation.GateReport) []string {
	var names []string
	for _, check := range report.Checks {
		if !check.Pass {
			names = append(names, check.Name)
		}
	}
	sort.Strings(names)
	return names
}

func TestBuildFromEmptyPassesTheGate(t *testing.T) {
	b := newBuild(t)

	b.mustUpdate(t)

	for _, source := range builtSources() {
		testhelper.AssertSucceededAfter(t, b.knowledge, source.name, time.Time{})
		if got := testhelper.UpstreamTotal(t, b.knowledge, source.name); got == nil || *got != source.upstreamTotal {
			t.Errorf("%s upstream_total = %v, want %d", source.name, got, source.upstreamTotal)
		}
	}
	before := b.contents(t)
	report := b.gate(t)
	if !report.Passed || len(failedChecks(report)) > 0 {
		t.Fatalf("gate failed: %v", failedChecks(report))
	}
	if after := b.contents(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Error("the gate changed the database")
	}
}

func TestGateReportIsJSONWithOneEntryPerCheck(t *testing.T) {
	b := newBuild(t)
	b.mustUpdate(t)

	var out bytes.Buffer
	if err := b.gate(t).WriteJSON(&out); err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		Passed bool                         `json:"passed"`
		Checks []map[string]json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, out.String())
	}
	if !decoded.Passed || len(decoded.Checks) == 0 {
		t.Fatalf("report = %s", out.String())
	}
	var names []string
	for _, check := range decoded.Checks {
		for _, field := range []string{"name", "expected", "actual", "pass"} {
			if _, ok := check[field]; !ok {
				t.Errorf("check %s has no %q", check["name"], field)
			}
		}
		var name string
		_ = json.Unmarshal(check["name"], &name)
		names = append(names, name)
	}
	for _, want := range []string{"config.rows", "migrations.knowledge", "migrations.config", "dated_restore"} {
		if !slices.Contains(names, want) {
			t.Errorf("no %s check in %v", want, names)
		}
	}
	for _, source := range builtSourceNames() {
		for _, check := range []string{".rows", ".last_outcome", ".watermark"} {
			if !slices.Contains(names, source+check) {
				t.Errorf("no %s check in %v", source+check, names)
			}
		}
	}
}

// genericBreaks makes each check every build has fail on its own.
func genericBreaks() []gateBreak {
	breaks := []gateBreak{
		{"second config row", []string{"config.rows"}, func(t *testing.T, b build) {
			b.exec(t, b.config, "INSERT INTO config (npm_last) VALUES (NULL)")
		}},
		{"no config row", []string{"config.rows"}, func(t *testing.T, b build) {
			b.exec(t, b.config, "DELETE FROM config")
		}},
		{"knowledge migration missing", []string{"migrations.knowledge"}, func(t *testing.T, b build) {
			b.exec(t, b.knowledge, "DELETE FROM migrations WHERE name = ?", validation.ExpectedKnowledgeMigrations[0])
		}},
		{"config migration missing", []string{"migrations.config"}, func(t *testing.T, b build) {
			b.exec(t, b.config, "DELETE FROM migrations WHERE name = ?", validation.ExpectedConfigMigrations[0])
		}},
		{"dated restore marker", []string{"dated_restore"}, func(t *testing.T, b build) {
			b.exec(t, b.knowledge, "INSERT INTO knowledge_dated_restore (label) VALUES ('2025-05-27')")
		}},
	}
	for _, source := range builtSources() {
		name := source.name
		breaks = append(breaks,
			gateBreak{name + " has no rows", append([]string{name + ".rows"}, source.withoutRows...), func(t *testing.T, b build) {
				// An empty upstream keeps the stored count within its total, so only the row check fails.
				b.exec(t, b.knowledge, "TRUNCATE ? CASCADE", bun.Ident(name))
				b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET upstream_total = 0 WHERE source = ?", name)
			}},
			gateBreak{name + " last run failed", []string{name + ".last_outcome"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET last_outcome = 'failure' WHERE source = ?", name)
			}},
			gateBreak{name + " stale watermark", []string{name + ".watermark"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET watermark = now() - interval '400 days' WHERE source = ?", name)
			}},
			gateBreak{name + " no watermark", []string{name + ".watermark"}, func(t *testing.T, b build) {
				b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET watermark = NULL WHERE source = ?", name)
			}},
		)
	}
	return breaks
}

// upstreamTotalBreaks makes a source's stored records stop matching its upstream total.
func upstreamTotalBreaks(source string) []gateBreak {
	check := source + ".upstream_total"
	return []gateBreak{
		{source + " upstream total far above stored", []string{check}, func(t *testing.T, b build) {
			b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET upstream_total = upstream_total * 2 + 100 WHERE source = ?", source)
		}},
		{source + " no upstream total", []string{check}, func(t *testing.T, b build) {
			b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET upstream_total = NULL WHERE source = ?", source)
		}},
	}
}

func TestEachGateCheckFailsOnItsOwn(t *testing.T) {
	breaks := genericBreaks()
	for _, source := range builtSources() {
		breaks = append(breaks, source.breaks...)
	}
	for _, broken := range breaks {
		t.Run(broken.name, func(t *testing.T) {
			b := newBuild(t)
			b.mustUpdate(t)
			broken.apply(t, b)
			before := b.contents(t)

			report := b.gate(t)

			want := slices.Clone(broken.fails)
			sort.Strings(want)
			if got := failedChecks(report); !slices.Equal(got, want) {
				t.Errorf("failed checks = %v, want %v", got, want)
			}
			if report.Passed {
				t.Error("report passed")
			}
			if after := b.contents(t); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Error("the gate changed the database")
			}
		})
	}
}

func TestGateThresholdsComeFromTheEnvironment(t *testing.T) {
	for _, source := range builtSources() {
		t.Run(source.name, func(t *testing.T) {
			b := newBuild(t)
			b.mustUpdate(t)
			b.exec(t, b.knowledge, `UPDATE knowledge_source_sync SET
				upstream_total = upstream_total * 2, watermark = now() - interval '30 days' WHERE source = ?`, source.name)
			if failed := failedChecks(b.gate(t)); len(failed) == 0 {
				t.Fatal("the changes should fail the default thresholds")
			}

			t.Setenv("KNOWLEDGE_GATE_UPSTREAM_TOLERANCE_PERCENT", "60")
			t.Setenv("KNOWLEDGE_STALE_AFTER_HOURS_"+upper(source.name), "1000")

			if failed := failedChecks(b.gate(t)); len(failed) > 0 {
				t.Errorf("failed checks = %v, want none with relaxed thresholds", failed)
			}
		})
	}
}

func TestSourceWithAnEmptyUpstreamFails(t *testing.T) {
	for _, source := range builtSources() {
		t.Run(source.name, func(t *testing.T) {
			b := newBuild(t)
			source.serve(t, true)

			err := updateSources(b.knowledge, b.config, source.name)

			if !errors.Is(err, sourcesync.ErrNoUpstreamRecords) {
				t.Errorf("update = %v, want ErrNoUpstreamRecords", err)
			}
			testhelper.AssertFailed(t, b.knowledge, source.name)
			if got := testhelper.UpstreamTotal(t, b.knowledge, source.name); got != nil {
				t.Errorf("upstream_total = %d, want none", *got)
			}
		})
	}
}

func upper(source string) string {
	return string(bytes.ToUpper([]byte(source)))
}

// Every registered source is a real knowledge source.
func TestBuiltSourcesAreKnowledgeSources(t *testing.T) {
	for _, name := range builtSourceNames() {
		if !slices.Contains(knowledgedb.AllSources, name) {
			t.Errorf("%s is not a knowledge source", name)
		}
	}
}

func TestNVDConfigurationsToleranceComesFromTheEnvironment(t *testing.T) {
	b := newBuild(t)
	b.mustUpdate(t)
	// One of the two Analyzed or Modified CVEs, as NVD serves some old Modified CVEs
	b.exec(t, b.knowledge, "UPDATE nvd SET configurations = NULL WHERE nvd_id = 'CVE-2024-0002'")
	if failed := failedChecks(b.gate(t)); !slices.Equal(failed, []string{"nvd.configurations"}) {
		t.Fatalf("failed checks = %v, want nvd.configurations at the default tolerance", failed)
	}

	t.Setenv("KNOWLEDGE_GATE_NVD_MISSING_CONFIGURATIONS_PERCENT", "50")

	if failed := failedChecks(b.gate(t)); len(failed) > 0 {
		t.Errorf("failed checks = %v, want none at 50%%", failed)
	}
}

// waivedChecks lists the checks the report marks as waived.
func waivedChecks(report validation.GateReport) []string {
	var names []string
	for _, check := range report.Checks {
		if check.Waived {
			names = append(names, check.Name)
		}
	}
	sort.Strings(names)
	return names
}

func TestWaivedSourceChecksDoNotFailTheGateAndAreRecorded(t *testing.T) {
	source := builtSourceNames()[0]
	other := builtSourceNames()[1]
	b := newBuild(t)
	b.mustUpdate(t)
	b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET last_outcome = 'failure', watermark = NULL WHERE source = ?", source)
	t.Setenv("KNOWLEDGE_GATE_WAIVE", source+".*")
	t.Setenv("KNOWLEDGE_GATE_WAIVE_REASON", "upstream feed is empty")

	report := b.gate(t)

	want := []string{source + ".last_outcome", source + ".watermark"}
	if !report.Passed {
		t.Errorf("report failed on %v", failedChecks(report))
	}
	if got := waivedChecks(report); !slices.Equal(got, want) {
		t.Errorf("waived checks = %v, want %v", got, want)
	}
	if report.Waiver == nil || report.Waiver.Reason != "upstream feed is empty" || !slices.Equal(report.Waiver.Checks, want) {
		t.Errorf("waiver = %+v, want the reason and %v", report.Waiver, want)
	}
	if got := failedChecks(report); !slices.Equal(got, want) {
		t.Errorf("failed checks = %v, want the waived ones still reported as failing", got)
	}

	b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET last_outcome = 'failure' WHERE source = ?", other)
	if report := b.gate(t); report.Passed {
		t.Errorf("a failure outside the waiver passed the gate")
	}
}

func TestWaiverNamingAnExactCheckWaivesOnlyIt(t *testing.T) {
	source := builtSourceNames()[0]
	b := newBuild(t)
	b.mustUpdate(t)
	b.exec(t, b.knowledge, "UPDATE knowledge_source_sync SET last_outcome = 'failure', watermark = NULL WHERE source = ?", source)
	t.Setenv("KNOWLEDGE_GATE_WAIVE", source+".watermark")
	t.Setenv("KNOWLEDGE_GATE_WAIVE_REASON", "testing")

	report := b.gate(t)

	if report.Passed {
		t.Error("the unwaived last_outcome failure passed the gate")
	}
	if got := waivedChecks(report); !slices.Equal(got, []string{source + ".watermark"}) {
		t.Errorf("waived checks = %v", got)
	}
}

func TestPassingGateRecordsNoWaiver(t *testing.T) {
	b := newBuild(t)
	b.mustUpdate(t)
	t.Setenv("KNOWLEDGE_GATE_WAIVE", builtSourceNames()[0]+".*")
	t.Setenv("KNOWLEDGE_GATE_WAIVE_REASON", "testing")

	report := b.gate(t)

	if !report.Passed || report.Waiver != nil || len(waivedChecks(report)) > 0 {
		t.Errorf("report = passed %v, waiver %+v, want a pass with nothing waived", report.Passed, report.Waiver)
	}
}

func TestGateRefusesAnInvalidWaiver(t *testing.T) {
	cases := []struct{ name, waive, reason string }{
		{"no reason", "nvd.*", ""},
		{"structural check", "config.rows", "testing"},
		{"migrations", "migrations.knowledge", "testing"},
		{"dated restore", "dated_restore", "testing"},
		{"unknown source", "nope.*", "testing"},
		{"everything", "*", "testing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBuild(t)
			t.Setenv("KNOWLEDGE_GATE_WAIVE", c.waive)
			t.Setenv("KNOWLEDGE_GATE_WAIVE_REASON", c.reason)

			_, err := validation.RunGate(context.Background(), b.knowledge, b.config, time.Now(), builtSourceNames()...)

			if err == nil {
				t.Errorf("waiver %q with reason %q was accepted", c.waive, c.reason)
			}
		})
	}
}
