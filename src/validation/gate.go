package validation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Check is one entry of the completeness gate report.
type Check struct {
	Name     string `json:"name"`
	Expected any    `json:"expected"`
	Actual   any    `json:"actual"`
	Pass     bool   `json:"pass"`
	// Detail explains a failure, or the error that stopped the check.
	Detail string `json:"detail,omitempty"`
}

// GateReport is the completeness gate's result: every check, passing or not.
type GateReport struct {
	Passed bool    `json:"passed"`
	Checks []Check `json:"checks"`
}

// WriteJSON writes the report as indented JSON.
func (r GateReport) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// Gate is what a check reads. Every check runs in its own read-only transaction.
type Gate struct {
	Knowledge bun.IDB
	Config    bun.IDB
	Now       time.Time
}

// SourceCheck is one check a source adds to the gate, beyond the checks every source gets.
type SourceCheck func(ctx context.Context, gate Gate) Check

var sourceChecks = map[string][]SourceCheck{}

// registerSourceChecks adds a source's own checks. Each source registers from its own gate_<source>.go.
func registerSourceChecks(source string, checks ...SourceCheck) {
	sourceChecks[source] = append(sourceChecks[source], checks...)
}

// RunGate runs every completeness check without writing anything. Sources limits the
// per-source checks to those sources; with none it covers every knowledge source.
// A check that cannot run fails with its error as detail, so the error is only for
// a gate that could not start.
func RunGate(ctx context.Context, knowledgeDB, configDB *bun.DB, now time.Time, sources ...string) (GateReport, error) {
	if len(sources) == 0 {
		sources = knowledge.AllSources
	}
	var checks []Check
	run := func(check func(Gate) Check) error {
		return readOnly(ctx, knowledgeDB, func(knowledgeTx bun.Tx) error {
			return readOnly(ctx, configDB, func(configTx bun.Tx) error {
				checks = append(checks, check(Gate{Knowledge: knowledgeTx, Config: configTx, Now: now}))
				return nil
			})
		})
	}

	all := []func(Gate) Check{
		func(g Gate) Check { return configRowsCheck(ctx, g) },
		func(g Gate) Check {
			return migrationsCheck(ctx, "migrations.knowledge", g.Knowledge,
				envList("KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE", ExpectedKnowledgeMigrations))
		},
		func(g Gate) Check {
			return migrationsCheck(ctx, "migrations.config", g.Config,
				envList("KNOWLEDGE_EXPECTED_MIGRATIONS_CONFIG", ExpectedConfigMigrations))
		},
		func(g Gate) Check { return datedRestoreCheck(ctx, g) },
	}
	for _, source := range sources {
		all = append(all,
			func(g Gate) Check { return rowsCheck(ctx, g, source) },
			func(g Gate) Check { return lastOutcomeCheck(ctx, g, source) },
			func(g Gate) Check { return watermarkCheck(ctx, g, source) },
		)
		for _, check := range sourceChecks[source] {
			all = append(all, func(g Gate) Check { return check(ctx, g) })
		}
	}
	for _, check := range all {
		if err := run(check); err != nil {
			return GateReport{}, err
		}
	}

	report := GateReport{Passed: true, Checks: checks}
	for _, check := range checks {
		report.Passed = report.Passed && check.Pass
	}
	return report, nil
}

// readOnly runs fn in a read-only transaction and always rolls it back.
func readOnly(ctx context.Context, db *bun.DB, fn func(bun.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read-only transaction: %w", err)
	}
	defer tx.Rollback()
	return fn(tx)
}

// failed is a check that could not run.
func failed(name string, expected any, err error) Check {
	return Check{Name: name, Expected: expected, Pass: false, Detail: err.Error()}
}

func configRowsCheck(ctx context.Context, g Gate) Check {
	const name = "config.rows"
	var rows int64
	if err := g.Config.QueryRowContext(ctx, "SELECT count(*) FROM config").Scan(&rows); err != nil {
		return failed(name, 1, err)
	}
	check := Check{Name: name, Expected: 1, Actual: rows, Pass: rows == 1}
	if !check.Pass {
		check.Detail = "config must hold exactly one row of source watermarks"
	}
	return check
}

// migrationsCheck passes when every expected migration is recorded as applied.
func migrationsCheck(ctx context.Context, name string, db bun.IDB, expected []string) Check {
	var applied []string
	if err := db.NewRaw("SELECT name FROM migrations").Scan(ctx, &applied); err != nil {
		return failed(name, len(expected), err)
	}
	var missing []string
	for _, migration := range expected {
		if !slices.Contains(applied, migration) {
			missing = append(missing, migration)
		}
	}
	check := Check{Name: name, Expected: len(expected), Actual: len(expected) - len(missing), Pass: len(missing) == 0}
	if !check.Pass {
		check.Detail = "missing: " + strings.Join(missing, ", ")
	}
	return check
}

// datedRestoreCheck passes when the database carries no dated-restore marker.
func datedRestoreCheck(ctx context.Context, g Gate) Check {
	const name = "dated_restore"
	var exists bool
	if err := g.Knowledge.QueryRowContext(ctx, "SELECT to_regclass('knowledge_dated_restore') IS NOT NULL").Scan(&exists); err != nil {
		return failed(name, nil, err)
	}
	if !exists {
		return Check{Name: name, Expected: nil, Actual: nil, Pass: true}
	}
	var label string
	err := g.Knowledge.QueryRowContext(ctx, "SELECT label FROM knowledge_dated_restore").Scan(&label)
	if errors.Is(err, sql.ErrNoRows) {
		return Check{Name: name, Expected: nil, Actual: nil, Pass: true}
	}
	if err != nil {
		return failed(name, nil, err)
	}
	return Check{Name: name, Expected: nil, Actual: label, Pass: false, Detail: "a dated restore is not a current knowledge database"}
}

// rowsCheck passes when the source holds active rows.
func rowsCheck(ctx context.Context, g Gate, source string) Check {
	name := source + ".rows"
	current, err := countSource(ctx, g.Knowledge, source)
	if err != nil {
		return failed(name, "> 0", err)
	}
	return Check{Name: name, Expected: "> 0", Actual: current.rows, Pass: current.rows > 0}
}

// syncRow reads one source's outcome and watermark; a missing row reads as empty.
func syncRow(ctx context.Context, db bun.IDB, source string) (knowledge.SourceSync, error) {
	var row knowledge.SourceSync
	err := db.QueryRowContext(ctx,
		"SELECT last_outcome, watermark FROM knowledge_source_sync WHERE source = ?", source).
		Scan(&row.LastOutcome, &row.Watermark)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	return row, nil
}

// upstreamTotal reads one source's recorded upstream total, nil when none is recorded.
func upstreamTotal(ctx context.Context, db bun.IDB, source string) (*int64, error) {
	var total sql.NullInt64
	err := db.QueryRowContext(ctx,
		"SELECT upstream_total FROM knowledge_source_sync WHERE source = ?", source).Scan(&total)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if !total.Valid {
		return nil, nil
	}
	return &total.Int64, nil
}

func lastOutcomeCheck(ctx context.Context, g Gate, source string) Check {
	name := source + ".last_outcome"
	row, err := syncRow(ctx, g.Knowledge, source)
	if err != nil {
		return failed(name, knowledge.SourceSyncSuccess, err)
	}
	check := Check{Name: name, Expected: knowledge.SourceSyncSuccess, Pass: false}
	if row.LastOutcome != nil {
		check.Actual = *row.LastOutcome
		check.Pass = *row.LastOutcome == knowledge.SourceSyncSuccess
	}
	return check
}

// watermarkCheck passes when the watermark is set and within KNOWLEDGE_STALE_AFTER_HOURS_<SOURCE>.
func watermarkCheck(ctx context.Context, g Gate, source string) Check {
	name := source + ".watermark"
	limit := time.Duration(knowledge.StaleAfterHours(source) * float64(time.Hour))
	expected := fmt.Sprintf("within %s of %s", limit, g.Now.UTC().Format(time.RFC3339))
	row, err := syncRow(ctx, g.Knowledge, source)
	if err != nil {
		return failed(name, expected, err)
	}
	if row.Watermark == nil {
		return Check{Name: name, Expected: expected, Actual: nil, Pass: false, Detail: "source has no watermark"}
	}
	return Check{
		Name:     name,
		Expected: expected,
		Actual:   row.Watermark.UTC().Format(time.RFC3339),
		Pass:     g.Now.Sub(*row.Watermark) <= limit,
	}
}

// upstreamTotalCheck passes when the source's stored records, active and retired,
// are within the tolerance of the upstream total its last successful update recorded.
func upstreamTotalCheck(source string) SourceCheck {
	return func(ctx context.Context, g Gate) Check {
		name := source + ".upstream_total"
		tolerance := upstreamTolerancePercent(source)
		total, err := upstreamTotal(ctx, g.Knowledge, source)
		if err != nil {
			return failed(name, nil, err)
		}
		stored, err := countWhere(ctx, g.Knowledge, source, "TRUE")
		if err != nil {
			return failed(name, total, err)
		}
		if total == nil {
			return Check{Name: name, Expected: nil, Actual: stored, Pass: false, Detail: "no upstream total recorded"}
		}
		check := Check{
			Name:     name,
			Expected: *total,
			Actual:   stored,
			Pass:     math.Abs(float64(stored-*total)) <= float64(*total)*tolerance/100,
		}
		if !check.Pass {
			check.Detail = fmt.Sprintf("stored records are more than %g%% from the upstream total", tolerance)
		}
		return check
	}
}
