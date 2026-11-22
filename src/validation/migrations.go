package validation

// The API knowledge and config migrations a build must have applied, oldest first; keep equal to api/src/migrations.
// KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE and _CONFIG (comma-separated) replace them.
var (
	ExpectedKnowledgeMigrations = []string{
		"CreateKnowledgeBetaBaseline1796200000000",
	}
	ExpectedConfigMigrations = []string{
		"CreateConfigBetaBaseline1796200000000",
	}
)
