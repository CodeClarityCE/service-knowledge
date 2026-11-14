package validation

// The API knowledge and config migrations a build must have applied, oldest first; keep equal to api/src/migrations.
// KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE and _CONFIG (comma-separated) replace them.
var (
	ExpectedKnowledgeMigrations = []string{
		"CreateKnowledgeBaseline1754600000000",
		"Init1754648228805",
		"AddLanguageAgnosticPackageVersionTables1754758000000",
		"CleanupIncorrectTables1754760000000",
		"DropJsVersionTable1754762000000",
		"CreateFriendsOfPhpTable1755451900000",
		"AddPHPVulnerabilityIndexes1755452000000",
		"AddVulnerabilitySearchIndexes1756296558000",
		"AddVlaiColumns1757000000000",
		"AddEpssTable1757100000000",
		"CreatePackageVulnerabilityWithFKs1767100000000",
		"CreateGcveTable1770000000000",
		"AddGcveToPackageVulnerability1770100000000",
		"CreateKnowledgeSourceSync1794182400000",
		"ExtendKnowledgeSoundTypes1794268800000",
		"AddKnowledgeValidation1794355200000",
		"AddKnowledgeSourceOrigins1794441600000",
		"AddKnowledgeSourceUpstreamTotal1794528000000",
		"AllowMissingFriendsOfPhpDates1794614400000",
	}
	ExpectedConfigMigrations = []string{
		"CreateConfigBaseline1754600000000",
		"AddGcveLastToConfig1770200000000",
		"AddOsvLastToConfig1785829532189",
	}
)
