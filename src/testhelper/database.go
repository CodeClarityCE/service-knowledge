package testhelper

import (
	"os"
	"testing"

	"github.com/CodeClarityCE/utility-boilerplates"
	"github.com/uptrace/bun"
)

// SetupKnowledgeTestDB sets up a knowledge database connection for testing
func SetupKnowledgeTestDB(t *testing.T) (*bun.DB, func()) {
	service, cleanup := setupService(t)
	if service == nil {
		return nil, func() {}
	}
	return service.DB.Knowledge, cleanup
}

// SetupKnowledgeAndConfigTestDB sets up both knowledge and config database connections for testing
func SetupKnowledgeAndConfigTestDB(t *testing.T) (*bun.DB, *bun.DB, func()) {
	service, cleanup := setupService(t)
	if service == nil {
		return nil, nil, func() {}
	}
	return service.DB.Knowledge, service.DB.Config, cleanup
}

// setupService creates a knowledge service for testing
func setupService(t *testing.T) (*knowledgeService, func()) {
	// Set test database environment
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	// Create KnowledgeService for testing
	service, err := createKnowledgeService()
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		service.Close()
	}

	return service, cleanup
}

// createKnowledgeService creates a knowledge service instance
func createKnowledgeService() (*knowledgeService, error) {
	// Initialize ServiceBase for database connections
	serviceBase, err := boilerplates.CreateServiceBase()
	if err != nil {
		return nil, err
	}

	service := &knowledgeService{
		serviceBase: serviceBase,
		DB:          serviceBase.DB,
	}

	return service, nil
}

// knowledgeService wraps database connections for testing
type knowledgeService struct {
	serviceBase *boilerplates.ServiceBase
	DB          *boilerplates.ServiceDatabases
}

// Close closes the ServiceBase and all database connections
func (s *knowledgeService) Close() {
	if s.serviceBase != nil {
		s.serviceBase.Close()
	}
}
