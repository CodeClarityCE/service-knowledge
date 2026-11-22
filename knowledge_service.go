package main

import (
	"log"

	"github.com/CodeClarityCE/utility-boilerplates"
	"github.com/sirupsen/logrus"
)

// KnowledgeService wraps database connections for the knowledge service
type KnowledgeService struct {
	serviceBase *boilerplates.ServiceBase
	DB          *boilerplates.ServiceDatabases
}

// KnowledgeService creates a new KnowledgeService with database connections
func CreateKnowledgeService() (*KnowledgeService, error) {
	// Initialize ServiceBase for database connections
	serviceBase, err := boilerplates.CreateServiceBase()
	if err != nil {
		return nil, err
	}

	service := &KnowledgeService{
		serviceBase: serviceBase,
		DB:          serviceBase.DB,
	}

	log.Printf("Knowledge service initialized with database connections")
	return service, nil
}

// Close closes the ServiceBase and all database connections
func (s *KnowledgeService) Close() {
	if s.serviceBase != nil {
		if err := s.serviceBase.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close the knowledge service")
		}
	}
}
