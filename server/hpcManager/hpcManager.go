package hpcManager

import (
	"context"
	"fmt"
	"time"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/hpc_management"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/dbManager"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/server/statusManager"
	"github.com/go-openapi/runtime/middleware"
)

const (
	statusDuplicated = iota
	statusFail
	statusMissing
	statusOK
	statusForbidden
)

// HPCResourceManager is the struct defined to group and contain all the methods
// that interact with the hpcresource endpoint.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
// - BasePath: a string with the base path of the system.
type HPCResourceManager struct {
	db       *dbManager.DbParameter
	monit    *statusManager.StatusManager
	BasePath string
}

// New is the function to create the struct HPCResourceManager that grant access
// to the methods to interact with the HPCResource endpoint.
// Parameters:
// - db: a reference to the DbParameter to be able to interact with the db methods.
// - bp: a string containing the base path of the service.
// Returns:
// - HPCResourceManager: struct to interact with hpcresource endpoint functionalities.
func New(db *dbManager.DbParameter, monit *statusManager.StatusManager, bp string) *HPCResourceManager {

	monit.InitEndpoint("hpcresource")

	return &HPCResourceManager{
		db:       db,
		monit:    monit,
		BasePath: bp,
	}

}

// CreateHPCResource (Swagger func) is the function behind the (POST) API Endpoint
// /hpc/resource
// Its function is to create a new hpcresource with the model provided.
func (m *HPCResourceManager) CreateHPCResource(ctx context.Context, params hpc_management.CreateHPCResourceParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("hpcresource", callTime)

	i, s, e := m.db.AddHPCResource(ctx, *params.HPCResource)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("hpc", callTime)

		return hpc_management.NewCreateHPCResourceForbidden().WithPayload(&rValue)

	case statusDuplicated:

		rValue := models.ConflictResponse{
			Message: "The Resource already exists in the system.",
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewCreateHPCResourceConflict().WithPayload(&rValue)

	case statusOK:

		rValue := models.CreatedResponse{
			ID:   i,
			Link: m.BasePath + "/hpc/resource/" + i,
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewCreateHPCResourceCreated().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewCreateHPCResourceInternalServerError().WithPayload(&rValue)

	}

}

// DeleteHPCResource (Swagger func) is the function behind the (DELETE) API Endpoint
// /hpc/resource/{id}
// Its function is to delete the information that the system has about the
// hpcresource whose ID is provided.
func (m *HPCResourceManager) DeleteHPCResource(ctx context.Context, params hpc_management.DeleteHPCResourceParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("hpcresource", callTime)

	s, e := m.db.DeleteHPCResource(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("hpc", callTime)

		return hpc_management.NewDeleteHPCResourceForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Resource couldn't be found in the system.",
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewDeleteHPCResourceNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			ID:      (string)(params.ID),
			Message: "The Resource was removed from the system.",
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewDeleteHPCResourceOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewDeleteHPCResourceInternalServerError().WithPayload(&rValue)

	}

}

// GetHPCResource (Swagger func) is the function behind the (GET) API Endpoint
// /hpc/resource
// Its function is to retrieve the information that the system has about the
// hpcresource whose ID is provided.
func (m *HPCResourceManager) GetHPCResource(ctx context.Context, params hpc_management.GetHPCResourceParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("hpcresource", callTime)

	h, s, e := m.db.GetHPCResource(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("hpc", callTime)

		return hpc_management.NewGetHPCResourceForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Resource couldn't be found in the system.",
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewGetHPCResourceNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewGetHPCResourceOK().WithPayload(h)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewGetHPCResourceInternalServerError().WithPayload(&rValue)

	}
}

// ListHPCResources (Swagger func) is the function behind the (GET) API Endpoint
// /hpc/resource/{id}
// Its function is to provide a list containing all the hpcresource in the system.
func (m *HPCResourceManager) ListHPCResources(ctx context.Context, params hpc_management.ListHPCResourcesParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("hpcresource", callTime)

	l, s, e := m.db.ListHPCResources(ctx, *params.Scope)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("hpc", callTime)

		return hpc_management.NewListHPCResourcesForbidden().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewListHPCResourcesOK().WithPayload(l)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewListHPCResourcesInternalServerError().WithPayload(&rValue)

	}
}

// UpdateHPCResource (Swagger func) is the function behind the (PUT) API Endpoint
// /hpc/resource/{id}
// Its function is to update the hpcresource whose ID is provided with the new data.
func (m *HPCResourceManager) UpdateHPCResource(ctx context.Context, params hpc_management.UpdateHPCResourceParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("hpcresource", callTime)

	hpcresource := params.HPCResource
	hpcresource.HPCResourceID = params.ID

	h, s, e := m.db.UpdateHPCResource(ctx, *hpcresource)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("hpc", callTime)

		return hpc_management.NewUpdateHPCResourceForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Resource couldn't be found in the system.",
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewUpdateHPCResourceNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewUpdateHPCResourceOK().WithPayload(h)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("hpcresource", callTime)

		return hpc_management.NewUpdateHPCResourceInternalServerError().WithPayload(&rValue)

	}

}
