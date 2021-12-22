package organizationManager

import (
	"context"
	"fmt"
	"time"

	"github.com/lexis-project/lexis-backend-services-userorg-service.git/models"
	"github.com/lexis-project/lexis-backend-services-userorg-service.git/restapi/operations/organization_management"
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

// OrganizationManager is the struct defined to group and contain all the methods
// that interact with the organization endpoint.
// Parameters:
// - db: a DbParameter reference to be able to use the DBManager methods.
// - BasePath: a string with the base path of the system.
type OrganizationManager struct {
	db       *dbManager.DbParameter
	monit    *statusManager.StatusManager
	BasePath string
}

// New is the function to create the struct OrganizationManager that grant access
// to the methods to interact with the Organization endpoint.
// Parameters:
// - db: a reference to the DbParameter to be able to interact with the db methods.
// - monit: a reference to the StatusManager to be able to interact with the
// status subsystem.
// - bp: a string containing the base path of the service.
// Returns:
// - OrganizationManager: struct to interact with organization endpoint functionalities.
func New(db *dbManager.DbParameter, monit *statusManager.StatusManager, bp string) *OrganizationManager {

	monit.InitEndpoint("organization")

	return &OrganizationManager{
		db:       db,
		monit:    monit,
		BasePath: bp,
	}

}

// CreateOrganization (Swagger func) is the function behind the (POST) API Endpoint
// /organization
// Its function is to create a new organization with the model provided.
func (m *OrganizationManager) CreateOrganization(ctx context.Context, params organization_management.CreateOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	i, s, e := m.db.AddOrganization(ctx, *params.Organization)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewCreateOrganizationForbidden().WithPayload(&rValue)

	case statusDuplicated:

		rValue := models.ConflictResponse{
			Message: "The Organization already exists in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewCreateOrganizationConflict().WithPayload(&rValue)

	case statusOK:

		rValue := models.CreatedResponse{
			ID:   i.String(),
			Link: m.BasePath + "/organization/" + i.String(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewCreateOrganizationCreated().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewCreateOrganizationInternalServerError().WithPayload(&rValue)

	}

}

// DeleteOrganization (Swagger func) is the function behind the (DELETE) API Endpoint
// /organization/{id}
// Its function is to delete the information that the system has about the
// organization whose ID is provided.
func (m *OrganizationManager) DeleteOrganization(ctx context.Context, params organization_management.DeleteOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	s, e := m.db.DeleteOrganization(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteOrganizationForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Organization couldn't be found in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteOrganizationNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			ID:      (string)(params.ID),
			Message: "The Organization was deleted from the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteOrganizationOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteOrganizationInternalServerError().WithPayload(&rValue)

	}

}

// GetOrganization (Swagger func) is the function behind the (GET) API Endpoint
// /organization
// Its function is to retrieve the information that the system has about the
// organization whose ID is provided.
func (m *OrganizationManager) GetOrganization(ctx context.Context, params organization_management.GetOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	o, s, e := m.db.GetOrganization(ctx, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewGetOrganizationForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Organization couldn't be found in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewGetOrganizationNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewGetOrganizationOK().WithPayload(o)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewGetOrganizationInternalServerError().WithPayload(&rValue)

	}

}

// ListOrganizations (Swagger func) is the function behind the (GET) API Endpoint
// /organization/{id}
// Its function is to provide a list containing all the organization in the system.
func (m *OrganizationManager) ListOrganizations(ctx context.Context, params organization_management.ListOrganizationsParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	l, s, e := m.db.ListOrganizations(ctx, *params.Scope)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewListOrganizationsForbidden().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewListOrganizationsOK().WithPayload(l)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewListOrganizationsInternalServerError().WithPayload(&rValue)

	}

}

// UpdateOrganization (Swagger func) is the function behind the (PUT) API Endpoint
// /organization/{id}
// Its function is to update the organization whose ID is provided with the new data.
func (m *OrganizationManager) UpdateOrganization(ctx context.Context, params organization_management.UpdateOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	org := params.Organization
	org.ID = params.ID

	o, s, e := m.db.UpdateOrganization(ctx, *org)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewUpdateOrganizationForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Organization couldn't be found in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewUpdateOrganizationNotFound().WithPayload(&rValue)

	case statusOK:

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewUpdateOrganizationOK().WithPayload(o)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewUpdateOrganizationInternalServerError().WithPayload(&rValue)

	}

}

func (m *OrganizationManager) AddUserToOrganization(ctx context.Context, params organization_management.AddUserToOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	s, e := m.db.AddUserToOrg(ctx, params.UserID, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewAddUserToOrganizationForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Organization/User couldn't be found in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewAddUserToOrganizationNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.OKResponse{
			Message: "User updated successfully.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewAddUserToOrganizationOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewAddUserToOrganizationInternalServerError().WithPayload(&rValue)

	}

}

func (m *OrganizationManager) DeleteUserFromOrganization(ctx context.Context, params organization_management.DeleteUserFromOrganizationParams) middleware.Responder {

	callTime := time.Now()
	m.monit.APIHit("organization", callTime)

	s, e := m.db.DeleteUserFromOrg(ctx, params.UserID, params.ID)

	switch s {

	case statusForbidden:

		rValue := models.ErrorResponse{
			Message: e.Error(),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteUserFromOrganizationForbidden().WithPayload(&rValue)

	case statusMissing:

		rValue := models.MissingResponse{
			Message: "The Organization/User couldn't be found in the system.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteUserFromOrganizationNotFound().WithPayload(&rValue)

	case statusOK:

		rValue := models.DeletedResponse{
			Message: "User updated successfully.",
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteUserFromOrganizationOK().WithPayload(&rValue)

	default:

		rValue := models.ErrorResponse{
			Message: fmt.Sprintf("Something unexpected happened. Error: %v", e),
		}

		m.monit.APIHitDone("organization", callTime)

		return organization_management.NewDeleteUserFromOrganizationInternalServerError().WithPayload(&rValue)

	}

}
